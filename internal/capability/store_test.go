package capability

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func openTestCapabilityStore(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "capability.sqlite")
	store, err := OpenStore(context.Background(), path)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("close store: %v", err)
		}
	})
	return store, path
}

func enabledClaims(t *testing.T, expiry time.Time) Claims {
	t.Helper()
	c, err := NewClaims(ClaimsInput{
		AgentType: "coder", Mode: "launch", RunID: "run-1", WorkItemID: "wi-1",
		AllowedModels: []string{"anthropic/claude"}, CallBudget: 5, TokenBudget: 500, Expiry: expiry,
	})
	if err != nil {
		t.Fatalf("NewClaims: %v", err)
	}
	return c
}

func enabledRequest() Request {
	return Request{AgentType: "coder", Mode: "launch", RunID: "run-1", WorkItemID: "wi-1", Model: "anthropic/claude"}
}

func TestIssueReturnsHandleOnceAndStoresHashOnly(t *testing.T) {
	store, path := openTestCapabilityStore(t)
	ctx := context.Background()
	handle, err := store.Issue(ctx, enabledClaims(t, time.Now().Add(time.Hour)))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if len(handle) != handleBytes*2 {
		t.Fatalf("handle length = %d, want %d", len(handle), handleBytes*2)
	}
	// The plaintext handle must NOT appear anywhere in the on-disk store.
	if err := store.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	// #nosec G304 -- path is the test-owned temp store file created above.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read store file: %v", err)
	}
	// The WAL may hold recent writes; check both files.
	blobs := [][]byte{raw}
	// #nosec G304 -- path is the test-owned temp store file created above.
	if wal, err := os.ReadFile(path + "-wal"); err == nil {
		blobs = append(blobs, wal)
	}
	for _, b := range blobs {
		if len(b) > 0 && contains(b, []byte(handle)) {
			t.Fatal("plaintext handle found in the on-disk store")
		}
	}
}

func TestVerifyReturnsTrustedClaims(t *testing.T) {
	store, _ := openTestCapabilityStore(t)
	ctx := context.Background()
	handle, err := store.Issue(ctx, enabledClaims(t, time.Now().Add(time.Hour)))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	claims, res, err := store.Verify(ctx, handle)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.RunID() != "run-1" || claims.AgentType() != "coder" || !claims.AllowsModel("anthropic/claude") {
		t.Fatalf("verified claims = %+v", claims)
	}
	if res.Calls != 0 || res.Tokens != 0 {
		t.Fatalf("fresh reservation = %+v, want zero", res)
	}
}

func TestVerifyRejectsMalformedUnknownRevokedExpired(t *testing.T) {
	store, _ := openTestCapabilityStore(t)
	ctx := context.Background()

	if _, _, err := store.Verify(ctx, "not-hex"); !errors.Is(err, ErrHandleMalformed) {
		t.Fatalf("malformed = %v, want ErrHandleMalformed", err)
	}
	// Well-formed but unknown.
	unknown := "00000000000000000000000000000000000000000000000000000000000000ab"
	if _, _, err := store.Verify(ctx, unknown); !errors.Is(err, ErrHandleNotFound) {
		t.Fatalf("unknown = %v, want ErrHandleNotFound", err)
	}

	revokedHandle, err := store.Issue(ctx, enabledClaims(t, time.Now().Add(time.Hour)))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if err := store.Revoke(ctx, revokedHandle); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, _, err := store.Verify(ctx, revokedHandle); !errors.Is(err, ErrRevoked) {
		t.Fatalf("revoked = %v, want ErrRevoked", err)
	}
	// Revoke is idempotent.
	if err := store.Revoke(ctx, revokedHandle); err != nil {
		t.Fatalf("second Revoke should be no-op success: %v", err)
	}

	// Expired.
	base := time.Date(2026, 9, 22, 0, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return base }
	expHandle, err := store.Issue(ctx, enabledClaims(t, base.Add(time.Minute)))
	if err != nil {
		t.Fatalf("Issue expiring: %v", err)
	}
	store.now = func() time.Time { return base.Add(2 * time.Minute) }
	if _, _, err := store.Verify(ctx, expHandle); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired = %v, want ErrExpired", err)
	}
}

func TestReserveEnforcesBudgetAndAccumulates(t *testing.T) {
	store, _ := openTestCapabilityStore(t)
	ctx := context.Background()
	handle, err := store.Issue(ctx, enabledClaims(t, time.Now().Add(time.Hour))) // call_budget=5, token=500
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	req := enabledRequest()
	req.Calls = 2
	req.Tokens = 200
	res, err := store.Reserve(ctx, handle, req)
	if err != nil {
		t.Fatalf("first Reserve: %v", err)
	}
	if res.Calls != 2 || res.Tokens != 200 {
		t.Fatalf("after first reserve = %+v", res)
	}
	// Second reservation accumulates.
	res, err = store.Reserve(ctx, handle, req)
	if err != nil {
		t.Fatalf("second Reserve: %v", err)
	}
	if res.Calls != 4 || res.Tokens != 400 {
		t.Fatalf("after second reserve = %+v", res)
	}
	// Third would exceed the call budget (4+2=6 > 5).
	if _, err := store.Reserve(ctx, handle, req); !errors.Is(err, ErrCallBudget) {
		t.Fatalf("over-budget Reserve = %v, want ErrCallBudget", err)
	}
}

func TestConcurrentReserveNeverExceedsBudget(t *testing.T) {
	store, _ := openTestCapabilityStore(t)
	ctx := context.Background()
	// call_budget=5: exactly 5 single-call reservations may succeed.
	handle, err := store.Issue(ctx, enabledClaims(t, time.Now().Add(time.Hour)))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	const attempts = 20
	var wg sync.WaitGroup
	var mu sync.Mutex
	success := 0
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := enabledRequest()
			req.Calls = 1
			req.Tokens = 1
			if _, err := store.Reserve(ctx, handle, req); err == nil {
				mu.Lock()
				success++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if success != 5 {
		t.Fatalf("concurrent reservations succeeded %d times, want exactly 5 (call_budget)", success)
	}
	_, res, err := store.Verify(ctx, handle)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Calls != 5 {
		t.Fatalf("final reserved calls = %d, want 5", res.Calls)
	}
}

func TestReserveModelDisabledDeniesModelRequest(t *testing.T) {
	store, _ := openTestCapabilityStore(t)
	ctx := context.Background()
	disabled, err := NewClaims(ClaimsInput{
		AgentType: "youknowme-curator", Mode: "reconcile", RunID: "run-2", WorkItemID: "wi-2",
		AllowedModels: nil, CallBudget: 0, TokenBudget: 0, Expiry: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("NewClaims disabled: %v", err)
	}
	handle, err := store.Issue(ctx, disabled)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	// Identity-only reservation (zero) is allowed.
	idReq := Request{AgentType: "youknowme-curator", Mode: "reconcile", RunID: "run-2", WorkItemID: "wi-2"}
	if _, err := store.Reserve(ctx, handle, idReq); err != nil {
		t.Fatalf("identity-only reserve on model-disabled: %v", err)
	}
	// A model reservation is denied.
	modelReq := idReq
	modelReq.Model = "anything"
	if _, err := store.Reserve(ctx, handle, modelReq); !errors.Is(err, ErrModelDenied) {
		t.Fatalf("model reserve on model-disabled = %v, want ErrModelDenied", err)
	}
}

func TestStoreValidate(t *testing.T) {
	store, _ := openTestCapabilityStore(t)
	ctx := context.Background()
	if _, err := store.Issue(ctx, enabledClaims(t, time.Now().Add(time.Hour))); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if err := store.Validate(ctx); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestOpenStoreRejectsRelativePath(t *testing.T) {
	if _, err := OpenStore(context.Background(), "relative.sqlite"); err == nil {
		t.Fatal("OpenStore accepted a relative path")
	}
}

func contains(haystack, needle []byte) bool {
	if len(needle) == 0 || len(haystack) < len(needle) {
		return false
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if string(haystack[i:i+len(needle)]) == string(needle) {
			return true
		}
	}
	return false
}
