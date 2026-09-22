package capability

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testRESTHandler(t *testing.T) (*RESTHandler, string) {
	t.Helper()
	store, _ := openTestCapabilityStore(t)
	handle, err := store.Issue(context.Background(), enabledClaims(t, time.Now().Add(time.Hour)))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	return NewRESTHandler(store, "test-token"), handle
}

func do(t *testing.T, h http.Handler, method, path, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatalf("encode body: %v", err)
		}
	}
	req := httptest.NewRequest(method, path, &buf)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestRESTRequiresAuth(t *testing.T) {
	h, handle := testRESTHandler(t)
	rec := do(t, h, http.MethodPost, "/v1/capabilities/verify", "", verifyRequest{Handle: handle})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token = %d, want 401", rec.Code)
	}
	rec = do(t, h, http.MethodPost, "/v1/capabilities/verify", "wrong", verifyRequest{Handle: handle})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token = %d, want 401", rec.Code)
	}
}

func TestRESTDisabledWithoutStoreOrToken(t *testing.T) {
	h := NewRESTHandler(nil, "test-token")
	rec := do(t, h, http.MethodPost, "/v1/capabilities/verify", "test-token", verifyRequest{Handle: "x"})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("nil store = %d, want 404", rec.Code)
	}
	store, _ := openTestCapabilityStore(t)
	h2 := NewRESTHandler(store, "")
	rec = do(t, h2, http.MethodPost, "/v1/capabilities/verify", "anything", verifyRequest{Handle: "x"})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("empty token = %d, want 404", rec.Code)
	}
}

func TestRESTRejectsGET(t *testing.T) {
	h, _ := testRESTHandler(t)
	rec := do(t, h, http.MethodGet, "/v1/capabilities/verify", "test-token", nil)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET = %d, want 405", rec.Code)
	}
}

func TestRESTVerifyReserveRevokeFlow(t *testing.T) {
	h, handle := testRESTHandler(t)

	rec := do(t, h, http.MethodPost, "/v1/capabilities/verify", "test-token", verifyRequest{Handle: handle})
	if rec.Code != http.StatusOK {
		t.Fatalf("verify = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), handle) {
		t.Fatal("verify response echoed the plaintext handle")
	}
	var vr verifyResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &vr); err != nil {
		t.Fatalf("decode verify: %v", err)
	}
	if vr.RunID != "run-1" {
		t.Fatalf("verify run_id = %q", vr.RunID)
	}

	rec = do(t, h, http.MethodPost, "/v1/capabilities/reserve", "test-token",
		reserveRequest{Handle: handle, Model: "anthropic/claude", Calls: 1, Tokens: 10})
	if rec.Code != http.StatusOK {
		t.Fatalf("reserve = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	var rr reserveResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &rr); err != nil {
		t.Fatalf("decode reserve: %v", err)
	}
	if rr.ReservedCalls != 1 || rr.ReservedTokens != 10 {
		t.Fatalf("reserve response = %+v", rr)
	}

	rec = do(t, h, http.MethodPost, "/v1/capabilities/revoke", "test-token", revokeRequest{Handle: handle})
	if rec.Code != http.StatusNoContent {
		t.Fatalf("revoke = %d, want 204", rec.Code)
	}
	// After revoke, verify is a conflict.
	rec = do(t, h, http.MethodPost, "/v1/capabilities/verify", "test-token", verifyRequest{Handle: handle})
	if rec.Code != http.StatusConflict {
		t.Fatalf("verify after revoke = %d, want 409", rec.Code)
	}
}

func TestRESTReserveRejectsNegative(t *testing.T) {
	h, handle := testRESTHandler(t)
	rec := do(t, h, http.MethodPost, "/v1/capabilities/reserve", "test-token",
		reserveRequest{Handle: handle, Calls: -1})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("negative reserve = %d, want 400", rec.Code)
	}
}

func TestRESTMalformedHandle(t *testing.T) {
	h, _ := testRESTHandler(t)
	rec := do(t, h, http.MethodPost, "/v1/capabilities/verify", "test-token", verifyRequest{Handle: "nope"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("malformed handle = %d, want 400", rec.Code)
	}
}

func TestRESTUnknownPath(t *testing.T) {
	h, _ := testRESTHandler(t)
	rec := do(t, h, http.MethodPost, "/v1/capabilities/frobnicate", "test-token", map[string]string{})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown path = %d, want 404", rec.Code)
	}
}
