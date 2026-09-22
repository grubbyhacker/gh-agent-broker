package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"gh-agent-broker/internal/capability"
)

// capTestFixture wires the proxy Service against a REAL broker capability store
// mounted behind the private REST API, so seam tests exercise the actual
// verify/reserve transaction rather than a mock. The proxy's capability client
// authenticates to the API with a static token; a run authenticates to the
// proxy with its opaque handle.
type capTestFixture struct {
	svc      *Service
	store    *capability.Store
	api      *httptest.Server
	upstream *httptest.Server
	auditP   string
}

// capAPIAuth is the static token the fake private capability API accepts; it is
// a test fixture value, not a real credential.
const capAPIAuth = "cap-fixture-value" // #nosec G101 -- test fixture, not a credential

func newCapFixture(t *testing.T, upstreamHandler http.HandlerFunc) *capTestFixture {
	t.Helper()
	dir := t.TempDir()
	store, err := capability.OpenStore(context.Background(), filepath.Join(dir, "cap.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("close capability store: %v", err)
		}
	})

	mux := http.NewServeMux()
	mux.Handle("/v1/capabilities/", capability.NewRESTHandler(store, capAPIAuth))
	api := httptest.NewServer(mux)
	t.Cleanup(api.Close)

	if upstreamHandler == nil {
		upstreamHandler = func(w http.ResponseWriter, r *http.Request) {
			writeProxyTestJSON(t, w, map[string]interface{}{
				"id": "chat-1", "model": "gpt-test",
				"choices": []map[string]interface{}{{"message": map[string]interface{}{"content": `{"ok":true}`}}},
				"usage":   map[string]int{"total_tokens": 7},
			})
		}
	}
	upstream := httptest.NewServer(upstreamHandler)
	t.Cleanup(upstream.Close)

	auditP := filepath.Join(dir, "audit.jsonl")
	svc, err := NewService(Config{
		AuthToken:          "proxy-token",
		CodexAuthToken:     "codex-token",
		UpstreamURL:        upstream.URL + "/v1",
		UpstreamKey:        "upstream-secret",
		CodexUpstreamKey:   "codex-upstream-secret",
		AllowedModels:      []string{"gpt-test"},
		CodexAllowedModels: []CodexModelConfig{{Name: "ykm-codex-haiku", UpstreamModel: "anthropic/claude-haiku-4.5"}, {Name: "ykm-codex-sonnet", UpstreamModel: "anthropic/claude-sonnet-4.5"}},
		StatePath:          filepath.Join(dir, "state.json"),
		AuditPath:          auditP,
		MaxCallsPerRun:     999, // legacy local budget must be unused under enforcement
		MaxTokensPerRun:    999999,
		MaxRequestBytes:    4096,
		MaxResponseBytes:   4096,
		Timeout:            Duration{2 * time.Second},
		CapabilityAPIURL:   api.URL,
		CapabilityAPIToken: capAPIAuth,
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	t.Cleanup(func() {
		if err := svc.audit.Close(); err != nil {
			t.Errorf("close audit: %v", err)
		}
	})
	return &capTestFixture{svc: svc, store: store, api: api, upstream: upstream, auditP: auditP}
}

func (f *capTestFixture) issueEnabled(t *testing.T, runID, workItemID string, calls, tokens int64, expiry time.Time, models ...string) string {
	t.Helper()
	claims, err := capability.NewClaims(capability.ClaimsInput{
		AgentType: "curator", Mode: "reconcile", RunID: runID, WorkItemID: workItemID,
		AllowedModels: models, CallBudget: calls, TokenBudget: tokens, Expiry: expiry,
	})
	if err != nil {
		t.Fatalf("NewClaims: %v", err)
	}
	handle, err := f.store.Issue(context.Background(), claims)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	return handle
}

func modelCallWithHandle(svc *Service, handle, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/v1/model/call", bytes.NewBufferString(body))
	if handle != "" {
		req.Header.Set("Authorization", "Bearer "+handle)
	}
	resp := httptest.NewRecorder()
	svc.ServeHTTP(resp, req)
	return resp
}

func decodeJSONBody(t *testing.T, r *http.Request, out any) {
	t.Helper()
	if err := json.NewDecoder(r.Body).Decode(out); err != nil {
		t.Fatalf("decode upstream body: %v", err)
	}
}

func TestCapabilityConfigEnablesEnforcement(t *testing.T) {
	f := newCapFixture(t, nil)
	if !f.svc.cfg.capabilityEnabled() {
		t.Fatal("capabilityEnabled = false with URL+token set")
	}
	if f.svc.caps == nil {
		t.Fatal("caps client not constructed")
	}
}

func TestCapabilityPartialConfigRejected(t *testing.T) {
	base := Config{
		AuthToken: "t", UpstreamURL: "http://u/v1", AllowedModels: []string{"m"},
		StatePath: "/tmp/x", MaxCallsPerRun: 1, MaxTokensPerRun: 1, MaxRequestBytes: 1, MaxResponseBytes: 1,
	}
	urlOnly := base
	urlOnly.CapabilityAPIURL = "http://cap/"
	if err := urlOnly.Validate(); err == nil {
		t.Fatal("URL without token should be rejected")
	}
	tokenOnly := base
	tokenOnly.CapabilityAPIToken = "tok"
	if err := tokenOnly.Validate(); err == nil {
		t.Fatal("token without URL should be rejected")
	}
	badScheme := base
	badScheme.CapabilityAPIURL = "cap-host:9000"
	badScheme.CapabilityAPIToken = "tok"
	if err := badScheme.Validate(); err == nil {
		t.Fatal("non-http capability URL should be rejected")
	}
}

func TestModelCallCapabilityHappyPathDerivesVerifiedRunID(t *testing.T) {
	f := newCapFixture(t, func(w http.ResponseWriter, r *http.Request) {
		writeProxyTestJSON(t, w, map[string]interface{}{
			"id": "chat-1", "model": "gpt-test",
			"choices": []map[string]interface{}{{"message": map[string]interface{}{"content": "ok"}}},
			"usage":   map[string]int{"total_tokens": 5},
		})
	})
	handle := f.issueEnabled(t, "run-verified", "wi-1", 3, 100, time.Now().Add(time.Hour), "gpt-test")
	// Caller asserts NO run_id in body; identity is derived from the handle.
	requestBody := `{"model":"gpt-test","max_tokens":10,"messages":[{"role":"user","content":"x"}]}`
	resp := modelCallWithHandle(f.svc, handle, requestBody)
	if resp.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", resp.Code, resp.Body.String())
	}
	claims, res, err := f.store.Verify(context.Background(), handle)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.RunID() != "run-verified" {
		t.Fatalf("run id = %q", claims.RunID())
	}
	wantTokens := int64(len(requestBody) + 10)
	if res.Calls != 1 || res.Tokens != wantTokens {
		t.Fatalf("reservation = %+v, want 1 call / %d preflight tokens", res, wantTokens)
	}
	audit := readTestFile(t, f.auditP)
	if strings.Contains(audit, handle) {
		t.Fatal("audit leaked the plaintext handle")
	}
	if !strings.Contains(audit, `"run_id":"run-verified"`) {
		t.Fatalf("audit missing verified run id: %s", audit)
	}
}

func TestModelCallCapabilityRejectsSpoofedRunID(t *testing.T) {
	f := newCapFixture(t, nil)
	handle := f.issueEnabled(t, "run-real", "wi-1", 3, 100, time.Now().Add(time.Hour), "gpt-test")
	// Caller supplies a DIFFERENT run_id than the handle's verified claim.
	resp := modelCallWithHandle(f.svc, handle, `{"run_id":"run-attacker","model":"gpt-test","max_tokens":10,"messages":[{"role":"user","content":"x"}]}`)
	if resp.Code != http.StatusForbidden {
		t.Fatalf("spoofed run_id status = %d, want 403; body=%s", resp.Code, resp.Body.String())
	}
	if !strings.Contains(resp.Body.String(), "run_id_mismatch") {
		t.Fatalf("body = %s, want run_id_mismatch", resp.Body.String())
	}
	// No reservation may have been recorded for the spoof attempt.
	_, res, err := f.store.Verify(context.Background(), handle)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Calls != 0 || res.Tokens != 0 {
		t.Fatalf("reservation = %+v after spoof, want zero", res)
	}
}

func TestModelCallCapabilityMissingHandle(t *testing.T) {
	f := newCapFixture(t, nil)
	resp := modelCallWithHandle(f.svc, "", `{"model":"gpt-test","max_tokens":10,"messages":[{"role":"user","content":"x"}]}`)
	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("missing handle status = %d, want 401", resp.Code)
	}
	if got := resp.Header().Get("WWW-Authenticate"); got == "" {
		t.Fatal("missing WWW-Authenticate challenge")
	}
}

func TestModelCallCapabilityModelDenied(t *testing.T) {
	f := newCapFixture(t, nil)
	handle := f.issueEnabled(t, "run-1", "wi-1", 3, 100, time.Now().Add(time.Hour), "gpt-test")
	resp := modelCallWithHandle(f.svc, handle, `{"model":"forbidden-model","max_tokens":10,"messages":[{"role":"user","content":"x"}]}`)
	if resp.Code != http.StatusForbidden {
		t.Fatalf("denied model status = %d, want 403", resp.Code)
	}
	if !strings.Contains(resp.Body.String(), "capability_denied") {
		t.Fatalf("body = %s", resp.Body.String())
	}
}

func TestModelCallCapabilityModelDisabledDeniesAllCalls(t *testing.T) {
	f := newCapFixture(t, nil)
	// model-disabled capability: no models, zero budgets.
	handle := f.issueEnabled(t, "run-id-only", "wi-1", 0, 0, time.Now().Add(time.Hour))
	resp := modelCallWithHandle(f.svc, handle, `{"model":"gpt-test","max_tokens":10,"messages":[{"role":"user","content":"x"}]}`)
	if resp.Code != http.StatusForbidden {
		t.Fatalf("model-disabled status = %d, want 403", resp.Code)
	}
}

func TestModelCallCapabilityCallBudgetExhausted(t *testing.T) {
	f := newCapFixture(t, nil)
	handle := f.issueEnabled(t, "run-1", "wi-1", 1, 100, time.Now().Add(time.Hour), "gpt-test")
	if resp := modelCallWithHandle(f.svc, handle, `{"model":"gpt-test","max_tokens":10,"messages":[{"role":"user","content":"x"}]}`); resp.Code != http.StatusOK {
		t.Fatalf("first call status = %d", resp.Code)
	}
	resp := modelCallWithHandle(f.svc, handle, `{"model":"gpt-test","max_tokens":10,"messages":[{"role":"user","content":"x"}]}`)
	if resp.Code != http.StatusForbidden {
		t.Fatalf("budget-exhausted status = %d, want 403", resp.Code)
	}
	if !strings.Contains(resp.Body.String(), "capability_denied") {
		t.Fatalf("body = %s", resp.Body.String())
	}
}

func TestModelCallCapabilityExpiredFailsClosed(t *testing.T) {
	f := newCapFixture(t, nil)
	handle := f.issueEnabled(t, "run-1", "wi-1", 3, 100, time.Now().Add(50*time.Millisecond), "gpt-test")
	time.Sleep(80 * time.Millisecond)
	resp := modelCallWithHandle(f.svc, handle, `{"model":"gpt-test","max_tokens":10,"messages":[{"role":"user","content":"x"}]}`)
	if resp.Code != http.StatusForbidden {
		t.Fatalf("expired status = %d, want 403", resp.Code)
	}
}

func TestModelCallCapabilityRevokedFailsClosed(t *testing.T) {
	f := newCapFixture(t, nil)
	handle := f.issueEnabled(t, "run-1", "wi-1", 3, 100, time.Now().Add(time.Hour), "gpt-test")
	if err := f.store.Revoke(context.Background(), handle); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	resp := modelCallWithHandle(f.svc, handle, `{"model":"gpt-test","max_tokens":10,"messages":[{"role":"user","content":"x"}]}`)
	if resp.Code != http.StatusForbidden {
		t.Fatalf("revoked status = %d, want 403", resp.Code)
	}
}

func TestModelCallCapabilityAPIUnavailableFailsClosed(t *testing.T) {
	f := newCapFixture(t, nil)
	handle := f.issueEnabled(t, "run-1", "wi-1", 3, 100, time.Now().Add(time.Hour), "gpt-test")
	f.api.Close() // authority is now unreachable
	resp := modelCallWithHandle(f.svc, handle, `{"model":"gpt-test","max_tokens":10,"messages":[{"role":"user","content":"x"}]}`)
	if resp.Code != http.StatusServiceUnavailable {
		t.Fatalf("unavailable status = %d, want 503", resp.Code)
	}
	if !strings.Contains(resp.Body.String(), "capability_unavailable") {
		t.Fatalf("body = %s", resp.Body.String())
	}
}

func TestModelCallCapabilityWrongAPITokenFailsClosed(t *testing.T) {
	f := newCapFixture(t, nil)
	// Corrupt the client's API token: the private API returns 401 -> fail closed.
	f.svc.caps.token = "wrong-token"
	handle := f.issueEnabled(t, "run-1", "wi-1", 3, 100, time.Now().Add(time.Hour), "gpt-test")
	resp := modelCallWithHandle(f.svc, handle, `{"model":"gpt-test","max_tokens":10,"messages":[{"role":"user","content":"x"}]}`)
	if resp.Code != http.StatusForbidden {
		t.Fatalf("bad api token status = %d, want 403", resp.Code)
	}
}

// TestModelCallCapabilityConcurrentReservationRespectsBudget drives N concurrent
// model calls on ONE handle whose call budget is less than N, and asserts that
// exactly budget calls are allowed — the broker's atomic reserve transaction is
// the single serialization point. This is the concurrent-reservation seam test.
func TestModelCallCapabilityConcurrentReservationRespectsBudget(t *testing.T) {
	f := newCapFixture(t, func(w http.ResponseWriter, r *http.Request) {
		writeProxyTestJSON(t, w, map[string]interface{}{
			"id": "chat", "model": "gpt-test",
			"choices": []map[string]interface{}{{"message": map[string]interface{}{"content": "ok"}}},
			"usage":   map[string]int{"total_tokens": 0},
		})
	})
	const budget = 5
	const attempts = 40
	handle := f.issueEnabled(t, "run-race", "wi-1", budget, 1000, time.Now().Add(time.Hour), "gpt-test")

	var wg sync.WaitGroup
	var mu sync.Mutex
	allowed, denied := 0, 0
	wg.Add(attempts)
	for i := 0; i < attempts; i++ {
		go func() {
			defer wg.Done()
			resp := modelCallWithHandle(f.svc, handle, `{"model":"gpt-test","max_tokens":10,"messages":[{"role":"user","content":"x"}]}`)
			mu.Lock()
			defer mu.Unlock()
			switch resp.Code {
			case http.StatusOK:
				allowed++
			case http.StatusForbidden:
				denied++
			default:
				t.Errorf("unexpected status %d: %s", resp.Code, resp.Body.String())
			}
		}()
	}
	wg.Wait()

	if allowed != budget {
		t.Fatalf("allowed = %d, want exactly %d (budget)", allowed, budget)
	}
	if allowed+denied != attempts {
		t.Fatalf("allowed+denied = %d, want %d", allowed+denied, attempts)
	}
	_, res, err := f.store.Verify(context.Background(), handle)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Calls != budget {
		t.Fatalf("final reserved calls = %d, want %d", res.Calls, budget)
	}
}

// codexResponseWithHandle drives the codex surface under enforcement: the handle
// is the Bearer credential; X-GH-Agent-Run-ID (if set) is the legacy caller
// field used only to reject a mismatch.
func codexResponseWithHandle(svc *Service, handle, body, callerRunID string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/v1/responses", bytes.NewBufferString(body))
	if handle != "" {
		req.Header.Set("Authorization", "Bearer "+handle)
	}
	if callerRunID != "" {
		req.Header.Set("X-GH-Agent-Run-ID", callerRunID)
	}
	resp := httptest.NewRecorder()
	svc.ServeHTTP(resp, req)
	return resp
}

func TestCodexResponsesCapabilityDerivesRunIDAndReserves(t *testing.T) {
	var upstreamModel string
	f := newCapFixture(t, func(w http.ResponseWriter, r *http.Request) {
		var b struct {
			Model string `json:"model"`
		}
		decodeJSONBody(t, r, &b)
		upstreamModel = b.Model
		writeProxyTestJSON(t, w, map[string]interface{}{
			"id": "resp-1", "object": "response", "model": b.Model,
			"usage": map[string]int{"total_tokens": 6},
		})
	})
	handle := f.issueEnabled(t, "run-codex", "wi-1", 3, 100, time.Now().Add(time.Hour), "ykm-codex-haiku")
	requestBody := `{"model":"ykm-codex-haiku","max_output_tokens":10,"input":"x"}`
	resp := codexResponseWithHandle(f.svc, handle, requestBody, "")
	if resp.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", resp.Code, resp.Body.String())
	}
	if upstreamModel != "anthropic/claude-haiku-4.5" {
		t.Fatalf("upstream model = %q", upstreamModel)
	}
	_, res, err := f.store.Verify(context.Background(), handle)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	rewritten, err := rewriteJSONModel([]byte(requestBody), "anthropic/claude-haiku-4.5")
	if err != nil {
		t.Fatalf("rewriteJSONModel: %v", err)
	}
	wantTokens := int64(len(rewritten) + 10)
	if res.Calls != 1 || res.Tokens != wantTokens {
		t.Fatalf("reservation = %+v, want 1 call / %d preflight tokens", res, wantTokens)
	}
}

func TestCodexResponsesCapabilityRejectsSpoofedRunID(t *testing.T) {
	f := newCapFixture(t, nil)
	handle := f.issueEnabled(t, "run-real", "wi-1", 3, 100, time.Now().Add(time.Hour), "ykm-codex-haiku")
	resp := codexResponseWithHandle(f.svc, handle, `{"model":"ykm-codex-haiku","max_output_tokens":10,"input":"x"}`, "run-attacker")
	if resp.Code != http.StatusForbidden {
		t.Fatalf("spoofed run id status = %d, want 403", resp.Code)
	}
	if !strings.Contains(resp.Body.String(), "run_id_mismatch") {
		t.Fatalf("body = %s", resp.Body.String())
	}
}

func TestCodexResponsesCapabilityModelDenied(t *testing.T) {
	f := newCapFixture(t, nil)
	// Handle grants ykm-codex-haiku, request a codex alias not in allowed_models.
	handle := f.issueEnabled(t, "run-1", "wi-1", 3, 100, time.Now().Add(time.Hour), "ykm-codex-haiku")
	resp := codexResponseWithHandle(f.svc, handle, `{"model":"ykm-codex-sonnet","max_output_tokens":10,"input":"x"}`, "")
	if resp.Code != http.StatusForbidden {
		t.Fatalf("denied model status = %d, want 403; body=%s", resp.Code, resp.Body.String())
	}
}

func TestModelCallCapabilityRequiresMaxTokensBeforeUpstream(t *testing.T) {
	called := false
	f := newCapFixture(t, func(w http.ResponseWriter, r *http.Request) {
		called = true
		writeProxyTestJSON(t, w, map[string]string{"unexpected": "upstream call"})
	})
	handle := f.issueEnabled(t, "run-1", "wi-1", 1, 100, time.Now().Add(time.Hour), "gpt-test")
	resp := modelCallWithHandle(f.svc, handle, `{"model":"gpt-test","messages":[{"role":"user","content":"x"}]}`)
	if resp.Code != http.StatusBadRequest || !strings.Contains(resp.Body.String(), "max_tokens_required") {
		t.Fatalf("status=%d body=%s", resp.Code, resp.Body.String())
	}
	if called {
		t.Fatal("upstream called without a pre-reserved output cap")
	}
	_, res, err := f.store.Verify(context.Background(), handle)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Calls != 0 || res.Tokens != 0 {
		t.Fatalf("reservation = %+v, want zero", res)
	}
}

func TestModelCallCapabilityTokenBudgetDeniedBeforeUpstream(t *testing.T) {
	called := false
	f := newCapFixture(t, func(w http.ResponseWriter, r *http.Request) {
		called = true
		writeProxyTestJSON(t, w, map[string]string{"unexpected": "upstream call"})
	})
	handle := f.issueEnabled(t, "run-1", "wi-1", 1, 1, time.Now().Add(time.Hour), "gpt-test")
	resp := modelCallWithHandle(f.svc, handle, `{"model":"gpt-test","max_tokens":10,"messages":[{"role":"user","content":"x"}]}`)
	if resp.Code != http.StatusForbidden || !strings.Contains(resp.Body.String(), "capability_denied") {
		t.Fatalf("status=%d body=%s", resp.Code, resp.Body.String())
	}
	if called {
		t.Fatal("upstream called after preflight token-budget denial")
	}
}

func TestCodexCapabilityRequiresMaxOutputTokensBeforeUpstream(t *testing.T) {
	called := false
	f := newCapFixture(t, func(w http.ResponseWriter, r *http.Request) {
		called = true
		writeProxyTestJSON(t, w, map[string]string{"unexpected": "upstream call"})
	})
	handle := f.issueEnabled(t, "run-codex", "wi-1", 1, 100, time.Now().Add(time.Hour), "ykm-codex-haiku")
	resp := codexResponseWithHandle(f.svc, handle, `{"model":"ykm-codex-haiku","input":"x"}`, "")
	if resp.Code != http.StatusBadRequest || !strings.Contains(resp.Body.String(), "max_output_tokens_required") {
		t.Fatalf("status=%d body=%s", resp.Code, resp.Body.String())
	}
	if called {
		t.Fatal("upstream called without a pre-reserved Responses output cap")
	}
}
