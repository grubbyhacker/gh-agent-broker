package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gh-agent-broker/internal/api"
	"gh-agent-broker/internal/audit"
	"gh-agent-broker/internal/config"
	"gh-agent-broker/internal/correlation"
	"gh-agent-broker/internal/githubapp"
	"gh-agent-broker/internal/idempotency"
)

// capVerifyResult is the fake capability API's programmable verdict.
type capVerifyResult struct {
	status int
	body   map[string]interface{}
}

type corrBrokerFixture struct {
	broker     *Server
	corr       *correlation.Store
	auditPath  string
	idemPath   string
	capToken   string
	createN    *int64 // count of POST /pulls (CreatePull) calls
	sawHandle  *atomic.Value
	openPulls  *[]map[string]interface{}
	capHandler func(handle string) capVerifyResult
}

const corrCapToken = "corr-fixture-value" // #nosec G101 -- test fixture, not a credential

// newCorrelationBroker builds a broker with authenticated correlation enabled,
// wired to a fake capability API and a fake GitHub. capHandler decides each
// verify verdict from the presented handle.
func newCorrelationBroker(t *testing.T, capHandler func(handle string) capVerifyResult) *corrBrokerFixture {
	t.Helper()
	var createN int64
	sawHandle := &atomic.Value{}
	openPulls := &[]map[string]interface{}{}

	// Fake capability API: authenticates with the deployment-owned token and
	// reads the handle from the body only.
	capAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+corrCapToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.URL.Path != "/v1/capabilities/verify" {
			t.Fatalf("unexpected cap API path %s", r.URL.Path)
		}
		var body struct {
			Handle string `json:"handle"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode cap verify body: %v", err)
		}
		sawHandle.Store(body.Handle)
		res := capHandler(body.Handle)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(res.status)
		if res.body != nil {
			if err := json.NewEncoder(w).Encode(res.body); err != nil {
				t.Fatalf("encode cap verify response: %v", err)
			}
		}
	}))
	t.Cleanup(capAPI.Close)

	// Fake GitHub: token issuance, list-open-pulls (reconcile), create-pull.
	ghAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/app/installations/42/access_tokens":
			writeTestJSON(t, w, map[string]string{"token": "fake-install-token", "expires_at": time.Now().Add(time.Hour).Format(time.RFC3339)})
		case r.Method == http.MethodGet && r.URL.Path == "/repos/owner/repo/pulls":
			writeTestJSON(t, w, *openPulls)
		case r.Method == http.MethodPost && r.URL.Path == "/repos/owner/repo/pulls":
			n := atomic.AddInt64(&createN, 1)
			num := 100 + n
			// A created PR becomes an open PR for any subsequent reconcile.
			*openPulls = append(*openPulls, map[string]interface{}{
				"id": num, "number": num, "state": "open", "title": "t",
				"head": map[string]string{"ref": "agent/agent-1/feat", "sha": "abc"},
				"base": map[string]string{"ref": "main"},
			})
			writeTestJSON(t, w, map[string]interface{}{"id": num, "number": num, "url": "https://api.fake/pulls", "html_url": "https://fake/owner/repo/pull"})
		default:
			t.Fatalf("unexpected fake GitHub request: %s %s", r.Method, r.URL.String())
		}
	}))
	t.Cleanup(ghAPI.Close)

	keyPath := writeTestPrivateKey(t)
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")
	idemPath := filepath.Join(dir, "idempotency.json")
	storePath := filepath.Join(dir, "correlation.db")
	cfg := &config.Config{
		Audit:       config.AuditConfig{Path: auditPath},
		Idempotency: config.IdempotencyConfig{StatePath: idemPath},
		GitHub: config.GitHubConfig{
			AppID: 1, PrivateKeyPath: keyPath, APIBaseURL: ghAPI.URL, GitBaseURL: "https://github.invalid",
			Installations: map[string]int64{"owner/repo": 42},
		},
		Correlation: config.CorrelationConfig{
			StorePath: storePath, CapabilityAPIURL: capAPI.URL, CapabilityAPIToken: corrCapToken,
		},
		Agents: []config.Agent{{
			ID: "agent-1", Enabled: true, Secret: "agent-secret",
			Repositories: []string{"owner/repo"}, Operations: []string{"pull.create"},
			BaseBranches: []string{"main"}, BranchPatterns: []string{"^agent/agent-1/.+$"},
		}},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("config validate: %v", err)
	}
	auditLog, err := audit.New(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := auditLog.Close(); err != nil {
			t.Errorf("close audit: %v", err)
		}
	})
	gh, err := githubapp.New(cfg.GitHub)
	if err != nil {
		t.Fatal(err)
	}
	broker, err := New("", cfg, gh, auditLog)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if broker.corr != nil {
			if err := broker.corr.Close(); err != nil {
				t.Errorf("close correlation store: %v", err)
			}
		}
	})
	return &corrBrokerFixture{
		broker: broker, corr: broker.corr, auditPath: auditPath, idemPath: idemPath,
		capToken: corrCapToken, createN: &createN, sawHandle: sawHandle, openPulls: openPulls,
		capHandler: capHandler,
	}
}

func okClaims(handle string) capVerifyResult {
	return capVerifyResult{status: http.StatusOK, body: map[string]interface{}{
		"agent_type": "curator", "mode": "reconcile", "run_id": "run-123", "work_item_id": "wi-9",
	}}
}

func pullCreateBody() map[string]interface{} {
	return map[string]interface{}{"title": "t", "head": "agent/agent-1/feat", "base": "main"}
}

func corrPullRequest(t *testing.T, f *corrBrokerFixture, handle, idemKey string, body map[string]interface{}) *httptest.ResponseRecorder {
	headers := map[string]string{}
	if handle != "" {
		headers[capHeader] = handle
	}
	if idemKey != "" {
		headers["Idempotency-Key"] = idemKey
	}
	return brokerRequestHeaders(t, f.broker, http.MethodPost, "/v1/repos/owner/repo/pulls", body, headers)
}

func TestPullCreateCorrelationMissingHandle(t *testing.T) {
	f := newCorrelationBroker(t, okClaims)
	resp := corrPullRequest(t, f, "", "key-1", pullCreateBody())
	assertStatus(t, resp, http.StatusUnauthorized)
	if !strings.Contains(resp.Body.String(), "capability_required") {
		t.Fatalf("body = %s", resp.Body.String())
	}
	if atomic.LoadInt64(f.createN) != 0 {
		t.Fatal("CreatePull called without a capability")
	}
}

func TestPullCreateCorrelationInvalidHandle(t *testing.T) {
	f := newCorrelationBroker(t, func(string) capVerifyResult { return capVerifyResult{status: http.StatusNotFound} })
	resp := corrPullRequest(t, f, "deadbeef", "key-1", pullCreateBody())
	assertStatus(t, resp, http.StatusForbidden)
	if !strings.Contains(resp.Body.String(), "capability_denied") {
		t.Fatalf("body = %s", resp.Body.String())
	}
	if atomic.LoadInt64(f.createN) != 0 {
		t.Fatal("CreatePull called with an invalid capability")
	}
}

func TestPullCreateCorrelationRevokedHandle(t *testing.T) {
	f := newCorrelationBroker(t, func(string) capVerifyResult { return capVerifyResult{status: http.StatusConflict} })
	resp := corrPullRequest(t, f, "revoked-handle", "key-1", pullCreateBody())
	assertStatus(t, resp, http.StatusForbidden)
}

func TestPullCreateCorrelationExpiredHandle(t *testing.T) {
	f := newCorrelationBroker(t, func(string) capVerifyResult { return capVerifyResult{status: http.StatusConflict} })
	resp := corrPullRequest(t, f, "expired-handle", "key-1", pullCreateBody())
	assertStatus(t, resp, http.StatusForbidden)
}

func TestPullCreateCorrelationAPIUnavailableFailsClosed(t *testing.T) {
	f := newCorrelationBroker(t, func(string) capVerifyResult { return capVerifyResult{status: http.StatusInternalServerError} })
	resp := corrPullRequest(t, f, "handle", "key-1", pullCreateBody())
	assertStatus(t, resp, http.StatusServiceUnavailable)
	if !strings.Contains(resp.Body.String(), "capability_unavailable") {
		t.Fatalf("body = %s", resp.Body.String())
	}
	if atomic.LoadInt64(f.createN) != 0 {
		t.Fatal("CreatePull called while the capability API was unavailable")
	}
}

func TestPullCreateCorrelationRequiresIdempotencyKey(t *testing.T) {
	f := newCorrelationBroker(t, okClaims)
	resp := corrPullRequest(t, f, "handle", "", pullCreateBody())
	assertStatus(t, resp, http.StatusBadRequest)
	if !strings.Contains(resp.Body.String(), "idempotency_key_required") {
		t.Fatalf("body = %s", resp.Body.String())
	}
}

func TestPullCreateCorrelationRejectsSpoofedIdentity(t *testing.T) {
	f := newCorrelationBroker(t, okClaims)
	body := pullCreateBody()
	// Caller asserts a run_id that disagrees with the verified claim (run-123).
	body["metadata"] = map[string]string{"run_id": "run-attacker"}
	resp := corrPullRequest(t, f, "handle", "key-1", body)
	assertStatus(t, resp, http.StatusForbidden)
	if !strings.Contains(resp.Body.String(), "identity_mismatch") {
		t.Fatalf("body = %s", resp.Body.String())
	}
	if atomic.LoadInt64(f.createN) != 0 {
		t.Fatal("CreatePull called on a spoofed-identity request")
	}
}

func TestPullCreateCorrelationSpoofIgnoredWhenAbsent(t *testing.T) {
	// A caller that supplies NO identity metadata is fine: identity is derived
	// entirely from the verified claims.
	f := newCorrelationBroker(t, okClaims)
	resp := corrPullRequest(t, f, "handle", "key-1", pullCreateBody())
	assertStatus(t, resp, http.StatusCreated)
	corr, err := f.corr.GetByOperation(context.Background(), pullCreateOperationID("agent-1", "owner/repo", "agent/agent-1/feat", "main", idempotencyKeyDigest("key-1")))
	if err != nil {
		t.Fatalf("correlation not recorded: %v", err)
	}
	if corr.RunID != "run-123" || corr.WorkItemID != "wi-9" || corr.AgentType != "curator" || corr.Mode != "reconcile" {
		t.Fatalf("correlation identity = %+v", corr)
	}
}

func TestPullCreateCorrelationSuccessRecordsCorrelationAndOutbox(t *testing.T) {
	f := newCorrelationBroker(t, okClaims)
	resp := corrPullRequest(t, f, "good-handle", "key-1", pullCreateBody())
	assertStatus(t, resp, http.StatusCreated)
	if atomic.LoadInt64(f.createN) != 1 {
		t.Fatalf("CreatePull calls = %d, want 1", atomic.LoadInt64(f.createN))
	}
	ctx := context.Background()
	pending, err := f.corr.PendingCount(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if pending != 1 {
		t.Fatalf("outbox pending = %d, want 1 (one event awaiting Signal Plane)", pending)
	}
	// The handle must never appear in the audit log.
	auditBytes, err := os.ReadFile(f.auditPath)
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	if strings.Contains(string(auditBytes), "good-handle") {
		t.Fatal("audit leaked the plaintext capability handle")
	}
	_ = auditBytes
}

func TestPullCreateCorrelationIdempotentRetrySinglePR(t *testing.T) {
	f := newCorrelationBroker(t, okClaims)
	body := pullCreateBody()
	first := corrPullRequest(t, f, "good-handle", "key-1", body)
	assertStatus(t, first, http.StatusCreated)
	second := corrPullRequest(t, f, "good-handle", "key-1", body)
	assertStatus(t, second, http.StatusCreated)
	if got := atomic.LoadInt64(f.createN); got != 1 {
		t.Fatalf("CreatePull calls = %d, want 1 across an idempotent retry", got)
	}
	numOf := func(resp *httptest.ResponseRecorder) int {
		var out struct {
			Number int `json:"number"`
		}
		if err := json.Unmarshal(resp.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v; body=%s", err, resp.Body.String())
		}
		return out.Number
	}
	if numOf(first) != numOf(second) || numOf(first) == 0 {
		t.Fatalf("retry returned a different PR: first=%d second=%d", numOf(first), numOf(second))
	}
	// Exactly one outbox event: the retry must not have recorded a second
	// correlation or emitted a second event.
	pending, err := f.corr.PendingCount(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if pending != 1 {
		t.Fatalf("outbox pending = %d after idempotent retry, want 1", pending)
	}
}

func TestPullCreateCorrelationKeyConflictRejected(t *testing.T) {
	f := newCorrelationBroker(t, okClaims)
	first := corrPullRequest(t, f, "good-handle", "key-1", pullCreateBody())
	assertStatus(t, first, http.StatusCreated)
	// Same key, different content -> conflict, not a wrong-PR replay.
	other := map[string]interface{}{"title": "different", "head": "agent/agent-1/feat", "base": "main", "body": "changed"}
	resp := corrPullRequest(t, f, "good-handle", "key-1", other)
	assertStatus(t, resp, http.StatusConflict)
}

func TestPullCreateCorrelationConcurrentRetrySinglePR(t *testing.T) {
	f := newCorrelationBroker(t, okClaims)
	body := pullCreateBody()
	const n = 12
	var wg sync.WaitGroup
	var created int64
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			resp := corrPullRequest(t, f, "good-handle", "key-race", body)
			if resp.Code == http.StatusCreated {
				atomic.AddInt64(&created, 1)
			}
		}()
	}
	wg.Wait()
	if got := atomic.LoadInt64(f.createN); got != 1 {
		t.Fatalf("CreatePull calls = %d, want exactly 1 under concurrent identical retries", got)
	}
	// Exactly one correlation for the operation.
	if _, err := f.corr.GetByOperation(context.Background(), pullCreateOperationID("agent-1", "owner/repo", "agent/agent-1/feat", "main", idempotencyKeyDigest("key-race"))); err != nil {
		t.Fatalf("expected one correlation: %v", err)
	}
}

// TestPullCreateCorrelationRecoversAfterCrashWithoutDuplicatePR simulates a
// crash AFTER GitHub created the PR but BEFORE the correlation/idempotency was
// committed: a durable PENDING idempotency reservation exists and the PR is open
// on GitHub, but no correlation row was written. The retry must reconcile to the
// existing open PR WITHOUT creating a second one, then record the correlation.
func TestPullCreateCorrelationRecoversAfterCrashWithoutDuplicatePR(t *testing.T) {
	f := newCorrelationBroker(t, okClaims)

	keyDigest := idempotencyKeyDigest("key-crash")
	stableOpID := pullCreateOperationID("agent-1", "owner/repo", "agent/agent-1/feat", "main", keyDigest)
	// Stage the interrupted state: the exact broker-marked PR #200 and a durable
	// pending idempotency reservation for the same scoped key, with no
	// correlation recorded.
	*f.openPulls = append(*f.openPulls, map[string]interface{}{
		"id": 200, "number": 200, "state": "open", "title": "t",
		"body": "operation_id: " + stableOpID,
		"head": map[string]string{"ref": "agent/agent-1/feat", "sha": "abc"},
		"base": map[string]string{"ref": "main"},
	})
	scopedKey := "pull.create:agent-1:owner/repo:" + keyDigest
	digest := pullCreateRequestDigest("owner/repo", api.PullCreateRequest{Title: "t", Head: "agent/agent-1/feat", Base: "main"})
	if _, _, _, err := idempotency.ReserveExact(f.broker.cfg.Idempotency, scopedKey, "pull.create", digest, ""); err != nil {
		t.Fatalf("stage pending reservation: %v", err)
	}

	resp := corrPullRequest(t, f, "good-handle", "key-crash", pullCreateBody())
	assertStatus(t, resp, http.StatusCreated)
	// No NEW PR created: reconciled to the existing open #200.
	if got := atomic.LoadInt64(f.createN); got != 0 {
		t.Fatalf("CreatePull calls = %d, want 0 (reconcile to existing PR)", got)
	}
	corr, err := f.corr.GetByOperation(context.Background(), pullCreateOperationID("agent-1", "owner/repo", "agent/agent-1/feat", "main", keyDigest))
	if err != nil {
		t.Fatalf("correlation not recorded on recovery: %v", err)
	}
	if corr.PRNumber != 200 {
		t.Fatalf("recovered correlation PR = %d, want 200", corr.PRNumber)
	}
}

func TestCorrelationConfigDisabledKeepsLegacyPath(t *testing.T) {
	// A broker without correlation config does not require a handle and records
	// nothing.
	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/app/installations/42/access_tokens":
			writeTestJSON(t, w, map[string]string{"token": "fake-install-token", "expires_at": time.Now().Add(time.Hour).Format(time.RFC3339)})
		case r.Method == http.MethodPost && r.URL.Path == "/repos/owner/repo/pulls":
			writeTestJSON(t, w, map[string]interface{}{"id": 5, "number": 5, "html_url": "https://fake/owner/repo/pull/5"})
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer apiServer.Close()
	broker := newTestBroker(t, apiServer.URL, "https://github.invalid", config.Agent{
		ID: "agent-1", Enabled: true, Secret: "agent-secret",
		Repositories: []string{"owner/repo"}, Operations: []string{"pull.create"},
		BaseBranches: []string{"main"}, BranchPatterns: []string{"^agent/agent-1/.+$"},
	})
	if broker.corr != nil {
		t.Fatal("correlation store constructed without config")
	}
	resp := brokerRequest(t, broker, http.MethodPost, "/v1/repos/owner/repo/pulls", map[string]interface{}{
		"title": "t", "head": "agent/agent-1/feat", "base": "main",
	})
	assertStatus(t, resp, http.StatusCreated)
}

func TestPullCreateCorrelationDoesNotAdoptUnmarkedHeadPR(t *testing.T) {
	f := newCorrelationBroker(t, okClaims)
	*f.openPulls = append(*f.openPulls, map[string]interface{}{
		"id": 200, "number": 200, "state": "open", "title": "t",
		"body": "unrelated pull request",
		"head": map[string]string{"ref": "agent/agent-1/feat", "sha": "abc"},
		"base": map[string]string{"ref": "main"},
	})
	keyDigest := idempotencyKeyDigest("key-unmarked")
	scopedKey := "pull.create:agent-1:owner/repo:" + keyDigest
	digest := pullCreateRequestDigest("owner/repo", api.PullCreateRequest{Title: "t", Head: "agent/agent-1/feat", Base: "main"})
	if _, _, _, err := idempotency.ReserveExact(f.broker.cfg.Idempotency, scopedKey, "pull.create", digest, ""); err != nil {
		t.Fatalf("stage pending reservation: %v", err)
	}

	resp := corrPullRequest(t, f, "good-handle", "key-unmarked", pullCreateBody())
	assertStatus(t, resp, http.StatusCreated)
	if got := atomic.LoadInt64(f.createN); got != 1 {
		t.Fatalf("CreatePull calls = %d, want 1; unrelated head PR must not be adopted", got)
	}
	corr, err := f.corr.GetByOperation(context.Background(), pullCreateOperationID("agent-1", "owner/repo", "agent/agent-1/feat", "main", keyDigest))
	if err != nil {
		t.Fatalf("correlation not recorded: %v", err)
	}
	if corr.PRNumber == 200 {
		t.Fatal("unmarked pre-existing PR was incorrectly correlated")
	}
}
