package sandbox

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type transportContextFixture struct {
	cfg      Config
	store    *AuthorityWorkerStore
	service  *AuthorityWorkerService
	handler  http.Handler
	worker   AuthorityWorker
	secret   string
	requests []AgentdTransportContextRequest
}

func newTransportContextFixture(t *testing.T, sessions int) *transportContextFixture {
	t.Helper()
	ctx := context.Background()
	cfg := authorityTestConfig(t)
	profile := cfg.AuthorityProfiles["writer"]
	profile.SessionCapacity = sessions
	profile.SessionIsolation.WorkspaceRoot = t.TempDir()
	profile.SessionIsolation.UIDStart, profile.SessionIsolation.GIDStart = os.Getuid(), os.Getgid()
	cfg.AuthorityProfiles["writer"] = profile
	//nolint:gosec // This synthetic secret authorizes only the isolated test store.
	secret := "agentd-transport-context-test-secret"
	t.Setenv(profile.BrokerSecretEnv, secret)
	store := openAuthorityTestStore(t, cfg.AuthorityStore)
	service := NewAuthorityWorkerService(cfg, store, &fakeAuthorityRuntime{}, nil, allowTestAuthorityIssuance{})
	service.newID = func() (string, error) { return "transport-context-worker", nil }
	worker, err := service.Provision(ctx, "coordinator", "writer")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.SetHealth(ctx, "coordinator", worker.WorkerID, "ready", true); err != nil {
		t.Fatal(err)
	}
	fixture := &transportContextFixture{cfg: cfg, store: store, service: service, handler: NewAuthorityRESTHandler(service), worker: worker, secret: secret}
	for i := 0; i < sessions; i++ {
		work := "transport-context-work-" + string(rune('a'+i))
		registered := registeredRequest(t, work, "route-"+work)
		registered.IdempotencyKey = "registered-key-" + work
		lease, err := store.AcquireRegistered(ctx, "coordinator", registered, profile.IssuanceGeneration)
		if err != nil {
			t.Fatal(err)
		}
		workspacePath := "/proof/agentd-transport-context/" + lease.SessionLineageID
		if _, err := store.db.ExecContext(ctx, `INSERT INTO authority_session_workspaces(binding_digest,worker_id,uid,gid,workspace_path,created_at,session_lineage_id) VALUES(?,?,?,?,?,?,?)`, lease.BindingDigest, lease.WorkerID, 20000+i, 20000+i, workspacePath, formatAuthorityTime(service.now()), lease.SessionLineageID); err != nil {
			t.Fatal(err)
		}
		sessionID := "agentd-" + lease.SessionLineageID
		if err := store.BindAgentdSession(ctx, "session:"+work, sessionID); err != nil {
			t.Fatal(err)
		}
		fixture.requests = append(fixture.requests, AgentdTransportContextRequest{
			Version: agentdTransportContextProtocolVersion, SessionID: sessionID, CoordinatorBinding: "session:" + work,
			SessionLineageID: lease.SessionLineageID, WorkerID: worker.WorkerID,
			WorkerStorageLineageID: worker.WorkerStorageLineageID, WorkerFenceEpoch: worker.WorkerFenceEpoch,
			AuthorityProfile: lease.Profile, AuthorityProfileVersion: lease.ProfileVersion, PolicyDigest: lease.PolicyDigest,
		})
	}
	return fixture
}

func (f *transportContextFixture) av1() string {
	return deriveAgentdValidationToken(f.secret, f.worker.WorkerID, f.worker.WorkerStorageLineageID, f.worker.WorkerFenceEpoch)
}

func requestTransportContext(t *testing.T, handler http.Handler, method, path, token string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	return response
}

func encodeTransportContextRequest(t *testing.T, request AgentdTransportContextRequest) []byte {
	t.Helper()
	body, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func decodeTransportContextResponse(t *testing.T, response *httptest.ResponseRecorder) AgentdTransportContextResponse {
	t.Helper()
	var out AgentdTransportContextResponse
	decoder := json.NewDecoder(response.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestAgentdTransportContextHandlerBindsCapacityTwoSessionsAndRefusesCrossSession(t *testing.T) {
	fixture := newTransportContextFixture(t, 2)
	contexts := make([]string, 2)
	for i, request := range fixture.requests {
		response := requestTransportContext(t, fixture.handler, http.MethodPost, "/v1/authority-workers/agentd/transport-context", fixture.av1(), encodeTransportContextRequest(t, request))
		if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("session %d status=%d cache=%q body=%s", i, response.Code, response.Header().Get("Cache-Control"), response.Body.String())
		}
		out := decodeTransportContextResponse(t, response)
		if out.Version != agentdTransportContextProtocolVersion || !strings.HasPrefix(out.TransportContext, "atc1.") || len(out.TransportContext) != 48 || strings.Contains(response.Body.String(), fixture.av1()) {
			t.Fatalf("session %d response=%+v", i, out)
		}
		contexts[i] = out.TransportContext
		resolved, err := (&TransportObserver{store: fixture.store}).ResolveAuthority(context.Background(), out.TransportContext)
		if err != nil || resolved.SessionLineageID != request.SessionLineageID || resolved.WorkerID != request.WorkerID {
			t.Fatalf("session %d authority=%+v err=%v", i, resolved, err)
		}
	}
	if contexts[0] == contexts[1] {
		t.Fatal("capacity-two sessions received one shared child capability")
	}
	crossed := fixture.requests[0]
	crossed.CoordinatorBinding = fixture.requests[1].CoordinatorBinding
	response := requestTransportContext(t, fixture.handler, http.MethodPost, "/v1/authority-workers/agentd/transport-context", fixture.av1(), encodeTransportContextRequest(t, crossed))
	assertTransportContextError(t, response, http.StatusForbidden, "transport_context_denied")
}

func TestAgentdTransportContextHandlerRefusesAuthSchemaAndEveryMismatchedCoordinate(t *testing.T) {
	fixture := newTransportContextFixture(t, 1)
	request := fixture.requests[0]
	path := "/v1/authority-workers/agentd/transport-context"
	for name, token := range map[string]string{"absent": "", "atc1 child": deriveTransportContext(fixture.store.salt, TransportAuthority{Principal: "not-authority"}), "wrong av1": deriveAgentdValidationToken(fixture.secret, "other-worker", request.WorkerStorageLineageID, request.WorkerFenceEpoch)} {
		t.Run(name, func(t *testing.T) {
			response := requestTransportContext(t, fixture.handler, http.MethodPost, path, token, encodeTransportContextRequest(t, request))
			assertTransportContextError(t, response, http.StatusForbidden, "transport_context_denied")
		})
	}
	xHeaderRequest := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(encodeTransportContextRequest(t, request)))
	xHeaderRequest.Header.Set("X-Sandbox-Token", fixture.av1())
	xHeaderResponse := httptest.NewRecorder()
	fixture.handler.ServeHTTP(xHeaderResponse, xHeaderRequest)
	assertTransportContextError(t, xHeaderResponse, http.StatusForbidden, "transport_context_denied")
	mutations := map[string]func(*AgentdTransportContextRequest){
		"version":                   func(r *AgentdTransportContextRequest) { r.Version = "broker/agentd-transport-context/v2" },
		"session":                   func(r *AgentdTransportContextRequest) { r.SessionID = "agentd-other-session" },
		"coordinator binding":       func(r *AgentdTransportContextRequest) { r.CoordinatorBinding = "session:other-work" },
		"session lineage":           func(r *AgentdTransportContextRequest) { r.SessionLineageID = strings.Repeat("a", 32) },
		"worker":                    func(r *AgentdTransportContextRequest) { r.WorkerID = "other-worker" },
		"worker storage lineage":    func(r *AgentdTransportContextRequest) { r.WorkerStorageLineageID = strings.Repeat("b", 32) },
		"worker fence":              func(r *AgentdTransportContextRequest) { r.WorkerFenceEpoch++ },
		"authority profile":         func(r *AgentdTransportContextRequest) { r.AuthorityProfile = "reader" },
		"authority profile version": func(r *AgentdTransportContextRequest) { r.AuthorityProfileVersion = strings.Repeat("c", 64) },
		"policy digest":             func(r *AgentdTransportContextRequest) { r.PolicyDigest = strings.Repeat("d", 64) },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			changed := request
			mutate(&changed)
			response := requestTransportContext(t, fixture.handler, http.MethodPost, path, fixture.av1(), encodeTransportContextRequest(t, changed))
			assertTransportContextError(t, response, http.StatusForbidden, "transport_context_denied")
		})
	}
	for name, body := range map[string][]byte{
		"unknown":   append(bytes.TrimSuffix(encodeTransportContextRequest(t, request), []byte("}")), []byte(`,"principal":"caller"}`)...),
		"trailing":  append(encodeTransportContextRequest(t, request), []byte(` {}`)...),
		"oversized": []byte(`{"padding":"` + strings.Repeat("x", 4096) + `"}`),
	} {
		t.Run(name, func(t *testing.T) {
			response := requestTransportContext(t, fixture.handler, http.MethodPost, path, fixture.av1(), body)
			assertTransportContextError(t, response, http.StatusBadRequest, "invalid_transport_context_request")
		})
	}
	response := requestTransportContext(t, fixture.handler, http.MethodGet, path, fixture.av1(), nil)
	assertTransportContextError(t, response, http.StatusMethodNotAllowed, "method_not_allowed")
}

func TestAgentdTransportContextRestartReleaseAndNoPersistence(t *testing.T) {
	fixture := newTransportContextFixture(t, 1)
	request := fixture.requests[0]
	body := encodeTransportContextRequest(t, request)
	path := "/v1/authority-workers/agentd/transport-context"
	firstResponse := requestTransportContext(t, fixture.handler, http.MethodPost, path, fixture.av1(), body)
	if firstResponse.Code != http.StatusOK {
		t.Fatalf("first status=%d body=%s", firstResponse.Code, firstResponse.Body.String())
	}
	first := decodeTransportContextResponse(t, firstResponse).TransportContext
	reopened, err := OpenAuthorityWorkerStore(context.Background(), fixture.cfg.AuthorityStore)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := reopened.Close(); err != nil {
			t.Errorf("close reopened authority store: %v", err)
		}
	})
	restarted := NewAuthorityWorkerService(fixture.cfg, reopened, &fakeAuthorityRuntime{}, nil, allowTestAuthorityIssuance{})
	replayResponse := requestTransportContext(t, NewAuthorityRESTHandler(restarted), http.MethodPost, path, fixture.av1(), body)
	if replayResponse.Code != http.StatusOK || decodeTransportContextResponse(t, replayResponse).TransportContext != first {
		t.Fatalf("restart status=%d body=%s", replayResponse.Code, replayResponse.Body.String())
	}
	if _, err := fixture.service.Release(context.Background(), "coordinator", request.CoordinatorBinding); err != nil {
		t.Fatal(err)
	}
	stale := requestTransportContext(t, fixture.handler, http.MethodPost, path, fixture.av1(), body)
	assertTransportContextError(t, stale, http.StatusForbidden, "transport_context_denied")
	if _, err := (&TransportObserver{store: fixture.store}).ResolveAuthority(context.Background(), first); err == nil {
		t.Fatal("released session child capability remained active")
	}
	if _, err := fixture.store.db.ExecContext(context.Background(), `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		t.Fatal(err)
	}
	for _, file := range []string{fixture.cfg.AuthorityStore, fixture.cfg.AuthorityStore + "-wal"} {
		stored, err := os.ReadFile(file) //nolint:gosec // The test reads only its isolated authority store files.
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		if bytes.Contains(stored, []byte(first)) || bytes.Contains(stored, []byte(fixture.av1())) {
			t.Fatalf("credential persisted in %s", filepath.Base(file))
		}
	}
}

func TestAgentdTransportContextWaitsForConfirmedAdoptionAndFencesPredecessor(t *testing.T) {
	ctx := context.Background()
	fixture := newTransportContextFixture(t, 1)
	path := "/v1/authority-workers/agentd/transport-context"
	predecessorRequest := fixture.requests[0]
	predecessorResponse := requestTransportContext(t, fixture.handler, http.MethodPost, path, fixture.av1(), encodeTransportContextRequest(t, predecessorRequest))
	if predecessorResponse.Code != http.StatusOK {
		t.Fatalf("predecessor status=%d body=%s", predecessorResponse.Code, predecessorResponse.Body.String())
	}
	predecessorContext := decodeTransportContextResponse(t, predecessorResponse).TransportContext
	workspace, err := fixture.store.SessionWorkspace(ctx, predecessorRequest.CoordinatorBinding)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.service.SetHealth(ctx, "coordinator", fixture.worker.WorkerID, "lost", false); err != nil {
		t.Fatal(err)
	}
	fixture.service.newID = func() (string, error) { return "transport-context-successor", nil }
	successor, err := fixture.service.Replace(ctx, "coordinator", fixture.worker.WorkerID, "lost")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.service.SetHealth(ctx, "coordinator", successor.WorkerID, "ready", true); err != nil {
		t.Fatal(err)
	}
	lease, err := fixture.store.GetLease(ctx, "coordinator", predecessorRequest.CoordinatorBinding)
	if err != nil {
		t.Fatal(err)
	}
	reassignment, err := fixture.store.Reassign(ctx, "coordinator", predecessorRequest.CoordinatorBinding, lease.SessionLineageID, fixture.worker.WorkerID, fixture.worker.WorkerFenceEpoch, "transport-context-reassign", workspace, fixture.cfg.AuthorityProfiles["writer"].IssuanceGeneration)
	if err != nil {
		t.Fatal(err)
	}
	adoption, err := fixture.store.AgentdAdoption(ctx, reassignment.Lease.BindingDigest)
	if err != nil || adoption.State != authorityAdoptionPending {
		t.Fatalf("pending adoption=%+v err=%v", adoption, err)
	}
	successorRequest := predecessorRequest
	successorRequest.WorkerID = successor.WorkerID
	successorRequest.WorkerStorageLineageID = successor.WorkerStorageLineageID
	successorRequest.WorkerFenceEpoch = successor.WorkerFenceEpoch
	successorRequest.AuthorityProfileVersion = successor.ProfileVersion
	successorRequest.PolicyDigest = successor.PolicyDigest
	successorAV1 := deriveAgentdValidationToken(fixture.secret, successor.WorkerID, successor.WorkerStorageLineageID, successor.WorkerFenceEpoch)
	pending := requestTransportContext(t, fixture.handler, http.MethodPost, path, successorAV1, encodeTransportContextRequest(t, successorRequest))
	assertTransportContextError(t, pending, http.StatusForbidden, "transport_context_denied")
	runtime, ok := fixture.service.runtime.(*fakeAuthorityRuntime)
	if !ok {
		t.Fatal("transport context fixture runtime type changed")
	}
	runtime.adopt = func(_ context.Context, worker AuthorityWorker, sessionID string, _ agentdRegisteredAdoptRequest) (agentdSessionStatus, error) {
		return agentdSessionStatus{
			Version: agentdSessionProtocolVersion, SessionID: sessionID, CoordinatorBinding: predecessorRequest.CoordinatorBinding,
			AuthorityBinding: predecessorRequest.AuthorityProfile, WorkerID: worker.WorkerID, StorageLineageID: worker.WorkerStorageLineageID,
			FenceEpoch: worker.WorkerFenceEpoch, SessionLineageID: predecessorRequest.SessionLineageID,
			Workspace: agentdSessionWorkspace{WorkspaceRef: workspace.Path, UID: workspace.UID, GID: workspace.GID},
			Phase:     "active", TurnIDs: []string{}, NextCursor: 1,
		}, nil
	}
	if err := fixture.service.confirmAgentdAdoption(ctx, adoption); err != nil {
		t.Fatal(err)
	}
	confirmed := requestTransportContext(t, fixture.handler, http.MethodPost, path, successorAV1, encodeTransportContextRequest(t, successorRequest))
	if confirmed.Code != http.StatusOK {
		t.Fatalf("confirmed status=%d body=%s", confirmed.Code, confirmed.Body.String())
	}
	successorContext := decodeTransportContextResponse(t, confirmed).TransportContext
	if successorContext == predecessorContext {
		t.Fatal("adoption reused predecessor child capability")
	}
	stale := requestTransportContext(t, fixture.handler, http.MethodPost, path, fixture.av1(), encodeTransportContextRequest(t, predecessorRequest))
	assertTransportContextError(t, stale, http.StatusForbidden, "transport_context_denied")
	if _, err := (&TransportObserver{store: fixture.store}).ResolveAuthority(ctx, predecessorContext); err == nil {
		t.Fatal("predecessor capability survived confirmed adoption")
	}
}

func TestAgentdTransportContextManifestPinsHandlerContract(t *testing.T) {
	manifestBytes, err := os.ReadFile("../../contracts/agentd-transport-context-v1.json") //nolint:gosec // Fixed checked-in broker-owned contract.
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(manifestBytes)
	if got := hex.EncodeToString(sum[:]); got != "634ba381e4d2eb7c8a6e16e0c75b4986b1bc7524fc567aa4fc488daef13f61a6" {
		t.Fatalf("manifest digest=%s", got)
	}
	var manifest struct {
		Version  string `json:"version"`
		Endpoint struct {
			URL                        string `json:"url"`
			Method                     string `json:"method"`
			Path                       string `json:"path"`
			RequestContentType         string `json:"requestContentType"`
			RequestBodyLimitBytes      int    `json:"requestBodyLimitBytes"`
			ClientDeadlineMilliseconds int    `json:"clientDeadlineMilliseconds"`
		} `json:"endpoint"`
		Request struct {
			Version              string   `json:"version"`
			AdditionalProperties bool     `json:"additionalProperties"`
			RequiredFields       []string `json:"requiredFields"`
		} `json:"request"`
		Response struct {
			Status                  int      `json:"status"`
			Version                 string   `json:"version"`
			RequiredFields          []string `json:"requiredFields"`
			TransportContextPattern string   `json:"transportContextPattern"`
			CacheControl            string   `json:"cacheControl"`
		} `json:"response"`
	}
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Version != "broker-agentd-transport-context-contract/v1" || manifest.Endpoint.Method != http.MethodPost || manifest.Endpoint.Path != "/v1/authority-workers/agentd/transport-context" || manifest.Endpoint.URL != agentdBrokerTransportContextURL || manifest.Endpoint.RequestContentType != "application/json" || manifest.Endpoint.RequestBodyLimitBytes != 4096 || manifest.Endpoint.ClientDeadlineMilliseconds != 250 || manifest.Request.Version != agentdTransportContextProtocolVersion || manifest.Request.AdditionalProperties || manifest.Response.Status != http.StatusOK || manifest.Response.Version != agentdTransportContextProtocolVersion || manifest.Response.TransportContextPattern != `^atc1\.[A-Za-z0-9_-]{43}$` || manifest.Response.CacheControl != "no-store" {
		t.Fatalf("manifest drifted: %+v", manifest)
	}
	wantRequestFields := []string{"version", "sessionId", "coordinatorBinding", "sessionLineageId", "workerId", "workerStorageLineageId", "workerFenceEpoch", "authorityProfile", "authorityProfileVersion", "policyDigest"}
	if !equalStrings(manifest.Request.RequiredFields, wantRequestFields) || !equalStrings(manifest.Response.RequiredFields, []string{"version", "transportContext"}) {
		t.Fatalf("manifest fields request=%q response=%q", manifest.Request.RequiredFields, manifest.Response.RequiredFields)
	}
	fixture := newTransportContextFixture(t, 1)
	response := requestTransportContext(t, fixture.handler, manifest.Endpoint.Method, manifest.Endpoint.Path, fixture.av1(), encodeTransportContextRequest(t, fixture.requests[0]))
	if response.Code != manifest.Response.Status || response.Header().Get("Cache-Control") != manifest.Response.CacheControl {
		t.Fatalf("manifest-driven handler status=%d cache=%q body=%s", response.Code, response.Header().Get("Cache-Control"), response.Body.String())
	}
}

func assertTransportContextError(t *testing.T, response *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if response.Code != status || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("status=%d cache=%q body=%s", response.Code, response.Header().Get("Cache-Control"), response.Body.String())
	}
	var out restError
	if err := json.Unmarshal(response.Body.Bytes(), &out); err != nil || out.Code != code {
		t.Fatalf("error=%+v decode=%v", out, err)
	}
}
