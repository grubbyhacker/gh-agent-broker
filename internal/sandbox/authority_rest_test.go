package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

type coordinatorTestRuntime struct {
	*fakeAuthorityRuntime
	worker    AuthorityWorker
	method    string
	path      string
	body      json.RawMessage
	result    json.RawMessage
	status    int
	calls     int
	responses []json.RawMessage
	statuses  []int
}

func (r *coordinatorTestRuntime) AgentdSessionRequest(_ context.Context, worker AuthorityWorker, method, path string, body json.RawMessage) (int, json.RawMessage, error) {
	r.worker, r.method, r.path, r.body = worker, method, path, bytes.Clone(body)
	r.calls++
	if len(r.responses) >= r.calls {
		return r.statuses[r.calls-1], bytes.Clone(r.responses[r.calls-1]), nil
	}
	parts := strings.Split(path, "/")
	sessionID := "agentd-session"
	if len(parts) > 3 && parts[1] == "v1" && parts[2] == "sessions" {
		sessionID = parts[3]
	}
	if len(r.result) != 0 {
		status := r.status
		if status == 0 {
			status = http.StatusAccepted
		}
		return status, bytes.Clone(r.result), nil
	}
	return http.StatusAccepted, json.RawMessage(`{"sessionId":"` + sessionID + `","turnId":"turn-1","phase":"queued"}`), nil
}

func TestCoordinatorV1SubmitIsBrokerMediated(t *testing.T) {
	ctx := context.Background()
	cfg := authorityTestConfig(t)
	profile := cfg.AuthorityProfiles["writer"]
	profile.SessionIsolation.WorkspaceRoot = t.TempDir()
	cfg.AuthorityProfiles["writer"] = profile
	store := openAuthorityTestStore(t, cfg.AuthorityStore)
	runtime := &coordinatorTestRuntime{fakeAuthorityRuntime: &fakeAuthorityRuntime{}}
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	auditLog, err := NewAuditLogger(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestAudit(t, auditLog)
	service := NewAuthorityWorkerService(cfg, store, runtime, auditLog, allowTestAuthorityIssuance{})
	service.newID = func() (string, error) { return "coordinator-worker", nil }
	worker, err := service.Provision(ctx, "coordinator", "writer")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.SetHealth(ctx, "coordinator", worker.WorkerID, "ready", true); err != nil {
		t.Fatal(err)
	}
	lease, err := service.Acquire(ctx, "coordinator", AuthorityWorkerRequest{Profile: "writer", IdempotencyKey: "lease-key", SessionBinding: "logical-session"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.db.ExecContext(ctx, `INSERT INTO authority_session_workspaces(binding_digest,worker_id,uid,gid,workspace_path,created_at,session_lineage_id) VALUES(?,?,?,?,?,?,?)`, lease.BindingDigest, worker.WorkerID, 20000, 20000, filepath.Join(profile.SessionIsolation.WorkspaceRoot, lease.SessionLineageID), formatAuthorityTime(service.now()), lease.SessionLineageID); err != nil {
		t.Fatal(err)
	}
	if err = store.BindAgentdSession(ctx, "logical-session", "agentd-session"); err != nil {
		t.Fatal(err)
	}
	handler := NewAuthorityRESTHandler(service)
	body := []byte(`{"session_binding":"logical-session","idempotency_key":"turn-key","prompt":"make the registered change"}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/authority-workers/coordinator/v1/sessions/submit", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer coordinator-test-token")
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.Code, resp.Body.String())
	}
	if runtime.path != "/v1/sessions/agentd-session/turns" {
		t.Fatalf("legacy lease did not use legacy path: %q", runtime.path)
	}
}

func TestCoordinatorV1BlocksCommandsUntilReassignmentAdoptionIsConfirmed(t *testing.T) {
	fixture := newAuthorityAdoptionFixture(t, 1)
	fixture.commit(t, 0)
	runtime := &coordinatorTestRuntime{fakeAuthorityRuntime: fixture.runtime}
	service := NewAuthorityWorkerService(fixture.cfg, fixture.store, runtime, nil, allowTestAuthorityIssuance{})
	request := CoordinatorSessionRequest{
		SessionBinding: fixture.bindings[0],
		IdempotencyKey: "blocked-turn",
		Prompt:         "make the registered change",
	}

	if _, err := service.CoordinatorSessionCommand(context.Background(), "coordinator", "submit", request); err == nil || !strings.Contains(err.Error(), "not confirmed") {
		t.Fatalf("pending adoption routed command: %v", err)
	}
}

func TestRegisteredCoordinatorAgentdV2Contract(t *testing.T) {
	ctx := context.Background()
	fixture, err := os.ReadFile("../../testdata/agentd/registered-turn-v2.golden.json") //nolint:gosec // Fixed checked-in contract fixture.
	if err != nil {
		t.Fatal(err)
	}
	var golden struct {
		Request  json.RawMessage `json:"request"`
		Response json.RawMessage `json:"response"`
		Events   json.RawMessage `json:"events"`
	}
	if err := json.Unmarshal(fixture, &golden); err != nil {
		t.Fatal(err)
	}
	var exactRequest struct {
		Version             string                   `json:"version"`
		IdempotencyKey      string                   `json:"idempotencyKey"`
		TaskKind            string                   `json:"taskKind"`
		AdmissionTaskDigest string                   `json:"admissionTaskDigest"`
		TaskEvidenceDigest  string                   `json:"taskEvidenceDigest"`
		Parameters          RegisteredTaskParameters `json:"parameters"`
	}
	if err := json.Unmarshal(golden.Request, &exactRequest); err != nil {
		t.Fatal(err)
	}
	bodyMethod, _, body := coordinatorRegisteredAgentdRequest("submit", "session-42", CoordinatorSessionRequest{IdempotencyKey: exactRequest.IdempotencyKey}, registeredAdmission{Task: RegisteredTask{TaskKind: exactRequest.TaskKind, TaskEvidenceDigest: exactRequest.TaskEvidenceDigest, Parameters: exactRequest.Parameters}, Digest: exactRequest.AdmissionTaskDigest})
	var gotRequest, wantRequest any
	if json.Unmarshal(body, &gotRequest) != nil || json.Unmarshal(golden.Request, &wantRequest) != nil || bodyMethod != http.MethodPost || !reflect.DeepEqual(gotRequest, wantRequest) {
		t.Fatalf("registered request drifted\nwant=%s\ngot=%s", golden.Request, body)
	}
	if _, err := validateRegisteredTurnResponse(golden.Response, "session-42", "turn-42"); err != nil {
		t.Fatalf("golden acknowledgement rejected: %v", err)
	}
	if _, err := validateRegisteredEventsResponse(golden.Events, registeredTurnState{SessionID: "session-42", TurnID: "turn:turn-42", ModelEffectID: "model:turn-42"}, 0, "sha256:"+strings.Repeat("a", 64), githubGreenPRContractDigest, "sha256:"+strings.Repeat("b", 64)); err != nil {
		t.Fatalf("golden events rejected: %v", err)
	}

	cfg := authorityTestConfig(t)
	profile := cfg.AuthorityProfiles["writer"]
	profile.SessionIsolation.WorkspaceRoot = t.TempDir()
	profile.SessionIsolation.UIDStart, profile.SessionIsolation.GIDStart = os.Getuid(), os.Getgid()
	cfg.AuthorityProfiles["writer"] = profile
	store := openAuthorityTestStore(t, cfg.AuthorityStore)
	runtime := &coordinatorTestRuntime{fakeAuthorityRuntime: &fakeAuthorityRuntime{}}
	service := NewAuthorityWorkerService(cfg, store, runtime, nil, allowTestAuthorityIssuance{})
	service.newID = func() (string, error) { return "registered-contract-worker", nil }
	worker, err := service.Provision(ctx, "coordinator", "writer")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.SetHealth(ctx, "coordinator", worker.WorkerID, "ready", true); err != nil {
		t.Fatal(err)
	}
	admissionRequest := registeredRequest(t, "turn-42", "route-42")
	admissionRequest.IdempotencyKey = "turn-42"
	_, err = service.AcquireRegisteredSession(ctx, "coordinator", admissionRequest)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.BindAgentdSession(ctx, admissionRequest.SessionBinding, "session-42"); err != nil {
		t.Fatal(err)
	}
	queued := `{"version":"agentd/registered-events/v2","events":[{"cursor":1,"sessionId":"session-42","turnId":"turn:turn-42","modelEffectId":"model:turn-42","attempt":0,"phase":"queued","workerId":"worker-42","storageLineageId":"lineage-42","fenceEpoch":7,"admissionTaskDigest":"` + admissionRequest.AdmissionTaskDigest + `","taskEvidenceDigest":"` + admissionRequest.Task.TaskEvidenceDigest + `"},{"cursor":2,"sessionId":"session-42","turnId":"turn:turn-42","modelEffectId":"model:turn-42","attempt":0,"phase":"green","workerId":"worker-42","storageLineageId":"lineage-42","fenceEpoch":7,"admissionTaskDigest":"` + admissionRequest.AdmissionTaskDigest + `","taskEvidenceDigest":"` + admissionRequest.Task.TaskEvidenceDigest + `","verifier":{"phase":"green","outcome":"satisfied","contractDigest":"` + githubGreenPRContractDigest + `","taskEvidenceDigest":"` + admissionRequest.Task.TaskEvidenceDigest + `","headRevision":"broker:head:turn-42","reasons":[],"evidenceRefs":["broker:observation:turn-42"]}}],"nextCursor":2}`
	queued = strings.ReplaceAll(queued, "worker-42", worker.WorkerID)
	queued = strings.ReplaceAll(queued, "lineage-42", worker.WorkerStorageLineageID)
	queued = strings.ReplaceAll(queued, `"fenceEpoch":7`, `"fenceEpoch":`+strconv.FormatInt(worker.WorkerFenceEpoch, 10))
	submitKey := "agentd:registered-turn:v1:turn-42"
	queued = strings.ReplaceAll(queued, `"turnId":"turn:turn-42"`, `"turnId":"turn:`+submitKey+`"`)
	queued = strings.ReplaceAll(queued, `"modelEffectId":"model:turn-42"`, `"modelEffectId":"model:`+submitKey+`"`)
	runtime.statuses = []int{http.StatusAccepted, http.StatusOK, http.StatusOK, http.StatusOK}
	runtime.responses = []json.RawMessage{
		[]byte(`{"version":"agentd/registered-turn/v2","sessionId":"session-42","turnId":"turn:` + submitKey + `","modelEffectId":"model:` + submitKey + `","phase":"queued","cursor":1}`),
		[]byte(queued),
		[]byte(`{"version":"agentd/registered-events/v2","events":[],"nextCursor":2}`),
		[]byte(`{"version":"agentd/registered-events/v2","events":[],"nextCursor":2}`),
	}
	submit := CoordinatorSessionRequest{SessionBinding: admissionRequest.SessionBinding, IdempotencyKey: submitKey}
	if _, err := service.CoordinatorSessionCommand(ctx, "coordinator", "submit", submit); err != nil {
		t.Fatal(err)
	}
	if _, err := service.CoordinatorSessionCommand(ctx, "coordinator", "submit", submit); err != nil || runtime.calls != 1 {
		t.Fatalf("duplicate submit calls=%d err=%v", runtime.calls, err)
	}
	if _, err := service.CoordinatorSessionCommand(ctx, "coordinator", "events", CoordinatorSessionRequest{SessionBinding: admissionRequest.SessionBinding}); err != nil {
		t.Fatal(err)
	}
	if runtime.path != "/v1/registered-sessions/session-42/events?version=agentd%2Fregistered-events%2Fv2&after=0" {
		t.Fatalf("first events path=%q", runtime.path)
	}
	if _, err := service.CoordinatorSessionCommand(ctx, "coordinator", "events", CoordinatorSessionRequest{SessionBinding: admissionRequest.SessionBinding, After: 2}); err != nil {
		t.Fatal(err)
	}
	if runtime.path != "/v1/registered-sessions/session-42/events?version=agentd%2Fregistered-events%2Fv2&after=2" || runtime.calls != 3 {
		t.Fatalf("cursor did not advance: path=%q calls=%d", runtime.path, runtime.calls)
	}
	if _, err := service.CoordinatorSessionCommand(ctx, "coordinator", "events", CoordinatorSessionRequest{SessionBinding: admissionRequest.SessionBinding}); err == nil || !strings.Contains(err.Error(), "cursor") {
		t.Fatalf("replayed cursor was accepted: %v", err)
	}
	if runtime.calls != 3 || strings.Contains(runtime.path, "/verify") {
		t.Fatalf("registered forwarding drifted: path=%q calls=%d", runtime.path, runtime.calls)
	}
	handler := NewAuthorityRESTHandler(service)
	turnBody, err := json.Marshal(CoordinatorRegisteredTurnRequest{Version: "agentd/registered-lifecycle/v1", SessionBinding: admissionRequest.SessionBinding, IdempotencyKey: submitKey, TaskKind: admissionRequest.Task.TaskKind, AdmissionTaskDigest: admissionRequest.AdmissionTaskDigest, TaskEvidenceDigest: admissionRequest.Task.TaskEvidenceDigest, Parameters: admissionRequest.Task.Parameters})
	if err != nil {
		t.Fatal(err)
	}
	turnRequest := httptest.NewRequest(http.MethodPost, "/v1/authority-workers/coordinator/v1/registered-turn", bytes.NewReader(turnBody))
	turnRequest.Header.Set("Authorization", "Bearer coordinator-test-token")
	turnResponse := httptest.NewRecorder()
	handler.ServeHTTP(turnResponse, turnRequest)
	if turnResponse.Code != http.StatusAccepted || runtime.calls != 3 {
		t.Fatalf("registered turn REST replay status=%d calls=%d body=%s", turnResponse.Code, runtime.calls, turnResponse.Body.String())
	}
	eventsBody := []byte(`{"sessionBinding":"` + admissionRequest.SessionBinding + `","after":2}`)
	eventsRequest := httptest.NewRequest(http.MethodPost, "/v1/authority-workers/coordinator/v1/registered-events", bytes.NewReader(eventsBody))
	eventsRequest.Header.Set("Authorization", "Bearer coordinator-test-token")
	eventsResponse := httptest.NewRecorder()
	handler.ServeHTTP(eventsResponse, eventsRequest)
	if eventsResponse.Code != http.StatusOK || runtime.calls != 4 {
		t.Fatalf("registered events REST status=%d calls=%d body=%s", eventsResponse.Code, runtime.calls, eventsResponse.Body.String())
	}
	if _, err := validateRegisteredTurnResponse([]byte(`{"version":"agentd/registered-turn/v1","sessionId":"session-42","turnId":"turn:turn-42","modelEffectId":"model:turn-42","phase":"queued","cursor":1}`), "session-42", "turn-42"); err == nil {
		t.Fatal("wrong response version accepted")
	}
	if _, err := validateRegisteredTurnResponse([]byte(`{"version":"agentd/registered-turn/v2","sessionId":"session-42","turnId":"turn:turn-42","modelEffectId":"model:turn-42","phase":"queued","cursor":1,"extra":true}`), "session-42", "turn-42"); err == nil {
		t.Fatal("extra turn response field accepted")
	}
	if _, err := validateRegisteredTurnResponse([]byte(`{"version":"agentd/registered-turn/v2","sessionId":"session-42","turnId":"turn:turn-42","modelEffectId":"model:turn-42","phase":"queued"}`), "session-42", "turn-42"); err == nil {
		t.Fatal("missing turn cursor accepted")
	}
	if _, err := validateRegisteredTurnResponse([]byte(`{"version":"agentd/registered-turn/v2","sessionId":"session-42","turnId":"turn:turn-42","modelEffectId":"model:turn-42","phase":"queued","cursor":1} {}`), "session-42", "turn-42"); err == nil {
		t.Fatal("trailing turn JSON accepted")
	}
	if _, err := validateRegisteredEventsResponse([]byte(`{"version":"agentd/registered-events/v2","events":[],"nextCursor":2,"extra":true}`), registeredTurnState{SessionID: "session-42", TurnID: "turn:turn-42", ModelEffectID: "model:turn-42"}, 2, admissionRequest.AdmissionTaskDigest, admissionRequest.Task.ContractDigest, admissionRequest.Task.TaskEvidenceDigest); err == nil {
		t.Fatal("extra event response field accepted")
	}
}

func TestRegisteredVerifierProjectionIsStrictAndAcceptsLocalEscalation(t *testing.T) {
	const digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	turn := registeredTurnState{SessionID: "session-42", TurnID: "turn:turn-42", ModelEffectID: "model:turn-42"}
	localEscalated := `{"version":"agentd/registered-events/v2","events":[{"cursor":1,"sessionId":"session-42","turnId":"turn:turn-42","modelEffectId":"model:turn-42","attempt":0,"phase":"escalated","workerId":"worker-42","storageLineageId":"lineage-42","fenceEpoch":7,"admissionTaskDigest":"` + digest + `","taskEvidenceDigest":"` + digest + `","verifier":{"phase":"escalated","outcome":"escalated","contractDigest":"` + digest + `","taskEvidenceDigest":"` + digest + `","headRevision":"local:unavailable:verifier:turn-42:observation:1","reasons":[{"code":"deadline","evidenceRef":"local:deadline:` + digest + `:verifier:turn-42:observation:1"}],"evidenceRefs":["local:deadline:` + digest + `:verifier:turn-42:observation:1"]}}],"nextCursor":1}`
	if _, err := validateRegisteredEventsResponse([]byte(localEscalated), turn, 0, digest, digest, digest); err != nil {
		t.Fatalf("local escalation rejected: %v", err)
	}
	for _, name := range []string{"missing_attempt", "null_cursor", "missing_head", "null_reason_ref", "extra_reason", "refused_outcome", "phase_mismatch", "empty_evidence"} {
		payload := localEscalated
		switch name {
		case "missing_attempt":
			payload = strings.Replace(payload, `,"attempt":0`, "", 1)
		case "null_cursor":
			payload = strings.Replace(payload, `"cursor":1`, `"cursor":null`, 1)
		case "missing_head":
			payload = strings.Replace(payload, `,"headRevision":"local:unavailable:verifier:turn-42:observation:1"`, "", 1)
		case "null_reason_ref":
			payload = strings.Replace(payload, `"evidenceRef":"local:deadline:`, `"evidenceRef":null,"discard":"local:deadline:`, 1)
		case "extra_reason":
			payload = strings.Replace(payload, `{"code":"deadline"`, `{"extra":true,"code":"deadline"`, 1)
		case "refused_outcome":
			payload = strings.Replace(payload, `"outcome":"escalated"`, `"outcome":"refused"`, 1)
		case "phase_mismatch":
			payload = strings.Replace(payload, `"phase":"escalated","outcome":"escalated"`, `"phase":"red","outcome":"escalated"`, 1)
		case "empty_evidence":
			payload = strings.Replace(payload, `"evidenceRefs":["local:deadline:`, `"evidenceRefs":[],"discard":["local:deadline:`, 1)
		}
		if _, err := validateRegisteredEventsResponse([]byte(payload), turn, 0, digest, digest, digest); err == nil {
			t.Fatalf("%s verifier projection accepted", name)
		}
	}
}

func TestRegisteredEventsPhaseFailureVerifierCoupling(t *testing.T) {
	const digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	turn := registeredTurnState{SessionID: "session-42", TurnID: "turn:turn-42", ModelEffectID: "model:turn-42"}
	verifier := func(phase, outcome string) *registeredVerifierProjection {
		reasons := []registeredVerifierReason{}
		if outcome != "satisfied" {
			reasons = append(reasons, registeredVerifierReason{Code: outcome, EvidenceRef: "broker:observation:turn-42"})
		}
		return &registeredVerifierProjection{Phase: phase, Outcome: outcome, ContractDigest: digest, TaskEvidenceDigest: digest, HeadRevision: "broker:head:turn-42", Reasons: reasons, EvidenceRefs: []string{"broker:observation:turn-42"}}
	}
	wrongContractDigest := verifier("green", "satisfied")
	wrongContractDigest.ContractDigest = "sha256:" + strings.Repeat("b", 64)
	wrongEvidenceDigest := verifier("green", "satisfied")
	wrongEvidenceDigest.TaskEvidenceDigest = "sha256:" + strings.Repeat("c", 64)
	for _, tc := range []struct {
		name, phase, failure string
		verifier             *registeredVerifierProjection
		valid                bool
	}{
		{"queued without failure", "queued", "", nil, true},
		{"authorized without failure", "authorized", "", nil, true},
		{"running without failure", "running", "", nil, true},
		{"completed without failure", "completed", "", nil, true},
		{"pending verifier", "pending", "", verifier("pending", "waiting"), true},
		{"green verifier", "green", "", verifier("green", "satisfied"), true},
		{"red verifier", "red", "", verifier("red", "missing_or_stale"), true},
		{"refused verifier", "refused", "", verifier("refused", "escalated"), true},
		{"escalated verifier", "escalated", "", verifier("escalated", "escalated"), true},
		{"credential mint failure", "authorized", "credential_mint_failed", nil, true},
		{"runtime failure", "failed", "runtime_failed", nil, true},
		{"credential expired", "escalated", "credential_expired", nil, true},
		{"runtime outcome uncertain", "escalated", "runtime_outcome_uncertain", verifier("escalated", "escalated"), true},
		{"failed without failure", "failed", "", nil, false},
		{"verifier phase mismatch", "queued", "", verifier("green", "satisfied"), false},
		{"verifier wrong contract digest", "green", "", wrongContractDigest, false},
		{"verifier wrong evidence digest", "green", "", wrongEvidenceDigest, false},
		{"credential mint wrong phase", "queued", "credential_mint_failed", nil, false},
		{"credential mint with verifier", "authorized", "credential_mint_failed", verifier("green", "satisfied"), false},
		{"runtime failure wrong phase", "escalated", "runtime_failed", nil, false},
		{"credential expired with verifier", "escalated", "credential_expired", verifier("escalated", "escalated"), false},
		{"uncertain without verifier", "escalated", "runtime_outcome_uncertain", nil, false},
		{"uncertain wrong phase", "failed", "runtime_outcome_uncertain", verifier("escalated", "escalated"), false},
		{"uncertain wrong verifier", "escalated", "runtime_outcome_uncertain", verifier("refused", "escalated"), false},
		{"unknown failure", "failed", "runtime_outcome_unknown", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload, err := json.Marshal(registeredEventsResponse{Version: registeredEventsResponseVersion, Events: []registeredEventProjection{{Cursor: 1, SessionID: turn.SessionID, TurnID: turn.TurnID, ModelEffectID: turn.ModelEffectID, Attempt: 1, Phase: tc.phase, WorkerID: "worker-42", StorageLineageID: "lineage-42", FenceEpoch: 7, AdmissionTaskDigest: digest, TaskEvidenceDigest: digest, Verifier: tc.verifier, Failure: tc.failure}}, NextCursor: 1})
			if err != nil {
				t.Fatal(err)
			}
			_, err = validateRegisteredEventsResponse(payload, turn, 0, digest, digest, digest)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%t, err=%v", tc.valid, err)
			}
		})
	}
}

func TestCoordinatorWireFixturesAreStable(t *testing.T) {
	created := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	lease := AuthorityLease{Principal: "coordinator", Profile: "writer", WorkerID: "worker-1", SessionLineageID: "11111111111111111111111111111111", WorkerStorageLineageID: "22222222222222222222222222222222", WorkerFenceEpoch: 1, ProfileVersion: "profile-v1", PolicyDigest: strings.Repeat("a", 64), BindingDigest: "binding-digest", IdempotencyDigest: "idempotency-digest", CreatedAt: created}
	admission := CoordinatorLeaseAdmission{Version: coordinatorProtocolVersion, Admission: AuthoritySessionAdmission{Lease: lease, Workspace: SessionWorkspace{UID: 20000, GID: 20000, Path: "/var/lib/agentd/workspaces/11111111111111111111111111111111", SessionLineageID: lease.SessionLineageID}}}
	status := CoordinatorReassignmentStatus{Version: coordinatorProtocolVersion, SessionBinding: "logical-session", SessionLineageID: lease.SessionLineageID, AuthorityProfile: "writer", ProfileVersion: lease.ProfileVersion, PolicyDigest: lease.PolicyDigest, Predecessor: agentdWorkerBinding{WorkerID: "worker-1", StorageLineageID: lease.WorkerStorageLineageID, FenceEpoch: 1}, Successor: agentdWorkerBinding{WorkerID: "worker-2", StorageLineageID: lease.WorkerStorageLineageID, FenceEpoch: 2}, IdempotencyKey: "opaque-rebind-key", State: "confirmed"}
	for _, fixture := range []struct {
		name, path string
		value      any
	}{{"lease-v1.json", "../../testdata/coordinator-wire/lease-v1.json", admission}, {"reassignment-status-v1.json", "../../testdata/coordinator-wire/reassignment-status-v1.json", status}} {
		want, err := os.ReadFile(fixture.path) //nolint:gosec // Paths are fixed checked-in wire fixtures, not runtime input.
		if err != nil {
			t.Fatal(err)
		}
		got, err := json.Marshal(fixture.value)
		if err != nil {
			t.Fatal(err)
		}
		var wantValue, gotValue any
		if json.Unmarshal(want, &wantValue) != nil || json.Unmarshal(got, &gotValue) != nil || !reflect.DeepEqual(wantValue, gotValue) {
			t.Fatalf("fixture %s drifted\nwant=%s\ngot=%s", fixture.name, want, got)
		}
	}
}

func TestAuthorityRESTSessionReassignmentContract(t *testing.T) {
	ctx := context.Background()
	cfg := authorityTestConfig(t)
	store := openAuthorityTestStore(t, cfg.AuthorityStore)
	runtime := &fakeAuthorityRuntime{}
	service := NewAuthorityWorkerService(cfg, store, runtime, nil, allowTestAuthorityIssuance{})
	ids := []string{"rest-old", "rest-new"}
	service.newID = func() (string, error) { id := ids[0]; ids = ids[1:]; return id, nil }
	old, err := service.Provision(ctx, "coordinator", "writer")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.SetHealth(ctx, "coordinator", old.WorkerID, "ready", true); err != nil {
		t.Fatal(err)
	}
	lease, err := service.Acquire(ctx, "coordinator", AuthorityWorkerRequest{Profile: "writer", IdempotencyKey: "rest-lease", SessionBinding: "rest-session"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `INSERT INTO authority_session_workspaces(binding_digest,worker_id,uid,gid,workspace_path,created_at,session_lineage_id) VALUES(?,?,?,?,?,?,?)`, lease.BindingDigest, old.WorkerID, 21000, 21000, "/durable/rest-session", formatAuthorityTime(service.now()), lease.SessionLineageID); err != nil {
		t.Fatal(err)
	}
	if err := store.BindAgentdSession(ctx, "rest-session", "agentd-rest-session"); err != nil {
		t.Fatal(err)
	}
	runtime.rebind = successfulAgentdRebind("rest-session", lease, SessionWorkspace{UID: 21000, GID: 21000, Path: "/durable/rest-session", SessionLineageID: lease.SessionLineageID, AgentdSessionID: "agentd-rest-session"})
	replacement, err := service.Replace(ctx, "coordinator", old.WorkerID, "lost")
	if err != nil {
		t.Fatal(err)
	}
	handler := NewAuthorityRESTHandler(service)
	body := []byte(`{"session_binding":"rest-session","session_lineage_id":"` + lease.SessionLineageID + `","predecessor_worker_id":"rest-old","predecessor_worker_fence_epoch":1,"idempotency_key":"rest-reassign"}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/authority-workers/leases/reassign", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer coordinator-test-token")
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusConflict || !bytes.Contains(resp.Body.Bytes(), []byte(`"code":"reassignment_not_ready"`)) {
		t.Fatalf("not-ready status=%d body=%s", resp.Code, resp.Body.String())
	}
	if _, err := service.SetHealth(ctx, "coordinator", replacement.WorkerID, "ready", true); err != nil {
		t.Fatal(err)
	}
	req = httptest.NewRequest(http.MethodPost, "/v1/authority-workers/leases/reassign", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer coordinator-test-token")
	resp = httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("reassign status=%d body=%s", resp.Code, resp.Body.String())
	}
	var out AuthoritySessionReassignment
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil || out.ReplacementWorkerID != replacement.WorkerID || out.Replay {
		t.Fatalf("response=%+v err=%v", out, err)
	}
	statusBody := []byte(`{"session_binding":"rest-session","predecessor_fence_epoch":1}`)
	for token, want := range map[string]int{"coordinator-test-token": http.StatusOK, "session-test-token": http.StatusNotFound} {
		req = httptest.NewRequest(http.MethodPost, "/v1/authority-workers/coordinator/v1/reassignments/status", bytes.NewReader(statusBody))
		req.Header.Set("Authorization", "Bearer "+token)
		resp = httptest.NewRecorder()
		handler.ServeHTTP(resp, req)
		if resp.Code != want {
			t.Fatalf("status token=%s code=%d body=%s", token, resp.Code, resp.Body.String())
		}
	}
	// Unknown authority-bearing fields are rejected rather than being silently
	// interpreted as a caller override.
	for name, field := range map[string]string{
		"image":             `"image":"forbidden"`,
		"successor":         `"successor":{"workerId":"caller-selected"}`,
		"agentd endpoint":   `"agentd_endpoint":"http://caller.invalid"`,
		"coordinator token": `"coordinator_token":"caller-secret"`,
	} {
		bad := []byte(`{"session_binding":"rest-session","session_lineage_id":"` + lease.SessionLineageID + `","predecessor_worker_id":"rest-old","predecessor_worker_fence_epoch":1,"idempotency_key":"rest-reassign-2",` + field + `}`)
		req = httptest.NewRequest(http.MethodPost, "/v1/authority-workers/leases/reassign", bytes.NewReader(bad))
		req.Header.Set("Authorization", "Bearer coordinator-test-token")
		resp = httptest.NewRecorder()
		handler.ServeHTTP(resp, req)
		if resp.Code != http.StatusBadRequest {
			t.Fatalf("%s override status=%d body=%s", name, resp.Code, resp.Body.String())
		}
	}
}
