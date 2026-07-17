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
	"strings"
	"testing"
	"time"
)

type coordinatorTestRuntime struct {
	*fakeAuthorityRuntime
	worker AuthorityWorker
	method string
	path   string
	body   json.RawMessage
}

func (r *coordinatorTestRuntime) AgentdSessionRequest(_ context.Context, worker AuthorityWorker, method, path string, body json.RawMessage) (int, json.RawMessage, error) {
	r.worker, r.method, r.path, r.body = worker, method, path, bytes.Clone(body)
	return http.StatusAccepted, json.RawMessage(`{"sessionId":"agentd-session","turnId":"turn-1","phase":"queued"}`), nil
}

func TestCoordinatorV1SubmitIsBrokerMediated(t *testing.T) {
	ctx := context.Background()
	cfg := authorityTestConfig(t)
	profile := cfg.AuthorityProfiles["writer"]
	profile.SessionIsolation.WorkspaceRoot = t.TempDir()
	cfg.AuthorityProfiles["writer"] = profile
	store := openAuthorityTestStore(t, cfg.AuthorityStore)
	runtime := &coordinatorTestRuntime{fakeAuthorityRuntime: &fakeAuthorityRuntime{}}
	service := NewAuthorityWorkerService(cfg, store, runtime, nil)
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
	if runtime.worker.WorkerID != lease.WorkerID || runtime.path != "/v1/sessions/agentd-session/turns" || runtime.method != http.MethodPost || !bytes.Contains(runtime.body, []byte(`"idempotencyKey":"turn-key"`)) {
		t.Fatalf("broker projection worker=%+v method=%s path=%s body=%s", runtime.worker, runtime.method, runtime.path, runtime.body)
	}
	var out CoordinatorSessionResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil || out.Version != coordinatorProtocolVersion || out.Lease.ProfileVersion == "" || out.Lease.PolicyDigest == "" {
		t.Fatalf("response=%+v err=%v", out, err)
	}
	for _, forbidden := range []string{"worker_id", "profile", "model", "runtime", "agentd_session_id", "endpoint"} {
		bad := []byte(strings.TrimSuffix(string(body), "}") + `,"` + forbidden + `":"caller-selected"}`)
		req = httptest.NewRequest(http.MethodPost, "/v1/authority-workers/coordinator/v1/sessions/submit", bytes.NewReader(bad))
		req.Header.Set("Authorization", "Bearer coordinator-test-token")
		resp = httptest.NewRecorder()
		handler.ServeHTTP(resp, req)
		if resp.Code != http.StatusBadRequest {
			t.Fatalf("forbidden %s status=%d body=%s", forbidden, resp.Code, resp.Body.String())
		}
	}
}

func TestCoordinatorWireFixturesAreStable(t *testing.T) {
	created := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	lease := AuthorityLease{Principal: "coordinator", Profile: "writer", WorkerID: "worker-1", SessionLineageID: "11111111111111111111111111111111", WorkerStorageLineageID: "22222222222222222222222222222222", WorkerFenceEpoch: 1, ProfileVersion: "profile-v1", PolicyDigest: "policy-v1", BindingDigest: "binding-digest", IdempotencyDigest: "idempotency-digest", CreatedAt: created}
	admission := CoordinatorLeaseAdmission{Version: coordinatorProtocolVersion, Admission: AuthoritySessionAdmission{Lease: lease, Workspace: SessionWorkspace{UID: 20000, GID: 20000, Path: "/var/lib/agentd/workspaces/11111111111111111111111111111111", SessionLineageID: lease.SessionLineageID}}}
	status := CoordinatorReassignmentStatus{Version: coordinatorProtocolVersion, SessionBinding: "logical-session", SessionLineageID: lease.SessionLineageID, AuthorityProfile: "writer", Predecessor: agentdWorkerBinding{WorkerID: "worker-1", StorageLineageID: lease.WorkerStorageLineageID, FenceEpoch: 1}, Successor: agentdWorkerBinding{WorkerID: "worker-2", StorageLineageID: lease.WorkerStorageLineageID, FenceEpoch: 2}, IdempotencyKey: "opaque-rebind-key", State: "confirmed"}
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
	service := NewAuthorityWorkerService(cfg, store, runtime, nil)
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
