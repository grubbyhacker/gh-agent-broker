package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

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
