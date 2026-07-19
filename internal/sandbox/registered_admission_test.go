package sandbox

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func registeredRequest(t *testing.T, work, route string) RegisteredAdmissionRequest {
	t.Helper()
	r := RegisteredAdmissionRequest{Version: coordinatorRegisteredProtocolVersion, Profile: "writer", IdempotencyKey: "registered-key", SessionBinding: "session:" + work, Source: RegisteredTaskSource{WorkItemID: work, RouteSnapshotID: route}, Task: RegisteredTask{TaskKind: "repository_change_v1", TaskVersion: "1.0.0", CompletionContract: "repository_state_v1", VerifierID: "repository_state_v1", ContractDigest: repositoryContractDigest, TaskEvidenceDigest: "sha256:" + strings.Repeat("a", 64), Parameters: RegisteredTaskParameters{RepositoryID: "neutral/repository-proof", BaseRevision: strings.Repeat("b", 40), BranchRef: "agent/repository-proof/settled", ValidationSelection: "required"}}}
	task := r.Task
	canonical := `{"registered_task":{"completionContract":"` + task.CompletionContract + `","contractDigest":"` + task.ContractDigest + `","parameters":{"baseRevision":"` + task.Parameters.BaseRevision + `","branchRef":"` + task.Parameters.BranchRef + `","repositoryId":"` + task.Parameters.RepositoryID + `","validationSelection":"required"},"taskEvidenceDigest":"` + task.TaskEvidenceDigest + `","taskKind":"` + task.TaskKind + `","taskVersion":"` + task.TaskVersion + `","verifierId":"` + task.VerifierID + `"},"registered_task_source":{"route_snapshot_id":"` + r.Source.RouteSnapshotID + `","work_item_id":"` + r.Source.WorkItemID + `"}}`
	s := sha256.Sum256([]byte(canonical))
	r.AdmissionTaskDigest = "sha256:" + hex.EncodeToString(s[:])
	return r
}

func TestRegisteredAdmissionRESTRequiresExactVersionAndStrictJSON(t *testing.T) {
	ctx := context.Background()
	cfg := authorityTestConfig(t)
	profile := cfg.AuthorityProfiles["writer"]
	profile.SessionIsolation.WorkspaceRoot = t.TempDir()
	profile.SessionIsolation.UIDStart = os.Getuid()
	profile.SessionIsolation.GIDStart = os.Getgid()
	cfg.AuthorityProfiles["writer"] = profile
	store := openAuthorityTestStore(t, cfg.AuthorityStore)
	service := NewAuthorityWorkerService(cfg, store, &fakeAuthorityRuntime{}, nil, allowTestAuthorityIssuance{})
	service.newID = func() (string, error) { return "registered-rest-worker", nil }
	worker, err := service.Provision(ctx, "coordinator", "writer")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.SetHealth(ctx, "coordinator", worker.WorkerID, "ready", true); err != nil {
		t.Fatal(err)
	}
	handler := NewAuthorityRESTHandler(service)
	request := registeredRequest(t, "rest-work", "rest-route")
	for name, mutate := range map[string]func(map[string]any){
		"success":         func(_ map[string]any) {},
		"missing_version": func(v map[string]any) { delete(v, "version") },
		"wrong_version":   func(v map[string]any) { v["version"] = "broker/coordinator/v1" },
		"unknown_version": func(v map[string]any) { v["version"] = "broker/coordinator/v3" },
		"unknown_field":   func(v map[string]any) { v["caller_task"] = "forbidden" },
	} {
		t.Run(name, func(t *testing.T) {
			copy := request
			raw, err := json.Marshal(copy)
			if err != nil {
				t.Fatal(err)
			}
			var wire map[string]any
			if err := json.Unmarshal(raw, &wire); err != nil {
				t.Fatal(err)
			}
			mutate(wire)
			raw, err = json.Marshal(wire)
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(http.MethodPost, "/v1/authority-workers/coordinator/v2/leases", bytes.NewReader(raw))
			req.Header.Set("Authorization", "Bearer coordinator-test-token")
			resp := httptest.NewRecorder()
			handler.ServeHTTP(resp, req)
			if name == "success" && resp.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", resp.Code, resp.Body.String())
			}
			if name != "success" && resp.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s", resp.Code, resp.Body.String())
			}
		})
	}
}

func TestRegisteredCoordinatorLeaseAdmissionVersions(t *testing.T) {
	ctx := context.Background()
	newService := func(t *testing.T) (*AuthorityWorkerStore, http.Handler) {
		t.Helper()
		cfg := authorityTestConfig(t)
		profile := cfg.AuthorityProfiles["writer"]
		profile.SessionIsolation.WorkspaceRoot = t.TempDir()
		profile.SessionIsolation.UIDStart = os.Getuid()
		profile.SessionIsolation.GIDStart = os.Getgid()
		cfg.AuthorityProfiles["writer"] = profile
		cfg.AuthorityPrincipals["legacy-coordinator"] = AuthorityPrincipal{
			Token:           "legacy-coordinator-test-token",
			AllowedProfiles: []string{"writer"},
			AllowedActions:  []string{"acquire"},
		}
		store := openAuthorityTestStore(t, cfg.AuthorityStore)
		service := NewAuthorityWorkerService(cfg, store, &fakeAuthorityRuntime{}, nil, allowTestAuthorityIssuance{})
		service.newID = func() (string, error) { return "registered-version-worker", nil }
		worker, err := service.Provision(ctx, "coordinator", "writer")
		if err != nil {
			t.Fatal(err)
		}
		if _, err = service.SetHealth(ctx, "coordinator", worker.WorkerID, "ready", true); err != nil {
			t.Fatal(err)
		}
		return store, NewAuthorityRESTHandler(service)
	}

	t.Run("registered principal is refused on v1 before effects", func(t *testing.T) {
		store, handler := newService(t)
		req := httptest.NewRequest(http.MethodPost, "/v1/authority-workers/coordinator/v1/leases", strings.NewReader(`not-json`))
		req.Header.Set("Authorization", "Bearer coordinator-test-token")
		resp := httptest.NewRecorder()
		handler.ServeHTTP(resp, req)
		if resp.Code != http.StatusConflict || !strings.Contains(resp.Body.String(), "registered coordinator principal must use coordinator/v2 leases") {
			t.Fatalf("status=%d body=%s", resp.Code, resp.Body.String())
		}
		var leases, workspaces, admissions int
		if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM authority_session_leases`).Scan(&leases); err != nil {
			t.Fatal(err)
		}
		if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM authority_session_workspaces`).Scan(&workspaces); err != nil {
			t.Fatal(err)
		}
		if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM authority_registered_admissions`).Scan(&admissions); err != nil {
			t.Fatal(err)
		}
		if leases != 0 || workspaces != 0 || admissions != 0 {
			t.Fatalf("v1 denial had effects: leases=%d workspaces=%d admissions=%d", leases, workspaces, admissions)
		}
	})

	t.Run("separately authorized non-registered principal retains v1", func(t *testing.T) {
		store, handler := newService(t)
		body := `{"profile":"writer","idempotency_key":"legacy-key","session_binding":"legacy-session"}`
		req := httptest.NewRequest(http.MethodPost, "/v1/authority-workers/coordinator/v1/leases", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer legacy-coordinator-test-token")
		resp := httptest.NewRecorder()
		handler.ServeHTTP(resp, req)
		if resp.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", resp.Code, resp.Body.String())
		}
		if _, err := store.RegisteredAdmission(ctx, "legacy-coordinator", "legacy-session"); !errors.Is(err, sql.ErrNoRows) {
			t.Fatalf("legacy v1 admission err=%v", err)
		}
	})

	t.Run("v2 remains the registered acquisition", func(t *testing.T) {
		store, handler := newService(t)
		request := registeredRequest(t, "version-work", "version-route")
		body, err := json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost, "/v1/authority-workers/coordinator/v2/leases", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer coordinator-test-token")
		resp := httptest.NewRecorder()
		handler.ServeHTTP(resp, req)
		if resp.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", resp.Code, resp.Body.String())
		}
		if _, err := store.RegisteredAdmission(ctx, "coordinator", request.SessionBinding); err != nil {
			t.Fatalf("v2 registered admission err=%v", err)
		}
	})
}

func TestRegisteredAdmissionV2IsDurableAndRejectsConflicts(t *testing.T) {
	ctx := context.Background()
	cfg := authorityTestConfig(t)
	p := cfg.AuthorityProfiles["writer"]
	p.SessionIsolation.WorkspaceRoot = t.TempDir()
	cfg.AuthorityProfiles["writer"] = p
	store := openAuthorityTestStore(t, cfg.AuthorityStore)
	service := NewAuthorityWorkerService(cfg, store, &fakeAuthorityRuntime{}, nil, allowTestAuthorityIssuance{})
	service.newID = func() (string, error) { return "registered-worker", nil }
	w, err := service.Provision(ctx, "coordinator", "writer")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.SetHealth(ctx, "coordinator", w.WorkerID, "ready", true); err != nil {
		t.Fatal(err)
	}
	r := registeredRequest(t, "work-1", "route-1")
	admittedLease, err := store.AcquireRegistered(ctx, "coordinator", r, 1)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := store.AcquireRegistered(ctx, "coordinator", r, 1)
	if err != nil || !replay.Replay || replay.WorkerID != admittedLease.WorkerID {
		t.Fatalf("replay=%+v err=%v", replay, err)
	}
	changed := r
	changed.Source.RouteSnapshotID = "route-2"
	if _, err = service.AcquireRegisteredSession(ctx, "coordinator", changed); err == nil || !strings.Contains(err.Error(), "mismatch") {
		t.Fatalf("different source err=%v", err)
	}
	changed = r
	changed.Task.Parameters.BranchRef = "agent/repository-proof/other"
	if _, err = service.AcquireRegisteredSession(ctx, "coordinator", changed); err == nil {
		t.Fatal("different task was admitted")
	}
}

func TestRegisteredAdmissionRejectsUnconfiguredPrincipalAndDigest(t *testing.T) {
	r := registeredRequest(t, "work-2", "route-2")
	r.AdmissionTaskDigest = "sha256:" + strings.Repeat("f", 64)
	if _, err := validateRegisteredAdmission(r); err == nil {
		t.Fatal("bad digest accepted")
	}
	cfg := authorityTestConfig(t)
	cfg.RegisteredCoordinatorPrincipal = "other"
	service := NewAuthorityWorkerService(cfg, openAuthorityTestStore(t, cfg.AuthorityStore), &fakeAuthorityRuntime{}, nil, allowTestAuthorityIssuance{})
	if _, err := service.AcquireRegisteredSession(context.Background(), "coordinator", registeredRequest(t, "work-3", "route-3")); err == nil || !strings.Contains(err.Error(), "not configured") {
		t.Fatalf("err=%v", err)
	}
}

func TestRegisteredReassignmentUsesAdoptionAndReplays(t *testing.T) {
	ctx := context.Background()
	cfg := authorityTestConfig(t)
	p := cfg.AuthorityProfiles["writer"]
	p.SessionCapacity = 1
	cfg.AuthorityProfiles["writer"] = p
	store := openAuthorityTestStore(t, cfg.AuthorityStore)
	runtime := &fakeAuthorityRuntime{}
	service := NewAuthorityWorkerService(cfg, store, runtime, nil, allowTestAuthorityIssuance{})
	ids := []string{"registered-old", "registered-new"}
	service.newID = func() (string, error) { id := ids[0]; ids = ids[1:]; return id, nil }
	old, err := service.Provision(ctx, "coordinator", "writer")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.SetHealth(ctx, "coordinator", old.WorkerID, "ready", true); err != nil {
		t.Fatal(err)
	}
	lease, err := store.AcquireRegistered(ctx, "coordinator", registeredRequest(t, "adopt-work", "adopt-route"), p.IssuanceGeneration)
	if err != nil {
		t.Fatal(err)
	}
	workspace := SessionWorkspace{UID: 20000, GID: 20000, Path: "/durable/registered-adopt", SessionLineageID: lease.SessionLineageID, AgentdSessionID: "registered-agentd-session"}
	if _, err = store.db.ExecContext(ctx, `INSERT INTO authority_session_workspaces(binding_digest,worker_id,uid,gid,workspace_path,created_at,session_lineage_id) VALUES(?,?,?,?,?,?,?)`, lease.BindingDigest, old.WorkerID, workspace.UID, workspace.GID, workspace.Path, formatAuthorityTime(time.Now().UTC()), lease.SessionLineageID); err != nil {
		t.Fatal(err)
	}
	if err = store.BindAgentdSession(ctx, "session:adopt-work", "registered-agentd-session"); err != nil {
		t.Fatal(err)
	}
	if _, err = service.SetHealth(ctx, "coordinator", old.WorkerID, "lost", false); err != nil {
		t.Fatal(err)
	}
	replacement, err := service.Replace(ctx, "coordinator", old.WorkerID, "lost")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.SetHealth(ctx, "coordinator", replacement.WorkerID, "ready", true); err != nil {
		t.Fatal(err)
	}
	if _, err = store.RegisteredAdmission(ctx, "coordinator", "session:adopt-work"); err != nil {
		t.Fatal(err)
	}
	var calls []agentdRegisteredAdoptRequest
	runtime.adopt = func(_ context.Context, worker AuthorityWorker, sessionID string, request agentdRegisteredAdoptRequest) (agentdSessionStatus, error) {
		calls = append(calls, request)
		return agentdSessionStatus{Version: agentdSessionProtocolVersion, SessionID: sessionID, CoordinatorBinding: "session:adopt-work", AuthorityBinding: "writer", WorkerID: worker.WorkerID, StorageLineageID: worker.WorkerStorageLineageID, FenceEpoch: worker.WorkerFenceEpoch, SessionLineageID: lease.SessionLineageID, Workspace: agentdSessionWorkspace{WorkspaceRef: workspace.Path, UID: workspace.UID, GID: workspace.GID}, Phase: "active", TurnIDs: []string{}, NextCursor: 1}, nil
	}
	request := AuthoritySessionReassignmentRequest{SessionBinding: "session:adopt-work", SessionLineageID: lease.SessionLineageID, PredecessorWorkerID: old.WorkerID, PredecessorWorkerFenceEpoch: old.WorkerFenceEpoch, IdempotencyKey: "registered-adopt-one"}
	if _, err = service.ReassignSession(ctx, "coordinator", request); err != nil {
		t.Fatal(err)
	}
	request.IdempotencyKey = "registered-adopt-two"
	if replay, err := service.ReassignSession(ctx, "coordinator", request); err != nil || !replay.Replay {
		t.Fatalf("replay=%+v err=%v", replay, err)
	}
	if len(calls) != 1 || calls[0].Version != "agentd/registered-lifecycle/v1" || calls[0].PredecessorWorker != old.WorkerID || calls[0].PredecessorEpoch != old.WorkerFenceEpoch || calls[0].IdempotencyKey == request.IdempotencyKey {
		t.Fatalf("registered adoption calls=%+v", calls)
	}
}

func TestRegisteredAdmissionDurableReadFailsClosedOnCorruption(t *testing.T) {
	ctx := context.Background()
	cfg := authorityTestConfig(t)
	profile := cfg.AuthorityProfiles["writer"]
	profile.SessionIsolation.WorkspaceRoot = t.TempDir()
	profile.SessionIsolation.UIDStart = os.Getuid()
	profile.SessionIsolation.GIDStart = os.Getgid()
	cfg.AuthorityProfiles["writer"] = profile
	store := openAuthorityTestStore(t, cfg.AuthorityStore)
	service := NewAuthorityWorkerService(cfg, store, &fakeAuthorityRuntime{}, nil, allowTestAuthorityIssuance{})
	service.newID = func() (string, error) { return "corruption-worker", nil }
	worker, err := service.Provision(ctx, "coordinator", "writer")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.SetHealth(ctx, "coordinator", worker.WorkerID, "ready", true); err != nil {
		t.Fatal(err)
	}
	request := registeredRequest(t, "corrupt-work", "corrupt-route")
	lease, err := store.AcquireRegistered(ctx, "coordinator", request, 1)
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]string{
		"protocol": "UPDATE authority_registered_admissions SET protocol_version='broker/coordinator/v1' WHERE binding_digest=?",
		"source":   "UPDATE authority_registered_admissions SET work_item_id='other-work' WHERE binding_digest=?",
		"json":     "UPDATE authority_registered_admissions SET canonical_task_json='{}' WHERE binding_digest=?",
		"digest":   "UPDATE authority_registered_admissions SET admission_task_digest='sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' WHERE binding_digest=?",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := store.db.ExecContext(ctx, change, lease.BindingDigest); err != nil {
				t.Fatal(err)
			}
			if _, err := store.RegisteredAdmission(ctx, "coordinator", request.SessionBinding); err == nil {
				t.Fatal("corrupt durable admission was accepted")
			}
			if _, err := store.db.ExecContext(ctx, `UPDATE authority_registered_admissions SET protocol_version=?,work_item_id=?,route_snapshot_id=?,canonical_task_json=?,admission_task_digest=? WHERE binding_digest=?`, coordinatorRegisteredProtocolVersion, request.Source.WorkItemID, request.Source.RouteSnapshotID, mustRegisteredCanonical(t, request), request.AdmissionTaskDigest, lease.BindingDigest); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func mustRegisteredCanonical(t *testing.T, request RegisteredAdmissionRequest) string {
	t.Helper()
	admission, err := validateRegisteredAdmission(request)
	if err != nil {
		t.Fatal(err)
	}
	return admission.CanonicalJSON
}
