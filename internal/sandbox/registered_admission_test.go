package sandbox

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func registeredRequest(t *testing.T, work, route string) RegisteredAdmissionRequest {
	t.Helper()
	r := RegisteredAdmissionRequest{Profile: "writer", IdempotencyKey: "registered-key", SessionBinding: "session:" + work, Source: RegisteredTaskSource{WorkItemID: work, RouteSnapshotID: route}, Task: RegisteredTask{TaskKind: "repository_change_v1", TaskVersion: "1.0.0", CompletionContract: "repository_state_v1", VerifierID: "repository_state_v1", ContractDigest: repositoryContractDigest, TaskEvidenceDigest: "sha256:" + strings.Repeat("a", 64), Parameters: RegisteredTaskParameters{RepositoryID: "neutral/repository-proof", BaseRevision: strings.Repeat("b", 40), BranchRef: "agent/repository-proof/settled", ValidationSelection: "required"}}}
	task := r.Task
	canonical := `{"registered_task":{"completionContract":"` + task.CompletionContract + `","contractDigest":"` + task.ContractDigest + `","parameters":{"baseRevision":"` + task.Parameters.BaseRevision + `","branchRef":"` + task.Parameters.BranchRef + `","repositoryId":"` + task.Parameters.RepositoryID + `","validationSelection":"required"},"taskEvidenceDigest":"` + task.TaskEvidenceDigest + `","taskKind":"` + task.TaskKind + `","taskVersion":"` + task.TaskVersion + `","verifierId":"` + task.VerifierID + `"},"registered_task_source":{"route_snapshot_id":"` + r.Source.RouteSnapshotID + `","work_item_id":"` + r.Source.WorkItemID + `}}`
	s := sha256.Sum256([]byte(canonical))
	r.AdmissionTaskDigest = "sha256:" + hex.EncodeToString(s[:])
	return r
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
