package sandbox

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

type fakeAuthorityRuntime struct {
	mu          sync.Mutex
	created     []AuthorityWorkerSpec
	stopped     []string
	workers     map[string]AuthorityRuntimeResult
	physical    int
	err         error
	unhealthy   bool
	afterCreate func()
}

func (f *fakeAuthorityRuntime) Create(_ context.Context, spec AuthorityWorkerSpec) (AuthorityRuntimeResult, error) {
	f.mu.Lock()
	f.created = append(f.created, spec)
	if f.err != nil {
		err := f.err
		f.mu.Unlock()
		return AuthorityRuntimeResult{}, err
	}
	if f.workers == nil {
		f.workers = make(map[string]AuthorityRuntimeResult)
	}
	result, ok := f.workers[spec.WorkerID]
	if !ok {
		result = AuthorityRuntimeResult{ContainerID: "container-" + spec.WorkerID, ImageDigest: "sha256:2222222222222222222222222222222222222222222222222222222222222222"}
		f.workers[spec.WorkerID] = result
		f.physical++
	}
	afterCreate := f.afterCreate
	f.mu.Unlock()
	if afterCreate != nil {
		afterCreate()
	}
	return result, nil
}

func (f *fakeAuthorityRuntime) Stop(_ context.Context, containerID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stopped = append(f.stopped, containerID)
	return nil
}

func (f *fakeAuthorityRuntime) Healthy(_ context.Context, _ string) (bool, string, error) {
	if f.unhealthy {
		return false, "synthetic_unhealthy", nil
	}
	if f.err != nil {
		return false, "synthetic_unhealthy", f.err
	}
	return true, "synthetic_liveness_ok", nil
}

func TestAuthorityReconcileUnhealthyCheckpointsAndReplaces(t *testing.T) {
	ctx := context.Background()
	cfg := authorityTestConfig(t)
	profile := cfg.AuthorityProfiles["writer"]
	profile.Checkpoint.Directory = t.TempDir()
	cfg.AuthorityProfiles["writer"] = profile
	key := make([]byte, 32)
	key[0] = 1
	t.Setenv(profile.Checkpoint.KeyEnv, base64.StdEncoding.EncodeToString(key))
	store := openAuthorityTestStore(t, cfg.AuthorityStore)
	runtime := &fakeAuthorityRuntime{}
	service := NewAuthorityWorkerService(cfg, store, runtime, nil).WithCheckpointStore(NewCheckpointStore(cfg, store))
	ids := []string{"old-reconcile-health", "new-reconcile-health"}
	service.newID = func() (string, error) { id := ids[0]; ids = ids[1:]; return id, nil }
	old, err := service.Provision(ctx, "coordinator", "writer")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.SetHealth(ctx, "coordinator", old.WorkerID, "ready", true); err != nil {
		t.Fatal(err)
	}
	if _, err = service.Acquire(ctx, "coordinator", AuthorityWorkerRequest{Profile: "writer", IdempotencyKey: "reconcile-health", SessionBinding: "reconcile-health-session"}); err != nil {
		t.Fatal(err)
	}
	runtime.unhealthy = true
	if err := service.Reconcile(ctx, "coordinator"); err != nil {
		t.Fatal(err)
	}
	old, err = store.GetWorker(ctx, old.WorkerID)
	if err != nil {
		t.Fatal(err)
	}
	if old.State != AuthorityWorkerUnhealthy {
		t.Fatalf("old=%+v", old)
	}
	entries, err := os.ReadDir(profile.Checkpoint.Directory)
	if err != nil || len(entries) != 1 {
		t.Fatalf("evidence entries=%v err=%v", entries, err)
	}
	if err := VerifyCheckpoint(filepath.Join(profile.Checkpoint.Directory, entries[0].Name()), profile, old); err != nil {
		t.Fatalf("checkpoint verify after unhealthy reconcile: %v", err)
	}
	if old.ReplacementWorker == "" {
		t.Fatal("unhealthy worker was not replaced")
	}
}

func TestAuthorityProfileValidationAndDigest(t *testing.T) {
	cfg := authorityTestConfig(t)
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	first, policy, err := authorityProfileDigest("writer", cfg.AuthorityProfiles["writer"])
	if err != nil {
		t.Fatal(err)
	}
	profile := cfg.AuthorityProfiles["writer"]
	profile.Repositories = []string{"owner/other", "owner/repo"}
	profile.Operations = []string{"pull.create", "git.receive-pack"}
	second, reorderedPolicy, err := authorityProfileDigest("writer", profile)
	if err != nil {
		t.Fatal(err)
	}
	if first != second || policy != reorderedPolicy {
		t.Fatal("profile digest changed under set reordering")
	}

	cfg.Production = true
	profile.Image = "example.com/agentd:latest"
	cfg.AuthorityProfiles["writer"] = profile
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "pinned by digest") {
		t.Fatalf("Validate() error = %v, want digest denial", err)
	}

	cfg = authorityTestConfig(t)
	profile = cfg.AuthorityProfiles["writer"]
	profile.Platform = "linux/arm64"
	cfg.AuthorityProfiles["writer"] = profile
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "platform must be linux/amd64") {
		t.Fatalf("Validate() error = %v, want platform denial", err)
	}

	cfg = authorityTestConfig(t)
	profile = cfg.AuthorityProfiles["writer"]
	profile.ExtraMounts = []ExtraMount{{SourcePath: "/var/run/docker.sock", MountPath: "/runtime/docker.sock"}}
	cfg.AuthorityProfiles["writer"] = profile
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "Docker socket") {
		t.Fatalf("Validate() error = %v, want Docker socket denial", err)
	}

	cfg = authorityTestConfig(t)
	profile = cfg.AuthorityProfiles["writer"]
	profile.CredentialBundle = "codex"
	cfg.AuthorityProfiles["writer"] = profile
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "does not allow authority profile") {
		t.Fatalf("Validate() error = %v, want credential bundle profile denial", err)
	}
	bundle := cfg.Bundles["codex"]
	bundle.AllowedAuthorityProfiles = []string{"writer"}
	cfg.Bundles["codex"] = bundle
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() with reviewed credential bundle error = %v", err)
	}
}

func TestAuthorityWorkerRequestRejectsAuthorityOverrides(t *testing.T) {
	for _, field := range []string{"image", "platform", "command", "credentials", "mounts", "network", "repo", "operations", "user", "isolation"} {
		body := `{"profile":"writer","idempotency_key":"one","session_binding":"session-1","` + field + `":"forbidden"}`
		var request AuthorityWorkerRequest
		if err := json.Unmarshal([]byte(body), &request); err == nil || !strings.Contains(err.Error(), "unknown field") {
			t.Fatalf("field %q error = %v, want unknown field", field, err)
		}
	}
	var request AuthorityWorkerRequest
	if err := json.Unmarshal([]byte(`{"profile":"writer","idempotency_key":"one","session_binding":"session-1"}{}`), &request); err == nil {
		t.Fatal("request accepted a trailing JSON value")
	}
}

func TestAuthorityWorkerLifecycleCapacityDrainReleaseAndReplacement(t *testing.T) {
	ctx := context.Background()
	cfg := authorityTestConfig(t)
	store := openAuthorityTestStore(t, cfg.AuthorityStore)
	runtime := &fakeAuthorityRuntime{}
	auditPath := filepath.Join(t.TempDir(), "authority-audit.jsonl")
	audit, err := NewAuditLogger(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := audit.Close(); err != nil {
			t.Errorf("close audit: %v", err)
		}
	})
	service := NewAuthorityWorkerService(cfg, store, runtime, audit)
	ids := []string{"worker-one", "worker-two", "worker-three"}
	service.newID = func() (string, error) { id := ids[0]; ids = ids[1:]; return id, nil }

	worker, err := service.Provision(ctx, "coordinator", "writer")
	if err != nil {
		t.Fatalf("Provision() error = %v", err)
	}
	if worker.State != AuthorityWorkerStarting || worker.ContainerID != "container-worker-one" {
		t.Fatalf("worker = %+v", worker)
	}
	if worker.ImageReference != cfg.AuthorityProfiles["writer"].Image || worker.ImageDigest != "sha256:2222222222222222222222222222222222222222222222222222222222222222" {
		t.Fatalf("image identity = %+v", worker)
	}
	if len(runtime.created) != 1 || runtime.created[0].Image != cfg.AuthorityProfiles["writer"].Image || runtime.created[0].Platform != "linux/amd64" || runtime.created[0].BrokerSecretEnv != "WRITER_BROKER_CREDENTIAL" {
		t.Fatalf("immutable runtime spec = %+v", runtime.created)
	}
	worker, err = service.SetHealth(ctx, "coordinator", worker.WorkerID, "synthetic_ready", true)
	if err != nil || worker.State != AuthorityWorkerReady {
		t.Fatalf("SetHealth() worker=%+v err=%v", worker, err)
	}
	if _, err := service.Drain(ctx, "session-only", worker.WorkerID, "not_allowed"); err == nil || !strings.Contains(err.Error(), "policy denial") {
		t.Fatalf("session-only lifecycle mutation error = %v", err)
	}

	firstRequest := AuthorityWorkerRequest{Profile: "writer", IdempotencyKey: "private-idempotency-one", SessionBinding: "private-session-one"}
	first, err := service.Acquire(ctx, "coordinator", firstRequest)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := service.Acquire(ctx, "coordinator", firstRequest)
	if err != nil || !replay.Replay || replay.WorkerID != first.WorkerID {
		t.Fatalf("replay=%+v err=%v", replay, err)
	}
	second, err := service.Acquire(ctx, "coordinator", AuthorityWorkerRequest{Profile: "writer", IdempotencyKey: "two", SessionBinding: "session-two"})
	if err != nil || second.WorkerID != worker.WorkerID {
		t.Fatalf("second=%+v err=%v", second, err)
	}
	if _, err := service.Acquire(ctx, "coordinator", AuthorityWorkerRequest{Profile: "writer", IdempotencyKey: "three", SessionBinding: "session-three"}); err == nil || !strings.Contains(err.Error(), "no ready worker capacity") {
		t.Fatalf("capacity error = %v", err)
	}

	drained, err := service.Drain(ctx, "coordinator", worker.WorkerID, "profile_upgrade")
	if err != nil || drained.State != AuthorityWorkerDraining {
		t.Fatalf("Drain()=%+v err=%v", drained, err)
	}
	if _, err := service.Acquire(ctx, "coordinator", AuthorityWorkerRequest{Profile: "writer", IdempotencyKey: "four", SessionBinding: "session-four"}); err == nil {
		t.Fatal("draining worker admitted a new session")
	}
	released, err := service.Release(ctx, "coordinator", firstRequest.SessionBinding)
	if err != nil || released.Replay {
		t.Fatalf("Release()=%+v err=%v", released, err)
	}
	released, err = service.Release(ctx, "coordinator", firstRequest.SessionBinding)
	if err != nil || !released.Replay {
		t.Fatalf("replayed Release()=%+v err=%v", released, err)
	}

	updatedProfile := service.cfg.AuthorityProfiles["writer"]
	updatedProfile.Image = "example.com/agentd@sha256:3333333333333333333333333333333333333333333333333333333333333333"
	updatedProfile.Operations = append(updatedProfile.Operations, "pull.read")
	service.cfg.AuthorityProfiles["writer"] = updatedProfile
	replacement, err := service.Replace(ctx, "coordinator", worker.WorkerID, "profile_upgrade")
	if err != nil || replacement.WorkerID != "worker-two" || replacement.Generation != 2 || replacement.State != AuthorityWorkerStarting {
		t.Fatalf("Replace()=%+v err=%v", replacement, err)
	}
	if replacement.ProfileVersion == worker.ProfileVersion || replacement.PolicyDigest == worker.PolicyDigest || replacement.ImageReference != updatedProfile.Image {
		t.Fatalf("replacement did not attest current profile: old=%+v replacement=%+v", worker, replacement)
	}
	if runtime.created[1].ProfileVersion != replacement.ProfileVersion || runtime.created[1].Operations[len(runtime.created[1].Operations)-1] != "pull.read" {
		t.Fatalf("replacement runtime spec = %+v", runtime.created[1])
	}
	replayedReplacement, err := service.Replace(ctx, "coordinator", worker.WorkerID, "profile_upgrade")
	if err != nil || replayedReplacement.WorkerID != replacement.WorkerID || len(runtime.created) != 2 {
		t.Fatalf("replayed Replace()=%+v creates=%d err=%v", replayedReplacement, len(runtime.created), err)
	}

	if _, err := service.Acquire(ctx, "intruder", firstRequest); err == nil || !strings.Contains(err.Error(), "policy denial") {
		t.Fatalf("unauthorized Acquire() error = %v", err)
	}
	if err := audit.file.Sync(); err != nil {
		t.Fatal(err)
	}
	//nolint:gosec // G304: auditPath is a test-owned path under t.TempDir.
	auditBytes, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{firstRequest.IdempotencyKey, firstRequest.SessionBinding, "WRITER_BROKER_CREDENTIAL"} {
		if strings.Contains(string(auditBytes), secret) {
			t.Fatalf("audit leaked %q: %s", secret, auditBytes)
		}
	}
}

func TestAuthorityWorkerStoreRecoversAndSerializesCapacity(t *testing.T) {
	ctx := context.Background()
	cfg := authorityTestConfig(t)
	store, err := OpenAuthorityWorkerStore(ctx, cfg.AuthorityStore)
	if err != nil {
		t.Fatal(err)
	}
	runtime := &fakeAuthorityRuntime{}
	service := NewAuthorityWorkerService(cfg, store, runtime, nil)
	service.newID = func() (string, error) { return "worker-persisted", nil }
	worker, err := service.Provision(ctx, "coordinator", "writer")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.SetHealth(ctx, "coordinator", worker.WorkerID, "ready", true); err != nil {
		t.Fatal(err)
	}

	const contenders = 12
	results := make(chan error, contenders)
	var wg sync.WaitGroup
	for i := 0; i < contenders; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			_, err := service.Acquire(ctx, "coordinator", AuthorityWorkerRequest{Profile: "writer", IdempotencyKey: fmt.Sprintf("idem-%d", index), SessionBinding: fmt.Sprintf("binding-%d", index)})
			results <- err
		}(i)
	}
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		}
	}
	if successes != 2 {
		t.Fatalf("successful capacity leases = %d, want 2", successes)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenAuthorityWorkerStore(ctx, cfg.AuthorityStore)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := reopened.Close(); err != nil {
			t.Errorf("close reopened store: %v", err)
		}
	})
	recovered, err := reopened.GetWorker(ctx, worker.WorkerID)
	if err != nil {
		t.Fatal(err)
	}
	if recovered.State != AuthorityWorkerReady || recovered.AssignedSessions != 2 || recovered.ProfileVersion == "" || recovered.PolicyDigest == "" {
		t.Fatalf("recovered worker = %+v", recovered)
	}
}

func TestAuthorityWorkerReplacementFailureKeepsOldWorkerAvailableAndRetries(t *testing.T) {
	ctx := context.Background()
	cfg := authorityTestConfig(t)
	store := openAuthorityTestStore(t, cfg.AuthorityStore)
	runtime := &fakeAuthorityRuntime{}
	service := NewAuthorityWorkerService(cfg, store, runtime, nil)
	ids := []string{"old-worker", "failed-replacement", "retry-replacement"}
	service.newID = func() (string, error) { id := ids[0]; ids = ids[1:]; return id, nil }
	old, err := service.Provision(ctx, "coordinator", "writer")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.SetHealth(ctx, "coordinator", old.WorkerID, "ready", true); err != nil {
		t.Fatal(err)
	}
	runtime.err = errors.New("synthetic create failure")
	if _, err := service.Replace(ctx, "coordinator", old.WorkerID, "unhealthy"); err == nil {
		t.Fatal("Replace() succeeded despite runtime failure")
	}
	old, err = store.GetWorker(ctx, old.WorkerID)
	if err != nil {
		t.Fatal(err)
	}
	if old.State != AuthorityWorkerReady || old.ReplacementWorker != "" {
		t.Fatalf("old worker after failed replacement = %+v", old)
	}
	runtime.err = nil
	replacement, err := service.Replace(ctx, "coordinator", old.WorkerID, "unhealthy")
	if err != nil {
		t.Fatalf("replacement retry error = %v", err)
	}
	if replacement.WorkerID != "retry-replacement" || replacement.State != AuthorityWorkerStarting {
		t.Fatalf("replacement retry = %+v", replacement)
	}
	old, err = store.GetWorker(ctx, old.WorkerID)
	if err != nil {
		t.Fatal(err)
	}
	if old.State != AuthorityWorkerReady || old.ReplacementWorker != replacement.WorkerID {
		t.Fatalf("old worker before replacement readiness = %+v", old)
	}
	if _, err := service.SetHealth(ctx, "coordinator", replacement.WorkerID, "ready", true); err != nil {
		t.Fatal(err)
	}
	old, err = store.GetWorker(ctx, old.WorkerID)
	if err != nil {
		t.Fatal(err)
	}
	if old.State != AuthorityWorkerDraining {
		t.Fatalf("old worker after replacement readiness = %+v", old)
	}
}

func TestAuthorityWorkerReplacementReconcilesPersistedProvisioningIntent(t *testing.T) {
	ctx := context.Background()
	cfg := authorityTestConfig(t)
	store := openAuthorityTestStore(t, cfg.AuthorityStore)
	runtime := &fakeAuthorityRuntime{}
	service := NewAuthorityWorkerService(cfg, store, runtime, nil)
	service.newID = func() (string, error) { return "old-reconcile", nil }
	old, err := service.Provision(ctx, "coordinator", "writer")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.SetHealth(ctx, "coordinator", old.WorkerID, "ready", true); err != nil {
		t.Fatal(err)
	}
	profile := cfg.AuthorityProfiles["writer"]
	profileVersion, policyDigest, err := authorityProfileDigest("writer", profile)
	if err != nil {
		t.Fatal(err)
	}
	planned := AuthorityWorker{WorkerID: "persisted-replacement", Profile: "writer", ProfileVersion: profileVersion, PolicyDigest: policyDigest, ImageReference: profile.Image, Generation: 2, State: AuthorityWorkerProvisioning, Capacity: profile.SessionCapacity, DrainReason: "reconcile"}
	if _, created, err := store.LinkReplacement(ctx, old.WorkerID, planned, profile.MaxWorkers); err != nil || !created {
		t.Fatalf("LinkReplacement() created=%v err=%v", created, err)
	}
	createdBeforeCrash, err := runtime.Create(ctx, authoritySpec(planned, profile, cfg))
	if err != nil {
		t.Fatal(err)
	}
	if runtime.physical != 2 {
		t.Fatalf("physical workers before crash = %d, want old plus replacement", runtime.physical)
	}
	// Simulate a broker crash after the idempotent runtime creation succeeds but
	// before its identity is recorded in SQLite. The retry must ensure the same
	// WorkerID instead of creating another physical worker.
	service.newID = func() (string, error) { return "unused-new-id", nil }
	reconciled, err := service.Replace(ctx, "coordinator", old.WorkerID, "reconcile")
	if err != nil {
		t.Fatalf("Replace() reconciliation error = %v", err)
	}
	if reconciled.WorkerID != planned.WorkerID || reconciled.ContainerID != createdBeforeCrash.ContainerID || reconciled.State != AuthorityWorkerStarting || len(runtime.created) != 3 || runtime.created[2].WorkerID != planned.WorkerID {
		t.Fatalf("reconciled=%+v runtime creates=%+v", reconciled, runtime.created)
	}
	if runtime.physical != 2 {
		t.Fatalf("physical workers after reconciliation = %d, want no duplicate", runtime.physical)
	}
	old, err = store.GetWorker(ctx, old.WorkerID)
	if err != nil {
		t.Fatal(err)
	}
	if old.State != AuthorityWorkerReady {
		t.Fatalf("old worker drained before replacement readiness: %+v", old)
	}
}

func TestAuthorityWorkerConcurrentReplacementReconciliationSharesRuntimeIdentity(t *testing.T) {
	ctx := context.Background()
	cfg := authorityTestConfig(t)
	store := openAuthorityTestStore(t, cfg.AuthorityStore)
	runtime := &fakeAuthorityRuntime{}
	service := NewAuthorityWorkerService(cfg, store, runtime, nil)
	service.newID = func() (string, error) { return "old-concurrent", nil }
	old, err := service.Provision(ctx, "coordinator", "writer")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.SetHealth(ctx, "coordinator", old.WorkerID, "ready", true); err != nil {
		t.Fatal(err)
	}
	profile := cfg.AuthorityProfiles["writer"]
	profileVersion, policyDigest, err := authorityProfileDigest("writer", profile)
	if err != nil {
		t.Fatal(err)
	}
	planned := AuthorityWorker{WorkerID: "concurrent-replacement", Profile: "writer", ProfileVersion: profileVersion, PolicyDigest: policyDigest, ImageReference: profile.Image, Generation: 2, State: AuthorityWorkerProvisioning, Capacity: profile.SessionCapacity, DrainReason: "reconcile concurrently"}
	if _, created, err := store.LinkReplacement(ctx, old.WorkerID, planned, profile.MaxWorkers); err != nil || !created {
		t.Fatalf("LinkReplacement() created=%v err=%v", created, err)
	}

	arrived := make(chan struct{}, 2)
	release := make(chan struct{})
	runtime.afterCreate = func() {
		arrived <- struct{}{}
		<-release
	}
	service.newID = func() (string, error) { return "unused-concurrent-id", nil }
	type replaceResult struct {
		worker AuthorityWorker
		err    error
	}
	results := make(chan replaceResult, 2)
	for range 2 {
		go func() {
			worker, err := service.Replace(ctx, "coordinator", old.WorkerID, "reconcile concurrently")
			results <- replaceResult{worker: worker, err: err}
		}()
	}
	<-arrived
	<-arrived
	close(release)
	for range 2 {
		result := <-results
		if result.err != nil || result.worker.WorkerID != planned.WorkerID || result.worker.ContainerID != "container-"+planned.WorkerID {
			t.Fatalf("concurrent reconciliation = %+v err=%v", result.worker, result.err)
		}
	}
	if runtime.physical != 2 || len(runtime.stopped) != 0 {
		t.Fatalf("physical workers=%d compensating stops=%v", runtime.physical, runtime.stopped)
	}
	old, err = store.GetWorker(ctx, old.WorkerID)
	if err != nil {
		t.Fatal(err)
	}
	replacement, err := store.GetWorker(ctx, planned.WorkerID)
	if err != nil {
		t.Fatal(err)
	}
	if old.State != AuthorityWorkerReady || old.ReplacementWorker != planned.WorkerID || replacement.State != AuthorityWorkerStarting {
		t.Fatalf("post-reconciliation old=%+v replacement=%+v", old, replacement)
	}
}

func TestAuthorityWorkerHungAndUnhealthyReplacementPreservesOldCapacityUntilReady(t *testing.T) {
	ctx := context.Background()
	cfg := authorityTestConfig(t)
	store := openAuthorityTestStore(t, cfg.AuthorityStore)
	runtime := &fakeAuthorityRuntime{}
	service := NewAuthorityWorkerService(cfg, store, runtime, nil)
	ids := []string{"old-capacity", "replacement-capacity"}
	service.newID = func() (string, error) { id := ids[0]; ids = ids[1:]; return id, nil }
	old, err := service.Provision(ctx, "coordinator", "writer")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.SetHealth(ctx, "coordinator", old.WorkerID, "ready", true); err != nil {
		t.Fatal(err)
	}
	replacement, err := service.Replace(ctx, "coordinator", old.WorkerID, "health replacement")
	if err != nil {
		t.Fatal(err)
	}

	first, err := service.Acquire(ctx, "coordinator", AuthorityWorkerRequest{Profile: "writer", IdempotencyKey: "hung-1", SessionBinding: "hung-session-1"})
	if err != nil || first.WorkerID != old.WorkerID {
		t.Fatalf("acquire while replacement hung = %+v err=%v", first, err)
	}
	if _, err := service.SetHealth(ctx, "coordinator", replacement.WorkerID, "startup probe failed", false); err != nil {
		t.Fatal(err)
	}
	second, err := service.Acquire(ctx, "coordinator", AuthorityWorkerRequest{Profile: "writer", IdempotencyKey: "hung-2", SessionBinding: "hung-session-2"})
	if err != nil || second.WorkerID != old.WorkerID {
		t.Fatalf("acquire while replacement unhealthy = %+v err=%v", second, err)
	}
	old, err = store.GetWorker(ctx, old.WorkerID)
	if err != nil {
		t.Fatal(err)
	}
	if old.State != AuthorityWorkerReady || old.AssignedSessions != old.Capacity {
		t.Fatalf("old worker before readiness cutover = %+v", old)
	}

	if _, err := service.SetHealth(ctx, "coordinator", replacement.WorkerID, "ready", true); err != nil {
		t.Fatal(err)
	}
	third, err := service.Acquire(ctx, "coordinator", AuthorityWorkerRequest{Profile: "writer", IdempotencyKey: "ready-3", SessionBinding: "ready-session-3"})
	if err != nil || third.WorkerID != replacement.WorkerID {
		t.Fatalf("acquire after readiness cutover = %+v err=%v", third, err)
	}
	old, err = store.GetWorker(ctx, old.WorkerID)
	if err != nil {
		t.Fatal(err)
	}
	replacement, err = store.GetWorker(ctx, replacement.WorkerID)
	if err != nil {
		t.Fatal(err)
	}
	if old.State != AuthorityWorkerDraining || replacement.State != AuthorityWorkerReady || replacement.AssignedSessions != 1 {
		t.Fatalf("readiness cutover old=%+v replacement=%+v", old, replacement)
	}
}

func TestAuthorityWorkerReplacementReadinessRequiresDurablePredecessorLink(t *testing.T) {
	ctx := context.Background()
	cfg := authorityTestConfig(t)
	store := openAuthorityTestStore(t, cfg.AuthorityStore)
	profile := cfg.AuthorityProfiles["writer"]
	profileVersion, policyDigest, err := authorityProfileDigest("writer", profile)
	if err != nil {
		t.Fatal(err)
	}
	orphan := AuthorityWorker{WorkerID: "orphan-generation", Profile: "writer", ProfileVersion: profileVersion, PolicyDigest: policyDigest, ImageReference: profile.Image, Generation: 2, State: AuthorityWorkerProvisioning, Capacity: profile.SessionCapacity}
	if _, err := store.CreateWorker(ctx, orphan, profile.MaxWorkers); err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpdateWorkerRuntime(ctx, orphan.WorkerID, "container-orphan", "sha256:2222222222222222222222222222222222222222222222222222222222222222"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetWorkerHealth(ctx, orphan.WorkerID, "ready", true); err == nil || !strings.Contains(err.Error(), "refusing readiness cutover") {
		t.Fatalf("SetWorkerHealth() error = %v, want missing predecessor denial", err)
	}
	stored, err := store.GetWorker(ctx, orphan.WorkerID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.State != AuthorityWorkerStarting {
		t.Fatalf("orphan replacement state = %q, want starting", stored.State)
	}
}

func TestAuthorityWorkerCompensatesPostCreatePersistenceFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cfg := authorityTestConfig(t)
	store := openAuthorityTestStore(t, cfg.AuthorityStore)
	runtime := &fakeAuthorityRuntime{afterCreate: cancel}
	service := NewAuthorityWorkerService(cfg, store, runtime, nil)
	service.newID = func() (string, error) { return "cancelled-worker", nil }
	_, provisionErr := service.Provision(ctx, "coordinator", "writer")
	if provisionErr == nil {
		t.Fatal("Provision() succeeded after context cancellation")
	}
	if len(runtime.stopped) != 1 || runtime.stopped[0] != "container-cancelled-worker" {
		t.Fatalf("compensating stops = %#v", runtime.stopped)
	}
	worker, err := store.GetWorker(context.Background(), "cancelled-worker")
	if err != nil {
		t.Fatal(err)
	}
	if worker.State != AuthorityWorkerFailed || worker.Health != "runtime_state_persist_failed" {
		t.Fatalf("compensated worker = %+v; provision error = %v", worker, provisionErr)
	}
}

func TestAuthorityWorkerReleaseAuthorizesBeforeMutation(t *testing.T) {
	ctx := context.Background()
	cfg := authorityTestConfig(t)
	store := openAuthorityTestStore(t, cfg.AuthorityStore)
	service := NewAuthorityWorkerService(cfg, store, &fakeAuthorityRuntime{}, nil)
	service.newID = func() (string, error) { return "release-worker", nil }
	worker, err := service.Provision(ctx, "coordinator", "writer")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.SetHealth(ctx, "coordinator", worker.WorkerID, "ready", true); err != nil {
		t.Fatal(err)
	}
	request := AuthorityWorkerRequest{Profile: "writer", IdempotencyKey: "release-idem", SessionBinding: "release-binding"}
	if _, err := service.Acquire(ctx, "session-only", request); err != nil {
		t.Fatal(err)
	}
	principal := service.cfg.AuthorityPrincipals["session-only"]
	principal.AllowedActions = []string{"acquire"}
	service.cfg.AuthorityPrincipals["session-only"] = principal
	if _, err := service.Release(ctx, "session-only", request.SessionBinding); err == nil || !strings.Contains(err.Error(), "policy denial") {
		t.Fatalf("revoked release error = %v", err)
	}
	worker, err = store.GetWorker(ctx, worker.WorkerID)
	if err != nil {
		t.Fatal(err)
	}
	if worker.AssignedSessions != 1 {
		t.Fatalf("assigned sessions after denied release = %d", worker.AssignedSessions)
	}
}

func TestDrainWritesEncryptedCheckpointEvidenceAndRestoreFailsClosed(t *testing.T) {
	ctx := context.Background()
	cfg := authorityTestConfig(t)
	checkpointDir := t.TempDir()
	profile := cfg.AuthorityProfiles["writer"]
	profile.Checkpoint.Directory = checkpointDir
	cfg.AuthorityProfiles["writer"] = profile
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	t.Setenv(profile.Checkpoint.KeyEnv, base64.StdEncoding.EncodeToString(key))
	store := openAuthorityTestStore(t, cfg.AuthorityStore)
	service := NewAuthorityWorkerService(cfg, store, &fakeAuthorityRuntime{}, nil).WithCheckpointStore(NewCheckpointStore(cfg, store))
	service.newID = func() (string, error) { return "checkpoint-worker", nil }
	worker, err := service.Provision(ctx, "coordinator", "writer")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.SetHealth(ctx, "coordinator", worker.WorkerID, "liveness_ok_session_admission_deferred", true); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Acquire(ctx, "coordinator", AuthorityWorkerRequest{Profile: "writer", IdempotencyKey: "checkpoint-idem", SessionBinding: "checkpoint-session"}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Drain(ctx, "coordinator", worker.WorkerID, "replacement"); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(checkpointDir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("checkpoint entries=%v err=%v", entries, err)
	}
	path := filepath.Join(checkpointDir, entries[0].Name())
	if err := VerifyCheckpoint(path, profile, worker); err != nil {
		t.Fatalf("verify checkpoint: %v", err)
	}
	wrong := worker
	wrong.ProfileVersion = "wrong-profile"
	if err := VerifyCheckpoint(path, profile, wrong); err == nil {
		t.Fatal("checkpoint accepted wrong profile")
	}
	t.Setenv(profile.Checkpoint.KeyEnv, base64.StdEncoding.EncodeToString(make([]byte, 32)))
	if err := VerifyCheckpoint(path, profile, worker); err == nil {
		t.Fatal("checkpoint accepted wrong cryptographic material")
	}
	if err := os.WriteFile(path, []byte(`{"schema_version":999}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyCheckpoint(path, profile, worker); err == nil {
		t.Fatal("checkpoint accepted unknown schema")
	}
}

func authorityTestConfig(t *testing.T) Config {
	t.Helper()
	cfg := baseTestConfig(t)
	cfg.Repositories = []string{"owner/repo", "owner/other"}
	cfg.ApplyDefaults()
	cfg.AuthorityStore = filepath.Join(t.TempDir(), "authority-workers.sqlite")
	//nolint:gosec // G101: this is a synthetic environment-variable name, not a credential value.
	cfg.AuthorityProfiles = map[string]AuthorityProfile{
		"writer": {
			Image:         "example.com/agentd@sha256:1111111111111111111111111111111111111111111111111111111111111111",
			Platform:      "linux/amd64",
			Command:       []string{"bun", "run", "src/cli.ts", "serve"},
			Resources:     Resources{CPUShares: 128, MemoryMB: 512, PidsLimit: 128},
			NetworkPolicy: "sandbox", BrokerAgentID: "writer", BrokerSecretEnv: "WRITER_BROKER_CREDENTIAL",
			Repositories: []string{"owner/repo", "owner/other"},
			BranchPolicy: BranchPolicy{AllowedPatterns: []string{`^agent/writer/[A-Za-z0-9_.:-]+$`}, BaseBranches: []string{"main"}, GeneratePrefix: "agent/writer"},
			Operations:   []string{"git.receive-pack", "pull.create"}, MaxWorkers: 2, SessionCapacity: 2,
			SessionIsolation: SessionIsolation{Primitive: "uid_gid_0700", WorkspaceRoot: "/var/lib/agentd/sessions", UIDStart: 20000, GIDStart: 20000},
			Checkpoint:       CheckpointPolicy{Directory: "/var/lib/agentd/checkpoints", KeyEnv: "AUTHORITY_CHECKPOINT_KEY"},
			Storage:          AuthorityStorage{SessionVolume: "authority-sessions", CheckpointVolume: "authority-checkpoints", EvidenceVolume: "authority-evidence"},
		},
	}
	cfg.AuthorityPrincipals = map[string]AuthorityPrincipal{
		"coordinator":  {Token: "coordinator-test-token", AllowedProfiles: []string{"writer"}, AllowedActions: []string{"provision", "health", "acquire", "release", "drain", "replace"}},
		"session-only": {Token: "session-test-token", AllowedProfiles: []string{"writer"}, AllowedActions: []string{"acquire", "release"}},
	}
	return cfg
}

func openAuthorityTestStore(t *testing.T, path string) *AuthorityWorkerStore {
	t.Helper()
	store, err := OpenAuthorityWorkerStore(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("close authority store: %v", err)
		}
	})
	return store
}
