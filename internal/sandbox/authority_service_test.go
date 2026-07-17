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
	"time"
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
	rebind      func(context.Context, AuthorityWorker, string, agentdRebindRequest) (agentdSessionStatus, error)
}

type fakeAuthenticatedReadinessRuntime struct {
	*fakeAuthorityRuntime
	probed []string
}

func (f *fakeAuthenticatedReadinessRuntime) AgentdReady(_ context.Context, worker AuthorityWorker) (bool, string, error) {
	f.probed = append(f.probed, worker.WorkerID)
	return false, "synthetic_agentd_not_ready", nil
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

func (f *fakeAuthorityRuntime) RebindAgentdSession(ctx context.Context, worker AuthorityWorker, sessionID string, request agentdRebindRequest) (agentdSessionStatus, error) {
	if f.rebind == nil {
		return agentdSessionStatus{}, &agentdRebindError{retryable: true}
	}
	return f.rebind(ctx, worker, sessionID, request)
}

func TestAuthorityReconcileAppliesAuthenticatedReadinessOnlyToConfiguredProfiles(t *testing.T) {
	ctx := context.Background()
	cfg := authorityTestConfig(t)
	agentdProfile := cfg.AuthorityProfiles["writer"]
	agentdProfile.AgentdReadiness = &AgentdReadiness{ContractVersion: "agentd/control/v1", Port: 8080, Path: "/readyz"}
	cfg.AuthorityProfiles["writer"] = agentdProfile
	legacyProfile := agentdProfile
	legacyProfile.BrokerAgentID = "legacy"
	legacyProfile.AgentdReadiness = nil
	cfg.AuthorityProfiles["legacy"] = legacyProfile
	principal := cfg.AuthorityPrincipals["coordinator"]
	principal.AllowedProfiles = append(principal.AllowedProfiles, "legacy")
	cfg.AuthorityPrincipals["coordinator"] = principal

	store := openAuthorityTestStore(t, cfg.AuthorityStore)
	runtime := &fakeAuthenticatedReadinessRuntime{fakeAuthorityRuntime: &fakeAuthorityRuntime{}}
	service := NewAuthorityWorkerService(cfg, store, runtime, nil)
	agentdWorker, err := service.Provision(ctx, "coordinator", "writer")
	if err != nil {
		t.Fatal(err)
	}
	legacyWorker, err := service.Provision(ctx, "coordinator", "legacy")
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Reconcile(ctx, "coordinator"); err != nil {
		t.Fatal(err)
	}
	agentdWorker, err = store.GetWorker(ctx, agentdWorker.WorkerID)
	if err != nil {
		t.Fatal(err)
	}
	legacyWorker, err = store.GetWorker(ctx, legacyWorker.WorkerID)
	if err != nil {
		t.Fatal(err)
	}
	if agentdWorker.State != AuthorityWorkerStarting || legacyWorker.State != AuthorityWorkerReady {
		t.Fatalf("agentd state=%q legacy state=%q", agentdWorker.State, legacyWorker.State)
	}
	if got, want := runtime.probed, []string{agentdWorker.WorkerID}; !equalStrings(got, want) {
		t.Fatalf("readiness probes=%q, want only applicable worker %q", got, want)
	}
}

func TestLegacyAuthorityProfileDigestOmitsAgentdReadiness(t *testing.T) {
	profile := authorityTestConfig(t).AuthorityProfiles["writer"]
	encoded, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "agentd_readiness") {
		t.Fatalf("legacy profile encoding changed: %s", encoded)
	}
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
	checkpointEntries, err := os.ReadDir(filepath.Join(profile.Checkpoint.Directory, entries[0].Name()))
	if err != nil || len(checkpointEntries) != 1 {
		t.Fatalf("lineage evidence entries=%v err=%v", checkpointEntries, err)
	}
	if err := VerifyCheckpoint(filepath.Join(profile.Checkpoint.Directory, entries[0].Name(), checkpointEntries[0].Name()), profile, old); err != nil {
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
	productionWithoutAuthorityCredentials := cfg
	productionWithoutAuthorityCredentials.Production = true
	if err := productionWithoutAuthorityCredentials.Validate(); err != nil {
		t.Fatalf("Validate() production profile with credential_bundle unset error = %v", err)
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
	profile.AgentdReadiness = &AgentdReadiness{ContractVersion: "agentd/control/v1", Port: 8080, Path: "/readyz"}
	profile.SessionIsolation.WorkspaceRoot = "/var/lib/agentd/sessions"
	cfg.AuthorityProfiles["writer"] = profile
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), `agentd/control/v1 requires workspace_root "/var/lib/agentd/workspaces"`) {
		t.Fatalf("Validate() error = %v, want fixed agentd workspace root denial", err)
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

	cfg = authorityTestConfig(t)
	profile = cfg.AuthorityProfiles["writer"]
	profile.CredentialBundle = "agentd-staging-auth"
	cfg.AuthorityProfiles["writer"] = profile
	cfg.Bundles["agentd-staging-auth"] = CredentialBundle{SourceVolume: "agentd-staging-auth", MountPath: authorityCodexHomeMountPath, ReadOnly: true, AllowedAuthorityProfiles: []string{"writer"}, SecretFiles: []string{"auth.json"}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() with reviewed authority volume credential error = %v", err)
	}
	spec := authoritySpec(AuthorityWorker{WorkerID: "volume-credential", Profile: "writer"}, profile, cfg)
	if mount := spec.CredentialMount; !mount.Volume || mount.Source != "agentd-staging-auth" || mount.Target != authorityCodexHomeMountPath || !mount.ReadOnly {
		t.Fatalf("authority credential mount=%+v, want named read-only volume", mount)
	}

	for name, tc := range map[string]struct {
		mutate func(*Config)
		want   string
	}{
		"conflicting sources": {func(cfg *Config) {
			bundle := cfg.Bundles["agentd-staging-auth"]
			bundle.SourcePath = "/srv/agentd-auth"
			cfg.Bundles["agentd-staging-auth"] = bundle
		}, "exactly one of source_path or source_volume"},
		"unsafe volume": {func(cfg *Config) {
			bundle := cfg.Bundles["agentd-staging-auth"]
			bundle.SourceVolume = "../../host"
			cfg.Bundles["agentd-staging-auth"] = bundle
		}, "source_volume is unsafe"},
		"writable mount": {func(cfg *Config) {
			bundle := cfg.Bundles["agentd-staging-auth"]
			bundle.ReadOnly = false
			cfg.Bundles["agentd-staging-auth"] = bundle
		}, "readonly must be true"},
		"wrong mount target": {func(cfg *Config) {
			bundle := cfg.Bundles["agentd-staging-auth"]
			bundle.MountPath = "/credentials/agentd"
			cfg.Bundles["agentd-staging-auth"] = bundle
		}, `source_volume must mount at "/var/empty/.codex"`},
		"unknown authority profile": {func(cfg *Config) {
			bundle := cfg.Bundles["agentd-staging-auth"]
			bundle.AllowedAuthorityProfiles = []string{"caller-selected"}
			cfg.Bundles["agentd-staging-auth"] = bundle
		}, "allows unknown authority profile"},
		"session volume collision": {func(cfg *Config) {
			bundle := cfg.Bundles["agentd-staging-auth"]
			bundle.SourceVolume = cfg.AuthorityProfiles["writer"].Storage.SessionVolume
			cfg.Bundles["agentd-staging-auth"] = bundle
		}, "managed storage volumes"},
		"checkpoint volume collision": {func(cfg *Config) {
			bundle := cfg.Bundles["agentd-staging-auth"]
			bundle.SourceVolume = cfg.AuthorityProfiles["writer"].Storage.CheckpointVolume
			cfg.Bundles["agentd-staging-auth"] = bundle
		}, "managed storage volumes"},
		"evidence volume collision": {func(cfg *Config) {
			bundle := cfg.Bundles["agentd-staging-auth"]
			bundle.SourceVolume = cfg.AuthorityProfiles["writer"].Storage.EvidenceVolume
			cfg.Bundles["agentd-staging-auth"] = bundle
		}, "managed storage volumes"},
		"production credential": {func(cfg *Config) { cfg.Production = true }, "must not configure credentials in production mode"},
	} {
		t.Run(name, func(t *testing.T) {
			invalid := cfg
			invalid.Bundles = cloneCredentialBundles(cfg.Bundles)
			tc.mutate(&invalid)
			if err := invalid.Validate(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate() error=%v, want %q", err, tc.want)
			}
		})
	}
}

func TestAuthorityCredentialVolumeRejectsOtherProfileManagedStorage(t *testing.T) {
	for _, storage := range []struct {
		name   string
		volume func(AuthorityStorage) string
	}{
		{name: "session", volume: func(storage AuthorityStorage) string { return storage.SessionVolume }},
		{name: "checkpoint", volume: func(storage AuthorityStorage) string { return storage.CheckpointVolume }},
		{name: "evidence", volume: func(storage AuthorityStorage) string { return storage.EvidenceVolume }},
	} {
		t.Run(storage.name, func(t *testing.T) {
			cfg := authorityTestConfig(t)
			cfg.AuthorityProfiles["reader"] = cfg.AuthorityProfiles["writer"]
			reader := cfg.AuthorityProfiles["reader"]
			reader.Storage.SessionVolume = "reader-sessions"
			reader.Storage.CheckpointVolume = "reader-checkpoints"
			reader.Storage.EvidenceVolume = "reader-evidence"
			cfg.AuthorityProfiles["reader"] = reader

			bundle := cfg.Bundles["agentd-staging-auth"]
			bundle.AllowedAuthorityProfiles = []string{"writer"}
			bundle.SourceVolume = storage.volume(reader.Storage)
			cfg.Bundles["agentd-staging-auth"] = bundle

			if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), `authority profile "reader" managed storage volumes`) {
				t.Fatalf("Validate() error = %v, want cross-profile managed storage denial", err)
			}
		})
	}
}

func cloneCredentialBundles(in map[string]CredentialBundle) map[string]CredentialBundle {
	out := make(map[string]CredentialBundle, len(in))
	for name, bundle := range in {
		out[name] = bundle
	}
	return out
}

func TestAuthorityWorkerRequestRejectsAuthorityOverrides(t *testing.T) {
	for _, field := range []string{"image", "platform", "command", "credentials", "credential_bundle", "source_volume", "mount_path", "mounts", "network", "repo", "operations", "user", "isolation", "cap_add"} {
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

func TestAuthorityWorkerCommandBecomesDockerEntrypoint(t *testing.T) {
	cfg := authorityTestConfig(t)
	profile := cfg.AuthorityProfiles["writer"]
	worker := AuthorityWorker{WorkerID: "entrypoint", Profile: "writer", ProfileVersion: "version", PolicyDigest: "policy", WorkerStorageLineageID: "11111111111111111111111111111111", WorkerFenceEpoch: 7}
	runtime := authorityWorkerRuntimeSpec(authoritySpec(worker, profile, cfg), "secret", "coordinator-secret", nil)
	if !equalStrings(runtime.Entrypoint, fixedAgentdCommand) || len(runtime.Command) != 0 || runtime.WorkingDir != "" {
		t.Fatalf("runtime entrypoint=%q command=%q", runtime.Entrypoint, runtime.Command)
	}
	if got, want := runtime.Env["AGENTD_STATE_PATH"], agentdControlV1WorkspaceRoot+"/.agentd-state/agentd.sqlite3"; got != want {
		t.Fatalf("AGENTD_STATE_PATH=%q, want %q", got, want)
	}
	if got := runtime.Env["AGENTD_SESSION_ROOT"]; got != agentdControlV1WorkspaceRoot {
		t.Fatalf("AGENTD_SESSION_ROOT=%q, want %q", got, agentdControlV1WorkspaceRoot)
	}
	if got, want := runtime.Env["AGENTD_BROKER_VALIDATION_URL"], "http://sandbox-broker:8091/v1/authority-workers/agentd/session-validation"; got != want {
		t.Fatalf("AGENTD_BROKER_VALIDATION_URL=%q, want %q", got, want)
	}
	validationToken := runtime.Env["AGENTD_BROKER_VALIDATION_TOKEN"]
	wantValidationToken := deriveAgentdValidationToken("secret", worker.WorkerID, worker.WorkerStorageLineageID, worker.WorkerFenceEpoch)
	if validationToken != wantValidationToken || validationToken == "secret" || validationToken == runtime.Env[profile.BrokerSecretEnv] {
		t.Fatal("agentd broker validation token is not an opaque generation-bound derivation")
	}
	for _, other := range []string{
		deriveAgentdValidationToken("secret", "other-worker", worker.WorkerStorageLineageID, worker.WorkerFenceEpoch),
		deriveAgentdValidationToken("secret", worker.WorkerID, "22222222222222222222222222222222", worker.WorkerFenceEpoch),
		deriveAgentdValidationToken("secret", worker.WorkerID, worker.WorkerStorageLineageID, worker.WorkerFenceEpoch+1),
	} {
		if validationToken == other {
			t.Fatal("agentd broker validation token was not bound to the exact worker generation")
		}
	}
	if runtime.User != "bun" || !runtime.AllowAgentdSetuidLauncherPrivilegeTransition {
		t.Fatalf("agentd runtime user=%q privilege transition=%t", runtime.User, runtime.AllowAgentdSetuidLauncherPrivilegeTransition)
	}
	for key, want := range map[string]string{"AGENTD_WORKER_ID": worker.WorkerID, "AGENTD_STORAGE_LINEAGE_ID": worker.WorkerStorageLineageID, "AGENTD_FENCE_EPOCH": "7"} {
		if got := runtime.Env[key]; got != want {
			t.Fatalf("%s=%q, want %q", key, got, want)
		}
	}
}

func TestPrivateAgentdStateDirectoryCannotBeAllocatedAsSessionWorkspace(t *testing.T) {
	if validOpaqueLineageID(agentdControlV1StateDirectory) {
		t.Fatalf("private state directory %q must not be a valid session lineage", agentdControlV1StateDirectory)
	}
	cfg := authorityTestConfig(t)
	store := openAuthorityTestStore(t, cfg.AuthorityStore)
	lease := AuthorityLease{
		BindingDigest:          "binding",
		WorkerID:               "worker",
		SessionLineageID:       agentdControlV1StateDirectory,
		WorkerStorageLineageID: "11111111111111111111111111111111",
	}
	if _, err := store.AllocateSessionWorkspace(context.Background(), lease, cfg.AuthorityProfiles["writer"].SessionIsolation); err == nil || !strings.Contains(err.Error(), "lineage is malformed") {
		t.Fatalf("private state directory allocation error=%v, want malformed lineage denial", err)
	}
}

func TestAuthorityWorkerLifecycleCapacityDrainReleaseAndReplacement(t *testing.T) {
	ctx := context.Background()
	cfg := authorityTestConfig(t)
	validationSecret := t.Name()
	t.Setenv(cfg.AuthorityProfiles["writer"].BrokerSecretEnv, validationSecret)
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

	originalProfile := service.cfg.AuthorityProfiles["writer"]
	updatedProfile := originalProfile
	updatedProfile.Image = "example.com/agentd@sha256:3333333333333333333333333333333333333333333333333333333333333333"
	updatedProfile.Operations = append(updatedProfile.Operations, "pull.read")
	service.cfg.AuthorityProfiles["writer"] = updatedProfile
	if _, err := service.Replace(ctx, "coordinator", worker.WorkerID, "profile_upgrade"); err == nil || !strings.Contains(err.Error(), "immutable") {
		t.Fatalf("replacement accepted changed immutable profile: %v", err)
	}
	service.cfg.AuthorityProfiles["writer"] = originalProfile
	replacement, err := service.Replace(ctx, "coordinator", worker.WorkerID, "profile_upgrade")
	if err != nil || replacement.WorkerID != "worker-two" || replacement.Generation != 2 || replacement.State != AuthorityWorkerStarting || replacement.ProfileVersion != worker.ProfileVersion || replacement.PolicyDigest != worker.PolicyDigest {
		t.Fatalf("Replace()=%+v err=%v", replacement, err)
	}
	if replacement.WorkerStorageLineageID != worker.WorkerStorageLineageID || replacement.WorkerFenceEpoch != worker.WorkerFenceEpoch+1 {
		t.Fatalf("replacement storage generation old=%+v replacement=%+v", worker, replacement)
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
	derivedValidationToken := deriveAgentdValidationToken(validationSecret, worker.WorkerID, worker.WorkerStorageLineageID, worker.WorkerFenceEpoch)
	for _, secret := range []string{firstRequest.IdempotencyKey, firstRequest.SessionBinding, "WRITER_BROKER_CREDENTIAL", validationSecret, derivedValidationToken} {
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
	if old.State != AuthorityWorkerStopped {
		t.Fatalf("zero-lease predecessor after replacement readiness = %+v", old)
	}
	if len(runtime.stopped) != 1 || runtime.stopped[0] != old.ContainerID {
		t.Fatalf("retired predecessor runtime stops = %v, want %q", runtime.stopped, old.ContainerID)
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
	orphan := AuthorityWorker{WorkerID: "orphan-generation", Profile: "writer", ProfileVersion: profileVersion, PolicyDigest: policyDigest, ImageReference: profile.Image, Generation: 1, State: AuthorityWorkerProvisioning, Capacity: profile.SessionCapacity}
	if _, err := store.CreateWorker(ctx, orphan, profile.MaxWorkers); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE authority_workers SET generation=2,worker_fence_epoch=2 WHERE worker_id=?`, orphan.WorkerID); err != nil {
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
	lineageEntries, err := os.ReadDir(filepath.Join(checkpointDir, entries[0].Name()))
	if err != nil || len(lineageEntries) != 1 {
		t.Fatalf("lineage checkpoint entries=%v err=%v", lineageEntries, err)
	}
	path := filepath.Join(checkpointDir, entries[0].Name(), lineageEntries[0].Name())
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

func TestAuthoritySessionReassignmentIsAtomicIdempotentAndProfileBound(t *testing.T) {
	ctx := context.Background()
	cfg := authorityTestConfig(t)
	profile := cfg.AuthorityProfiles["writer"]
	profile.SessionCapacity = 1
	cfg.AuthorityProfiles["writer"] = profile
	store := openAuthorityTestStore(t, cfg.AuthorityStore)
	runtime := &fakeAuthorityRuntime{}
	service := NewAuthorityWorkerService(cfg, store, runtime, nil)
	ids := []string{"reassign-old", "reassign-new"}
	service.newID = func() (string, error) { id := ids[0]; ids = ids[1:]; return id, nil }
	old, err := service.Provision(ctx, "coordinator", "writer")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.SetHealth(ctx, "coordinator", old.WorkerID, "ready", true); err != nil {
		t.Fatal(err)
	}
	lease, err := service.Acquire(ctx, "coordinator", AuthorityWorkerRequest{Profile: "writer", IdempotencyKey: "lease-idem", SessionBinding: "logical-session"})
	if err != nil {
		t.Fatal(err)
	}
	// The workspace is durable session state; reassignment must preserve its
	// allocation while transferring its worker association.
	if _, err := store.db.ExecContext(ctx, `INSERT INTO authority_session_workspaces(binding_digest,worker_id,uid,gid,workspace_path,created_at,session_lineage_id) VALUES(?,?,?,?,?,?,?)`, lease.BindingDigest, old.WorkerID, 20000, 20000, "/durable/session", formatAuthorityTime(time.Now().UTC()), lease.SessionLineageID); err != nil {
		t.Fatal(err)
	}
	if err := store.BindAgentdSession(ctx, "logical-session", "agentd-reassign-session"); err != nil {
		t.Fatal(err)
	}
	runtime.rebind = successfulAgentdRebind("logical-session", lease, SessionWorkspace{UID: 20000, GID: 20000, Path: "/durable/session", SessionLineageID: lease.SessionLineageID, AgentdSessionID: "agentd-reassign-session"})
	if _, err := service.SetHealth(ctx, "coordinator", old.WorkerID, "abrupt_container_loss", false); err != nil {
		t.Fatal(err)
	}
	replacement, err := service.Replace(ctx, "coordinator", old.WorkerID, "abrupt_predecessor_loss")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.SetHealth(ctx, "coordinator", replacement.WorkerID, "ready", true); err != nil {
		t.Fatal(err)
	}
	request := AuthoritySessionReassignmentRequest{SessionBinding: "logical-session", SessionLineageID: lease.SessionLineageID, PredecessorWorkerID: old.WorkerID, PredecessorWorkerFenceEpoch: lease.WorkerFenceEpoch, IdempotencyKey: "reassign-idem"}
	if _, err := store.db.ExecContext(ctx, `UPDATE authority_workers SET replacement_worker_id='' WHERE worker_id=?`, old.WorkerID); err != nil {
		t.Fatal(err)
	}
	missingReplacement := request
	missingReplacement.IdempotencyKey = "missing-recorded-successor"
	if _, err := service.ReassignSession(ctx, "coordinator", missingReplacement); !isReassignmentCode(err, ReassignmentNotReady) {
		t.Fatalf("missing recorded successor error=%v", err)
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE authority_workers SET replacement_worker_id=? WHERE worker_id=?`, replacement.WorkerID, old.WorkerID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE authority_workers SET worker_storage_lineage_id=? WHERE worker_id=?`, "22222222222222222222222222222222", replacement.WorkerID); err != nil {
		t.Fatal(err)
	}
	wrongLineage := request
	wrongLineage.IdempotencyKey = "wrong-successor-lineage"
	if _, err := service.ReassignSession(ctx, "coordinator", wrongLineage); !isReassignmentCode(err, ReassignmentConflictingReplacement) {
		t.Fatalf("wrong successor lineage error=%v", err)
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE authority_workers SET worker_storage_lineage_id=?,worker_fence_epoch=? WHERE worker_id=?`, old.WorkerStorageLineageID, old.WorkerFenceEpoch+2, replacement.WorkerID); err != nil {
		t.Fatal(err)
	}
	wrongEpoch := request
	wrongEpoch.IdempotencyKey = "wrong-successor-epoch"
	if _, err := service.ReassignSession(ctx, "coordinator", wrongEpoch); !isReassignmentCode(err, ReassignmentConflictingReplacement) {
		t.Fatalf("wrong successor epoch error=%v", err)
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE authority_workers SET worker_fence_epoch=? WHERE worker_id=?`, old.WorkerFenceEpoch+1, replacement.WorkerID); err != nil {
		t.Fatal(err)
	}
	fillerLease, err := service.Acquire(ctx, "session-only", AuthorityWorkerRequest{Profile: "writer", IdempotencyKey: "filler-lease-idem", SessionBinding: "filler-logical-session"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.ReassignSession(ctx, "session-only", AuthoritySessionReassignmentRequest{SessionBinding: "filler-logical-session", SessionLineageID: fillerLease.SessionLineageID, PredecessorWorkerID: old.WorkerID, PredecessorWorkerFenceEpoch: old.WorkerFenceEpoch, IdempotencyKey: "other-reassign-idem"}); err == nil || !strings.Contains(err.Error(), "policy denial") {
		t.Fatalf("cross-profile/principal escalation error=%v", err)
	}
	if _, err := service.ReassignSession(ctx, "coordinator", request); err == nil || !isReassignmentCode(err, ReassignmentCapacity) {
		t.Fatalf("capacity reassignment error=%v", err)
	}
	if _, err := service.Release(ctx, "session-only", "filler-logical-session"); err != nil {
		t.Fatal(err)
	}
	assigned, err := service.ReassignSession(ctx, "coordinator", request)
	if err != nil {
		t.Fatal(err)
	}
	if assigned.Lease.WorkerID != replacement.WorkerID || assigned.Replay {
		t.Fatalf("reassignment=%+v", assigned)
	}
	replayed, err := service.ReassignSession(ctx, "coordinator", request)
	if err != nil || !replayed.Replay || replayed.Lease.WorkerID != replacement.WorkerID {
		t.Fatalf("replayed=%+v err=%v", replayed, err)
	}
	workspace, err := store.SessionWorkspace(ctx, "logical-session")
	if err != nil || workspace.Path != "/durable/session" || workspace.UID != 20000 {
		t.Fatalf("workspace=%+v err=%v", workspace, err)
	}
	oldAfter, err := store.GetWorker(ctx, old.WorkerID)
	if err != nil {
		t.Fatal(err)
	}
	newAfter, err := store.GetWorker(ctx, replacement.WorkerID)
	if err != nil || oldAfter.AssignedSessions != 0 || newAfter.AssignedSessions != 1 || oldAfter.State != AuthorityWorkerStopped {
		t.Fatalf("old=%+v new=%+v err=%v", oldAfter, newAfter, err)
	}
	if _, err := service.ReassignSession(ctx, "coordinator", AuthoritySessionReassignmentRequest{SessionBinding: "logical-session", SessionLineageID: lease.SessionLineageID, PredecessorWorkerID: "not-the-predecessor", PredecessorWorkerFenceEpoch: lease.WorkerFenceEpoch, IdempotencyKey: "stale-idem"}); err == nil || !isReassignmentCode(err, ReassignmentStalePredecessor) {
		t.Fatalf("stale reassignment error=%v", err)
	}
}

func TestAuthoritySessionFenceDeniesPredecessorAndReplaysCutover(t *testing.T) {
	ctx := context.Background()
	cfg := authorityTestConfig(t)
	t.Setenv("WRITER_BROKER_CREDENTIAL", "agentd-broker-test-token")
	store := openAuthorityTestStore(t, cfg.AuthorityStore)
	runtime := &fakeAuthorityRuntime{}
	service := NewAuthorityWorkerService(cfg, store, runtime, nil)
	ids := []string{"fence-old", "fence-new"}
	service.newID = func() (string, error) { id := ids[0]; ids = ids[1:]; return id, nil }
	old, err := service.Provision(ctx, "coordinator", "writer")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.SetHealth(ctx, "coordinator", old.WorkerID, "ready", true); err != nil {
		t.Fatal(err)
	}
	lease, err := service.Acquire(ctx, "coordinator", AuthorityWorkerRequest{Profile: "writer", IdempotencyKey: "fence-lease", SessionBinding: "fence-session"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.db.ExecContext(ctx, `INSERT INTO authority_session_workspaces(binding_digest,worker_id,uid,gid,workspace_path,created_at,session_lineage_id) VALUES(?,?,?,?,?,?,?)`, lease.BindingDigest, old.WorkerID, 20000, 20000, "/durable/fence-session", formatAuthorityTime(time.Now().UTC()), lease.SessionLineageID); err != nil {
		t.Fatal(err)
	}
	if err = store.BindAgentdSession(ctx, "fence-session", "agentd-fence-session"); err != nil {
		t.Fatal(err)
	}
	runtime.rebind = successfulAgentdRebind("fence-session", lease, SessionWorkspace{UID: 20000, GID: 20000, Path: "/durable/fence-session", SessionLineageID: lease.SessionLineageID, AgentdSessionID: "agentd-fence-session"})
	if lease.SessionLineageID == "" || lease.WorkerFenceEpoch != 1 || lease.WorkerStorageLineageID != old.WorkerStorageLineageID {
		t.Fatalf("lineage lease=%+v", lease)
	}
	oldToken := deriveAgentdValidationToken("agentd-broker-test-token", old.WorkerID, old.WorkerStorageLineageID, old.WorkerFenceEpoch)
	oldRequest := AgentdSessionValidationRequest{WorkerID: old.WorkerID, WorkerStorageLineageID: old.WorkerStorageLineageID, WorkerFenceEpoch: old.WorkerFenceEpoch, SessionLineageID: lease.SessionLineageID}
	if got, err := service.ValidateAgentdSession(ctx, oldToken, oldRequest); err != nil || !got.Authorized {
		t.Fatalf("pre-cutover validation=%+v err=%v", got, err)
	}
	for name, mutated := range map[string]AgentdSessionValidationRequest{
		"cross-lineage": {WorkerID: old.WorkerID, WorkerStorageLineageID: "22222222222222222222222222222222", WorkerFenceEpoch: old.WorkerFenceEpoch, SessionLineageID: lease.SessionLineageID},
		"cross-epoch":   {WorkerID: old.WorkerID, WorkerStorageLineageID: old.WorkerStorageLineageID, WorkerFenceEpoch: old.WorkerFenceEpoch + 1, SessionLineageID: lease.SessionLineageID},
	} {
		if got, err := service.ValidateAgentdSession(ctx, oldToken, mutated); err != nil || got.Authorized || got.Code != "unauthorized" {
			t.Fatalf("%s validation=%+v err=%v", name, got, err)
		}
	}
	invalidAuth, err := service.ValidateAgentdSession(ctx, "invalid-generation-token", oldRequest)
	if err != nil {
		t.Fatal(err)
	}
	unknownRequest := oldRequest
	unknownRequest.WorkerID = "unknown-worker"
	unknownAuth, err := service.ValidateAgentdSession(ctx, "invalid-generation-token", unknownRequest)
	if err != nil || unknownAuth != invalidAuth || unknownAuth.Code != "unauthorized" {
		t.Fatalf("unknown=%+v invalid=%+v err=%v, want uniform unauthorized", unknownAuth, invalidAuth, err)
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

	request := AuthoritySessionReassignmentRequest{SessionBinding: "fence-session", SessionLineageID: lease.SessionLineageID, PredecessorWorkerID: old.WorkerID, PredecessorWorkerFenceEpoch: old.WorkerFenceEpoch, IdempotencyKey: "fence-reassign"}
	// Before the CAS, a wrong predecessor epoch must not mutate lease/accounting.
	wrong := request
	wrong.PredecessorWorkerFenceEpoch = 2
	wrong.IdempotencyKey = "before-cas"
	if _, err = service.ReassignSession(ctx, "coordinator", wrong); !isReassignmentCode(err, ReassignmentStalePredecessor) {
		t.Fatalf("before CAS error=%v", err)
	}
	assigned, err := service.ReassignSession(ctx, "coordinator", request)
	if err != nil || assigned.Lease.WorkerFenceEpoch != 2 || assigned.Lease.SessionLineageID != lease.SessionLineageID || assigned.Lease.WorkerStorageLineageID != lease.WorkerStorageLineageID {
		t.Fatalf("CAS result=%+v err=%v", assigned, err)
	}
	// This retry models a crash after durable CAS and before the HTTP response.
	replay, err := service.ReassignSession(ctx, "coordinator", request)
	if err != nil || !replay.Replay || replay.Lease.WorkerFenceEpoch != 2 {
		t.Fatalf("post-CAS replay=%+v err=%v", replay, err)
	}
	if got, err := service.ValidateAgentdSession(ctx, oldToken, oldRequest); err != nil || got.Authorized || got.Code != "fenced" {
		t.Fatalf("stale predecessor validation=%+v err=%v", got, err)
	}
	replacementRequest := AgentdSessionValidationRequest{WorkerID: replacement.WorkerID, WorkerStorageLineageID: replacement.WorkerStorageLineageID, WorkerFenceEpoch: replacement.WorkerFenceEpoch, SessionLineageID: lease.SessionLineageID}
	if got, err := service.ValidateAgentdSession(ctx, oldToken, replacementRequest); err != nil || got.Authorized || got.Code != "unauthorized" {
		t.Fatalf("cross-worker validation=%+v err=%v", got, err)
	}
	replacementToken := deriveAgentdValidationToken("agentd-broker-test-token", replacement.WorkerID, replacement.WorkerStorageLineageID, replacement.WorkerFenceEpoch)
	if got, err := service.ValidateAgentdSession(ctx, replacementToken, replacementRequest); err != nil || !got.Authorized {
		t.Fatalf("successor validation=%+v err=%v", got, err)
	}
	stale := request
	stale.IdempotencyKey = "stale-different-key"
	if retried, retryErr := service.ReassignSession(ctx, "coordinator", stale); retryErr != nil || !retried.Replay {
		t.Fatalf("exact transition with fresh request key=%+v err=%v", retried, retryErr)
	}
}

func TestAuthoritySessionRebindRetriesAfterCASWithStableAgentdCommand(t *testing.T) {
	ctx := context.Background()
	cfg := authorityTestConfig(t)
	store := openAuthorityTestStore(t, cfg.AuthorityStore)
	runtime := &fakeAuthorityRuntime{}
	service := NewAuthorityWorkerService(cfg, store, runtime, nil)
	ids := []string{"ordered-old", "ordered-successor"}
	service.newID = func() (string, error) { id := ids[0]; ids = ids[1:]; return id, nil }
	old, err := service.Provision(ctx, "coordinator", "writer")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.SetHealth(ctx, "coordinator", old.WorkerID, "ready", true); err != nil {
		t.Fatal(err)
	}
	lease, err := service.Acquire(ctx, "coordinator", AuthorityWorkerRequest{Profile: "writer", IdempotencyKey: "ordered-lease", SessionBinding: "ordered-session"})
	if err != nil {
		t.Fatal(err)
	}
	workspace := SessionWorkspace{UID: 20000, GID: 20000, Path: "/durable/ordered-session", SessionLineageID: lease.SessionLineageID, AgentdSessionID: "agentd-ordered-session"}
	if _, err = store.db.ExecContext(ctx, `INSERT INTO authority_session_workspaces(binding_digest,worker_id,uid,gid,workspace_path,created_at,session_lineage_id) VALUES(?,?,?,?,?,?,?)`, lease.BindingDigest, old.WorkerID, workspace.UID, workspace.GID, workspace.Path, formatAuthorityTime(time.Now().UTC()), lease.SessionLineageID); err != nil {
		t.Fatal(err)
	}
	if err = store.BindAgentdSession(ctx, "ordered-session", workspace.AgentdSessionID); err != nil {
		t.Fatal(err)
	}
	if _, err = service.SetHealth(ctx, "coordinator", old.WorkerID, "lost", false); err != nil {
		t.Fatal(err)
	}
	successor, err := service.Replace(ctx, "coordinator", old.WorkerID, "lost")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.SetHealth(ctx, "coordinator", successor.WorkerID, "ready", true); err != nil {
		t.Fatal(err)
	}

	var calls []agentdRebindRequest
	success := successfulAgentdRebind("ordered-session", lease, workspace)
	runtime.rebind = func(callCtx context.Context, worker AuthorityWorker, sessionID string, request agentdRebindRequest) (agentdSessionStatus, error) {
		calls = append(calls, request)
		current, leaseErr := store.GetLease(callCtx, "coordinator", "ordered-session")
		if leaseErr != nil || current.WorkerID != successor.WorkerID {
			t.Fatalf("agentd called before successor CAS: lease=%+v err=%v", current, leaseErr)
		}
		predecessor, workerErr := store.GetWorker(callCtx, old.WorkerID)
		if workerErr != nil || predecessor.State != AuthorityWorkerDraining || len(runtime.stopped) != 0 {
			t.Fatalf("predecessor retired before agentd verification: worker=%+v stopped=%v err=%v", predecessor, runtime.stopped, workerErr)
		}
		if worker.WorkerID != successor.WorkerID || sessionID != workspace.AgentdSessionID {
			t.Fatalf("rebind destination worker=%q session=%q", worker.WorkerID, sessionID)
		}
		if len(calls) == 1 {
			return agentdSessionStatus{}, &agentdRebindError{retryable: true}
		}
		return success(callCtx, worker, sessionID, request)
	}
	request := AuthoritySessionReassignmentRequest{SessionBinding: "ordered-session", SessionLineageID: lease.SessionLineageID, PredecessorWorkerID: old.WorkerID, PredecessorWorkerFenceEpoch: old.WorkerFenceEpoch, IdempotencyKey: "ordered-request-one"}
	first, err := service.ReassignSession(ctx, "coordinator", request)
	if !isReassignmentCode(err, ReassignmentRebindRetryable) || first.Lease.WorkerID != successor.WorkerID {
		t.Fatalf("post-CAS timeout result=%+v err=%v", first, err)
	}
	request.IdempotencyKey = "ordered-request-two"
	second, err := service.ReassignSession(ctx, "coordinator", request)
	if err != nil || !second.Replay || second.Lease.WorkerID != successor.WorkerID {
		t.Fatalf("rebind retry result=%+v err=%v", second, err)
	}
	if len(calls) != 2 || calls[0] != calls[1] {
		t.Fatalf("agentd rebind command changed across retry: %#v", calls)
	}
	if calls[0].IdempotencyKey == request.IdempotencyKey || len(calls[0].IdempotencyKey) != 64 {
		t.Fatalf("agentd idempotency key was not broker-derived: %q", calls[0].IdempotencyKey)
	}
	var records int
	if err = store.db.QueryRowContext(ctx, `SELECT count(*) FROM authority_session_reassignments WHERE binding_digest=?`, lease.BindingDigest).Scan(&records); err != nil || records != 1 {
		t.Fatalf("durable reassignment records=%d err=%v", records, err)
	}
	oldAfter, err := store.GetWorker(ctx, old.WorkerID)
	if err != nil || oldAfter.State != AuthorityWorkerStopped || len(runtime.stopped) != 1 {
		t.Fatalf("predecessor retirement after verified rebind worker=%+v stopped=%v err=%v", oldAfter, runtime.stopped, err)
	}
}

func TestAuthoritySessionRebindRejectsMismatchedSuccessBeforeRetirement(t *testing.T) {
	ctx := context.Background()
	cfg := authorityTestConfig(t)
	store := openAuthorityTestStore(t, cfg.AuthorityStore)
	runtime := &fakeAuthorityRuntime{}
	service := NewAuthorityWorkerService(cfg, store, runtime, nil)
	ids := []string{"mismatch-old", "mismatch-successor"}
	service.newID = func() (string, error) { id := ids[0]; ids = ids[1:]; return id, nil }
	old, err := service.Provision(ctx, "coordinator", "writer")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.SetHealth(ctx, "coordinator", old.WorkerID, "ready", true); err != nil {
		t.Fatal(err)
	}
	lease, err := service.Acquire(ctx, "coordinator", AuthorityWorkerRequest{Profile: "writer", IdempotencyKey: "mismatch-lease", SessionBinding: "mismatch-session"})
	if err != nil {
		t.Fatal(err)
	}
	workspace := SessionWorkspace{UID: 20000, GID: 20000, Path: "/durable/mismatch", SessionLineageID: lease.SessionLineageID, AgentdSessionID: "agentd-mismatch-session"}
	if _, err = store.db.ExecContext(ctx, `INSERT INTO authority_session_workspaces(binding_digest,worker_id,uid,gid,workspace_path,created_at,session_lineage_id) VALUES(?,?,?,?,?,?,?)`, lease.BindingDigest, old.WorkerID, workspace.UID, workspace.GID, workspace.Path, formatAuthorityTime(time.Now().UTC()), lease.SessionLineageID); err != nil {
		t.Fatal(err)
	}
	if err = store.BindAgentdSession(ctx, "mismatch-session", workspace.AgentdSessionID); err != nil {
		t.Fatal(err)
	}
	if _, err = service.SetHealth(ctx, "coordinator", old.WorkerID, "lost", false); err != nil {
		t.Fatal(err)
	}
	successor, err := service.Replace(ctx, "coordinator", old.WorkerID, "lost")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.SetHealth(ctx, "coordinator", successor.WorkerID, "ready", true); err != nil {
		t.Fatal(err)
	}
	valid := successfulAgentdRebind("mismatch-session", lease, workspace)
	runtime.rebind = func(callCtx context.Context, worker AuthorityWorker, sessionID string, request agentdRebindRequest) (agentdSessionStatus, error) {
		status, statusErr := valid(callCtx, worker, sessionID, request)
		status.WorkerID = "wrong-successor"
		return status, statusErr
	}
	request := AuthoritySessionReassignmentRequest{SessionBinding: "mismatch-session", SessionLineageID: lease.SessionLineageID, PredecessorWorkerID: old.WorkerID, PredecessorWorkerFenceEpoch: old.WorkerFenceEpoch, IdempotencyKey: "mismatch-reassign"}
	if _, err = service.ReassignSession(ctx, "coordinator", request); !isReassignmentCode(err, ReassignmentRebindRetryable) {
		t.Fatalf("mismatched agentd success error=%v", err)
	}
	oldAfter, workerErr := store.GetWorker(ctx, old.WorkerID)
	if workerErr != nil || oldAfter.State != AuthorityWorkerDraining || len(runtime.stopped) != 0 {
		t.Fatalf("mismatched success retired predecessor worker=%+v stopped=%v err=%v", oldAfter, runtime.stopped, workerErr)
	}
}

func TestAuthorityReconcileRecoversCrashBeforeAgentdAdoption(t *testing.T) {
	fixture := newAuthorityAdoptionFixture(t, 1)
	adoption := fixture.commit(t, 0)
	if adoption.State != authorityAdoptionPending {
		t.Fatalf("adoption state=%q, want pending", adoption.State)
	}
	originalKey := adoption.RebindIdempotencyKey
	if err := fixture.store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenAuthorityWorkerStore(context.Background(), fixture.cfg.AuthorityStore)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := reopened.Close(); err != nil {
			t.Errorf("close reopened store: %v", err)
		}
	})
	fixture.store = reopened
	fixture.service = NewAuthorityWorkerService(fixture.cfg, reopened, fixture.runtime, nil)

	var calls []agentdRebindRequest
	fixture.runtime.rebind = func(ctx context.Context, worker AuthorityWorker, sessionID string, request agentdRebindRequest) (agentdSessionStatus, error) {
		calls = append(calls, request)
		return successfulAgentdRebind(fixture.bindings[0], fixture.leases[0], fixture.workspaces[0])(ctx, worker, sessionID, request)
	}
	if err := fixture.service.Reconcile(context.Background(), "coordinator"); err != nil {
		t.Fatal(err)
	}
	confirmed, err := reopened.AgentdAdoption(context.Background(), adoption.BindingDigest)
	if err != nil || confirmed.State != authorityAdoptionConfirmed || confirmed.RebindIdempotencyKey != originalKey {
		t.Fatalf("confirmed adoption=%+v err=%v", confirmed, err)
	}
	assertAuthorityRetiredExactlyOnce(t, fixture)
	if len(calls) != 1 || calls[0].IdempotencyKey != originalKey {
		t.Fatalf("recovery calls=%+v, want one stable replay", calls)
	}
}

func TestAuthorityReconcileReplaysSuccessBeforeConfirmationMarker(t *testing.T) {
	fixture := newAuthorityAdoptionFixture(t, 1)
	adoption := fixture.commit(t, 0)
	var calls []agentdRebindRequest
	fixture.runtime.rebind = func(ctx context.Context, worker AuthorityWorker, sessionID string, request agentdRebindRequest) (agentdSessionStatus, error) {
		calls = append(calls, request)
		return successfulAgentdRebind(fixture.bindings[0], fixture.leases[0], fixture.workspaces[0])(ctx, worker, sessionID, request)
	}
	request := agentdRebindRequest{IdempotencyKey: adoption.RebindIdempotencyKey, Predecessor: adoption.Predecessor, Successor: adoption.Successor}
	if _, err := fixture.runtime.RebindAgentdSession(context.Background(), fixture.successor, adoption.AgentdSessionID, request); err != nil {
		t.Fatal(err)
	}
	if err := fixture.service.Reconcile(context.Background(), "coordinator"); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 || calls[0] != calls[1] {
		t.Fatalf("success-before-marker replay calls=%+v", calls)
	}
	assertAuthorityRetiredExactlyOnce(t, fixture)
	var records int
	var confirmedAt string
	if err := fixture.store.db.QueryRow(`SELECT count(*),max(adoption_confirmed_at) FROM authority_session_reassignments WHERE binding_digest=?`, adoption.BindingDigest).Scan(&records, &confirmedAt); err != nil {
		t.Fatal(err)
	}
	if records != 1 || confirmedAt == "" {
		t.Fatalf("records=%d confirmed_at=%q", records, confirmedAt)
	}
	if err := fixture.service.Reconcile(context.Background(), "coordinator"); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 {
		t.Fatalf("confirmed transition replayed again: calls=%d", len(calls))
	}
}

func TestAuthorityReconcileKeepsRetryableAndMismatchedAdoptionsPending(t *testing.T) {
	for _, tc := range []struct {
		name   string
		rebind func(agentdSessionStatus) (agentdSessionStatus, error)
	}{
		{name: "retryable", rebind: func(agentdSessionStatus) (agentdSessionStatus, error) {
			return agentdSessionStatus{}, &agentdRebindError{retryable: true}
		}},
		{name: "mismatched", rebind: func(status agentdSessionStatus) (agentdSessionStatus, error) {
			status.WorkerID = "wrong-successor"
			return status, nil
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newAuthorityAdoptionFixture(t, 1)
			var calls []agentdRebindRequest
			valid := successfulAgentdRebind(fixture.bindings[0], fixture.leases[0], fixture.workspaces[0])
			fixture.runtime.rebind = func(ctx context.Context, worker AuthorityWorker, sessionID string, request agentdRebindRequest) (agentdSessionStatus, error) {
				calls = append(calls, request)
				status, err := valid(ctx, worker, sessionID, request)
				if err != nil {
					return status, err
				}
				return tc.rebind(status)
			}
			request := fixture.requests[0]
			if _, err := fixture.service.ReassignSession(context.Background(), "coordinator", request); !isReassignmentCode(err, ReassignmentRebindRetryable) {
				t.Fatalf("ReassignSession() error=%v", err)
			}
			if err := fixture.service.Reconcile(context.Background(), "coordinator"); !isReassignmentCode(err, ReassignmentRebindRetryable) {
				t.Fatalf("Reconcile() error=%v", err)
			}
			adoption, err := fixture.store.AgentdAdoption(context.Background(), fixture.leases[0].BindingDigest)
			if err != nil || adoption.State != authorityAdoptionPending {
				t.Fatalf("adoption=%+v err=%v", adoption, err)
			}
			if len(calls) != 2 || calls[0] != calls[1] {
				t.Fatalf("rebind calls=%+v, want stable request and reconcile replay", calls)
			}
			assertAuthorityNotRetired(t, fixture)
		})
	}
}

func TestAuthorityConcurrentHealthAndReconcileRetiresOnlyAfterConfirmation(t *testing.T) {
	fixture := newAuthorityAdoptionFixture(t, 1)
	fixture.commit(t, 0)
	entered, proceed := make(chan struct{}), make(chan struct{})
	fixture.runtime.rebind = func(ctx context.Context, worker AuthorityWorker, sessionID string, request agentdRebindRequest) (agentdSessionStatus, error) {
		close(entered)
		<-proceed
		return successfulAgentdRebind(fixture.bindings[0], fixture.leases[0], fixture.workspaces[0])(ctx, worker, sessionID, request)
	}
	done := make(chan error, 1)
	go func() { done <- fixture.service.Reconcile(context.Background(), "coordinator") }()
	<-entered
	if _, err := fixture.service.SetHealth(context.Background(), "coordinator", fixture.successor.WorkerID, "concurrent_ready", true); err != nil {
		t.Fatal(err)
	}
	assertAuthorityNotRetired(t, fixture)
	close(proceed)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	assertAuthorityRetiredExactlyOnce(t, fixture)
}

func TestAuthorityMultipleSessionsRequireEveryAdoptionConfirmation(t *testing.T) {
	fixture := newAuthorityAdoptionFixture(t, 2)
	first, second := fixture.commit(t, 0), fixture.commit(t, 1)
	allowSecond := false
	callCount := map[string]int{}
	fixture.runtime.rebind = func(ctx context.Context, worker AuthorityWorker, sessionID string, request agentdRebindRequest) (agentdSessionStatus, error) {
		callCount[sessionID]++
		if sessionID == second.AgentdSessionID && !allowSecond {
			return agentdSessionStatus{}, &agentdRebindError{retryable: true}
		}
		index := 0
		if sessionID == second.AgentdSessionID {
			index = 1
		}
		return successfulAgentdRebind(fixture.bindings[index], fixture.leases[index], fixture.workspaces[index])(ctx, worker, sessionID, request)
	}
	if err := fixture.service.Reconcile(context.Background(), "coordinator"); !isReassignmentCode(err, ReassignmentRebindRetryable) {
		t.Fatalf("first Reconcile() error=%v", err)
	}
	firstAfter, err := fixture.store.AgentdAdoption(context.Background(), first.BindingDigest)
	if err != nil {
		t.Fatal(err)
	}
	secondAfter, err := fixture.store.AgentdAdoption(context.Background(), second.BindingDigest)
	if err != nil {
		t.Fatal(err)
	}
	if firstAfter.State != authorityAdoptionConfirmed || secondAfter.State != authorityAdoptionPending {
		t.Fatalf("first=%+v second=%+v", firstAfter, secondAfter)
	}
	assertAuthorityNotRetired(t, fixture)
	allowSecond = true
	if err := fixture.service.Reconcile(context.Background(), "coordinator"); err != nil {
		t.Fatal(err)
	}
	if callCount[first.AgentdSessionID] != 1 || callCount[second.AgentdSessionID] != 2 {
		t.Fatalf("rebind call count=%v", callCount)
	}
	assertAuthorityRetiredExactlyOnce(t, fixture)
}

func TestAuthorityTerminalAdoptionConflictRemainsActionable(t *testing.T) {
	fixture := newAuthorityAdoptionFixture(t, 1)
	calls := 0
	fixture.runtime.rebind = func(context.Context, AuthorityWorker, string, agentdRebindRequest) (agentdSessionStatus, error) {
		calls++
		return agentdSessionStatus{}, &agentdRebindError{code: "rebind_conflict"}
	}
	if _, err := fixture.service.ReassignSession(context.Background(), "coordinator", fixture.requests[0]); !isReassignmentCode(err, ReassignmentRebindConflict) {
		t.Fatalf("ReassignSession() error=%v", err)
	}
	if err := fixture.service.Reconcile(context.Background(), "coordinator"); !isReassignmentCode(err, ReassignmentRebindConflict) {
		t.Fatalf("Reconcile() error=%v", err)
	}
	adoption, err := fixture.store.AgentdAdoption(context.Background(), fixture.leases[0].BindingDigest)
	if err != nil || adoption.State != authorityAdoptionConflict || adoption.ErrorCode != "rebind_conflict" || calls != 1 {
		t.Fatalf("adoption=%+v calls=%d err=%v", adoption, calls, err)
	}
	assertAuthorityNotRetired(t, fixture)
}

func TestAuthoritySessionCanReassignAcrossMultipleGenerations(t *testing.T) {
	fixture := newAuthorityAdoptionFixture(t, 1)
	ctx := context.Background()
	fixture.runtime.rebind = successfulAgentdRebind(fixture.bindings[0], fixture.leases[0], fixture.workspaces[0])
	first, err := fixture.service.ReassignSession(ctx, "coordinator", fixture.requests[0])
	if err != nil {
		t.Fatal(err)
	}
	fixture.service.newID = func() (string, error) { return "adoption-third", nil }
	if _, err = fixture.service.SetHealth(ctx, "coordinator", first.ReplacementWorkerID, "lost-again", false); err != nil {
		t.Fatal(err)
	}
	third, err := fixture.service.Replace(ctx, "coordinator", first.ReplacementWorkerID, "second-generation-loss")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = fixture.service.SetHealth(ctx, "coordinator", third.WorkerID, "ready", true); err != nil {
		t.Fatal(err)
	}
	current, err := fixture.store.GetLease(ctx, "coordinator", fixture.bindings[0])
	if err != nil {
		t.Fatal(err)
	}
	fixture.runtime.rebind = successfulAgentdRebind(fixture.bindings[0], current, fixture.workspaces[0])
	request := AuthoritySessionReassignmentRequest{SessionBinding: fixture.bindings[0], SessionLineageID: current.SessionLineageID, PredecessorWorkerID: current.WorkerID, PredecessorWorkerFenceEpoch: current.WorkerFenceEpoch, IdempotencyKey: "adoption-second-generation"}
	second, err := fixture.service.ReassignSession(ctx, "coordinator", request)
	if err != nil {
		t.Fatal(err)
	}
	if second.ReplacementWorkerID != third.WorkerID || second.Lease.WorkerFenceEpoch != 3 {
		t.Fatalf("second reassignment=%+v", second)
	}
	var records int
	if err := fixture.store.db.QueryRowContext(ctx, `SELECT count(*) FROM authority_session_reassignments WHERE binding_digest=?`, current.BindingDigest).Scan(&records); err != nil || records != 2 {
		t.Fatalf("records=%d err=%v", records, err)
	}
	replay, err := fixture.service.ReassignSession(ctx, "coordinator", request)
	if err != nil || !replay.Replay || replay.ReplacementWorkerID != third.WorkerID {
		t.Fatalf("replay=%+v err=%v", replay, err)
	}
}

type authorityAdoptionFixture struct {
	cfg         Config
	store       *AuthorityWorkerStore
	runtime     *fakeAuthorityRuntime
	service     *AuthorityWorkerService
	predecessor AuthorityWorker
	successor   AuthorityWorker
	bindings    []string
	leases      []AuthorityLease
	workspaces  []SessionWorkspace
	requests    []AuthoritySessionReassignmentRequest
}

func newAuthorityAdoptionFixture(t *testing.T, sessions int) *authorityAdoptionFixture {
	t.Helper()
	ctx := context.Background()
	cfg := authorityTestConfig(t)
	store := openAuthorityTestStore(t, cfg.AuthorityStore)
	runtime := &fakeAuthorityRuntime{}
	service := NewAuthorityWorkerService(cfg, store, runtime, nil)
	ids := []string{"adoption-old", "adoption-successor"}
	service.newID = func() (string, error) { id := ids[0]; ids = ids[1:]; return id, nil }
	old, err := service.Provision(ctx, "coordinator", "writer")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.SetHealth(ctx, "coordinator", old.WorkerID, "ready", true); err != nil {
		t.Fatal(err)
	}
	fixture := &authorityAdoptionFixture{cfg: cfg, store: store, runtime: runtime, service: service, predecessor: old}
	for i := range sessions {
		binding := fmt.Sprintf("adoption-session-%d", i)
		lease, err := service.Acquire(ctx, "coordinator", AuthorityWorkerRequest{Profile: "writer", IdempotencyKey: fmt.Sprintf("adoption-lease-%d", i), SessionBinding: binding})
		if err != nil {
			t.Fatal(err)
		}
		workspace := SessionWorkspace{
			UID:              20000 + i,
			GID:              20000 + i,
			Path:             fmt.Sprintf("/durable/adoption-%d", i),
			SessionLineageID: lease.SessionLineageID,
			AgentdSessionID:  fmt.Sprintf("agentd-adoption-%d", i),
		}
		if _, err := store.db.ExecContext(ctx, `INSERT INTO authority_session_workspaces(binding_digest,worker_id,uid,gid,workspace_path,created_at,session_lineage_id) VALUES(?,?,?,?,?,?,?)`, lease.BindingDigest, old.WorkerID, workspace.UID, workspace.GID, workspace.Path, formatAuthorityTime(time.Now().UTC()), lease.SessionLineageID); err != nil {
			t.Fatal(err)
		}
		if err := store.BindAgentdSession(ctx, binding, workspace.AgentdSessionID); err != nil {
			t.Fatal(err)
		}
		fixture.bindings = append(fixture.bindings, binding)
		fixture.leases = append(fixture.leases, lease)
		fixture.workspaces = append(fixture.workspaces, workspace)
		fixture.requests = append(fixture.requests, AuthoritySessionReassignmentRequest{SessionBinding: binding, SessionLineageID: lease.SessionLineageID, PredecessorWorkerID: old.WorkerID, PredecessorWorkerFenceEpoch: old.WorkerFenceEpoch, IdempotencyKey: fmt.Sprintf("adoption-reassign-%d", i)})
	}
	if _, err := service.SetHealth(ctx, "coordinator", old.WorkerID, "lost", false); err != nil {
		t.Fatal(err)
	}
	successor, err := service.Replace(ctx, "coordinator", old.WorkerID, "lost")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.SetHealth(ctx, "coordinator", successor.WorkerID, "ready", true); err != nil {
		t.Fatal(err)
	}
	fixture.successor = successor
	return fixture
}

func (f *authorityAdoptionFixture) commit(t *testing.T, index int) authorityAgentdAdoption {
	t.Helper()
	request := f.requests[index]
	reassignment, err := f.store.Reassign(context.Background(), "coordinator", request.SessionBinding, request.SessionLineageID, request.PredecessorWorkerID, request.PredecessorWorkerFenceEpoch, request.IdempotencyKey, f.workspaces[index])
	if err != nil {
		t.Fatal(err)
	}
	adoption, err := f.store.AgentdAdoption(context.Background(), reassignment.Lease.BindingDigest)
	if err != nil {
		t.Fatal(err)
	}
	return adoption
}

func assertAuthorityNotRetired(t *testing.T, fixture *authorityAdoptionFixture) {
	t.Helper()
	worker, err := fixture.store.GetWorker(context.Background(), fixture.predecessor.WorkerID)
	if err != nil || worker.State != AuthorityWorkerDraining {
		t.Fatalf("predecessor=%+v err=%v, want draining", worker, err)
	}
	fixture.runtime.mu.Lock()
	defer fixture.runtime.mu.Unlock()
	if len(fixture.runtime.stopped) != 0 {
		t.Fatalf("predecessor stopped before adoption confirmation: %v", fixture.runtime.stopped)
	}
}

func assertAuthorityRetiredExactlyOnce(t *testing.T, fixture *authorityAdoptionFixture) {
	t.Helper()
	worker, err := fixture.store.GetWorker(context.Background(), fixture.predecessor.WorkerID)
	if err != nil || worker.State != AuthorityWorkerStopped {
		t.Fatalf("predecessor=%+v err=%v, want stopped", worker, err)
	}
	fixture.runtime.mu.Lock()
	defer fixture.runtime.mu.Unlock()
	if len(fixture.runtime.stopped) != 1 || fixture.runtime.stopped[0] != fixture.predecessor.ContainerID {
		t.Fatalf("runtime stops=%v, want exactly %q", fixture.runtime.stopped, fixture.predecessor.ContainerID)
	}
}

func isReassignmentCode(err error, want ReassignmentErrorCode) bool {
	var reassignmentErr *ReassignmentError
	return errors.As(err, &reassignmentErr) && reassignmentErr.Code == want
}

func successfulAgentdRebind(binding string, lease AuthorityLease, workspace SessionWorkspace) func(context.Context, AuthorityWorker, string, agentdRebindRequest) (agentdSessionStatus, error) {
	return func(_ context.Context, worker AuthorityWorker, sessionID string, request agentdRebindRequest) (agentdSessionStatus, error) {
		return agentdSessionStatus{
			Version:            agentdSessionProtocolVersion,
			SessionID:          sessionID,
			CoordinatorBinding: binding,
			AuthorityBinding:   lease.Profile,
			WorkerID:           request.Successor.WorkerID,
			StorageLineageID:   request.Successor.StorageLineageID,
			FenceEpoch:         request.Successor.FenceEpoch,
			SessionLineageID:   lease.SessionLineageID,
			Workspace:          agentdSessionWorkspace{WorkspaceRef: workspace.Path, UID: workspace.UID, GID: workspace.GID},
			Phase:              "active",
			TurnIDs:            []string{},
			NextCursor:         2,
		}, nil
	}
}

func authorityTestConfig(t *testing.T) Config {
	t.Helper()
	t.Setenv("AGENTD_COORDINATOR_TOKEN", "synthetic-agentd-coordinator-token")
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
			NetworkPolicy: "sandbox", BrokerAgentID: "writer", BrokerSecretEnv: "WRITER_BROKER_CREDENTIAL", CoordinatorTokenEnv: "AGENTD_COORDINATOR_TOKEN",
			Repositories: []string{"owner/repo", "owner/other"},
			BranchPolicy: BranchPolicy{AllowedPatterns: []string{`^agent/writer/[A-Za-z0-9_.:-]+$`}, BaseBranches: []string{"main"}, GeneratePrefix: "agent/writer"},
			Operations:   []string{"git.receive-pack", "pull.create"}, MaxWorkers: 2, SessionCapacity: 2,
			SessionIsolation: SessionIsolation{Primitive: "uid_gid_0700", WorkspaceRoot: agentdControlV1WorkspaceRoot, UIDStart: 20000, GIDStart: 20000},
			Checkpoint:       CheckpointPolicy{Directory: "/var/lib/agentd/checkpoints", KeyEnv: "AUTHORITY_CHECKPOINT_KEY"},
			Storage:          AuthorityStorage{SessionVolume: "authority-sessions", CheckpointVolume: "authority-checkpoints", EvidenceVolume: "authority-evidence"},
		},
	}
	cfg.AuthorityPrincipals = map[string]AuthorityPrincipal{
		"coordinator":  {Token: "coordinator-test-token", AllowedProfiles: []string{"writer"}, AllowedActions: []string{"provision", "health", "acquire", "release", "drain", "replace", "reassign"}},
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
