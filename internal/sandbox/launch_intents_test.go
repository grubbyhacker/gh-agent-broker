package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRESTLaunchRequiresValidIdempotencyKey(t *testing.T) {
	cfg := restTestConfig(t)
	service := newRESTTestService(t, cfg, newFakeRuntime(), testAudit(t))
	handler := NewRESTHandler(service)

	for _, tt := range []struct {
		name   string
		key    string
		status int
		code   string
	}{
		{name: "missing", status: http.StatusPreconditionRequired, code: "idempotency_key_required"},
		{name: "blank", key: " ", status: http.StatusBadRequest, code: "invalid_idempotency_key"},
		{name: "control", key: "bad\nkey", status: http.StatusBadRequest, code: "invalid_idempotency_key"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			req := restRequest(http.MethodPost, "/v1/launch-profiles/nightly/launch", "timer-secret", nil)
			if tt.key != "" {
				req.Header["Idempotency-Key"] = []string{tt.key}
			}
			resp := httptest.NewRecorder()
			handler.ServeHTTP(resp, req)
			if resp.Code != tt.status || !strings.Contains(resp.Body.String(), `"code":"`+tt.code+`"`) {
				t.Fatalf("status=%d body=%s", resp.Code, resp.Body.String())
			}
		})
	}
}

func TestRESTLaunchReplayCanonicalBodyUsesOneRuntimeAndRunID(t *testing.T) {
	cfg := restTestConfig(t)
	runtime := newFakeRuntime()
	service := newRESTTestService(t, cfg, runtime, testAudit(t))
	handler := NewRESTHandler(service)

	first := performLaunch(t, handler, "canonical-replay-key", nil)
	second := performLaunch(t, handler, "canonical-replay-key", []byte("{  }"))
	if first.RunID != second.RunID || first.Replay || !second.Replay {
		t.Fatalf("first=%+v second=%+v", first, second)
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if len(runtime.specs) != 1 {
		t.Fatalf("runtime creates=%d, want 1", len(runtime.specs))
	}
}

func TestRESTLaunchSameKeyChangedPayloadConflicts(t *testing.T) {
	cfg := restTestConfig(t)
	runtime := newFakeRuntime()
	service := newRESTTestService(t, cfg, runtime, testAudit(t))
	handler := NewRESTHandler(service)
	_ = performLaunch(t, handler, "conflict-key", []byte(`{"overrides":{"task":"first"}}`))

	req := restLaunchRequest("/v1/launch-profiles/nightly/launch", "timer-secret", "conflict-key", []byte(`{"overrides":{"task":"second"}}`))
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusConflict || !strings.Contains(resp.Body.String(), `"code":"idempotency_conflict"`) {
		t.Fatalf("status=%d body=%s", resp.Code, resp.Body.String())
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if len(runtime.specs) != 1 {
		t.Fatalf("runtime creates=%d, want 1", len(runtime.specs))
	}
}

func TestRESTLaunchIdempotencyNamespaceIncludesPrincipalAndProfile(t *testing.T) {
	cfg := restTestConfig(t)
	cfg.OperatorPrincipals["peer"] = OperatorPrincipal{
		Token: "peer-secret", AllowedProfiles: []string{"nightly"}, AllowedActions: []string{"launch"}, RunScope: "owned",
	}
	runtime := newFakeRuntime()
	handler := NewRESTHandler(newRESTTestService(t, cfg, runtime, testAudit(t)))
	first := performLaunch(t, handler, "shared-key", nil)
	req := restLaunchRequest("/v1/launch-profiles/nightly/launch", "peer-secret", "shared-key", nil)
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("peer launch status=%d body=%s", resp.Code, resp.Body.String())
	}
	var second LaunchAgentOutput
	if err := json.NewDecoder(resp.Body).Decode(&second); err != nil {
		t.Fatal(err)
	}
	if first.RunID == second.RunID {
		t.Fatalf("different principals shared run ID %q", first.RunID)
	}
	if len(runtime.specs) != 2 {
		t.Fatalf("runtime creates=%d, want 2 principal-scoped launches", len(runtime.specs))
	}
}

func TestRESTLaunchConcurrentDuplicateUsesOneRuntime(t *testing.T) {
	cfg := restTestConfig(t)
	runtime := newFakeRuntime()
	service := newRESTTestService(t, cfg, runtime, testAudit(t))
	handler := NewRESTHandler(service)

	const callers = 8
	outputs := make(chan LaunchAgentOutput, callers)
	errs := make(chan string, callers)
	var wg sync.WaitGroup
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := restLaunchRequest("/v1/launch-profiles/nightly/launch", "timer-secret", "concurrent-key", []byte(`{}`))
			resp := httptest.NewRecorder()
			handler.ServeHTTP(resp, req)
			if resp.Code != http.StatusOK {
				errs <- resp.Body.String()
				return
			}
			var out LaunchAgentOutput
			if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
				errs <- err.Error()
				return
			}
			outputs <- out
		}()
	}
	wg.Wait()
	close(outputs)
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent launch error: %s", err)
	}
	var runID string
	for out := range outputs {
		if runID == "" {
			runID = out.RunID
		}
		if out.RunID != runID {
			t.Fatalf("run ID=%q, want %q", out.RunID, runID)
		}
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if len(runtime.specs) != 1 {
		t.Fatalf("runtime creates=%d, want 1", len(runtime.specs))
	}
}

func TestLaunchIntentStoreConcurrentReservationAcrossConnections(t *testing.T) {
	cfg := restTestConfig(t)
	firstStore, err := OpenLaunchIntentStore(context.Background(), cfg.LaunchIntentStore)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := firstStore.Close(); err != nil {
			t.Errorf("close first store: %v", err)
		}
	}()
	secondStore, err := OpenLaunchIntentStore(context.Background(), cfg.LaunchIntentStore)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := secondStore.Close(); err != nil {
			t.Errorf("close second store: %v", err)
		}
	}()

	service := NewServiceWithLaunchIntents(cfg, newFakeRuntime(), testAudit(t), firstStore)
	first := persistableIntent(t, service, firstStore, "cross-connection-key")
	second := first
	second.RunID = "20260713T120000Z-aaaaaaaaaaaaaaaa"
	second.Metadata.RunID = second.RunID
	second.Plan.Metadata.RunID = second.RunID

	type result struct {
		intent  launchIntent
		created bool
		err     error
	}
	start := make(chan struct{})
	results := make(chan result, 2)
	for _, item := range []struct {
		store  *LaunchIntentStore
		intent launchIntent
	}{{firstStore, first}, {secondStore, second}} {
		go func() {
			<-start
			got, created, err := item.store.Create(context.Background(), item.intent, 0)
			results <- result{intent: got, created: created, err: err}
		}()
	}
	close(start)
	created := 0
	var runID string
	for range 2 {
		result := <-results
		if result.err != nil {
			t.Fatal(result.err)
		}
		if result.created {
			created++
		}
		if runID == "" {
			runID = result.intent.RunID
		} else if result.intent.RunID != runID {
			t.Fatalf("reserved run IDs differ: %q and %q", runID, result.intent.RunID)
		}
	}
	if created != 1 {
		t.Fatalf("created reservations=%d, want 1", created)
	}
}

func TestRESTLaunchReplayAfterRestartAndIndexReconstruction(t *testing.T) {
	cfg := restTestConfig(t)
	runtime := newFakeRuntime()
	firstService := newRESTTestService(t, cfg, runtime, testAudit(t))
	first := performLaunch(t, NewRESTHandler(firstService), "restart-replay-key", nil)
	meta, err := readMetadata(filepath.Join(cfg.RunsDir, first.RunID, "metadata.json"))
	if err != nil {
		t.Fatal(err)
	}
	if meta.Principal != "timer" || meta.IdempotencyKeyDigest == "" || meta.RequestFingerprint == "" || meta.LaunchConfigVersion == "" {
		t.Fatalf("launch ownership/index metadata incomplete: %+v", meta)
	}
	if _, err := firstService.launchIntents.db.ExecContext(context.Background(), "DELETE FROM launch_intents WHERE run_id=?", first.RunID); err != nil {
		t.Fatal(err)
	}

	secondService := newRESTTestService(t, cfg, runtime, testAudit(t))
	if err := secondService.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile() error=%v", err)
	}
	second := performLaunch(t, NewRESTHandler(secondService), "restart-replay-key", []byte("{}"))
	if second.RunID != first.RunID || !second.Replay {
		t.Fatalf("first=%+v second=%+v", first, second)
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if len(runtime.specs) != 1 {
		t.Fatalf("runtime creates=%d, want 1", len(runtime.specs))
	}
}

func TestLegacyConfigVersionAcceptsNonterminalOrdinaryWorkerIntentOnUpgrade(t *testing.T) {
	cfg := restTestConfig(t)
	cfg.RunsDir = "/tmp/gh-agent-broker-config-upgrade-regression/runs"
	t.Cleanup(func() {
		if err := os.RemoveAll("/tmp/gh-agent-broker-config-upgrade-regression"); err != nil {
			t.Errorf("remove upgrade regression fixture: %v", err)
		}
	})
	bundle := cfg.Bundles["codex"]
	bundle.SourcePath = "/srv/sandbox-test/bundle"
	cfg.Bundles["codex"] = bundle
	tmpl := cfg.Templates["worker"]
	tmpl.KnowledgeSnapshots = []string{"/srv/sandbox-test/knowledge.md"}
	tmpl.ExtraMounts = []ExtraMount{{SourcePath: "/srv/sandbox-test/evidence", MountPath: "/data/intake", ReadOnly: true}}
	cfg.Templates["worker"] = tmpl
	cfg.Audit.Path = "/srv/sandbox-test/audit.jsonl"
	cfg.StampLoaded(time.Unix(1, 0).UTC())

	// This digest was emitted by the release before source_volume was added.
	// Keeping the fixture literal ensures an empty new field cannot silently
	// alter the canonical shape and strand an ordinary-worker launch intent.
	const legacyConfigVersion = "5d3541645374a2e21fb78c756202e8fbc4cf86c2f71e58cc12801d58c22bab84"
	if cfg.ConfigVersion != legacyConfigVersion {
		t.Fatalf("legacy config version=%q, want %q", cfg.ConfigVersion, legacyConfigVersion)
	}
	service := newRESTTestService(t, cfg, newFakeRuntime(), testAudit(t))
	intent := persistRecoveryIntent(t, service, service.launchIntents, intentStateRunning)
	if intent.Plan.ConfigVersion != legacyConfigVersion {
		t.Fatalf("persisted config version=%q, want legacy %q", intent.Plan.ConfigVersion, legacyConfigVersion)
	}
	if err := service.Reconcile(context.Background()); err != nil {
		t.Fatalf("upgrade reconciliation rejected legacy nonterminal intent: %v", err)
	}
}

func TestLaunchIntentNeverPersistsOrAuditsRawKey(t *testing.T) {
	cfg := restTestConfig(t)
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	audit, err := NewAuditLogger(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	store, err := OpenLaunchIntentStore(context.Background(), cfg.LaunchIntentStore)
	if err != nil {
		t.Fatal(err)
	}
	service := NewServiceWithLaunchIntents(cfg, newFakeRuntime(), audit, store)
	handler := NewRESTHandler(service)
	rawKey := "raw-secret-idempotency-key-never-store"
	out := performLaunch(t, handler, rawKey, nil)
	if strings.Contains(mustJSON(t, out), rawKey) {
		t.Fatal("launch response contained raw idempotency key")
	}
	if err := audit.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec("PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{cfg.LaunchIntentStore, cfg.LaunchIntentStore + "-wal", cfg.LaunchIntentStore + "-shm", auditPath} {
		//nolint:gosec // G304: paths are test-owned files under temporary directories.
		data, err := os.ReadFile(path)
		if err != nil && os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(data, []byte(rawKey)) {
			t.Fatalf("raw key found in %s", path)
		}
	}
}

func TestReconcileLaunchIntentRecoversCreateAndStartAmbiguity(t *testing.T) {
	for _, state := range []string{intentStateCreatePending, intentStateStartPending} {
		t.Run(state, func(t *testing.T) {
			cfg := restTestConfig(t)
			store, err := OpenLaunchIntentStore(context.Background(), cfg.LaunchIntentStore)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := store.Close(); err != nil {
					t.Errorf("close store: %v", err)
				}
			}()
			runtime := newRecoveryRuntime()
			service := NewServiceWithLaunchIntents(cfg, runtime, testAudit(t), store)
			intent := persistRecoveryIntent(t, service, store, state)
			containerID := "container-" + intent.RunID
			if state == intentStateStartPending {
				intent.Metadata.ContainerID = containerID
				intent.Metadata.ImageDigest = intent.Metadata.Image
				intent.State = intentStateStartPending
				if err := store.Save(context.Background(), intent); err != nil {
					t.Fatal(err)
				}
				runtime.setRunning(containerID)
			} else {
				runtime.setNeverStarted(containerID)
			}
			if err := service.Reconcile(context.Background()); err != nil {
				t.Fatalf("Reconcile() error=%v", err)
			}
			got, found, err := store.Lookup(context.Background(), intent.Principal, intent.Profile, intent.KeyDigest)
			if err != nil || !found {
				t.Fatalf("lookup found=%v err=%v", found, err)
			}
			if got.State != intentStateRunning || got.Metadata.RunID != intent.RunID {
				t.Fatalf("recovered intent=%+v", got)
			}
			if state == intentStateCreatePending && runtime.startCalls != 1 {
				t.Fatalf("start calls=%d, want 1", runtime.startCalls)
			}
			if state == intentStateStartPending && runtime.startCalls != 0 {
				t.Fatalf("start calls=%d, want 0", runtime.startCalls)
			}
		})
	}
}

func TestReconcileRunningIntentOverridesStalePendingMetadata(t *testing.T) {
	cfg := restTestConfig(t)
	store, err := OpenLaunchIntentStore(context.Background(), cfg.LaunchIntentStore)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			t.Errorf("close store: %v", err)
		}
	}()
	runtime := newRecoveryRuntime()
	service := NewServiceWithLaunchIntents(cfg, runtime, testAudit(t), store)
	intent := persistRecoveryIntent(t, service, store, intentStateCreated)
	containerID := "container-" + intent.RunID
	intent.Metadata.ContainerID = containerID
	intent.Metadata.ImageDigest = intent.Metadata.Image
	intent.Metadata.Status = StatusRunning
	intent.State = intentStateRunning
	if err := store.Save(context.Background(), intent); err != nil {
		t.Fatal(err)
	}
	runtime.setRunning(containerID)

	stale := intent.Metadata
	stale.Status = StatusPending
	stale.ContainerID = ""
	if err := service.prepareDurableRun(stale, cfg.Templates[stale.Template]); err != nil {
		t.Fatal(err)
	}

	if err := service.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile() error=%v", err)
	}
	meta, err := service.lookupRun(intent.RunID)
	if err != nil {
		t.Fatal(err)
	}
	if meta.Status != StatusRunning || meta.ContainerID != containerID {
		t.Fatalf("reconciled metadata=%+v", meta)
	}
}

func performLaunch(t *testing.T, handler http.Handler, key string, body []byte) LaunchAgentOutput {
	t.Helper()
	req := restLaunchRequest("/v1/launch-profiles/nightly/launch", "timer-secret", key, body)
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("launch status=%d body=%s", resp.Code, resp.Body.String())
	}
	var out LaunchAgentOutput
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

func persistRecoveryIntent(t *testing.T, service *Service, store *LaunchIntentStore, state string) launchIntent {
	t.Helper()
	in := service.cfg.LaunchProfiles["nightly"].LaunchAgentInput
	in.Profile = "nightly"
	tmpl, runID, branch, limit, err := service.validateLaunch(in)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	meta := RunMetadata{
		RunID: runID, Profile: "nightly", Template: in.Template, Repo: in.Repo, BaseBranch: in.BaseBranch,
		Branch: branch, Task: in.Task, Focus: in.Focus, WorkerAgentID: workerAgentID(tmpl, runID),
		BrokerAgentID: tmpl.BrokerAgentID, CredentialBundle: tmpl.CredentialBundle, Image: tmpl.Image,
		Status: StatusPending, Deliverables: deliverables(in.Deliverables, tmpl.Deliverables), StartedAt: now, Deadline: now.Add(limit),
	}
	intent := launchIntent{
		Principal: "timer", Profile: "nightly", KeyDigest: store.digestKey("recovery-key-" + state),
		RequestFingerprint: requestFingerprint([]byte("{}")), RunID: runID, State: state, Metadata: meta,
		Plan: launchIntentPlan{Version: 1, ConfigVersion: service.cfg.ConfigVersion, Request: in, RuntimeSeconds: int64(limit / time.Second), Metadata: meta},
	}
	if _, created, err := store.Create(context.Background(), intent, 0); err != nil || !created {
		t.Fatalf("create intent created=%v err=%v", created, err)
	}
	return intent
}

func persistableIntent(t *testing.T, service *Service, store *LaunchIntentStore, key string) launchIntent {
	t.Helper()
	intent := persistRecoveryIntent(t, service, store, intentStateCreated)
	if _, err := store.db.ExecContext(context.Background(), "DELETE FROM launch_intents WHERE run_id=?", intent.RunID); err != nil {
		t.Fatal(err)
	}
	intent.KeyDigest = store.digestKey(key)
	return intent
}

func mustJSON(t *testing.T, value any) string {
	t.Helper()
	b, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

type recoveryRuntime struct {
	*fakeRuntime
	muRecovery sync.Mutex
	statuses   map[string]ContainerStatus
	startCalls int
}

func newRecoveryRuntime() *recoveryRuntime {
	return &recoveryRuntime{fakeRuntime: newFakeRuntime(), statuses: map[string]ContainerStatus{}}
}

func (r *recoveryRuntime) Create(_ context.Context, spec RuntimeSpec) (ContainerInfo, error) {
	r.muRecovery.Lock()
	defer r.muRecovery.Unlock()
	id := "container-" + spec.RunID
	status := r.statuses[id]
	lifecycle := ContainerNeverStarted
	if status.Running {
		lifecycle = ContainerRunning
	} else if !status.StartedAt.IsZero() {
		lifecycle = ContainerExited
	}
	return ContainerInfo{ID: id, ImageDigest: spec.Image, Existing: true, Lifecycle: lifecycle, Status: status}, nil
}

func (r *recoveryRuntime) Start(_ context.Context, containerID string) error {
	r.muRecovery.Lock()
	defer r.muRecovery.Unlock()
	r.startCalls++
	r.statuses[containerID] = ContainerStatus{ID: containerID, Running: true, StartedAt: time.Now().UTC()}
	r.mu.Lock()
	r.started[containerID] = true
	r.waiters[containerID] = make(chan struct{})
	r.mu.Unlock()
	return nil
}

func (r *recoveryRuntime) Inspect(_ context.Context, containerID string) (ContainerStatus, error) {
	r.muRecovery.Lock()
	defer r.muRecovery.Unlock()
	return r.statuses[containerID], nil
}

func (r *recoveryRuntime) setNeverStarted(containerID string) {
	r.statuses[containerID] = ContainerStatus{ID: containerID}
}

func (r *recoveryRuntime) setRunning(containerID string) {
	r.statuses[containerID] = ContainerStatus{ID: containerID, Running: true, StartedAt: time.Now().UTC()}
	r.mu.Lock()
	r.started[containerID] = true
	r.waiters[containerID] = make(chan struct{})
	r.mu.Unlock()
}
