package sandbox

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeCodexIssuer struct {
	mu       sync.Mutex
	issues   int
	consumes int
	cleanups int
}

func (f *fakeCodexIssuer) Issue(_ context.Context, _, _ string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.issues++
	return []byte(`{"tokens":{"access_token":"access-only","refresh_token":""}}`), nil
}

func (f *fakeCodexIssuer) Consume(_ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.consumes++
	return nil
}

func (f *fakeCodexIssuer) Cleanup(_ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cleanups++
	return nil
}

func TestCodexIssueWorkflowSeparatesPreparationIssuanceAndExecution(t *testing.T) {
	cfg := codexWorkflowTestConfig(t)
	cfg.ApplyDefaults()
	cfg.StampLoaded(time.Now().UTC())
	runtime := newFakeRuntime()
	store, err := OpenLaunchIntentStore(context.Background(), cfg.LaunchIntentStore)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if closeErr := store.Close(); closeErr != nil {
			t.Errorf("close launch intent store: %v", closeErr)
		}
	})
	service := NewServiceWithLaunchIntents(cfg, runtime, testAudit(t), store)
	issuer := &fakeCodexIssuer{}
	service.SetCodexCredentialIssuer(issuer)

	in := cfg.LaunchProfiles["terra-medium-v1"].LaunchAgentInput
	in.Profile = "terra-medium-v1"
	in.Parameters = map[string]any{"issue_number": 42, "source_delivery_id": "delivery-42"}
	out, err := service.LaunchProfile(context.Background(), "signal-plane", "terra-medium-v1", "key-42", "fingerprint-42", in)
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != StatusRunning {
		t.Fatalf("launch=%+v", out)
	}
	runtime.mu.Lock()
	if len(runtime.specs) != 1 {
		t.Fatalf("runtime specs=%d, want preparation only", len(runtime.specs))
	}
	prepSpec := runtime.specs[0]
	runtime.mu.Unlock()
	if prepSpec.RunID != out.RunID+"-prep" || !reflect.DeepEqual(prepSpec.Network, cfg.Networks["prep"]) {
		t.Fatalf("preparation spec=%+v", prepSpec)
	}
	for _, mount := range prepSpec.Mounts {
		if mount.Target == "/run/codex-issuance" || mount.Target == "/credentials/codex" {
			t.Fatalf("preparation received credential mount: %+v", mount)
		}
	}
	for name := range prepSpec.Env {
		if name == "AGENT_MODEL" || name == "HTTPS_PROXY" || name == "CODEX_HOME" {
			t.Fatalf("preparation received execution environment %q", name)
		}
	}

	writePreparationFixture(t, cfg, out.RunID, out.Branch)
	runtime.finish(out.RunID+"-prep", 0, "")
	waitFor(t, func() bool {
		runtime.mu.Lock()
		specCount := len(runtime.specs)
		runtime.mu.Unlock()
		issuer.mu.Lock()
		issueCount := issuer.issues
		consumeCount := issuer.consumes
		issuer.mu.Unlock()
		return specCount == 2 && issueCount == 1 && consumeCount == 1
	})
	runtime.mu.Lock()
	execSpec := runtime.specs[1]
	runtime.mu.Unlock()
	if execSpec.RunID != out.RunID+"-exec" || !reflect.DeepEqual(execSpec.Network, cfg.Networks["execution"]) {
		t.Fatalf("execution spec=%+v", execSpec)
	}
	if execSpec.Env["AGENT_MODEL"] != "gpt-5.6-terra" ||
		execSpec.Env["AGENT_REASONING_EFFORT"] != "medium" ||
		execSpec.Env["AGENT_CODEX_VERSION"] != "0.146.0" ||
		execSpec.Env["AGENT_FINAL_OUTPUT_LIMIT"] != "32768" ||
		execSpec.Env["CODEX_SUBSCRIPTION_RELAY_BASE_URL"] != codexRelayBaseURL {
		t.Fatalf("execution env=%+v", execSpec.Env)
	}
	for name, value := range execSpec.Env {
		if strings.Contains(strings.ToUpper(name), "PROXY") || strings.Contains(value, "access-only") ||
			strings.HasPrefix(name, "BROKER_") {
			t.Fatalf("execution contains forbidden secret/proxy environment %q=%q", name, value)
		}
	}
	for _, mount := range execSpec.Mounts {
		if mount.Target == "/run/codex-issuance" || strings.Contains(mount.Source, cfg.CodexHolder.IssuanceRoot) {
			t.Fatalf("execution received issuance mount: %+v", mount)
		}
	}
	for name, value := range execSpec.Labels {
		if strings.Contains(name, "auth") || strings.Contains(value, "access-only") {
			t.Fatalf("execution label contains credential metadata %q=%q", name, value)
		}
	}
	if execSpec.Tmpfs["/dev/shm"] != 64 || execSpec.StorageLimitMB != 8192 {
		t.Fatalf("execution bounds tmpfs=%+v storage=%d", execSpec.Tmpfs, execSpec.StorageLimitMB)
	}
	issuer.mu.Lock()
	if issuer.issues != 1 || issuer.consumes != 1 {
		t.Fatalf("issuances=%d consumes=%d, want one each", issuer.issues, issuer.consumes)
	}
	issuer.mu.Unlock()
	runtime.mu.Lock()
	injected := runtime.injections["container-"+out.RunID+"-exec:"+filepath.Join(codexInjectionDir, codexInjectionName)]
	started := runtime.started["container-"+out.RunID+"-exec"]
	runtime.mu.Unlock()
	if !started || !strings.Contains(string(injected), `"refresh_token":""`) {
		t.Fatalf("post-start injected bundle=%q started=%t", injected, started)
	}
	metadata, err := os.ReadFile(filepath.Join(cfg.RunsDir, out.RunID, "metadata.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(metadata), "access-only") || strings.Contains(string(metadata), "refresh_token") {
		t.Fatalf("run metadata contains credential material: %s", metadata)
	}

	writeExecutionFixture(t, cfg, out.RunID, out.Branch)
	runtime.finish(out.RunID+"-exec", 0, "")
	waitFor(t, func() bool {
		runtime.mu.Lock()
		defer runtime.mu.Unlock()
		return len(runtime.specs) == 3 && runtime.started["container-"+out.RunID+"-deliver"]
	})
	runtime.mu.Lock()
	deliverySpec := runtime.specs[2]
	runtime.mu.Unlock()
	if deliverySpec.RunID != out.RunID+"-deliver" ||
		!reflect.DeepEqual(deliverySpec.Network, cfg.Networks["delivery"]) {
		t.Fatalf("delivery spec=%+v", deliverySpec)
	}
	for name := range deliverySpec.Env {
		if strings.HasPrefix(name, "OPENAI_") || strings.HasPrefix(name, "CODEX_") ||
			name == "AGENT_MODEL" || name == "AGENT_REASONING_EFFORT" {
			t.Fatalf("delivery contains Codex authority %q", name)
		}
	}
	if deliverySpec.Env["BROKER_AGENT_SECRET"] == "" {
		t.Fatal("delivery is missing its private broker credential")
	}

	outputDir := filepath.Join(cfg.RunsDir, out.RunID, "output")
	result := map[string]any{
		"version": workerResultVersion, "outcome": "no_change_required", "run_id": out.RunID,
		"repository": in.Repo, "base_branch": in.BaseBranch, "branch": out.Branch,
		"verification": map[string]any{"status": "passed"}, "worker": "codex",
	}
	writeJSONFileForTest(t, filepath.Join(outputDir, "result.json"), result)
	if err := os.WriteFile(filepath.Join(outputDir, "final-summary.md"), []byte("No change is required.\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outputDir, "codex-usage.json"), []byte(`{"input_tokens":10,"cached_input_tokens":2,"output_tokens":3}`), 0o600); err != nil {
		t.Fatal(err)
	}
	runtime.finish(out.RunID+"-deliver", 0, "")
	waitFor(t, func() bool {
		_, terminalErr := service.GetTerminalResult(context.Background(), RunInput{RunID: out.RunID})
		return terminalErr == nil
	})
	terminal, err := service.GetTerminalResult(context.Background(), RunInput{RunID: out.RunID})
	if err != nil {
		t.Fatal(err)
	}
	if terminal.Outcome != "no_change_required" || terminal.Provenance == nil ||
		terminal.Provenance.Model != "gpt-5.6-terra" ||
		terminal.Provenance.ManifestSHA256 == "" ||
		terminal.Provenance.VerificationResult != "passed" ||
		terminal.Provenance.Usage["input_tokens"] != float64(10) {
		t.Fatalf("terminal=%+v provenance=%+v", terminal, terminal.Provenance)
	}
	if _, statErr := os.Stat(filepath.Join(cfg.CodexHolder.IssuanceRoot, out.RunID, "capability", "auth.json")); !os.IsNotExist(statErr) {
		t.Fatalf("host capability exists: %v", statErr)
	}
}

func writeExecutionFixture(t *testing.T, cfg Config, runID, branch string) {
	t.Helper()
	path := filepath.Join(cfg.RunsDir, runID, "work", "execution", "execution.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	writeJSONFileForTest(t, path, executionResult{
		Version: "codex-execution-result/v1", Status: "executed", RunID: runID,
		Repository: "owner/repo", Branch: branch,
		WorkspaceHead: "1111111111111111111111111111111111111111",
		RefsSHA256:    strings.Repeat("5", 64),
		DiffSHA256:    strings.Repeat("3", 64), FinalSHA256: strings.Repeat("4", 64),
		VerifySHA256: strings.Repeat("6", 64), Verification: "passed",
		FinalSizeBytes: 10,
	})
}

func TestCodexWorkflowReplayDoesNotDuplicatePreparation(t *testing.T) {
	cfg := codexWorkflowTestConfig(t)
	cfg.ApplyDefaults()
	cfg.StampLoaded(time.Now().UTC())
	runtime := newFakeRuntime()
	store, err := OpenLaunchIntentStore(context.Background(), cfg.LaunchIntentStore)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if closeErr := store.Close(); closeErr != nil {
			t.Errorf("close launch intent store: %v", closeErr)
		}
	})
	service := NewServiceWithLaunchIntents(cfg, runtime, testAudit(t), store)
	service.SetCodexCredentialIssuer(&fakeCodexIssuer{})
	in := cfg.LaunchProfiles["terra-medium-v1"].LaunchAgentInput
	in.Profile = "terra-medium-v1"
	in.Parameters = map[string]any{"issue_number": 1, "source_delivery_id": "delivery-1"}
	first, err := service.LaunchProfile(context.Background(), "signal-plane", "terra-medium-v1", "same", "fp", in)
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.LaunchProfile(context.Background(), "signal-plane", "terra-medium-v1", "same", "fp", in)
	if err != nil {
		t.Fatal(err)
	}
	if first.RunID != second.RunID || !second.Replay {
		t.Fatalf("first=%+v second=%+v", first, second)
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if len(runtime.specs) != 1 {
		t.Fatalf("preparation containers=%d, want one", len(runtime.specs))
	}
}

func TestCodexExecutionContaminationFailurePreventsDeliveryAndLeavesNoHostCredential(t *testing.T) {
	cfg := codexWorkflowTestConfig(t)
	cfg.ApplyDefaults()
	cfg.StampLoaded(time.Now().UTC())
	runtime := newFakeRuntime()
	store, err := OpenLaunchIntentStore(context.Background(), cfg.LaunchIntentStore)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if closeErr := store.Close(); closeErr != nil {
			t.Errorf("close launch intent store: %v", closeErr)
		}
	})
	service := NewServiceWithLaunchIntents(cfg, runtime, testAudit(t), store)
	service.SetCodexCredentialIssuer(&fakeCodexIssuer{})
	in := cfg.LaunchProfiles["terra-medium-v1"].LaunchAgentInput
	in.Profile = "terra-medium-v1"
	in.Parameters = map[string]any{"issue_number": 42, "source_delivery_id": "delivery-42"}
	out, err := service.LaunchProfile(context.Background(), "signal-plane", "terra-medium-v1", "contamination", "fp", in)
	if err != nil {
		t.Fatal(err)
	}
	writePreparationFixture(t, cfg, out.RunID, out.Branch)
	runtime.finish(out.RunID+"-prep", 0, "")
	waitFor(t, func() bool {
		runtime.mu.Lock()
		defer runtime.mu.Unlock()
		return len(runtime.specs) == 2 && runtime.started["container-"+out.RunID+"-exec"]
	})
	// The execution worker reports contamination by failing after purging its
	// host-backed work/output, so no valid bounded execution result exists.
	runtime.finish(out.RunID+"-exec", 71, "credential contamination")
	waitFor(t, func() bool {
		intent, found, lookupErr := store.LookupRun(context.Background(), out.RunID)
		return lookupErr == nil && found && intent.State == intentStateTerminal
	})
	runtime.mu.Lock()
	specCount := len(runtime.specs)
	runtime.mu.Unlock()
	if specCount != 2 {
		t.Fatalf("contamination launched delivery; runtime specs=%d", specCount)
	}
	if _, statErr := os.Stat(filepath.Join(cfg.CodexHolder.IssuanceRoot, out.RunID, "capability", "auth.json")); !os.IsNotExist(statErr) {
		t.Fatalf("host credential copy exists after contamination failure: %v", statErr)
	}
}

func TestCodexWorkflowRestartReinjectsWithoutDuplicateExecution(t *testing.T) {
	cfg := codexWorkflowTestConfig(t)
	cfg.ApplyDefaults()
	cfg.StampLoaded(time.Now().UTC())
	runtime := newFakeRuntime()
	store, err := OpenLaunchIntentStore(context.Background(), cfg.LaunchIntentStore)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if closeErr := store.Close(); closeErr != nil {
			t.Errorf("close launch intent store: %v", closeErr)
		}
	})
	issuer := &fakeCodexIssuer{}
	service := NewServiceWithLaunchIntents(cfg, runtime, testAudit(t), store)
	service.SetCodexCredentialIssuer(issuer)
	in := cfg.LaunchProfiles["terra-medium-v1"].LaunchAgentInput
	in.Profile = "terra-medium-v1"
	in.Parameters = map[string]any{"issue_number": 42, "source_delivery_id": "delivery-42"}
	out, err := service.LaunchProfile(context.Background(), "signal-plane", "terra-medium-v1", "restart", "fp", in)
	if err != nil {
		t.Fatal(err)
	}
	writePreparationFixture(t, cfg, out.RunID, out.Branch)
	runtime.finish(out.RunID+"-prep", 0, "")
	waitFor(t, func() bool {
		runtime.mu.Lock()
		ready := len(runtime.specs) == 2 && runtime.started["container-"+out.RunID+"-exec"]
		runtime.mu.Unlock()
		issuer.mu.Lock()
		accepted := issuer.issues == 1 && issuer.consumes == 1
		issuer.mu.Unlock()
		return ready && accepted
	})

	intent, found, err := store.LookupRun(context.Background(), out.RunID)
	if err != nil || !found {
		t.Fatalf("lookup intent found=%t err=%v", found, err)
	}
	intent.Metadata.Phase = codexPhaseBundleInject
	intent.State = intentStateRunning
	if err := store.Save(context.Background(), intent); err != nil {
		t.Fatal(err)
	}
	if err := service.writeMetadataFile(intent.Metadata); err != nil {
		t.Fatal(err)
	}

	restarted := NewServiceWithLaunchIntents(cfg, runtime, testAudit(t), store)
	restarted.SetCodexCredentialIssuer(issuer)
	if err := restarted.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		issuer.mu.Lock()
		defer issuer.mu.Unlock()
		return issuer.issues >= 2
	})
	runtime.mu.Lock()
	specCount := len(runtime.specs)
	runtime.mu.Unlock()
	if specCount != 2 {
		t.Fatalf("restart created %d containers, want one preparation and one execution", specCount)
	}
	writeExecutionFixture(t, cfg, out.RunID, out.Branch)
	runtime.finish(out.RunID+"-exec", 0, "")
	if err := restarted.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		runtime.mu.Lock()
		defer runtime.mu.Unlock()
		return len(runtime.specs) >= 3
	})
	restartedAgain := NewServiceWithLaunchIntents(cfg, runtime, testAudit(t), store)
	restartedAgain.SetCodexCredentialIssuer(issuer)
	if err := restartedAgain.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if len(runtime.specs) != 3 {
		t.Fatalf("restart created %d containers, want exactly one preparation, execution, and delivery", len(runtime.specs))
	}
}

func writePreparationFixture(t *testing.T, cfg Config, runID, branch string) {
	t.Helper()
	path := filepath.Join(cfg.RunsDir, runID, "work", "prepared", "preparation.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	writeJSONFileForTest(t, path, preparationResult{
		Version: "codex-preparation-result/v1", Status: "prepared", RunID: runID,
		Repository: "owner/repo", Branch: branch,
		WorkspaceHead:  "1111111111111111111111111111111111111111",
		RefsSHA256:     strings.Repeat("5", 64),
		ManifestSHA256: "2222222222222222222222222222222222222222222222222222222222222222",
		IssueNumber:    42, SourceDeliveryID: "delivery-42",
	})
}

func writeJSONFileForTest(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func waitFor(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("condition was not reached")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
