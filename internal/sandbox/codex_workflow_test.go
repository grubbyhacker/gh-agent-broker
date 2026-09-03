package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeCodexIssuer struct {
	mu         sync.Mutex
	issues     int
	consumes   int
	cleanups   int
	consumed   bool
	issueErr   error
	consumeErr error
	cleanupErr error
}

func (f *fakeCodexIssuer) Issue(_ context.Context, _, _ string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.issueErr != nil {
		return nil, f.issueErr
	}
	if f.consumed {
		return nil, errors.New("issuance already consumed")
	}
	f.issues++
	return []byte(`{"tokens":{"id_token":"identity-only","access_token":"access-only","refresh_token":""}}`), nil
}

func (f *fakeCodexIssuer) Consume(_ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.consumes++
	if f.consumeErr != nil {
		return f.consumeErr
	}
	f.consumed = true
	return nil
}

func (f *fakeCodexIssuer) Cleanup(_ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cleanups++
	return f.cleanupErr
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
		DiffSHA256:    strings.Repeat("3", 64), ValidatedTreeSHA: strings.Repeat("7", 40), FinalSHA256: strings.Repeat("4", 64),
		VerifySHA256: strings.Repeat("6", 64), Verification: "passed",
		FinalSizeBytes: 10,
	})
}

func writeExecutionFailureFixture(t *testing.T, cfg Config, runID, branch string, exitCode int, diagnostic string) {
	t.Helper()
	path := filepath.Join(cfg.RunsDir, runID, "work", "execution", "execution-failure.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	writeJSONFileForTest(t, path, executionFailure{
		Version: "codex-execution-failure/v1", Status: "failed", RunID: runID,
		Repository: "owner/repo", Branch: branch, Stage: "codex", ExitCode: exitCode,
		DiagnosticSource: "stderr", Diagnostic: diagnostic,
		EventsSizeBytes: 0, EventsSHA256: strings.Repeat("1", 64),
		StderrSizeBytes: int64(len(diagnostic)), StderrSHA256: strings.Repeat("2", 64),
	})
}

func TestCodexExecutionFailureProjectsBoundedOperationalDiagnostic(t *testing.T) {
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
	out, err := service.LaunchProfile(context.Background(), "signal-plane", "terra-medium-v1", "diagnostic", "fp", in)
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
		consumed := issuer.consumes == 1
		issuer.mu.Unlock()
		return ready && consumed
	})
	diagnostic := "missing field `id_token` at line 1 column 67"
	writeExecutionFailureFixture(t, cfg, out.RunID, out.Branch, 1, diagnostic)
	runtime.finish(out.RunID+"-exec", 1, "raw runtime output must not be projected")
	waitFor(t, func() bool {
		_, terminalErr := service.GetTerminalResult(context.Background(), RunInput{RunID: out.RunID})
		return terminalErr == nil
	})
	terminal, err := service.GetTerminalResult(context.Background(), RunInput{RunID: out.RunID})
	if err != nil {
		t.Fatal(err)
	}
	if terminal.Outcome != StatusFailed || terminal.FailureStage != "execution" ||
		!strings.Contains(terminal.FailureReason, diagnostic) ||
		strings.Contains(terminal.FailureReason, "raw runtime output") {
		t.Fatalf("terminal=%+v", terminal)
	}
	runtime.mu.Lock()
	specCount := len(runtime.specs)
	runtime.mu.Unlock()
	if specCount != 2 {
		t.Fatalf("failed execution launched delivery; runtime specs=%d", specCount)
	}
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

func TestCodexPostStartCredentialFailuresStopExecutionBeforeTerminalizing(t *testing.T) {
	tests := []struct {
		name      string
		stage     string
		configure func(*fakeRuntime, *fakeCodexIssuer)
	}{
		{
			name:  "issuance",
			stage: "credential_issuance",
			configure: func(_ *fakeRuntime, issuer *fakeCodexIssuer) {
				issuer.issueErr = errors.New("issue capability")
			},
		},
		{
			name:  "injection",
			stage: "credential_injection",
			configure: func(runtime *fakeRuntime, _ *fakeCodexIssuer) {
				runtime.injectionErr = errors.New("inject capability")
			},
		},
		{
			name:  "acceptance",
			stage: "credential_acceptance",
			configure: func(runtime *fakeRuntime, _ *fakeCodexIssuer) {
				runtime.acceptInjected = false
				runtime.waitForPathErr = errors.New("accept capability")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := codexWorkflowTestConfig(t)
			cfg.ApplyDefaults()
			cfg.StampLoaded(time.Now().UTC())
			runtime := newFakeRuntime()
			issuer := &fakeCodexIssuer{}
			tt.configure(runtime, issuer)
			store, err := OpenLaunchIntentStore(context.Background(), cfg.LaunchIntentStore)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if closeErr := store.Close(); closeErr != nil {
					t.Errorf("close launch intent store: %v", closeErr)
				}
			})
			auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
			auditLog, err := NewAuditLogger(auditPath)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { closeTestAudit(t, auditLog) })
			service := NewServiceWithLaunchIntents(cfg, runtime, auditLog, store)
			service.SetCodexCredentialIssuer(issuer)

			in := cfg.LaunchProfiles["terra-medium-v1"].LaunchAgentInput
			in.Profile = "terra-medium-v1"
			in.Parameters = map[string]any{"issue_number": 42, "source_delivery_id": "delivery-42"}
			out, err := service.LaunchProfile(
				context.Background(), "signal-plane", "terra-medium-v1", "failure-"+tt.name, "fp", in,
			)
			if err != nil {
				t.Fatal(err)
			}
			writePreparationFixture(t, cfg, out.RunID, out.Branch)
			runtime.finish(out.RunID+"-prep", 0, "")
			waitFor(t, func() bool {
				_, terminalErr := service.GetTerminalResult(context.Background(), RunInput{RunID: out.RunID})
				return terminalErr == nil
			})
			intent, found, err := store.LookupRun(context.Background(), out.RunID)
			if err != nil || !found || intent.State != intentStateTerminal {
				t.Fatalf("durable intent found=%t state=%q err=%v", found, intent.State, err)
			}

			executionID := "container-" + out.RunID + "-exec"
			runtime.mu.Lock()
			running := runtime.started[executionID]
			stopCalls := append([]string(nil), runtime.stopCalls...)
			specCount := len(runtime.specs)
			injected := runtime.injections[executionID+":"+filepath.Join(codexInjectionDir, codexInjectionName)]
			accepted := runtime.paths[executionID+":"+codexAcceptanceMarker]
			runtime.mu.Unlock()
			if running || !reflect.DeepEqual(stopCalls, []string{executionID}) {
				t.Fatalf("execution running=%t stop calls=%v, want one execution stop", running, stopCalls)
			}
			if len(injected) != 0 || accepted {
				t.Fatalf("execution tmpfs survived stop: bundle=%q accepted=%t", injected, accepted)
			}
			if specCount != 2 {
				t.Fatalf("credential failure launched delivery; runtime specs=%d", specCount)
			}

			terminal, err := service.GetTerminalResult(context.Background(), RunInput{RunID: out.RunID})
			if err != nil {
				t.Fatal(err)
			}
			if terminal.Status != StatusFailed || terminal.Outcome != StatusFailed ||
				terminal.FailureStage != tt.stage || terminal.FailureReason == "" {
				t.Fatalf("terminal=%+v", terminal)
			}
			again, err := service.GetTerminalResult(context.Background(), RunInput{RunID: out.RunID})
			if err != nil || !reflect.DeepEqual(terminal, again) {
				t.Fatalf("durable terminal changed: first=%+v second=%+v err=%v", terminal, again, err)
			}
			events := readAuditEvents(t, auditPath)
			finalized := 0
			for _, event := range events {
				if event.Operation == "run_finalized" && event.RunID == out.RunID && event.Terminal {
					finalized++
					if event.Status != StatusFailed || event.TerminalSource != "codex_"+tt.stage {
						t.Fatalf("terminal audit=%+v", event)
					}
				}
			}
			if finalized != 1 {
				t.Fatalf("terminal audit events=%d, want one; events=%+v", finalized, events)
			}
		})
	}
}

func TestCodexPostStartStopFailureIsBoundedAndVisible(t *testing.T) {
	cfg := codexWorkflowTestConfig(t)
	cfg.ApplyDefaults()
	cfg.StampLoaded(time.Now().UTC())
	runtime := newFakeRuntime()
	runtime.stopErr = errors.New("runtime stop unavailable")
	runtime.stopLeavesRunning = true
	issuer := &fakeCodexIssuer{issueErr: errors.New("issue capability")}
	store, err := OpenLaunchIntentStore(context.Background(), cfg.LaunchIntentStore)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if closeErr := store.Close(); closeErr != nil {
			t.Errorf("close launch intent store: %v", closeErr)
		}
	})
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	auditLog, err := NewAuditLogger(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeTestAudit(t, auditLog) })
	service := NewServiceWithLaunchIntents(cfg, runtime, auditLog, store)
	service.SetCodexCredentialIssuer(issuer)
	in := cfg.LaunchProfiles["terra-medium-v1"].LaunchAgentInput
	in.Profile = "terra-medium-v1"
	in.Parameters = map[string]any{"issue_number": 42, "source_delivery_id": "delivery-42"}
	out, err := service.LaunchProfile(
		context.Background(), "signal-plane", "terra-medium-v1", "stop-failure", "fp", in,
	)
	if err != nil {
		t.Fatal(err)
	}
	writePreparationFixture(t, cfg, out.RunID, out.Branch)
	runtime.finish(out.RunID+"-prep", 0, "")
	waitFor(t, func() bool {
		_, terminalErr := service.GetTerminalResult(context.Background(), RunInput{RunID: out.RunID})
		return terminalErr == nil
	})

	executionID := "container-" + out.RunID + "-exec"
	runtime.mu.Lock()
	running := runtime.started[executionID]
	stopCalls := append([]string(nil), runtime.stopCalls...)
	stopGraces := append([]time.Duration(nil), runtime.stopGraces...)
	stopDeadline := runtime.stopDeadline
	runtime.mu.Unlock()
	if !running || !reflect.DeepEqual(stopCalls, []string{executionID}) {
		t.Fatalf("execution running=%t stop calls=%v", running, stopCalls)
	}
	if !reflect.DeepEqual(stopGraces, []time.Duration{cfg.StopGrace.Duration}) {
		t.Fatalf("stop graces=%v, want %s", stopGraces, cfg.StopGrace.Duration)
	}
	remaining := time.Until(stopDeadline)
	if stopDeadline.IsZero() || remaining <= 0 || remaining > cfg.StopGrace.Duration+5*time.Second {
		t.Fatalf("stop deadline=%s remaining=%s", stopDeadline, remaining)
	}
	terminal, err := service.GetTerminalResult(context.Background(), RunInput{RunID: out.RunID})
	if err != nil {
		t.Fatal(err)
	}
	if terminal.Status != StatusFailed ||
		!strings.Contains(terminal.FailureReason, "runtime stop unavailable") ||
		!strings.Contains(terminal.FailureReason, "container remains running") {
		t.Fatalf("stop failure is not visible in terminal result: %+v", terminal)
	}
	events := readAuditEvents(t, auditPath)
	for _, event := range events {
		if event.Operation == "run_finalized" && event.RunID == out.RunID && event.Terminal {
			if !strings.Contains(event.Error, "runtime stop unavailable") ||
				!strings.Contains(event.Error, "container remains running") {
				t.Fatalf("stop failure is not visible in audit: %+v", event)
			}
			return
		}
	}
	t.Fatalf("terminal audit missing: %+v", events)
}

func TestCodexWorkflowRestartAdoptsAcceptedExecutionWithoutReinjection(t *testing.T) {
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
	intent.Metadata.Phase = codexPhaseBundleAccept
	intent.State = intentStateRunning
	if err := store.Save(context.Background(), intent); err != nil {
		t.Fatal(err)
	}
	if err := service.writeMetadataFile(intent.Metadata); err != nil {
		t.Fatal(err)
	}
	issuer.mu.Lock()
	issuer.consumed = false
	issuer.mu.Unlock()

	restarted := NewServiceWithLaunchIntents(cfg, runtime, testAudit(t), store)
	restarted.SetCodexCredentialIssuer(issuer)
	if err := restarted.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	intent, found, err = store.LookupRun(context.Background(), out.RunID)
	if err != nil || !found {
		t.Fatalf("lookup accepted intent found=%t err=%v", found, err)
	}
	intent.Metadata.Phase = codexPhaseBundleInject
	if err := store.Save(context.Background(), intent); err != nil {
		t.Fatal(err)
	}
	if err := restarted.writeMetadataFile(intent.Metadata); err != nil {
		t.Fatal(err)
	}
	restartedAfterConsume := NewServiceWithLaunchIntents(cfg, runtime, testAudit(t), store)
	restartedAfterConsume.SetCodexCredentialIssuer(issuer)
	if err := restartedAfterConsume.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	runtime.mu.Lock()
	specCount := len(runtime.specs)
	injectionCount := runtime.injectionCalls["container-"+out.RunID+"-exec"]
	runtime.mu.Unlock()
	if specCount != 2 {
		t.Fatalf("restart created %d containers, want one preparation and one execution", specCount)
	}
	issuer.mu.Lock()
	issueCount := issuer.issues
	consumeCount := issuer.consumes
	issuer.mu.Unlock()
	if issueCount != 1 || injectionCount != 1 {
		t.Fatalf("restart issued=%d injected=%d, want no replay after acceptance", issueCount, injectionCount)
	}
	if consumeCount != 3 {
		t.Fatalf("consume calls=%d, want acceptance and post-consume crash recovery", consumeCount)
	}
	recovered, found, err := store.LookupRun(context.Background(), out.RunID)
	if err != nil || !found {
		t.Fatalf("lookup recovered intent found=%t err=%v", found, err)
	}
	if recovered.Metadata.Status != StatusRunning || recovered.Metadata.Phase != codexPhaseExecutionRunning {
		t.Fatalf("recovered metadata=%+v", recovered.Metadata)
	}

	writeExecutionFixture(t, cfg, out.RunID, out.Branch)
	runtime.finish(out.RunID+"-exec", 0, "")
	if err := restartedAfterConsume.Reconcile(context.Background()); err != nil {
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

func TestCodexWorkflowRestartRunningExecutionOnlyReattachesWatcher(t *testing.T) {
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
	out, err := service.LaunchProfile(context.Background(), "signal-plane", "terra-medium-v1", "running-restart", "fp", in)
	if err != nil {
		t.Fatal(err)
	}
	writePreparationFixture(t, cfg, out.RunID, out.Branch)
	runtime.finish(out.RunID+"-prep", 0, "")
	waitFor(t, func() bool {
		intent, found, lookupErr := store.LookupRun(context.Background(), out.RunID)
		return lookupErr == nil && found && intent.Metadata.Phase == codexPhaseExecutionRunning
	})

	restarted := NewServiceWithLaunchIntents(cfg, runtime, testAudit(t), store)
	restarted.SetCodexCredentialIssuer(issuer)
	if err := restarted.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	runtime.mu.Lock()
	specCount := len(runtime.specs)
	injectionCount := runtime.injectionCalls["container-"+out.RunID+"-exec"]
	runtime.mu.Unlock()
	issuer.mu.Lock()
	issueCount := issuer.issues
	consumeCount := issuer.consumes
	issuer.mu.Unlock()
	if specCount != 2 || issueCount != 1 || consumeCount != 1 || injectionCount != 1 {
		t.Fatalf(
			"restart specs=%d issues=%d consumes=%d injections=%d, want pure adoption",
			specCount,
			issueCount,
			consumeCount,
			injectionCount,
		)
	}
	intent, found, err := store.LookupRun(context.Background(), out.RunID)
	if err != nil || !found {
		t.Fatalf("lookup intent found=%t err=%v", found, err)
	}
	if intent.State == intentStateTerminal || intent.Metadata.Status != StatusRunning {
		t.Fatalf("running execution was falsely terminalized: %+v", intent)
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

func readAuditEvents(t *testing.T, path string) []AuditEvent {
	t.Helper()
	data, err := os.ReadFile(path) // #nosec G304 -- the test passes its own temporary audit path.
	if err != nil {
		t.Fatal(err)
	}
	var events []AuditEvent
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var event AuditEvent
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatalf("decode audit event: %v", err)
		}
		events = append(events, event)
	}
	return events
}
