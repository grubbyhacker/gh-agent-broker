package sandbox

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestLaunchAgentBuildsSandboxedRuntimeSpec(t *testing.T) {
	cfg := baseTestConfig(t)
	auditLog := testAudit(t)
	defer closeTestAudit(t, auditLog)
	runtime := newFakeRuntime()
	service := NewService(cfg, runtime, auditLog)

	out, err := service.LaunchAgent(context.Background(), LaunchAgentInput{
		Template:   "worker",
		Task:       "make the change",
		Repo:       "owner/repo",
		BaseBranch: "main",
	})
	if err != nil {
		t.Fatalf("LaunchAgent() error = %v", err)
	}
	if out.Status != StatusRunning {
		t.Fatalf("status = %q", out.Status)
	}
	if !strings.HasPrefix(out.Branch, "agent/hermes-coder-01/") {
		t.Fatalf("generated branch = %q", out.Branch)
	}
	spec := runtime.lastSpec()
	if spec.User == "" || spec.User == "root" || spec.User == "0" {
		t.Fatalf("runtime user = %q", spec.User)
	}
	if spec.Env["BROKER_AGENT_SECRET"] != "broker-secret" {
		t.Fatalf("broker secret env not injected from template")
	}
	if spec.Env["HOME"] != "/work/home" || spec.Env["HERMES_HOME"] != "/work/hermes" {
		t.Fatalf("task-local homes not configured: HOME=%q HERMES_HOME=%q", spec.Env["HOME"], spec.Env["HERMES_HOME"])
	}
	if spec.Network.Network != "sandbox-net" {
		t.Fatalf("network = %+v", spec.Network)
	}
	assertMount(t, spec.Mounts, filepath.Join(cfg.RunsDir, out.RunID, "input"), "/input", true)
	assertMount(t, spec.Mounts, filepath.Join(cfg.RunsDir, out.RunID, "work"), "/work", false)
	assertMount(t, spec.Mounts, cfg.Bundles["codex"].SourcePath, "/credentials/codex", true)
	assertMount(t, spec.Mounts, filepath.Join(filepath.Dir(cfg.RunsDir), "evidence"), "/data/intake", true)
	if spec.Env["BROKER_AGENT_SECRET"] == spec.Labels["BROKER_AGENT_SECRET"] {
		t.Fatalf("secret leaked into labels")
	}
	if _, err := os.Stat(filepath.Join(cfg.RunsDir, out.RunID, "input", "knowledge.md")); err != nil {
		t.Fatalf("knowledge snapshot was not copied: %v", err)
	}
	for _, tt := range []struct {
		path string
		mode os.FileMode
	}{
		{path: filepath.Join(cfg.RunsDir, out.RunID), mode: 0o711},
		{path: filepath.Join(cfg.RunsDir, out.RunID, "input"), mode: 0o755},
		{path: filepath.Join(cfg.RunsDir, out.RunID, "input", "knowledge.md"), mode: 0o644},
		{path: filepath.Join(cfg.RunsDir, out.RunID, "work"), mode: 0o777},
		{path: filepath.Join(cfg.RunsDir, out.RunID, "output"), mode: 0o777},
		{path: filepath.Join(cfg.RunsDir, out.RunID, "lessons"), mode: 0o777},
		{path: filepath.Join(cfg.RunsDir, out.RunID, "logs"), mode: 0o700},
	} {
		info, err := os.Stat(tt.path)
		if err != nil {
			t.Fatalf("stat %s: %v", tt.path, err)
		}
		if got := info.Mode().Perm(); got != tt.mode {
			t.Fatalf("mode %s = %o, want %o", tt.path, got, tt.mode)
		}
	}
}

func TestLaunchAgentWritesTaskInputsAndMergesDeliverables(t *testing.T) {
	cfg := baseTestConfig(t)
	auditLog := testAudit(t)
	defer closeTestAudit(t, auditLog)
	service := NewService(cfg, newFakeRuntime(), auditLog)

	out, err := service.LaunchAgent(context.Background(), LaunchAgentInput{
		Template:     "worker",
		Task:         "write marker MARKER-ONE",
		Repo:         "owner/repo",
		BaseBranch:   "main",
		Focus:        "contract test",
		Deliverables: []string{"/output/extra.md", "/output/final-summary.md"},
	})
	if err != nil {
		t.Fatalf("LaunchAgent() error = %v", err)
	}
	inputDir := filepath.Join(cfg.RunsDir, out.RunID, "input")
	var contract TaskContract
	//nolint:gosec // G304: test reads the generated task contract under this test's temp run directory.
	b, err := os.ReadFile(filepath.Join(inputDir, "task.json"))
	if err != nil {
		t.Fatalf("read task.json: %v", err)
	}
	if err := json.Unmarshal(b, &contract); err != nil {
		t.Fatalf("decode task.json: %v", err)
	}
	if contract.Task != "write marker MARKER-ONE" || contract.Focus != "contract test" {
		t.Fatalf("unexpected task contract text: %+v", contract)
	}
	if contract.Repo != "owner/repo" || contract.BaseBranch != "main" || contract.Branch != out.Branch {
		t.Fatalf("unexpected repo contract: %+v", contract)
	}
	if contract.BrokerRemoteURL != "http://gh-agent-broker:8080/git/owner/repo.git" {
		t.Fatalf("broker remote URL = %q", contract.BrokerRemoteURL)
	}
	wantDeliverables := []string{"/output/final-summary.md", "/lessons/run-summary.md", "/output/extra.md"}
	if strings.Join(contract.Deliverables, ",") != strings.Join(wantDeliverables, ",") {
		t.Fatalf("deliverables = %#v, want %#v", contract.Deliverables, wantDeliverables)
	}
	for _, name := range []string{"task.md", "sandbox-rules.md"} {
		//nolint:gosec // G304: test reads generated task input files under this test's temp run directory.
		data, err := os.ReadFile(filepath.Join(inputDir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if strings.Contains(string(data), "broker-secret") {
			t.Fatalf("%s leaked broker secret: %q", name, string(data))
		}
	}
	//nolint:gosec // G304: test reads the generated sandbox rules under this test's temp run directory.
	rules, err := os.ReadFile(filepath.Join(inputDir, "sandbox-rules.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Broker remote URL", contract.BrokerRemoteURL, "/output/final-summary.md", "/lessons/run-summary.md"} {
		if !strings.Contains(string(rules), want) {
			t.Fatalf("sandbox-rules.md missing %q:\n%s", want, string(rules))
		}
	}
}

func TestLaunchAgentRejectsDisallowedInputs(t *testing.T) {
	cfg := baseTestConfig(t)
	service := NewService(cfg, newFakeRuntime(), testAudit(t))
	tests := []struct {
		name string
		in   LaunchAgentInput
		want string
	}{
		{
			name: "repo",
			in:   LaunchAgentInput{Template: "worker", Task: "task", Repo: "owner/other", BaseBranch: "main"},
			want: "not allowed",
		},
		{
			name: "branch",
			in:   LaunchAgentInput{Template: "worker", Task: "task", Repo: "owner/repo", BaseBranch: "main", Branch: "../bad"},
			want: "unsafe",
		},
		{
			name: "runtime",
			in:   LaunchAgentInput{Template: "worker", Task: "task", Repo: "owner/repo", BaseBranch: "main", MaxRuntimeMinutes: 99},
			want: "max_runtime_minutes",
		},
		{
			name: "seconds runtime too high",
			in:   LaunchAgentInput{Template: "worker", Task: "task", Repo: "owner/repo", BaseBranch: "main", MaxRuntimeSeconds: 601},
			want: "max_runtime_seconds",
		},
		{
			name: "mixed runtime units",
			in:   LaunchAgentInput{Template: "worker", Task: "task", Repo: "owner/repo", BaseBranch: "main", MaxRuntimeMinutes: 1, MaxRuntimeSeconds: 30},
			want: "only one",
		},
		{
			name: "task size",
			in:   LaunchAgentInput{Template: "worker", Task: strings.Repeat("x", cfg.MaxTaskBytes+1), Repo: "owner/repo", BaseBranch: "main"},
			want: "task exceeds",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := service.LaunchAgent(context.Background(), tt.in)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("LaunchAgent() error = %v, want containing %q", err, tt.want)
			}
			if !strings.Contains(err.Error(), "policy denial") {
				t.Fatalf("LaunchAgent() error = %v, want structured policy denial text", err)
			}
		})
	}
}

func TestLaunchAgentAcceptsShorterSecondRuntimeLimit(t *testing.T) {
	cfg := baseTestConfig(t)
	runtime := newFakeRuntime()
	service := NewService(cfg, runtime, testAudit(t))
	before := time.Now().UTC()
	out, err := service.LaunchAgent(context.Background(), LaunchAgentInput{
		Template:          "worker",
		Task:              "task",
		Repo:              "owner/repo",
		BaseBranch:        "main",
		MaxRuntimeSeconds: 3,
	})
	if err != nil {
		t.Fatalf("LaunchAgent() error = %v", err)
	}
	remaining := out.Deadline.Sub(before)
	if remaining < 2*time.Second || remaining > 5*time.Second {
		t.Fatalf("deadline = %v after launch start, want about 3s", remaining)
	}
	if spec := runtime.lastSpec(); spec.Timeout < 2*time.Second || spec.Timeout > 5*time.Second {
		t.Fatalf("runtime timeout = %v, want about 3s", spec.Timeout)
	}
}

func TestLaunchAgentInputRejectsUnknownJSONFields(t *testing.T) {
	forbidden := []string{"image", "command", "env", "mounts", "privileged", "network"}
	for _, field := range forbidden {
		t.Run(field, func(t *testing.T) {
			payload := `{"template":"worker","task":"task","repo":"owner/repo","base_branch":"main","` + field + `":"bad"}`
			var in LaunchAgentInput
			err := json.Unmarshal([]byte(payload), &in)
			if err == nil || !strings.Contains(err.Error(), field) {
				t.Fatalf("UnmarshalJSON() error = %v, want field %q rejection", err, field)
			}
		})
	}
}

func TestLogsAndArtifactsAreRedactedAndSymlinkSafe(t *testing.T) {
	cfg := baseTestConfig(t)
	runtime := newFakeRuntime()
	runtime.logs = "Authorization: Bearer broker-secret\nbundle value bundle-secret\n"
	service := NewService(cfg, runtime, testAudit(t))
	out, err := service.LaunchAgent(context.Background(), LaunchAgentInput{Template: "worker", Task: "task", Repo: "owner/repo", BaseBranch: "main"})
	if err != nil {
		t.Fatalf("LaunchAgent() error = %v", err)
	}

	logs, err := service.GetAgentLogs(context.Background(), LogsInput{RunID: out.RunID})
	if err != nil {
		t.Fatalf("GetAgentLogs() error = %v", err)
	}
	if strings.Contains(logs.Logs, "broker-secret") || strings.Contains(logs.Logs, "bundle-secret") {
		t.Fatalf("logs were not redacted: %q", logs.Logs)
	}

	outputDir := filepath.Join(cfg.RunsDir, out.RunID, "output")
	if err := os.WriteFile(filepath.Join(outputDir, "final-summary.md"), []byte("secret bundle-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", filepath.Join(outputDir, "passwd-link")); err != nil {
		t.Fatal(err)
	}
	collected, err := service.CollectArtifacts(context.Background(), RunInput{RunID: out.RunID})
	if err != nil {
		t.Fatalf("CollectArtifacts() error = %v", err)
	}
	if len(collected.Files) != 1 {
		t.Fatalf("files = %+v", collected.Files)
	}
	if collected.Files[0].Inline != "secret [REDACTED]" {
		t.Fatalf("inline = %q", collected.Files[0].Inline)
	}
	lessonsDir := filepath.Join(cfg.RunsDir, out.RunID, "lessons")
	if err := os.WriteFile(filepath.Join(lessonsDir, "run-summary.md"), []byte("lesson bundle-secret Authorization: Bearer abc123secret456"), 0o600); err != nil {
		t.Fatal(err)
	}
	lessons, err := service.CollectLessons(context.Background(), RunInput{RunID: out.RunID})
	if err != nil {
		t.Fatalf("CollectLessons() error = %v", err)
	}
	if strings.Contains(lessons.Files[0].Inline, "bundle-secret") || strings.Contains(lessons.Files[0].Inline, "abc123secret456") {
		t.Fatalf("lesson inline was not redacted: %q", lessons.Files[0].Inline)
	}
}

func TestRedactorReadsJSONSecretValues(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "auth.json"), []byte(`{
  "access_token": "codex-access-token-beta",
  "refresh_token": "codex-refresh-token-beta",
  "nested": {"id_token": "codex-id-token-beta"}
}`), 0o600); err != nil {
		t.Fatal(err)
	}
	redactor := RedactorForBundle(CredentialBundle{
		SourcePath:  root,
		SecretFiles: []string{"auth.json"},
	})
	got := redactor.Redact("access=codex-access-token-beta refresh=codex-refresh-token-beta id=codex-id-token-beta")
	for _, leaked := range []string{"codex-access-token-beta", "codex-refresh-token-beta", "codex-id-token-beta"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("Redact() leaked %q in %q", leaked, got)
		}
	}
}

func TestCleanupRejectsInvalidRunID(t *testing.T) {
	service := NewService(baseTestConfig(t), newFakeRuntime(), testAudit(t))
	if _, err := service.CleanupRun(context.Background(), RunInput{RunID: "../outside"}); err == nil {
		t.Fatalf("CleanupRun() unexpectedly allowed traversal run id")
	}
}

func TestTimeoutPreservesPartialArtifactsAndCleanupWorks(t *testing.T) {
	cfg := baseTestConfig(t)
	runtime := newFakeRuntime()
	service := NewService(cfg, runtime, testAudit(t))
	out, err := service.LaunchAgent(context.Background(), LaunchAgentInput{Template: "worker", Task: "timeout", Repo: "owner/repo", BaseBranch: "main"})
	if err != nil {
		t.Fatalf("LaunchAgent() error = %v", err)
	}
	outputDir := filepath.Join(cfg.RunsDir, out.RunID, "output")
	if err := os.WriteFile(filepath.Join(outputDir, "partial.txt"), []byte("partial output"), 0o600); err != nil {
		t.Fatal(err)
	}
	service.watchTimeout(context.Background(), out.RunID, time.Now().Add(10*time.Millisecond))
	status, err := service.GetAgentStatus(context.Background(), RunInput{RunID: out.RunID})
	if err != nil {
		t.Fatalf("GetAgentStatus() error = %v", err)
	}
	if status.Status != StatusTimedOut {
		t.Fatalf("status = %+v, want timed_out", status)
	}
	if status.Error != "run exceeded deadline" {
		t.Fatalf("timeout error = %q", status.Error)
	}
	if status.Diagnostics == nil || status.Diagnostics.Message != "run exceeded deadline" || status.Diagnostics.Source != "broker" {
		t.Fatalf("timeout diagnostics = %+v", status.Diagnostics)
	}
	artifacts, err := service.CollectArtifacts(context.Background(), RunInput{RunID: out.RunID})
	if err != nil {
		t.Fatalf("CollectArtifacts() error = %v", err)
	}
	if requireCollectedFile(t, artifacts, "partial.txt").Inline != "partial output" {
		t.Fatalf("partial artifact missing: %+v", artifacts.Files)
	}
	diagnostics := requireCollectedFile(t, artifacts, "wrapper-diagnostics.json")
	if !strings.Contains(diagnostics.Inline, "run exceeded deadline") {
		t.Fatalf("timeout diagnostics artifact = %q", diagnostics.Inline)
	}
	cleaned, err := service.CleanupRun(context.Background(), RunInput{RunID: out.RunID})
	if err != nil {
		t.Fatalf("CleanupRun() error = %v", err)
	}
	if cleaned.Status != StatusCleaned {
		t.Fatalf("cleanup status = %+v", cleaned)
	}
	if _, err := os.Stat(filepath.Join(cfg.RunsDir, out.RunID)); !os.IsNotExist(err) {
		t.Fatalf("run dir still exists or stat failed unexpectedly: %v", err)
	}
}

func TestTimeoutWatcherPreservesAlreadyExitedFailure(t *testing.T) {
	cfg := baseTestConfig(t)
	runtime := newFakeRuntime()
	runtime.logs = "stderr: permission denied\n"
	service := NewService(cfg, runtime, testAudit(t))
	out, err := service.LaunchAgent(context.Background(), LaunchAgentInput{Template: "worker", Task: "fail early", Repo: "owner/repo", BaseBranch: "main"})
	if err != nil {
		t.Fatalf("LaunchAgent() error = %v", err)
	}
	runtime.finish(out.RunID, 2, "permission denied")

	service.watchTimeout(context.Background(), out.RunID, time.Now().Add(10*time.Millisecond))
	status, err := service.GetAgentStatus(context.Background(), RunInput{RunID: out.RunID})
	if err != nil {
		t.Fatalf("GetAgentStatus() error = %v", err)
	}
	if status.Status != StatusFailed || status.ExitCode == nil || *status.ExitCode != 2 {
		t.Fatalf("status = %+v, want failed exit 2", status)
	}
	if strings.Contains(status.Error, "run exceeded deadline") {
		t.Fatalf("status misreported timeout: %+v", status)
	}
	if !strings.Contains(status.Error, "permission denied") {
		t.Fatalf("failure did not include captured error/log text: %+v", status)
	}
}

func TestGetAgentStatusReturnsWorkerDiagnostics(t *testing.T) {
	cfg := baseTestConfig(t)
	runtime := newFakeRuntime()
	service := NewService(cfg, runtime, testAudit(t))
	out, err := service.LaunchAgent(context.Background(), LaunchAgentInput{Template: "worker", Task: "fail", Repo: "owner/repo", BaseBranch: "main"})
	if err != nil {
		t.Fatalf("LaunchAgent() error = %v", err)
	}
	code := 30
	diagnostics := FailureDiagnostics{
		Status:              StatusFailed,
		ExitCode:            &code,
		Message:             "required deliverables missing",
		MissingDeliverables: []string{"/output/final-summary.md"},
	}
	if err := writeJSONFile(filepath.Join(cfg.RunsDir, out.RunID, "output", "wrapper-diagnostics.json"), diagnostics, 0o644); err != nil {
		t.Fatal(err)
	}
	runtime.finish(out.RunID, code, "")

	status, err := service.GetAgentStatus(context.Background(), RunInput{RunID: out.RunID})
	if err != nil {
		t.Fatalf("GetAgentStatus() error = %v", err)
	}
	if status.Status != StatusFailed || status.ExitCode == nil || *status.ExitCode != code {
		t.Fatalf("status = %+v, want failed exit %d", status, code)
	}
	if status.Diagnostics == nil {
		t.Fatalf("diagnostics missing from status: %+v", status)
	}
	if status.Diagnostics.Source != "worker" || status.Diagnostics.Message != "required deliverables missing" {
		t.Fatalf("diagnostics = %+v", status.Diagnostics)
	}
	if strings.Join(status.Diagnostics.MissingDeliverables, ",") != "/output/final-summary.md" {
		t.Fatalf("missing deliverables = %+v", status.Diagnostics.MissingDeliverables)
	}
}

func TestCompletionStatusFileWrittenForConfiguredTemplate(t *testing.T) {
	cfg := baseTestConfig(t)
	tmpl := cfg.Templates["worker"]
	tmpl.CompletionStatusPath = "/data/intake/curator-status.json"
	tmpl.ExtraMounts = []ExtraMount{{SourcePath: filepath.Join(filepath.Dir(cfg.RunsDir), "evidence"), MountPath: "/data/intake", ReadOnly: false}}
	cfg.Templates["worker"] = tmpl
	runtime := newFakeRuntime()
	service := NewService(cfg, runtime, testAudit(t))
	out, err := service.LaunchAgent(context.Background(), LaunchAgentInput{Template: "worker", Task: "done", Repo: "owner/repo", BaseBranch: "main"})
	if err != nil {
		t.Fatalf("LaunchAgent() error = %v", err)
	}
	runtime.finish(out.RunID, 0, "")

	meta := waitForMetadataStatus(t, cfg, out.RunID, StatusStopped)
	if meta.Status != StatusStopped {
		t.Fatalf("status = %+v, want stopped", meta)
	}
	var statusFile completionStatusFile
	if err := json.Unmarshal(runtime.writtenFile("/data/intake/curator-status.json"), &statusFile); err != nil {
		t.Fatalf("decode completion status: %v", err)
	}
	if statusFile.Status != "success" || statusFile.ExitCode != 0 || statusFile.Message != "worker completed successfully" {
		t.Fatalf("completion status = %+v", statusFile)
	}
	if statusFile.Timestamp.IsZero() {
		t.Fatalf("completion status timestamp missing: %+v", statusFile)
	}
}

func TestExitWatcherFinalizesRunAndWritesTerminalAudit(t *testing.T) {
	cfg := baseTestConfig(t)
	tmpl := cfg.Templates["worker"]
	tmpl.CompletionStatusPath = "/data/intake/curator-status.json"
	tmpl.ExtraMounts = []ExtraMount{{SourcePath: filepath.Join(filepath.Dir(cfg.RunsDir), "evidence"), MountPath: "/data/intake", ReadOnly: false}}
	cfg.Templates["worker"] = tmpl
	runtime := newFakeRuntime()
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	auditLog, err := NewAuditLogger(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestAudit(t, auditLog)
	service := NewService(cfg, runtime, auditLog)
	out, err := service.LaunchAgent(context.Background(), LaunchAgentInput{Template: "worker", Task: "done", Repo: "owner/repo", BaseBranch: "main"})
	if err != nil {
		t.Fatalf("LaunchAgent() error = %v", err)
	}
	runtime.finish(out.RunID, 0, "")
	meta := waitForMetadataStatus(t, cfg, out.RunID, StatusStopped)
	if meta.ExitCode == nil || *meta.ExitCode != 0 {
		t.Fatalf("exit code = %+v, want 0", meta.ExitCode)
	}
	var statusFile completionStatusFile
	if err := json.Unmarshal(runtime.writtenFile("/data/intake/curator-status.json"), &statusFile); err != nil {
		t.Fatalf("decode completion status: %v", err)
	}
	if statusFile.Status != "success" || statusFile.ExitCode != 0 {
		t.Fatalf("completion status = %+v", statusFile)
	}
	waitForTerminalAudit(t, auditPath, out.RunID, finalizeReasonWorkerExit, terminalSourceExited, StatusStopped)
}

func TestTimeoutStopAlreadyStoppedFinalizesExitedRun(t *testing.T) {
	cfg := baseTestConfig(t)
	tmpl := cfg.Templates["worker"]
	tmpl.CompletionStatusPath = "/data/intake/curator-status.json"
	tmpl.ExtraMounts = []ExtraMount{{SourcePath: filepath.Join(filepath.Dir(cfg.RunsDir), "evidence"), MountPath: "/data/intake", ReadOnly: false}}
	cfg.Templates["worker"] = tmpl
	runtime := newFakeRuntime()
	code := 0
	runtime.stopErr = DockerError{Method: "POST", Path: "/containers/test/stop?t=2", StatusCode: 304}
	runtime.stopExitCode = &code
	service := NewService(cfg, runtime, testAudit(t))
	out, err := service.LaunchAgent(context.Background(), LaunchAgentInput{Template: "worker", Task: "race", Repo: "owner/repo", BaseBranch: "main"})
	if err != nil {
		t.Fatalf("LaunchAgent() error = %v", err)
	}
	service.watchTimeout(context.Background(), out.RunID, time.Now().Add(10*time.Millisecond))
	status, err := service.GetAgentStatus(context.Background(), RunInput{RunID: out.RunID})
	if err != nil {
		t.Fatalf("GetAgentStatus() error = %v", err)
	}
	if status.Status != StatusStopped || status.ExitCode == nil || *status.ExitCode != 0 {
		t.Fatalf("status = %+v, want stopped exit 0", status)
	}
	if strings.Contains(status.Error, "run exceeded deadline") {
		t.Fatalf("stop 304 race was misreported as timeout: %+v", status)
	}
	var statusFile completionStatusFile
	if err := json.Unmarshal(runtime.writtenFile("/data/intake/curator-status.json"), &statusFile); err != nil {
		t.Fatalf("decode completion status: %v", err)
	}
	if statusFile.Status != "success" || statusFile.ExitCode != 0 {
		t.Fatalf("completion status = %+v", statusFile)
	}
}

func requireCollectedFile(t *testing.T, collection CollectionOutput, path string) FileManifest {
	t.Helper()
	for _, file := range collection.Files {
		if file.Path == path {
			return file
		}
	}
	t.Fatalf("file %q missing from %+v", path, collection.Files)
	return FileManifest{}
}

func waitForMetadataStatus(t *testing.T, cfg Config, runID, want string) RunMetadata {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	var last RunMetadata
	for time.Now().Before(deadline) {
		meta, err := readMetadata(filepath.Join(cfg.RunsDir, runID, "metadata.json"))
		if err != nil {
			t.Fatalf("read metadata: %v", err)
		}
		last = meta
		if meta.Status == want {
			return meta
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("metadata status = %+v, want %s", last, want)
	return RunMetadata{}
}

func readSandboxAuditEvents(t *testing.T, path string) []AuditEvent {
	t.Helper()
	// #nosec G304 -- test helper reads the audit path created by the test.
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	events := make([]AuditEvent, 0, len(lines))
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var ev AuditEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("decode audit line %q: %v", line, err)
		}
		events = append(events, ev)
	}
	return events
}

func hasTerminalAudit(events []AuditEvent, runID, reason, source, status string) bool {
	for _, ev := range events {
		if ev.Operation == "run_finalized" && ev.RunID == runID && ev.Terminal && ev.FinalizeReason == reason && ev.TerminalSource == source && ev.Status == status {
			return true
		}
	}
	return false
}

func waitForTerminalAudit(t *testing.T, path, runID, reason, source, status string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	var events []AuditEvent
	for time.Now().Before(deadline) {
		events = readSandboxAuditEvents(t, path)
		if hasTerminalAudit(events, runID, reason, source, status) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("terminal audit missing from %+v", events)
}

func baseTestConfig(t *testing.T) Config {
	t.Helper()
	root := t.TempDir()
	bundleDir := filepath.Join(root, "bundle")
	if err := os.MkdirAll(bundleDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundleDir, "token.txt"), []byte("bundle-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	knowledge := filepath.Join(root, "knowledge.md")
	if err := os.WriteFile(knowledge, []byte("knowledge"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		AuthToken:    "mcp-secret",
		RunsDir:      filepath.Join(root, "runs"),
		BrokerURL:    "http://gh-agent-broker:8080",
		Repositories: []string{"owner/repo"},
		Networks: map[string]NetworkPolicy{
			"sandbox": {Network: "sandbox-net"},
			"none":    {None: true},
		},
		Bundles: map[string]CredentialBundle{
			"codex": {
				SourcePath:       bundleDir,
				MountPath:        "/credentials/codex",
				ReadOnly:         true,
				AllowedTemplates: []string{"worker"},
				SecretFiles:      []string{"token.txt"},
			},
		},
		Templates: map[string]Template{
			"worker": testTemplate("example.com/worker@sha256:1111111111111111111111111111111111111111111111111111111111111111"),
		},
		MaxTaskBytes:      1024,
		MaxParameterBytes: 1024,
		LogByteLimit:      1024,
		StopGrace:         Duration{Duration: time.Second},
		Audit:             SandboxAuditConfig{Path: filepath.Join(root, "audit", "sandbox.jsonl")},
	}
	tmpl := cfg.Templates["worker"]
	tmpl.KnowledgeSnapshots = []string{knowledge}
	evidenceDir := filepath.Join(root, "evidence")
	if err := os.MkdirAll(evidenceDir, 0o700); err != nil {
		t.Fatal(err)
	}
	tmpl.ExtraMounts = []ExtraMount{{SourcePath: evidenceDir, MountPath: "/data/intake", ReadOnly: true}}
	cfg.Templates["worker"] = tmpl
	return cfg
}

func testTemplate(image string) Template {
	return Template{
		Image:             image,
		Command:           []string{"/usr/local/bin/worker", "--run"},
		User:              "10000:10000",
		NetworkPolicy:     "sandbox",
		MaxRuntimeMinutes: 10,
		BrokerAgentID:     "hermes-coder-01",
		BrokerAgentSecret: "broker-secret",
		BranchPolicy: BranchPolicy{
			AllowedPatterns: []string{`^agent/hermes-coder-01/[A-Za-z0-9_.:-]+$`},
			BaseBranches:    []string{"main"},
			GeneratePrefix:  "agent",
		},
		CredentialBundle: "codex",
		Resources: Resources{
			CPUShares: 128,
			MemoryMB:  512,
			PidsLimit: 128,
		},
		Deliverables: []string{"/output/final-summary.md", "/lessons/run-summary.md"},
	}
}

func testLaunchProfile() LaunchProfile {
	return LaunchProfile{
		LaunchAgentInput: LaunchAgentInput{
			Template:          "worker",
			Task:              "nightly task",
			Repo:              "owner/repo",
			BaseBranch:        "main",
			MaxRuntimeMinutes: 5,
			Deliverables:      []string{"/output/final-summary.md"},
			Focus:             "nightly",
		},
		AllowOverrides: []string{"task", "focus", "max_runtime_minutes"},
	}
}

func testAudit(t *testing.T) *AuditLogger {
	t.Helper()
	auditLog, err := NewAuditLogger(filepath.Join(t.TempDir(), "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	return auditLog
}

func closeTestAudit(t *testing.T, auditLog *AuditLogger) {
	t.Helper()
	if err := auditLog.Close(); err != nil {
		t.Fatal(err)
	}
}

func assertMount(t *testing.T, mounts []Mount, source, target string, readonly bool) {
	t.Helper()
	for _, mount := range mounts {
		if mount.Source == source && mount.Target == target && mount.ReadOnly == readonly {
			return
		}
	}
	t.Fatalf("mount %s:%s readonly=%v missing from %+v", source, target, readonly, mounts)
}

type fakeRuntime struct {
	mu           sync.Mutex
	specs        []RuntimeSpec
	logs         string
	started      map[string]bool
	exits        map[string]ContainerStatus
	writes       map[string][]byte
	waiters      map[string]chan struct{}
	waitClosed   map[string]bool
	stopErr      error
	stopExitCode *int
}

func newFakeRuntime() *fakeRuntime {
	return &fakeRuntime{started: map[string]bool{}, exits: map[string]ContainerStatus{}, writes: map[string][]byte{}, waiters: map[string]chan struct{}{}, waitClosed: map[string]bool{}}
}

func (f *fakeRuntime) Create(ctx context.Context, spec RuntimeSpec) (ContainerInfo, error) {
	_ = ctx
	f.mu.Lock()
	defer f.mu.Unlock()
	f.specs = append(f.specs, spec)
	containerID := "container-" + spec.RunID
	f.waiters[containerID] = make(chan struct{})
	return ContainerInfo{ID: containerID, ImageDigest: spec.Image}, nil
}

func (f *fakeRuntime) Start(ctx context.Context, containerID string) error {
	_ = ctx
	f.mu.Lock()
	defer f.mu.Unlock()
	f.started[containerID] = true
	return nil
}

func (f *fakeRuntime) Wait(ctx context.Context, containerID string) (ContainerStatus, error) {
	for {
		f.mu.Lock()
		if status, ok := f.exits[containerID]; ok {
			f.mu.Unlock()
			return status, nil
		}
		if !f.started[containerID] {
			f.mu.Unlock()
			return ContainerStatus{ID: containerID, Running: false}, nil
		}
		ch := f.waiters[containerID]
		f.mu.Unlock()
		select {
		case <-ctx.Done():
			return ContainerStatus{}, ctx.Err()
		case <-ch:
		}
	}
}

func (f *fakeRuntime) Inspect(ctx context.Context, containerID string) (ContainerStatus, error) {
	_ = ctx
	f.mu.Lock()
	defer f.mu.Unlock()
	if status, ok := f.exits[containerID]; ok {
		return status, nil
	}
	return ContainerStatus{ID: containerID, Running: f.started[containerID]}, nil
}

func (f *fakeRuntime) Logs(ctx context.Context, containerID string, limitBytes int) (string, error) {
	_, _ = ctx, containerID
	if len(f.logs) > limitBytes {
		return f.logs[len(f.logs)-limitBytes:], nil
	}
	return f.logs, nil
}

func (f *fakeRuntime) Stop(ctx context.Context, containerID string, grace time.Duration) error {
	_, _ = ctx, grace
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.stopErr != nil {
		if f.stopExitCode != nil {
			code := *f.stopExitCode
			f.exits[containerID] = ContainerStatus{ID: containerID, Running: false, ExitCode: &code, EndedAt: time.Now().UTC()}
		}
		f.started[containerID] = false
		f.closeWaiterLocked(containerID)
		return f.stopErr
	}
	f.started[containerID] = false
	f.closeWaiterLocked(containerID)
	return nil
}

func (f *fakeRuntime) Remove(ctx context.Context, containerID string) error {
	_ = ctx
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.started, containerID)
	return nil
}

func (f *fakeRuntime) WriteFile(ctx context.Context, image string, mounts []Mount, path string, contents []byte) error {
	_, _, _ = ctx, image, mounts
	f.mu.Lock()
	defer f.mu.Unlock()
	f.writes[path] = append([]byte(nil), contents...)
	return nil
}

func (f *fakeRuntime) lastSpec() RuntimeSpec {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.specs) == 0 {
		return RuntimeSpec{}
	}
	return f.specs[len(f.specs)-1]
}

func (f *fakeRuntime) finish(runID string, exitCode int, message string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	containerID := "container-" + runID
	f.started[containerID] = false
	code := exitCode
	f.exits[containerID] = ContainerStatus{
		ID:       containerID,
		Running:  false,
		ExitCode: &code,
		EndedAt:  time.Now().UTC(),
		Error:    message,
	}
	f.closeWaiterLocked(containerID)
}

func (f *fakeRuntime) writtenFile(path string) []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]byte(nil), f.writes[path]...)
}

func (f *fakeRuntime) closeWaiterLocked(containerID string) {
	if f.waitClosed[containerID] {
		return
	}
	ch, ok := f.waiters[containerID]
	if !ok {
		return
	}
	close(ch)
	f.waitClosed[containerID] = true
}
