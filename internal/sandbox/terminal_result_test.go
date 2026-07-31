package sandbox

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestTerminalResultPreservesBoundedRedactedWorkerOutputAcrossRestart(t *testing.T) {
	cfg := baseTestConfig(t)
	cfg.TerminalResultByteLimit = 512
	service := NewService(cfg, newFakeRuntime(), testAudit(t))
	meta := terminalTestMetadata("terminal-completed", StatusCompleted)
	if err := os.MkdirAll(filepath.Join(cfg.RunsDir, meta.RunID, "output"), 0o700); err != nil {
		t.Fatal(err)
	}
	result := `{"version":"repository-task-worker-result/v1","outcome":"ready_for_review","detail":"pull request created","stage":"completed","run_id":"terminal-completed","repository":"owner/repo","base_branch":"main","branch":"agent/test/terminal","verification":{"status":"passed"},"verify_task":"verify","dependency_manifest":"match","pull_request":{"number":42,"html_url":"https://github.example/owner/repo/pull/42","url":"https://api.github.example/repos/owner/repo/pulls/42"},"nested":{"note":"bundle-secret"}}`
	if err := os.WriteFile(filepath.Join(cfg.RunsDir, meta.RunID, "output", "result.json"), []byte(result), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfg.RunsDir, meta.RunID, "output", "final-summary.md"), []byte("Complete work product with bundle-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := service.persistTerminalResult(meta); err != nil {
		t.Fatal(err)
	}
	if err := service.writeMetadata(meta); err != nil {
		t.Fatal(err)
	}

	restarted := NewService(cfg, newFakeRuntime(), testAudit(t))
	if err := restarted.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, err := restarted.GetTerminalResult(context.Background(), RunInput{RunID: meta.RunID})
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != terminalResultVersion || got.Outcome != "ready_for_review" || got.IdempotencyKeyDigest != "idem-digest" || got.LaunchConfigVersion != "config-version" {
		t.Fatalf("correlation projection = %+v", got)
	}
	var expected map[string]any
	if err := json.Unmarshal([]byte(`{"version":"repository-task-worker-result/v1","outcome":"ready_for_review","detail":"pull request created","stage":"completed","run_id":"terminal-completed","repository":"owner/repo","base_branch":"main","branch":"agent/test/terminal","verification":{"status":"passed"},"verify_task":"verify","dependency_manifest":"match","pull_request":{"number":42,"html_url":"https://github.example/owner/repo/pull/42","url":"https://api.github.example/repos/owner/repo/pulls/42"},"nested":{"note":"[REDACTED]"}}`), &expected); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Result, expected) {
		t.Fatalf("worker result shape changed: got %#v, want %#v", got.Result, expected)
	}
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "bundle-secret") || !strings.Contains(got.FinalSummary, "[REDACTED]") {
		t.Fatalf("terminal result leaked canary: %s", encoded)
	}
	nested, ok := got.Result["nested"].(map[string]any)
	if !ok || nested["note"] != "[REDACTED]" {
		t.Fatalf("nested result was not redacted: %#v", got.Result)
	}
}

func TestReconcileBackfillsAndNormalizesLegacyTerminalResult(t *testing.T) {
	cfg := baseTestConfig(t)
	cfg.TerminalResultByteLimit = 1024
	meta := terminalTestMetadata("legacy-terminal", StatusCompleted)
	runDir := filepath.Join(cfg.RunsDir, meta.RunID)
	if err := os.MkdirAll(filepath.Join(runDir, "output"), 0o700); err != nil {
		t.Fatal(err)
	}
	result := `{"outcome":"no_change_required","detail":"task completed successfully; repository is unchanged","stage":"change detection","run_id":"legacy-terminal","repository":"owner/repo","base_branch":"main","branch":"agent/test/terminal","task":"optimize-images","verify_task":"validate","dependency_manifest":"match","nested":{"note":"bundle-secret"}}`
	if err := os.WriteFile(filepath.Join(runDir, "output", "result.json"), []byte(result), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(runDir, "output", "final-summary.md"), []byte("No change required; bundle-secret was not published."), 0o600); err != nil {
		t.Fatal(err)
	}
	service := NewService(cfg, newFakeRuntime(), testAudit(t))
	if err := service.writeMetadataFile(meta); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(service.terminalResultPath(meta.RunID)); !os.IsNotExist(err) {
		t.Fatalf("terminal projection should begin absent: %v", err)
	}

	restarted := NewService(cfg, newFakeRuntime(), testAudit(t))
	if err := restarted.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, err := restarted.GetTerminalResult(context.Background(), RunInput{RunID: meta.RunID})
	if err != nil {
		t.Fatal(err)
	}
	if got.Outcome != "no_change_required" || got.RunID != meta.RunID || got.Repo != meta.Repo || got.Branch != meta.Branch {
		t.Fatalf("terminal correlation = %+v", got)
	}
	if got.Result["version"] != workerResultVersion || got.Result["detail"] != "task completed successfully; repository is unchanged" {
		t.Fatalf("legacy worker result was not preserved and versioned: %#v", got.Result)
	}
	verification, ok := got.Result["verification"].(map[string]any)
	if !ok || verification["status"] != "passed" {
		t.Fatalf("legacy verification = %#v", got.Result["verification"])
	}
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "bundle-secret") || !strings.Contains(got.FinalSummary, "[REDACTED]") {
		t.Fatalf("legacy terminal result leaked canary: %s", encoded)
	}

	before, err := os.ReadFile(restarted.terminalResultPath(meta.RunID))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(runDir, "output", "result.json"), []byte(`{"outcome":"failed"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	again := NewService(cfg, newFakeRuntime(), testAudit(t))
	if err := again.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(again.terminalResultPath(meta.RunID))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(after, before) {
		t.Fatal("reconciliation overwrote an existing terminal projection")
	}
}

func TestTerminalResultFallbacksAreDeterministicAndNeverUseLogs(t *testing.T) {
	for _, status := range []string{StatusCompleted, StatusFailed, StatusTimedOut, StatusStopped, StatusCancelled} {
		t.Run(status, func(t *testing.T) {
			cfg := baseTestConfig(t)
			service := NewService(cfg, newFakeRuntime(), testAudit(t))
			meta := terminalTestMetadata("terminal-"+status, status)
			if err := os.MkdirAll(filepath.Join(cfg.RunsDir, meta.RunID, "output"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := service.persistTerminalResult(meta); err != nil {
				t.Fatal(err)
			}
			if err := service.writeMetadata(meta); err != nil {
				t.Fatal(err)
			}
			got, err := service.GetTerminalResult(context.Background(), RunInput{RunID: meta.RunID})
			if err != nil {
				t.Fatal(err)
			}
			if got.Status != status || got.Outcome != fallbackOutcome(status) || got.FailureStage != "terminal_result" || got.FailureReason != "result.json is absent" || got.FinalSummary != "" {
				t.Fatalf("fallback = %+v", got)
			}
		})
	}
}

func TestTerminalResultRejectsOversizeFinalSummary(t *testing.T) {
	cfg := baseTestConfig(t)
	cfg.TerminalResultByteLimit = 256
	service := NewService(cfg, newFakeRuntime(), testAudit(t))
	meta := terminalTestMetadata("terminal-oversize", StatusCompleted)
	if err := os.MkdirAll(filepath.Join(cfg.RunsDir, meta.RunID, "output"), 0o700); err != nil {
		t.Fatal(err)
	}
	result := `{"version":"repository-task-worker-result/v1","outcome":"no_change_required","run_id":"terminal-oversize","repository":"owner/repo","branch":"agent/test/terminal","verification":{"status":"passed"}}`
	if err := os.WriteFile(filepath.Join(cfg.RunsDir, meta.RunID, "output", "result.json"), []byte(result), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfg.RunsDir, meta.RunID, "output", "final-summary.md"), []byte(strings.Repeat("x", 257)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := service.persistTerminalResult(meta); err != nil {
		t.Fatal(err)
	}
	if err := service.writeMetadata(meta); err != nil {
		t.Fatal(err)
	}
	got, err := service.GetTerminalResult(context.Background(), RunInput{RunID: meta.RunID})
	if err != nil {
		t.Fatal(err)
	}
	if got.Outcome != StatusFailed || got.FailureReason != "final-summary.md exceeds terminal_result_byte_limit" || got.FinalSummary != "" {
		t.Fatalf("oversize result = %+v", got)
	}
}

func TestCodexFailurePreservesExactCompleteFinalOutput(t *testing.T) {
	for _, terminalSource := range []string{"codex_execution", "codex_execution_verification", "codex_delivery"} {
		t.Run(terminalSource, func(t *testing.T) {
			cfg := baseTestConfig(t)
			cfg.TerminalResultByteLimit = 256
			service := NewService(cfg, newFakeRuntime(), testAudit(t))
			meta := codexFailureTerminalMetadata("codex-final-"+terminalSource, terminalSource)
			output := filepath.Join(cfg.RunsDir, meta.RunID, "output")
			if err := os.MkdirAll(output, 0o700); err != nil {
				t.Fatal(err)
			}
			final := "Exact complete Codex final output.\nSecond line.\n"
			if err := os.WriteFile(filepath.Join(output, "codex-final.txt"), []byte(final), 0o600); err != nil {
				t.Fatal(err)
			}

			got := service.projectTerminalResult(meta)
			if got.Outcome != StatusFailed || got.FinalSummary != final ||
				got.FailureReason != "phase failed" {
				t.Fatalf("Codex failure projection = %+v", got)
			}
		})
	}
}

func TestCodexFailureCallsOutUnusableFinalOutputWithoutTruncation(t *testing.T) {
	tests := []struct {
		name    string
		content []byte
		write   bool
		reason  string
	}{
		{name: "missing", reason: "phase failed; codex-final.txt is absent after Codex execution began"},
		{name: "empty", write: true, reason: "phase failed; codex-final.txt is empty after Codex execution began"},
		{
			name: "oversized", write: true, content: []byte(strings.Repeat("x", 65)),
			reason: "phase failed; codex-final.txt exceeds terminal_result_byte_limit after Codex execution began",
		},
		{
			name: "invalid UTF-8", write: true, content: []byte{0xff, 0xfe},
			reason: "phase failed; codex-final.txt is not valid UTF-8 after Codex execution began",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := baseTestConfig(t)
			cfg.TerminalResultByteLimit = 64
			service := NewService(cfg, newFakeRuntime(), testAudit(t))
			meta := codexFailureTerminalMetadata("codex-unusable-"+strings.ReplaceAll(test.name, " ", "-"), "codex_execution")
			output := filepath.Join(cfg.RunsDir, meta.RunID, "output")
			if err := os.MkdirAll(output, 0o700); err != nil {
				t.Fatal(err)
			}
			if test.write {
				if err := os.WriteFile(filepath.Join(output, "codex-final.txt"), test.content, 0o600); err != nil {
					t.Fatal(err)
				}
			}

			got := service.projectTerminalResult(meta)
			if got.FailureReason != test.reason || got.FinalSummary != "" {
				t.Fatalf("Codex unusable-output projection = %+v", got)
			}
		})
	}
}

func TestCodexContaminationFailureReportsPurgeInsteadOfMissingOutput(t *testing.T) {
	cfg := baseTestConfig(t)
	service := NewService(cfg, newFakeRuntime(), testAudit(t))
	meta := codexFailureTerminalMetadata("codex-contamination", "codex_execution")
	runDir := filepath.Join(cfg.RunsDir, meta.RunID)
	for _, relative := range []string{"work", "lessons", "output"} {
		if err := os.MkdirAll(filepath.Join(runDir, relative), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(
		filepath.Join(runDir, "output", "codex-token-scan-failure"),
		[]byte("contamination\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	got := service.projectTerminalResult(meta)
	if got.FailureReason != "exact access-token contamination detected; disposable execution artifacts were purged" ||
		got.FinalSummary != "" {
		t.Fatalf("Codex contamination projection = %+v", got)
	}
}

func TestCodexContaminationPurgeFailureKeepsRunBlockedWithoutRemovalClaim(t *testing.T) {
	cfg := baseTestConfig(t)
	service := NewService(cfg, newFakeRuntime(), testAudit(t))
	meta := codexFailureTerminalMetadata("codex-purge-failed", "codex_execution")
	runDir := filepath.Join(cfg.RunsDir, meta.RunID)
	for _, relative := range []string{"work", "lessons", "output"} {
		if err := os.MkdirAll(filepath.Join(runDir, relative), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(
		filepath.Join(runDir, "work", "quarantined"),
		[]byte("unreadable credential-bearing artifact"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(runDir, "output", "codex-token-scan-failure"),
		[]byte("purge_failed\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	got := service.projectTerminalResult(meta)
	if got.FailureReason != "credential contamination cleanup could not be verified; host-backed artifacts remain quarantined and delivery is blocked" ||
		got.FinalSummary != "" {
		t.Fatalf("Codex purge failure projection = %+v", got)
	}
}

func TestRESTTerminalResultIsProfileScopedAndDoesNotBroadenExistingPrincipals(t *testing.T) {
	cfg := restTestConfig(t)
	cfg.OperatorPrincipals["reporter"] = OperatorPrincipal{Token: "reporter-secret", AllowedProfiles: []string{"nightly"}, AllowedActions: []string{"terminal_result"}, RunScope: "profile"}
	runtime := newFakeRuntime()
	service := newRESTTestService(t, cfg, runtime, testAudit(t))
	handler := NewRESTHandler(service)
	launched := performLaunch(t, handler, "terminal-read", nil)
	output := filepath.Join(cfg.RunsDir, launched.RunID, "output")
	if err := os.WriteFile(filepath.Join(output, "result.json"), []byte(`{"version":"repository-task-worker-result/v1","outcome":"ready_for_review"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(output, "final-summary.md"), []byte("The complete final work product."), 0o600); err != nil {
		t.Fatal(err)
	}
	runtime.finish(launched.RunID, 0, "")
	waitForMetadataStatus(t, cfg, launched.RunID, StatusCompleted)

	allowed := restRequest("GET", "/v1/runs/"+launched.RunID+"/terminal-result", "reporter-secret", nil)
	allowedResponse := httptest.NewRecorder()
	handler.ServeHTTP(allowedResponse, allowed)
	if allowedResponse.Code != 200 || !strings.Contains(allowedResponse.Body.String(), "The complete final work product.") {
		t.Fatalf("reporter response=%d %s", allowedResponse.Code, allowedResponse.Body.String())
	}
	denied := httptest.NewRecorder()
	handler.ServeHTTP(denied, restRequest("GET", "/v1/runs/"+launched.RunID+"/terminal-result", "operator-secret", nil))
	if denied.Code != 403 {
		t.Fatalf("existing broad operator response=%d body=%s", denied.Code, denied.Body.String())
	}
}

func terminalTestMetadata(runID, status string) RunMetadata {
	return RunMetadata{RunID: runID, Profile: "nightly", Template: "worker", Repo: "owner/repo", BaseBranch: "main", Branch: "agent/test/terminal", CredentialBundle: "codex", Status: status, StartedAt: time.Now().UTC(), EndedAt: time.Now().UTC(), IdempotencyKeyDigest: "idem-digest", RequestFingerprint: "request-fingerprint", LaunchConfigVersion: "config-version"}
}

func codexFailureTerminalMetadata(runID, terminalSource string) RunMetadata {
	meta := terminalTestMetadata(runID, StatusFailed)
	meta.Error = "phase failed"
	meta.TerminalSource = terminalSource
	meta.ExecutionStartedAt = time.Now().UTC()
	meta.Provenance = &CodexProvenance{}
	return meta
}
