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
	cfg.TerminalResultByteLimit = 32
	service := NewService(cfg, newFakeRuntime(), testAudit(t))
	meta := terminalTestMetadata("terminal-oversize", StatusCompleted)
	if err := os.MkdirAll(filepath.Join(cfg.RunsDir, meta.RunID, "output"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfg.RunsDir, meta.RunID, "output", "result.json"), []byte(`{"outcome":"ready_for_review"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfg.RunsDir, meta.RunID, "output", "final-summary.md"), []byte(strings.Repeat("x", 33)), 0o600); err != nil {
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

func TestRESTTerminalResultIsProfileScopedAndDoesNotBroadenExistingPrincipals(t *testing.T) {
	cfg := restTestConfig(t)
	cfg.OperatorPrincipals["reporter"] = OperatorPrincipal{Token: "reporter-secret", AllowedProfiles: []string{"nightly"}, AllowedActions: []string{"terminal_result"}, RunScope: "profile"}
	runtime := newFakeRuntime()
	service := newRESTTestService(t, cfg, runtime, testAudit(t))
	handler := NewRESTHandler(service)
	launched := performLaunch(t, handler, "terminal-read", nil)
	output := filepath.Join(cfg.RunsDir, launched.RunID, "output")
	if err := os.WriteFile(filepath.Join(output, "result.json"), []byte(`{"outcome":"ready_for_review"}`), 0o600); err != nil {
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
	return RunMetadata{RunID: runID, Profile: "nightly", Template: "worker", Repo: "owner/repo", Branch: "agent/test/terminal", CredentialBundle: "codex", Status: status, StartedAt: time.Now().UTC(), EndedAt: time.Now().UTC(), IdempotencyKeyDigest: "idem-digest", RequestFingerprint: "request-fingerprint", LaunchConfigVersion: "config-version"}
}
