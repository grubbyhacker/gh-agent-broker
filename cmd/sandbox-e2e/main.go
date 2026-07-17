package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type headerTransport struct {
	base  http.RoundTripper
	token string
}

func (t headerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.Header.Set("Authorization", "Bearer "+t.token)
	return t.base.RoundTrip(clone)
}

type launchOutput struct {
	RunID         string    `json:"run_id"`
	WorkerAgentID string    `json:"worker_agent_id"`
	Branch        string    `json:"branch"`
	Status        string    `json:"status"`
	Deadline      time.Time `json:"deadline"`
}

type statusOutput struct {
	RunID       string              `json:"run_id"`
	Status      string              `json:"status"`
	Branch      string              `json:"branch"`
	Repo        string              `json:"repo"`
	ExitCode    *int                `json:"exit_code"`
	Error       string              `json:"error"`
	Diagnostics *failureDiagnostics `json:"diagnostics"`
}

type failureDiagnostics struct {
	Source              string   `json:"source"`
	Status              string   `json:"status"`
	ExitCode            *int     `json:"exit_code"`
	Message             string   `json:"message"`
	MissingDeliverables []string `json:"missing_deliverables"`
}

type listAgentsOutput struct {
	Runs []statusOutput `json:"runs"`
}

type collectionOutput struct {
	RunID string         `json:"run_id"`
	Files []fileManifest `json:"files"`
}

type fileManifest struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
	Inline string `json:"inline"`
}

type markerResult struct {
	RunID string
	Final fileManifest
}

func main() {
	codexAuthOnly := flag.Bool("codex-auth-only", false, "run only the Codex credential bundle auth probe")
	hermesAuthOnly := flag.Bool("hermes-auth-only", false, "run only the Hermes credential bundle auth probe")
	taskMarkerOnly := flag.Bool("task-marker-only", false, "run only the task marker delivery regression")
	finalizationLive := flag.Bool("finalization-live", false, "run live finalization checks against a persistent sandbox broker")
	fast := flag.Bool("fast", false, "run the representative PR-gating sandbox lifecycle path")
	flag.Parse()
	selectedModes := 0
	for _, selected := range []bool{*codexAuthOnly, *hermesAuthOnly, *taskMarkerOnly, *finalizationLive, *fast} {
		if selected {
			selectedModes++
		}
	}
	if selectedModes > 1 {
		fatalf("only one focused E2E mode may be set")
	}
	authOnly := *codexAuthOnly || *hermesAuthOnly

	timeout, err := time.ParseDuration(envDefault("SANDBOX_E2E_TIMEOUT", "180s"))
	if err != nil {
		fatalf("invalid SANDBOX_E2E_TIMEOUT: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	endpoint := os.Getenv("SANDBOX_E2E_ENDPOINT")
	token := os.Getenv("SANDBOX_MCP_TOKEN")
	runsDir := os.Getenv("SANDBOX_E2E_RUNS_DIR")
	repo := envDefault("SANDBOX_E2E_REPO", "owner/repo")
	baseBranch := envDefault("SANDBOX_E2E_BASE_BRANCH", "main")
	workerTemplate := envDefault("SANDBOX_E2E_WORKER_TEMPLATE", "worker")
	sleeperTemplate := envDefault("SANDBOX_E2E_SLEEPER_TEMPLATE", "sleeper")
	missingDeliverableTemplate := envDefault("SANDBOX_E2E_MISSING_DELIVERABLE_TEMPLATE", "missing-deliverable")
	hermesTaskTemplate := envDefault("SANDBOX_E2E_HERMES_TASK_TEMPLATE", "hermes-task-worker")
	expectedSecrets := expectedRedactedSecrets()
	if endpoint == "" || token == "" || runsDir == "" {
		fatalf("SANDBOX_E2E_ENDPOINT, SANDBOX_MCP_TOKEN, and SANDBOX_E2E_RUNS_DIR are required")
	}

	httpClient := &http.Client{Transport: headerTransport{base: http.DefaultTransport, token: token}, Timeout: 30 * time.Second}
	client := mcp.NewClient(&mcp.Implementation{Name: "sandbox-e2e", Version: "v1"}, nil)
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint:             endpoint,
		HTTPClient:           httpClient,
		DisableStandaloneSSE: true,
	}, nil)
	if err != nil {
		fatalf("connect MCP: %v", err)
	}
	defer func() {
		if err := session.Close(); err != nil {
			fatalf("close MCP session: %v", err)
		}
	}()

	assertTools(ctx, session)

	if *finalizationLive {
		runFinalizationLive(ctx, session, runsDir, repo, baseBranch, hermesTaskTemplate, sleeperTemplate, expectedSecrets)
		return
	}

	callOK(ctx, session, "validate_template", map[string]any{"template": workerTemplate})
	expectToolErrorContains(ctx, session, "validate_template", map[string]any{"template": "missing"}, "unknown template")
	expectToolErrorContains(ctx, session, "dry_run_launch", map[string]any{"template": workerTemplate, "task": "x", "repo": repo, "base_branch": baseBranch, "image": "busybox"}, "unexpected additional properties")
	expectToolErrorContains(ctx, session, "dry_run_launch", map[string]any{"template": workerTemplate, "task": "x", "repo": "owner/other", "base_branch": baseBranch}, "policy denial")
	expectToolErrorContains(ctx, session, "dry_run_launch", map[string]any{"template": workerTemplate, "task": "x", "repo": repo, "base_branch": baseBranch, "branch": "../bad"}, "policy denial")
	expectToolErrorContains(ctx, session, "dry_run_launch", map[string]any{"template": workerTemplate, "task": strings.Repeat("x", 5000), "repo": repo, "base_branch": baseBranch}, "policy denial")

	dryRun := structured[launchOutput](callOK(ctx, session, "dry_run_launch", launchArgs(workerTemplate, "dry run", repo, baseBranch)))
	if dryRun.Status != "pending" || !strings.HasPrefix(dryRun.Branch, "agent/hermes-coder-01/") {
		fatalf("unexpected dry-run output: %+v", dryRun)
	}

	if *taskMarkerOnly {
		first := launchAndAssertMarker(ctx, session, workerTemplate, repo, baseBranch, "SMOKE-E2E-ONE", expectedSecrets)
		second := launchAndAssertMarker(ctx, session, workerTemplate, repo, baseBranch, "SMOKE-E2E-TWO", expectedSecrets)
		if strings.Contains(second.Final.Inline, "SMOKE-E2E-ONE") || strings.Contains(first.Final.Inline, "SMOKE-E2E-TWO") {
			fatalf("marker artifacts were not task-specific: first=%q second=%q", first.Final.Inline, second.Final.Inline)
		}
		assertCleanup(ctx, session, runsDir, first.RunID)
		assertCleanup(ctx, session, runsDir, second.RunID)
		fmt.Println("sandbox task marker E2E ok")
		return
	}

	workerTask := "real launch marker SMOKE-E2E-ONE"
	worker := structured[launchOutput](callOK(ctx, session, "launch_agent", launchArgsWithDeliverables(workerTemplate, workerTask, repo, baseBranch, []string{"repo/relative.md"})))
	if worker.Status != "running" {
		fatalf("worker launch status = %q", worker.Status)
	}
	workerStatus := waitStatus(ctx, session, worker.RunID, "stopped", "failed", "timed_out")
	if workerStatus.Status != "stopped" || workerStatus.ExitCode == nil || *workerStatus.ExitCode != 0 {
		fatalf("worker did not stop cleanly: %+v", workerStatus)
	}
	if !authOnly {
		inspectContainer(containerIDForRun(worker.RunID))
	}

	logs := callOK(ctx, session, "get_agent_logs", map[string]any{"run_id": worker.RunID, "max_bytes": 4096})
	assertRedacted("logs", text(logs), expectedSecrets)

	artifacts := structured[collectionOutput](callOK(ctx, session, "collect_artifacts", map[string]any{"run_id": worker.RunID}))
	for _, file := range artifacts.Files {
		assertRedacted("artifact "+file.Path, file.Inline, expectedSecrets)
	}
	if *codexAuthOnly {
		codexFinal := requireFile(artifacts, "codex-final.txt")
		if strings.TrimSpace(codexFinal.Inline) != "SANDBOX_CODEX_AUTH_OK" {
			fatalf("codex final output = %q", codexFinal.Inline)
		}
		requireFile(artifacts, "codex-events.jsonl")
	} else if *hermesAuthOnly {
		hermesFinal := requireFile(artifacts, "hermes-final.txt")
		if strings.TrimSpace(hermesFinal.Inline) != "HERMES_AUTH_OK" {
			fatalf("hermes final output = %q", hermesFinal.Inline)
		}
		status := requireFile(artifacts, "hermes-auth-status.txt")
		if !strings.Contains(status.Inline, "logged in") {
			fatalf("unexpected hermes auth status = %q", status.Inline)
		}
	} else {
		requireFile(artifacts, "broker-health.json")
	}
	final := requireFile(artifacts, "final-summary.md")
	assertRedacted("artifact inline", final.Inline, expectedSecrets)
	if !strings.Contains(final.Inline, "[REDACTED]") {
		if !authOnly {
			fatalf("artifact inline did not contain redaction marker: %q", final.Inline)
		}
	}
	lessons := structured[collectionOutput](callOK(ctx, session, "collect_lessons", map[string]any{"run_id": worker.RunID}))
	lesson := requireFile(lessons, "run-summary.md")
	assertRedacted("lesson inline", lesson.Inline, expectedSecrets)
	if !authOnly {
		assertContains("final summary marker", final.Inline, "SMOKE-E2E-ONE")
		assertContains("lesson summary marker", lesson.Inline, "SMOKE-E2E-ONE")
	}
	if *fast {
		assertCleanup(ctx, session, runsDir, worker.RunID)
		fmt.Println("sandbox MCP fast E2E ok")
		return
	}

	if authOnly {
		if os.Getenv("SANDBOX_E2E_SKIP_CLEANUP") == "" {
			assertCleanup(ctx, session, runsDir, worker.RunID)
		}
		if *hermesAuthOnly {
			fmt.Println("sandbox Hermes auth E2E ok")
		} else {
			fmt.Println("sandbox Codex auth E2E ok")
		}
		return
	}

	secondTask := "real launch marker SMOKE-E2E-TWO"
	second := structured[launchOutput](callOK(ctx, session, "launch_agent", launchArgsWithDeliverables(workerTemplate, secondTask, repo, baseBranch, []string{"repo/relative.md"})))
	secondStatus := waitStatus(ctx, session, second.RunID, "stopped", "failed", "timed_out")
	if secondStatus.Status != "stopped" || secondStatus.ExitCode == nil || *secondStatus.ExitCode != 0 {
		fatalf("second marker worker did not stop cleanly: %+v", secondStatus)
	}
	secondArtifacts := structured[collectionOutput](callOK(ctx, session, "collect_artifacts", map[string]any{"run_id": second.RunID}))
	secondFinal := requireFile(secondArtifacts, "final-summary.md")
	secondLessons := structured[collectionOutput](callOK(ctx, session, "collect_lessons", map[string]any{"run_id": second.RunID}))
	secondLesson := requireFile(secondLessons, "run-summary.md")
	assertContains("second final summary marker", secondFinal.Inline, "SMOKE-E2E-TWO")
	assertContains("second lesson summary marker", secondLesson.Inline, "SMOKE-E2E-TWO")
	if strings.Contains(secondFinal.Inline, "SMOKE-E2E-ONE") || strings.Contains(final.Inline, "SMOKE-E2E-TWO") {
		fatalf("marker artifacts were not task-specific: first=%q second=%q", final.Inline, secondFinal.Inline)
	}

	missing := structured[launchOutput](callOK(ctx, session, "launch_agent", launchArgs(missingDeliverableTemplate, "missing deliverable test", repo, baseBranch)))
	missingStatus := waitStatus(ctx, session, missing.RunID, "stopped", "failed", "timed_out")
	if missingStatus.Status != "failed" || missingStatus.ExitCode == nil || *missingStatus.ExitCode == 0 {
		fatalf("missing deliverable template did not fail: %+v", missingStatus)
	}
	if missingStatus.Diagnostics == nil || !strings.Contains(missingStatus.Diagnostics.Message, "required deliverables missing") {
		fatalf("missing deliverable diagnostics not returned in status: %+v", missingStatus)
	}
	missingArtifacts := structured[collectionOutput](callOK(ctx, session, "collect_artifacts", map[string]any{"run_id": missing.RunID}))
	requireFile(missingArtifacts, "wrapper-diagnostics.json")

	timeoutArgs := launchArgs(sleeperTemplate, "timeout test", repo, baseBranch)
	timeoutArgs["max_runtime_seconds"] = 5
	timeoutRun := structured[launchOutput](callOK(ctx, session, "launch_agent", timeoutArgs))
	timeoutStatus := waitStatus(ctx, session, timeoutRun.RunID, "stopped", "failed", "timed_out")
	if timeoutStatus.Status != "timed_out" || !strings.Contains(timeoutStatus.Error, "run exceeded deadline") {
		fatalf("timeout run did not time out with diagnostics: %+v", timeoutStatus)
	}
	if timeoutStatus.Diagnostics == nil || !strings.Contains(timeoutStatus.Diagnostics.Message, "run exceeded deadline") {
		fatalf("timeout diagnostics missing: %+v", timeoutStatus)
	}
	timeoutArtifacts := structured[collectionOutput](callOK(ctx, session, "collect_artifacts", map[string]any{"run_id": timeoutRun.RunID}))
	timeoutDiagnostics := requireFile(timeoutArtifacts, "wrapper-diagnostics.json")
	assertContains("timeout diagnostics artifact", timeoutDiagnostics.Inline, "run exceeded deadline")

	sleeper := structured[launchOutput](callOK(ctx, session, "launch_agent", launchArgs(sleeperTemplate, "stop test", repo, baseBranch)))
	running := waitStatus(ctx, session, sleeper.RunID, "running")
	if running.Status != "running" {
		fatalf("sleeper not running: %+v", running)
	}
	inspectContainer(containerIDForRun(sleeper.RunID))
	stopped := structured[statusOutput](callOK(ctx, session, "stop_agent", map[string]any{"run_id": sleeper.RunID}))
	if stopped.Status != "stopped" {
		fatalf("stop status = %+v", stopped)
	}

	assertCleanup(ctx, session, runsDir, worker.RunID)
	assertCleanup(ctx, session, runsDir, second.RunID)
	assertCleanup(ctx, session, runsDir, missing.RunID)
	assertCleanup(ctx, session, runsDir, timeoutRun.RunID)
	assertCleanup(ctx, session, runsDir, sleeper.RunID)
	fmt.Println("sandbox MCP E2E ok")
}

func assertTools(ctx context.Context, session *mcp.ClientSession) {
	tools, err := session.ListTools(ctx, nil)
	if err != nil {
		fatalf("list tools: %v", err)
	}
	wantTools := []string{"launch_agent", "dry_run_launch", "validate_template", "list_agents", "get_agent_status", "get_agent_logs", "stop_agent", "collect_artifacts", "collect_lessons", "cleanup_run"}
	for _, want := range wantTools {
		found := false
		for _, tool := range tools.Tools {
			if tool.Name == want {
				found = true
				break
			}
		}
		if !found {
			fatalf("tool %q missing from %v", want, tools.Tools)
		}
	}
}

func runFinalizationLive(ctx context.Context, session *mcp.ClientSession, runsDir, repo, baseBranch, hermesTaskTemplate, sleeperTemplate string, expectedSecrets []string) {
	callOK(ctx, session, "validate_template", map[string]any{"template": hermesTaskTemplate})
	callOK(ctx, session, "validate_template", map[string]any{"template": sleeperTemplate})
	expectToolErrorContains(ctx, session, "dry_run_launch", map[string]any{
		"template":    hermesTaskTemplate,
		"task":        "policy denial probe",
		"repo":        "grubbyhacker/not-allowed",
		"base_branch": baseBranch,
	}, "policy denial")

	failureMarker := "FAILURE_DIAGNOSTICS_20260513"
	failureTask := "Failure diagnostics probe. Write /output/final-summary.md and /lessons/run-summary.md with marker " + failureMarker + ", but intentionally do not create /output/required-never-created.txt. Do not push, create a PR, issue, or comment."
	failure := structured[launchOutput](callOK(ctx, session, "launch_agent", launchArgsWithDeliverables(hermesTaskTemplate, failureTask, repo, baseBranch, []string{
		"/output/final-summary.md",
		"/lessons/run-summary.md",
		"/output/required-never-created.txt",
	})))
	failureStatus := waitStatus(ctx, session, failure.RunID, "stopped", "failed", "timed_out")
	if failureStatus.Status != "failed" || failureStatus.ExitCode == nil || *failureStatus.ExitCode != 30 {
		includeLogsAndFail(ctx, session, failure.RunID, "failure diagnostics run status = %+v, want failed exit 30", failureStatus)
	}
	if failureStatus.Diagnostics == nil || !strings.Contains(failureStatus.Diagnostics.Message, "required deliverables missing") || !contains(failureStatus.Diagnostics.MissingDeliverables, "/output/required-never-created.txt") {
		fatalf("failure diagnostics missing required details: %+v", failureStatus)
	}
	failureArtifacts := structured[collectionOutput](callOK(ctx, session, "collect_artifacts", map[string]any{"run_id": failure.RunID}))
	assertRedacted("failure artifacts", text(callOK(ctx, session, "get_agent_logs", map[string]any{"run_id": failure.RunID, "max_bytes": 8192})), expectedSecrets)
	requireFile(failureArtifacts, "wrapper-diagnostics.json")
	assertCleanup(ctx, session, runsDir, failure.RunID)

	timeoutArgs := launchArgs(sleeperTemplate, "timeout probe", repo, baseBranch)
	timeoutArgs["max_runtime_seconds"] = 5
	timeoutRun := structured[launchOutput](callOK(ctx, session, "launch_agent", timeoutArgs))
	timeoutStatus := waitStatus(ctx, session, timeoutRun.RunID, "stopped", "failed", "timed_out")
	if timeoutStatus.Status != "timed_out" || !strings.Contains(timeoutStatus.Error, "run exceeded deadline") {
		fatalf("timeout run status = %+v, want timed_out", timeoutStatus)
	}
	if timeoutStatus.Diagnostics == nil || !strings.Contains(timeoutStatus.Diagnostics.Message, "run exceeded deadline") {
		fatalf("timeout diagnostics missing: %+v", timeoutStatus)
	}
	timeoutArtifacts := structured[collectionOutput](callOK(ctx, session, "collect_artifacts", map[string]any{"run_id": timeoutRun.RunID}))
	assertContains("timeout diagnostics artifact", requireFile(timeoutArtifacts, "wrapper-diagnostics.json").Inline, "run exceeded deadline")
	assertCleanup(ctx, session, runsDir, timeoutRun.RunID)

	ts := time.Now().UTC().Format("20060102-150405")
	marker := "DISPOSABLE_PR_20260513_FINAL_SANDBOX_" + ts
	branch := "agent/hermes-coder-01/disposable-pr-20260513-final-sandbox-" + ts
	prTask := "Disposable PR creation E2E. Use the gh-agent-broker skill/CLI and broker remote only. Clone or initialize " + repo + " through the broker. Use branch " + branch + ". Add a small file under sandbox-e2e/ containing marker " + marker + ". Commit it, push through the broker, and create a PR to " + baseBranch + " titled 'Sandbox disposable PR E2E 2026-05-13'. When creating the PR, include metadata Agent-Id=hermes-coder-01 and Hermes-Run-Id=" + marker + ". Write the PR URL and marker to /output/final-summary.md and /lessons/run-summary.md. Do not use direct GitHub tokens."
	prArgs := launchArgsWithDeliverables(hermesTaskTemplate, prTask, repo, baseBranch, []string{"/output/final-summary.md", "/lessons/run-summary.md"})
	prArgs["branch"] = branch
	prRun := structured[launchOutput](callOK(ctx, session, "launch_agent", prArgs))
	prStatus := waitStatus(ctx, session, prRun.RunID, "stopped", "failed", "timed_out")
	if prStatus.Status != "stopped" || prStatus.ExitCode == nil || *prStatus.ExitCode != 0 {
		includeLogsAndFail(ctx, session, prRun.RunID, "disposable PR run status = %+v, want stopped exit 0", prStatus)
	}
	prArtifacts := structured[collectionOutput](callOK(ctx, session, "collect_artifacts", map[string]any{"run_id": prRun.RunID}))
	for _, file := range prArtifacts.Files {
		assertRedacted("pr artifact "+file.Path, file.Inline, expectedSecrets)
	}
	prFinal := requireFile(prArtifacts, "final-summary.md")
	assertContains("disposable PR marker", prFinal.Inline, marker)
	assertContains("disposable PR URL", prFinal.Inline, "https://github.com/grubbyhacker/research/pull/")
	prLessons := structured[collectionOutput](callOK(ctx, session, "collect_lessons", map[string]any{"run_id": prRun.RunID}))
	assertContains("disposable PR lesson marker", requireFile(prLessons, "run-summary.md").Inline, marker)
	assertCleanup(ctx, session, runsDir, prRun.RunID)

	fmt.Printf("sandbox finalization live E2E ok: failure_run=%s timeout_run=%s pr_run=%s marker=%s\n", failure.RunID, timeoutRun.RunID, prRun.RunID, marker)
}

func includeLogsAndFail(ctx context.Context, session *mcp.ClientSession, runID, format string, args ...any) {
	logs := ""
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "get_agent_logs", Arguments: map[string]any{"run_id": runID, "max_bytes": 16384}})
	if err != nil {
		logs = err.Error()
	} else if result != nil {
		logs = text(result)
	}
	args = append(args, logs)
	fatalf(format+"\nlogs:\n%s", args...)
}

func envDefault(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func expectedRedactedSecrets() []string {
	values := []string{"broker-secret-e2e", "bundle-secret-e2e"}
	if path := os.Getenv("SANDBOX_E2E_EXPECT_REDACTED_FILE"); path != "" {
		//nolint:gosec // G304: E2E-only input points at the test credential bundle being verified.
		b, err := os.ReadFile(path)
		if err != nil {
			fatalf("read expected redaction file: %v", err)
		}
		values = append(values, jsonStringValues(b)...)
	}
	for _, item := range strings.Split(os.Getenv("SANDBOX_E2E_EXPECT_REDACTED"), ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			values = append(values, item)
		}
	}
	return values
}

func jsonStringValues(b []byte) []string {
	var decoded interface{}
	if err := json.Unmarshal(b, &decoded); err != nil {
		return nil
	}
	var values []string
	var walk func(interface{})
	walk = func(v interface{}) {
		switch x := v.(type) {
		case string:
			values = append(values, x)
		case []interface{}:
			for _, item := range x {
				walk(item)
			}
		case map[string]interface{}:
			for _, item := range x {
				walk(item)
			}
		}
	}
	walk(decoded)
	return values
}

func launchArgs(template, task, repo, baseBranch string) map[string]any {
	return map[string]any{"template": template, "task": task, "repo": repo, "base_branch": baseBranch}
}

func launchArgsWithDeliverables(template, task, repo, baseBranch string, deliverables []string) map[string]any {
	args := launchArgs(template, task, repo, baseBranch)
	args["deliverables"] = deliverables
	return args
}

func callOK(ctx context.Context, session *mcp.ClientSession, name string, args map[string]any) *mcp.CallToolResult {
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		fatalf("%s failed: %v", name, err)
	}
	if result.IsError {
		fatalf("%s returned tool error: %s", name, text(result))
	}
	return result
}

func expectToolErrorContains(ctx context.Context, session *mcp.ClientSession, name string, args map[string]any, want string) {
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		if !strings.Contains(err.Error(), want) {
			fatalf("%s returned error %q, want containing %q", name, err.Error(), want)
		}
		return
	}
	if result == nil || !result.IsError {
		fatalf("%s unexpectedly succeeded with args %+v: %+v", name, args, result)
	}
	if !strings.Contains(text(result), want) {
		fatalf("%s tool error text = %q, want containing %q", name, text(result), want)
	}
}

func structured[T any](result *mcp.CallToolResult) T {
	var out T
	b, err := json.Marshal(result.StructuredContent)
	if err != nil {
		fatalf("marshal structured content: %v", err)
	}
	if err := json.Unmarshal(b, &out); err != nil {
		fatalf("decode structured content: %v content=%s", err, string(b))
	}
	return out
}

func text(result *mcp.CallToolResult) string {
	var parts []string
	for _, content := range result.Content {
		if t, ok := content.(*mcp.TextContent); ok {
			parts = append(parts, t.Text)
		}
	}
	return strings.Join(parts, "\n")
}

func waitStatus(ctx context.Context, session *mcp.ClientSession, runID string, statuses ...string) statusOutput {
	want := map[string]bool{}
	for _, status := range statuses {
		want[status] = true
	}
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			fatalf("waiting for %s status %v: %v", runID, statuses, ctx.Err())
		case <-ticker.C:
			status := structured[statusOutput](callOK(ctx, session, "get_agent_status", map[string]any{"run_id": runID}))
			if want[status.Status] {
				return status
			}
		}
	}
}

func launchAndAssertMarker(ctx context.Context, session *mcp.ClientSession, template, repo, baseBranch, marker string, expectedSecrets []string) markerResult {
	task := fmt.Sprintf("Smoke test the sandbox task contract. Do not create a PR, issue, comment, or push. Write /output/final-summary.md and /lessons/run-summary.md, and include the exact marker %s in both files. Then exit successfully.", marker)
	worker := structured[launchOutput](callOK(ctx, session, "launch_agent", launchArgsWithDeliverables(template, task, repo, baseBranch, []string{"repo/relative.md"})))
	status := waitStatus(ctx, session, worker.RunID, "stopped", "failed", "timed_out")
	if status.Status != "stopped" || status.ExitCode == nil || *status.ExitCode != 0 {
		logText := ""
		logs, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "get_agent_logs", Arguments: map[string]any{"run_id": worker.RunID, "max_bytes": 8192}})
		if err != nil {
			logText = err.Error()
		} else if logs != nil {
			logText = text(logs)
		}
		fatalf("marker worker did not stop cleanly: status=%+v logs=%s", status, logText)
	}
	artifacts := structured[collectionOutput](callOK(ctx, session, "collect_artifacts", map[string]any{"run_id": worker.RunID}))
	for _, file := range artifacts.Files {
		assertRedacted("artifact "+file.Path, file.Inline, expectedSecrets)
	}
	final := requireFile(artifacts, "final-summary.md")
	assertContains("final summary marker", final.Inline, marker)
	lessons := structured[collectionOutput](callOK(ctx, session, "collect_lessons", map[string]any{"run_id": worker.RunID}))
	lesson := requireFile(lessons, "run-summary.md")
	assertRedacted("lesson inline", lesson.Inline, expectedSecrets)
	assertContains("lesson summary marker", lesson.Inline, marker)
	return markerResult{RunID: worker.RunID, Final: final}
}

func assertCleanup(ctx context.Context, session *mcp.ClientSession, runsDir, runID string) {
	cleaned := structured[statusOutput](callOK(ctx, session, "cleanup_run", map[string]any{"run_id": runID}))
	if cleaned.Status != "cleaned" {
		fatalf("cleanup status for %s = %+v", runID, cleaned)
	}
	if _, err := os.Stat(runDir(runsDir, runID)); !errors.Is(err, os.ErrNotExist) {
		fatalf("run dir %s still exists or stat failed unexpectedly: %v", runID, err)
	}
	list := structured[listAgentsOutput](callOK(ctx, session, "list_agents", map[string]any{}))
	for _, run := range list.Runs {
		if run.RunID == runID {
			fatalf("cleaned run %s is still listed: %+v", runID, list.Runs)
		}
	}
	assertNoContainerForRun(runID)
}

func runDir(runsDir, runID string) string {
	if strings.Contains(runID, "/") || strings.Contains(runID, "..") {
		fatalf("unsafe run id %q", runID)
	}
	//nolint:gosec // G703: runsDir is an E2E-controlled temp directory and runID is checked above.
	return filepath.Join(runsDir, runID)
}

func assertNoContainerForRun(runID string) {
	if os.Getenv("SANDBOX_E2E_SKIP_DOCKER_ASSERT") != "" {
		return
	}
	if strings.ContainsAny(runID, " \t\r\n") || strings.Contains(runID, "/") {
		fatalf("unsafe run id %q", runID)
	}
	//nolint:gosec // G204: E2E intentionally shells out to Docker; runID is validated before becoming a filter argument.
	out, err := exec.Command("docker", "ps", "-aq", "--filter", "label=gh-agent-broker.run_id="+runID).Output()
	if err != nil {
		fatalf("docker ps for run %s: %v", runID, err)
	}
	if strings.TrimSpace(string(out)) != "" {
		fatalf("run %s still has container(s): %q", runID, string(out))
	}
}

func containerIDForRun(runID string) string {
	if strings.ContainsAny(runID, " \t\r\n") || strings.Contains(runID, "/") {
		fatalf("unsafe run id %q", runID)
	}
	//nolint:gosec // G204: E2E intentionally shells out to Docker; runID is validated before becoming a filter argument.
	out, err := exec.Command("docker", "ps", "-aq", "--filter", "label=gh-agent-broker.run_id="+runID).Output()
	if err != nil {
		fatalf("docker ps for run %s: %v", runID, err)
	}
	ids := strings.Fields(string(out))
	if len(ids) != 1 {
		fatalf("run %s matched %d containers: %q", runID, len(ids), string(out))
	}
	return ids[0]
}

func inspectContainer(containerID string) {
	if strings.ContainsAny(containerID, " \t\r\n/") {
		fatalf("unsafe container id %q", containerID)
	}
	//nolint:gosec // G204: E2E intentionally shells out to Docker; containerID comes from `docker ps -aq` and is validated.
	out, err := exec.Command("docker", "inspect", containerID).Output()
	if err != nil {
		fatalf("docker inspect %s: %v", containerID, err)
	}
	var docs []struct {
		Config struct {
			User   string            `json:"User"`
			Labels map[string]string `json:"Labels"`
		} `json:"Config"`
		HostConfig struct {
			Privileged  bool     `json:"Privileged"`
			NetworkMode string   `json:"NetworkMode"`
			CapDrop     []string `json:"CapDrop"`
			SecurityOpt []string `json:"SecurityOpt"`
			PidsLimit   int64    `json:"PidsLimit"`
			Memory      int64    `json:"Memory"`
		} `json:"HostConfig"`
		Mounts []struct {
			Source      string `json:"Source"`
			Destination string `json:"Destination"`
			RW          bool   `json:"RW"`
		} `json:"Mounts"`
	}
	if err := json.Unmarshal(out, &docs); err != nil {
		fatalf("decode docker inspect: %v", err)
	}
	if len(docs) != 1 {
		fatalf("docker inspect returned %d docs", len(docs))
	}
	doc := docs[0]
	if doc.Config.User == "" || doc.Config.User == "0" || doc.Config.User == "root" {
		fatalf("container user is not non-root: %q", doc.Config.User)
	}
	if doc.HostConfig.Privileged {
		fatalf("container is privileged")
	}
	if doc.HostConfig.NetworkMode == "host" || doc.HostConfig.NetworkMode == "" {
		fatalf("unexpected network mode: %q", doc.HostConfig.NetworkMode)
	}
	if !contains(doc.HostConfig.CapDrop, "ALL") {
		fatalf("CapDrop does not include ALL: %+v", doc.HostConfig.CapDrop)
	}
	if !contains(doc.HostConfig.SecurityOpt, "no-new-privileges") {
		fatalf("SecurityOpt missing no-new-privileges: %+v", doc.HostConfig.SecurityOpt)
	}
	if doc.HostConfig.PidsLimit <= 0 || doc.HostConfig.Memory <= 0 {
		fatalf("resource limits missing: pids=%d memory=%d", doc.HostConfig.PidsLimit, doc.HostConfig.Memory)
	}
	for _, mount := range doc.Mounts {
		if mount.Destination == "/credentials/codex" && mount.RW {
			fatalf("credential mount is writable: %+v", mount)
		}
		if mount.Destination == "/input" && mount.RW {
			fatalf("input mount is writable: %+v", mount)
		}
	}
	for key, value := range doc.Config.Labels {
		if strings.Contains(strings.ToLower(key), "secret") || strings.Contains(value, "broker-secret-e2e") {
			fatalf("secret leaked into label %s=%s", key, value)
		}
	}
}

func requireFile(collection collectionOutput, path string) fileManifest {
	for _, file := range collection.Files {
		if file.Path == path {
			if file.Size <= 0 || file.SHA256 == "" {
				fatalf("file manifest missing size/hash: %+v", file)
			}
			return file
		}
	}
	fatalf("file %q missing from %+v", path, collection.Files)
	panic("unreachable")
}

func assertRedacted(label, value string, secrets []string) {
	for _, secret := range secrets {
		if strings.Contains(value, secret) {
			fatalf("%s leaked %s in %q", label, secret, value)
		}
	}
}

func assertContains(label, value, want string) {
	if !strings.Contains(value, want) {
		fatalf("%s missing %q in %q", label, want, value)
	}
}

func contains(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
