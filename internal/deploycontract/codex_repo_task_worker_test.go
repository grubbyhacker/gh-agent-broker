package deploycontract

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestCodexRepoTaskWorkerContract(t *testing.T) {
	t.Parallel()

	worker, err := os.ReadFile("../../workers/codex-repo-task/worker.sh")
	if err != nil {
		t.Fatalf("read Codex repository task worker: %v", err)
	}
	text := string(worker)

	for _, required := range []string{
		"readonly injection_dir='/dev/shm/codex-credential-injection'",
		"readonly injection_ready_marker='/dev/shm/codex-credential-injection-ready'",
		"readonly acceptance_marker='/dev/shm/codex-credential-accepted'",
		"readonly codex_home_base='/dev/shm/codex-home'",
		"/dev/shm must be tmpfs",
		": > \"$injection_ready_marker\"",
		"timed out waiting for in-memory Codex credential injection",
		"mv -f -- \"$temp_auth\" \"$CODEX_HOME/auth.json\"",
		"rm -f -- \"$capability_path\"",
		": > \"$acceptance_marker\"",
		"ID token is missing",
		"refresh_token must be explicitly empty",
		"validate_preparation",
		"codex exec",
		"--ephemeral",
		"--json",
		"--model \"$AGENT_MODEL\"",
		"model_reasoning_effort",
		"--skip-git-repo-check",
		"-C \"$repo_path\"",
		"-o \"$output_path/codex-final.txt\"",
		"Do not push, create a pull request, or contact GitHub;",
		"reject_broker_authority",
		"codex-execution-result/v1",
		"diff_sha256",
		"mise run \"$AGENT_VERIFY_TASK\"",
		"CODEX_DISABLE_ANALYTICS=1",
		"model_provider = \"codex-subscription-relay\"",
		"wire_api = \"responses\"",
		"requires_openai_auth = true",
		"unset HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY",
		"web_search = \"disabled\"",
		"enable_mcp_apps = false",
		"final output exceeds",
		"snapshot_git_identity",
		"verify_git_identity",
		"no-broker-access://codex-execution",
		"GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null",
		"scan_for_token_contamination",
		"purge_contaminated_artifacts",
		"codex-execution-failure/v1",
		"write_codex_failure_diagnostic",
	} {
		if !strings.Contains(text, required) {
			t.Errorf("Codex repository task worker must contain %q", required)
		}
	}

	if strings.Contains(text, "https://github.com") || strings.Contains(text, "git@github.com") {
		t.Error("Codex repository task worker must not use a direct GitHub remote")
	}
	mainStart := strings.Index(text, "if [[ \"${BASH_SOURCE[0]}\" == \"$0\" ]]; then")
	if mainStart == -1 {
		t.Fatal("Codex repository task worker must have a main block")
	}
	main := text[mainStart:]
	for _, forbidden := range []string{"git fetch", "dependency manifest", "issue-comments", "install_repository_dependencies"} {
		if strings.Contains(main, forbidden) {
			t.Errorf("execution worker must not perform preparation action %q", forbidden)
		}
	}
	for _, forbidden := range []string{"gh ", "ssh ", "tofu ", "ansible ", "doppler ", "scp ", "sftp "} {
		if strings.Contains(text, forbidden) {
			t.Errorf("Codex repository task worker must not depend on %q", strings.TrimSpace(forbidden))
		}
	}

	violations := codexExecContractViolations(text)
	if len(violations) > 0 {
		t.Errorf("Codex repository task worker authority contract violations:\n%s", strings.Join(violations, "\n"))
	}
}

func TestCodexRepoTaskWorkerSubmoduleHandling(t *testing.T) {
	cmd := exec.Command("bash", "workers/submodule_worker_test.sh", "workers/codex-repo-prep/worker.sh")
	cmd.Dir = "../.."
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("run preparation submodule regression test: %v\n%s", err, output)
	}
}

func TestCodexRepoTaskWorkerTerminalResult(t *testing.T) {
	cmd := exec.Command("bash", "workers/result_test.sh", "workers/codex-delivery/worker.sh")
	cmd.Dir = "../.."
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("run Codex result regression test: %v\n%s", err, output)
	}
}

func TestCodexRepoTaskWorkerSecurityBoundaries(t *testing.T) {
	cmd := exec.Command("bash", "-n", "workers/codex-repo-task/worker.sh", "workers/codex-delivery/worker.sh")
	cmd.Dir = "../.."
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("run Codex security boundary regression test: %v\n%s", err, output)
	}
}

func TestCodexRepoTaskWorkerScansFailedSubprocessesBeforeTerminalizing(t *testing.T) {
	cmd := exec.Command("bash", "workers/codex_failure_scan_test.sh")
	cmd.Dir = "../.."
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("run Codex failed-subprocess scan regression: %v\n%s", err, output)
	}
}

func TestCodexContaminationPurgeRestoresUnreadableDirectoriesAndFailsClosed(t *testing.T) {
	cmd := exec.Command("bash", "workers/codex_contamination_purge_test.sh")
	cmd.Dir = "../.."
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("run Codex contamination purge regression: %v\n%s", err, output)
	}
}

func TestCodexDeliveryRemovesExecutableRepositoryConfiguration(t *testing.T) {
	cmd := exec.Command("bash", "workers/codex_delivery_git_config_test.sh")
	cmd.Dir = "../.."
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("run Codex delivery Git-config regression: %v\n%s", err, output)
	}
}

func TestCodexDeliveryReconcilesOneExactPullRequest(t *testing.T) {
	cmd := exec.Command("bash", "workers/codex_delivery_reconcile_test.sh")
	cmd.Dir = "../.."
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("run Codex delivery reconciliation regression: %v\n%s", err, output)
	}
}

func TestPublishedBrokerImageCarriesCodexRepoTaskWorker(t *testing.T) {
	t.Parallel()

	dockerfile, err := os.ReadFile("../../Dockerfile")
	if err != nil {
		t.Fatalf("read Dockerfile: %v", err)
	}
	if !strings.Contains(string(dockerfile), "COPY --chmod=0755 workers/codex-repo-task/worker.sh /usr/local/bin/agent-codex-repo-task-worker") {
		t.Error("published broker image must install agent-codex-repo-task-worker as executable")
	}
	if !strings.Contains(string(dockerfile), "COPY --chmod=0755 workers/codex-repo-prep/worker.sh /usr/local/bin/agent-codex-repo-prep-worker") {
		t.Error("published broker image must install agent-codex-repo-prep-worker as executable")
	}
	if !strings.Contains(string(dockerfile), "COPY --chmod=0755 workers/codex-delivery/worker.sh /usr/local/bin/agent-codex-delivery-worker") {
		t.Error("published broker image must install agent-codex-delivery-worker as executable")
	}
}

func TestCodexDeliveryWorkerOwnsOnlyDeterministicDelivery(t *testing.T) {
	t.Parallel()
	worker, err := os.ReadFile("../../workers/codex-delivery/worker.sh")
	if err != nil {
		t.Fatal(err)
	}
	text := string(worker)
	for _, required := range []string{
		"reject_codex_authority", "validate_results", "restore_repository_authority",
		"gh-agent-broker-cli pr -broker \"$BROKER_URL\"",
		"gh-agent-broker-cli pulls", "gh-agent-broker-codex-run:", "ready_for_review",
	} {
		if !strings.Contains(text, required) {
			t.Errorf("delivery worker must contain %q", required)
		}
	}
	for _, forbidden := range []string{"codex exec", "CODEX_SUBSCRIPTION_RELAY_BASE_URL", "refresh_token"} {
		if strings.Contains(text, forbidden) {
			t.Errorf("delivery worker contains Codex execution authority %q", forbidden)
		}
	}
	if strings.Contains(text, "mise run \"$AGENT_VERIFY_TASK\"") {
		t.Error("delivery worker must never execute repository validation after receiving broker authority")
	}
	if !strings.Contains(text, "codex-stale-lease/v3") || !strings.Contains(text, "merge-tree --write-tree") {
		t.Error("delivery worker must return a structured stale-lease handoff")
	}
}

func TestCodexPreparationWorkerContract(t *testing.T) {
	t.Parallel()
	worker, err := os.ReadFile("../../workers/codex-repo-prep/worker.sh")
	if err != nil {
		t.Fatal(err)
	}
	text := string(worker)
	for _, required := range []string{
		"reject_credentials", "typed issue ingestion", "is_pull_request != true",
		"issue_comment_limit=30", "issue_context_byte_limit=24576",
		"stale image: dependency/submodule manifest mismatch", "hydrate_baked_submodules",
		"codex-preparation-result/v1", "source_delivery_id", "--slurpfile issue",
	} {
		if !strings.Contains(text, required) {
			t.Errorf("preparation worker must contain %q", required)
		}
	}
	for _, forbidden := range []string{"codex exec", "oauth/token", "refresh_token", "npm ci", "go mod download", "https://github.com", "--argfile"} {
		if strings.Contains(text, forbidden) {
			t.Errorf("preparation worker contains forbidden path %q", forbidden)
		}
	}
}
