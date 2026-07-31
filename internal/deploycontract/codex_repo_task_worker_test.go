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
		"readonly acceptance_marker='/dev/shm/codex-credential-accepted'",
		"readonly codex_home_base='/dev/shm/codex-home'",
		"/dev/shm must be tmpfs",
		"timed out waiting for in-memory Codex credential injection",
		"mv -f -- \"$temp_auth\" \"$CODEX_HOME/auth.json\"",
		"rm -f -- \"$capability_path\"",
		": > \"$acceptance_marker\"",
		"refresh_token must be explicitly empty",
		"validate_preparation",
		"codex exec",
		"--ephemeral",
		"--json",
		"--model \"$AGENT_MODEL\"",
		"model_reasoning_effort",
		"--skip-git-repo-check",
		"-C /work/repo",
		"-o /output/codex-final.txt",
		"Do not push, create a pull request, or contact GitHub directly",
		"no_change_required",
		"mise run \"$AGENT_VERIFY_TASK\"",
		"gh-agent-broker-cli pr -broker \"$BROKER_URL\"",
		"-metadata \"Agent-Id=${BROKER_AGENT_ID:?BROKER_AGENT_ID is required}\"",
		"CODEX_DISABLE_ANALYTICS=1",
		"model_provider = \"codex-subscription-relay\"",
		"wire_api = \"responses\"",
		"requires_openai_auth = true",
		"unset HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY",
		"web_search = \"disabled\"",
		"enable_mcp_apps = false",
		"final output exceeds",
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
	cmd := exec.Command("bash", "workers/result_test.sh", "workers/codex-repo-task/worker.sh")
	cmd.Dir = "../.."
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("run Codex result regression test: %v\n%s", err, output)
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
		"codex-preparation-result/v1", "source_delivery_id",
	} {
		if !strings.Contains(text, required) {
			t.Errorf("preparation worker must contain %q", required)
		}
	}
	for _, forbidden := range []string{"codex exec", "oauth/token", "refresh_token", "npm ci", "go mod download", "https://github.com"} {
		if strings.Contains(text, forbidden) {
			t.Errorf("preparation worker contains forbidden path %q", forbidden)
		}
	}
}
