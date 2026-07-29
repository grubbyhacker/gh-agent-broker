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
		"readonly credential_bundle_path='/credentials/codex/auth.json'",
		"credential bundle is writable",
		"alternate credential environment variable is visible",
		"credential bundle is visible at unexpected path",
		"readonly codex_home_base='/dev/shm/codex-home'",
		"/dev/shm must be tmpfs",
		"chmod 0600 \"$CODEX_HOME/auth.json\"",
		"credential bundle must be access-token-only with an empty refresh token",
		"access token is expired or expires too soon to start work",
		"set exactly one of AGENT_CODEX_PROMPT or AGENT_CODEX_PROMPT_FILE",
		"mise exec -- codex exec",
		"--ephemeral",
		"--skip-git-repo-check",
		"-C /work/repo",
		"-o /output/codex-final.txt",
		"Do not push, create a pull request, or contact GitHub directly",
		"Codex completed without a repository change",
		"mise run \"$AGENT_VERIFY_TASK\"",
		"gh-agent-broker-cli pr -broker \"$BROKER_URL\"",
		"-metadata \"Agent-Id=${BROKER_AGENT_ID:?BROKER_AGENT_ID is required for pull request metadata}\"",
	} {
		if !strings.Contains(text, required) {
			t.Errorf("Codex repository task worker must contain %q", required)
		}
	}

	if strings.Contains(text, "https://github.com") || strings.Contains(text, "git@github.com") {
		t.Error("Codex repository task worker must not use a direct GitHub remote")
	}
	for _, forbidden := range []string{"gh ", "ssh ", "tofu ", "ansible ", "doppler ", "scp ", "sftp "} {
		if strings.Contains(text, forbidden) {
			t.Errorf("Codex repository task worker must not depend on %q", strings.TrimSpace(forbidden))
		}
	}

	violations := codexExecContractViolations(strings.Replace(text, "mise exec -- codex exec", "codex exec", 1))
	if len(violations) > 0 {
		t.Errorf("Codex repository task worker authority contract violations:\n%s", strings.Join(violations, "\n"))
	}
}

func TestCodexRepoTaskWorkerJWTValidation(t *testing.T) {
	t.Parallel()

	cmd := exec.Command("bash", "workers/codex-repo-task/worker_test.sh")
	cmd.Dir = "../.."
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("run Codex repository task worker JWT regression test: %v\n%s", err, output)
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
}
