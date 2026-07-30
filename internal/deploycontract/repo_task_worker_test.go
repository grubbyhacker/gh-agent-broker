package deploycontract

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestRepoTaskWorkerContract(t *testing.T) {
	t.Parallel()

	worker, err := os.ReadFile("../../workers/repo-task/worker.sh")
	if err != nil {
		t.Fatalf("read repository task worker: %v", err)
	}
	text := string(worker)

	for _, required := range []string{
		"set -euo pipefail",
		"require_env BROKER_URL",
		"require_env AGENT_REPO",
		"require_env AGENT_BASE_BRANCH",
		"require_env AGENT_RUN_ID",
		"require_env AGENT_TASK",
		"require_env AGENT_BRANCH",
		"gh-agent-broker-cli health -broker \"$BROKER_URL\"",
		"gh-agent-broker-cli probe -broker \"$BROKER_URL\" -repo \"$AGENT_REPO\"",
		"git remote add origin placeholder",
		"gh-agent-broker-cli configure -broker \"$BROKER_URL\" -repo \"$AGENT_REPO\" -remote origin",
		"mise run \"$AGENT_TASK\"",
		"mise run \"$AGENT_VERIFY_TASK\"",
		"manifest match, using baked dependencies",
		"mise install --yes",
		"gh-agent-broker-cli pr -broker \"$BROKER_URL\"",
		"-metadata \"Agent-Id=${BROKER_AGENT_ID:?BROKER_AGENT_ID is required for pull request metadata}\"",
		"/output/result.json",
		"/output/final-summary.md",
	} {
		if !strings.Contains(text, required) {
			t.Errorf("repository task worker must contain %q", required)
		}
	}

	if strings.Contains(text, "https://github.com") || strings.Contains(text, "git@github.com") {
		t.Error("repository task worker must not use a direct GitHub remote")
	}
	if strings.Contains(text, "codex ") || strings.Contains(text, "OPENAI_API_KEY") {
		t.Error("repository task worker must remain model-free")
	}
}

func TestRepoTaskWorkerSubmoduleHandling(t *testing.T) {
	cmd := exec.Command("bash", "workers/submodule_worker_test.sh", "workers/repo-task/worker.sh")
	cmd.Dir = "../.."
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("run repository task worker submodule regression test: %v\n%s", err, output)
	}
}

func TestRepoTaskWorkerTerminalResult(t *testing.T) {
	cmd := exec.Command("bash", "workers/result_test.sh", "workers/repo-task/worker.sh")
	cmd.Dir = "../.."
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("run repository task worker terminal result regression test: %v\n%s", err, output)
	}
}

func TestPublishedBrokerImageCarriesRepoTaskWorker(t *testing.T) {
	t.Parallel()

	dockerfile, err := os.ReadFile("../../Dockerfile")
	if err != nil {
		t.Fatalf("read Dockerfile: %v", err)
	}
	if !strings.Contains(string(dockerfile), "COPY --chmod=0755 workers/repo-task/worker.sh /usr/local/bin/agent-repo-task-worker") {
		t.Error("published broker image must install agent-repo-task-worker as executable")
	}
}

func TestPublishedBrokerImageCarriesWorkerResultLibrary(t *testing.T) {
	t.Parallel()

	dockerfile, err := os.ReadFile("../../Dockerfile")
	if err != nil {
		t.Fatalf("read Dockerfile: %v", err)
	}
	if !strings.Contains(string(dockerfile), "COPY --chmod=0755 workers/result.sh /usr/local/lib/agent-worker-result.sh") {
		t.Error("published broker image must install the shared agent worker result library")
	}
}
