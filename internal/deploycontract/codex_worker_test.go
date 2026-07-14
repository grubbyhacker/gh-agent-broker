package deploycontract

import (
	"os"
	"strings"
	"testing"
)

func TestCodexImplementationWorkerUsesNonInteractiveAuthorityContract(t *testing.T) {
	t.Parallel()

	worker, err := os.ReadFile("../../workers/codex-implementation/worker.sh")
	if err != nil {
		t.Fatalf("read Codex implementation worker: %v", err)
	}

	args := codexExecArgs(t, string(worker))
	for _, flag := range []string{
		"--ephemeral",
		"--dangerously-bypass-approvals-and-sandbox",
	} {
		if count(args, flag) != 1 {
			t.Errorf("Codex implementation worker must invoke codex exec with exactly one %s; args: %q", flag, args)
		}
	}

	for _, arg := range args {
		if arg == "--full-auto" || arg == "--yolo" || strings.HasPrefix(arg, "--ask-for-approval") || strings.HasPrefix(arg, "--sandbox") {
			t.Errorf("Codex implementation worker must not use weaker or undocumented authority option %q; args: %q", arg, args)
		}
	}
}

func codexExecArgs(t *testing.T, worker string) []string {
	t.Helper()

	const invocation = "codex exec \\\n"
	start := strings.Index(worker, invocation)
	if start == -1 {
		t.Fatal("Codex implementation worker must invoke codex exec")
	}
	if strings.Contains(worker[start+len(invocation):], invocation) {
		t.Fatal("Codex implementation worker must have one codex exec invocation")
	}

	args := []string{"codex", "exec"}
	for _, line := range strings.Split(worker[start+len(invocation):], "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasSuffix(line, "\\") {
			break
		}
		args = append(args, strings.Fields(strings.TrimSpace(strings.TrimSuffix(line, "\\")))...)
	}
	if len(args) == 2 {
		t.Fatal("Codex implementation worker has no codex exec arguments")
	}
	return args
}

func count(args []string, want string) int {
	count := 0
	for _, arg := range args {
		if arg == want {
			count++
		}
	}
	return count
}
