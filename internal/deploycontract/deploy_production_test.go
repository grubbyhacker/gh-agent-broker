package deploycontract

import (
	"os"
	"regexp"
	"testing"
)

func TestProductionDeploySecretExports(t *testing.T) {
	t.Parallel()

	workflow, err := os.ReadFile("../../.github/workflows/deploy-production.yml")
	if err != nil {
		t.Fatalf("read production deploy workflow: %v", err)
	}
	const deployStep = "      - name: Deploy gh-agent-broker\n"
	start := regexp.MustCompile(regexp.QuoteMeta(deployStep)).FindIndex(workflow)
	if start == nil {
		t.Fatal("production deploy workflow must contain the gh-agent-broker deploy step")
	}
	workflow = workflow[start[0]:]
	if end := regexp.MustCompile(`(?m)^      - name:`).FindIndex(workflow[1:]); end != nil {
		workflow = workflow[:end[0]+1]
	}

	for _, secretName := range []string{
		"VPS_OPS_GH_BROKER_YKM_CURATOR_BROKER_SECRET",
		"VPS_OPS_GH_BROKER_YKM_CURATOR_APP_PEM",
		"VPS_OPS_GH_BROKER_YKM_CURATOR_SANDBOX_TIMER_TOKEN",
		"VPS_OPS_GH_BROKER_YKM_CURATOR_SANDBOX_ADMIN_TOKEN",
		"VPS_OPS_GH_BROKER_YKM_CURATOR_SANDBOX_STAGING_ADMIN_TOKEN",
		"VPS_OPS_GH_BROKER_OPENROUTER_CURATOR_API_KEY",
		"VPS_OPS_GH_BROKER_GH_AGENT_CODEX_PROXY_TOKEN",
		"VPS_OPS_GH_BROKER_CODEX_WORKER_AUTH_JSON",
		"VPS_OPS_GH_BROKER_CODEX_WORKER_OPERATOR_TOKEN",
		"VPS_OPS_SIGNAL_PLANE_DISPATCHER_BROKER_TOKEN",
	} {
		pattern := regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(secretName) + `:\s*\$\{\{\s*secrets\.` + regexp.QuoteMeta(secretName) + `\s*\}\}\s*$`)
		if !pattern.Match(workflow) {
			t.Errorf("production deploy workflow must export %s to vps-ops", secretName)
		}
	}
}
