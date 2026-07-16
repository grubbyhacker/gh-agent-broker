package deploycontract

import (
	"os"
	"regexp"
	"strings"
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
		"VPS_OPS_GH_BROKER_FLEIGLABS_REPO_AGENT_BROKER_SECRET",
		"VPS_OPS_GH_BROKER_FLEIGLABS_REPO_AGENT_APP_PEM",
		"VPS_OPS_GH_BROKER_YKM_CURATOR_APP_PEM",
		"VPS_OPS_GH_BROKER_YKM_CURATOR_SANDBOX_TIMER_TOKEN",
		"VPS_OPS_GH_BROKER_YKM_CURATOR_SANDBOX_ADMIN_TOKEN",
		"VPS_OPS_GH_BROKER_YKM_CURATOR_SANDBOX_STAGING_ADMIN_TOKEN",
		"VPS_OPS_GH_BROKER_OPENROUTER_CURATOR_API_KEY",
		"VPS_OPS_GH_BROKER_GH_AGENT_CODEX_PROXY_TOKEN",
	} {
		pattern := regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(secretName) + `:\s*\$\{\{\s*secrets\.` + regexp.QuoteMeta(secretName) + `\s*\}\}\s*$`)
		if !pattern.Match(workflow) {
			t.Errorf("production deploy workflow must export %s to vps-ops", secretName)
		}
	}
}

func TestProductionDeployUsesJobTokenForGHCROnlyInDeployStep(t *testing.T) {
	t.Parallel()

	workflow, err := os.ReadFile("../../.github/workflows/deploy-production.yml")
	if err != nil {
		t.Fatalf("read production deploy workflow: %v", err)
	}
	text := string(workflow)
	if !regexp.MustCompile(`(?m)^  packages: read$`).MatchString(text) {
		t.Fatal("production deploy workflow must grant packages: read")
	}

	//nolint:gosec // These are workflow variable names and GitHub context expressions, not credential values.
	for name, source := range map[string]string{
		"VPS_OPS_GH_BROKER_GHCR_PACKAGES_READ_TOKEN": `\$\{\{ github\.token \}\}`,
		"VPS_OPS_GH_BROKER_GHCR_PULL_USERNAME":       `\$\{\{ github\.actor \}\}`,
	} {
		pattern := regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(name) + `:\s*` + source + `\s*$`)
		matches := pattern.FindAllStringIndex(text, -1)
		if len(matches) != 1 {
			t.Errorf("%s must be exported exactly once from its GitHub context, got %d", name, len(matches))
		}
	}

	const deployStep = "      - name: Deploy gh-agent-broker\n"
	start := strings.Index(text, deployStep)
	if start < 0 {
		t.Fatal("production deploy workflow must contain the gh-agent-broker deploy step")
	}
	deploy := text[start:]
	if end := strings.Index(deploy[len(deployStep):], "\n      - name:"); end >= 0 {
		deploy = deploy[:len(deployStep)+end]
	}
	for _, name := range []string{"VPS_OPS_GH_BROKER_GHCR_PACKAGES_READ_TOKEN", "VPS_OPS_GH_BROKER_GHCR_PULL_USERNAME"} {
		if !strings.Contains(deploy, name) {
			t.Errorf("deploy step must export %s", name)
		}
	}
}

func TestProductionDeployOmitsRetiredProofSecrets(t *testing.T) {
	t.Parallel()

	workflow, err := os.ReadFile("../../.github/workflows/deploy-production.yml")
	if err != nil {
		t.Fatalf("read production deploy workflow: %v", err)
	}

	retiredNames := [][]string{
		{"VPS_OPS_SIGNAL_PLANE_DISPATCHER", "BROKER", "TOKEN"},
		{"VPS_OPS_GH_BROKER_CODEX_WORKER", "AUTH", "JSON"},
		{"VPS_OPS_GH_BROKER_CODEX_WORKER", "OPERATOR", "TOKEN"},
	}
	for _, parts := range retiredNames {
		retiredName := strings.Join(parts, "_")
		if regexp.MustCompile(regexp.QuoteMeta(retiredName)).Match(workflow) {
			t.Errorf("production deploy workflow must not export retired secret %s", retiredName)
		}
	}
}
