package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadResolvesSecretsAndDefaults(t *testing.T) {
	t.Setenv("TEST_AGENT_SECRET", "agent-secret")
	t.Setenv("TEST_ADMIN_SECRET", "admin-secret")

	path := filepath.Join(t.TempDir(), "config.yaml")
	writeFile(t, path, `
server:
  admin_secret_env: TEST_ADMIN_SECRET
audit:
  path: audit.jsonl
github:
  app_id: 1
  private_key_path: key.pem
  installations:
    owner/repo: 2
agents:
  - id: agent-1
    enabled: true
    secret_env: TEST_AGENT_SECRET
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Server.Listen != "127.0.0.1:8080" {
		t.Fatalf("default listen = %q", cfg.Server.Listen)
	}
	if cfg.Server.AdminSecret != "admin-secret" {
		t.Fatalf("admin secret not resolved")
	}
	if cfg.Agents[0].Secret != "agent-secret" {
		t.Fatalf("agent secret not resolved")
	}
}

func TestValidateRejectsDuplicateAgent(t *testing.T) {
	cfg := Config{
		GitHub: GitHubConfig{
			AppID:          1,
			PrivateKeyPath: "key.pem",
			Installations:  map[string]int64{"owner/repo": 2},
		},
		Agents: []Agent{
			{ID: "agent-1", Enabled: false},
			{ID: "agent-1", Enabled: false},
		},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatalf("Validate() error = nil, want duplicate agent error")
	}
}

func TestLoadSupportsNamedGitHubApps(t *testing.T) {
	t.Setenv("TEST_AGENT_SECRET", "agent-secret")
	path := filepath.Join(t.TempDir(), "config.yaml")
	writeFile(t, path, `
github:
  api_base_url: https://api.github.invalid
  git_base_url: https://github.invalid
  apps:
    coder:
      app_id: 1
      private_key_path: coder.pem
      installations:
        owner/code: 11
    reporter:
      app_id: 2
      private_key_path: reporter.pem
      installations:
        owner/issues: 22
agents:
  - id: reporter-1
    enabled: true
    secret_env: TEST_AGENT_SECRET
    github_app: reporter
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got := GitHubAppName(cfg.Agents[0]); got != "reporter" {
		t.Fatalf("GitHubAppName = %q", got)
	}
	if id, ok := cfg.InstallationIDForApp("reporter", "owner/issues"); !ok || id != 22 {
		t.Fatalf("reporter installation = %d/%v, want 22/true", id, ok)
	}
	if _, ok := cfg.InstallationIDForApp("reporter", "owner/code"); ok {
		t.Fatalf("reporter unexpectedly resolved coder installation")
	}
}

func TestBranchLifecycleGuardDefaultsWhenEnabled(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	writeFile(t, path, `
github:
  app_id: 1
  private_key_path: key.pem
  installations:
    owner/repo: 2
agents:
  - id: agent-1
    enabled: false
    branch_lifecycle_guard:
      mode: enforce
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	guard := cfg.Agents[0].BranchGuard
	if guard.Mode != "enforce" {
		t.Fatalf("guard mode = %q", guard.Mode)
	}
	if len(guard.StalePRStates) != 1 || guard.StalePRStates[0] != "closed" {
		t.Fatalf("stale states = %#v", guard.StalePRStates)
	}
	if len(guard.Operations) != 2 || guard.Operations[0] != "git.receive-pack" || guard.Operations[1] != "pull.create" {
		t.Fatalf("operations = %#v", guard.Operations)
	}
}

func TestValidateRejectsInvalidBranchLifecycleGuardMode(t *testing.T) {
	cfg := Config{
		GitHub: GitHubConfig{
			AppID:          1,
			PrivateKeyPath: "key.pem",
			Installations:  map[string]int64{"owner/repo": 2},
		},
		Agents: []Agent{{
			ID:          "agent-1",
			Enabled:     false,
			BranchGuard: BranchLifecycleGuard{Mode: "block"},
		}},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatalf("Validate() error = nil, want branch lifecycle guard mode error")
	}
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
