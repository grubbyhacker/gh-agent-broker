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

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
