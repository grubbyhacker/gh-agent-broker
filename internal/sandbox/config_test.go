package sandbox

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadExampleConfig(t *testing.T) {
	t.Setenv("SANDBOX_MCP_TOKEN", "mcp-secret")
	t.Setenv("HERMES_CODER_01_BROKER_SECRET", "broker-secret")
	cfg, err := Load(filepath.Join("..", "..", "configs", "sandbox.example.yaml"))
	if err != nil {
		t.Fatalf("Load(example) error = %v", err)
	}
	if cfg.MCPPath != "/mcp" || cfg.Templates["hermes-worker"].BrokerAgentSecret != "broker-secret" {
		t.Fatalf("loaded config = %+v", cfg)
	}
}

func TestConfigValidateRejectsUnsafeSettings(t *testing.T) {
	cfg := baseTestConfig(t)
	cfg.Production = true
	cfg.Templates["worker"] = testTemplate("example.com/worker:latest")
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "digest") {
		t.Fatalf("Validate() error = %v, want digest requirement", err)
	}

	cfg = baseTestConfig(t)
	tmpl := cfg.Templates["worker"]
	tmpl.NetworkPolicy = "missing"
	cfg.Templates["worker"] = tmpl
	err = cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "unknown network_policy") {
		t.Fatalf("Validate() error = %v, want unknown network policy", err)
	}

	cfg = baseTestConfig(t)
	bundle := cfg.Bundles["codex"]
	bundle.SourcePath = "relative"
	cfg.Bundles["codex"] = bundle
	err = cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "source_path must be absolute") {
		t.Fatalf("Validate() error = %v, want absolute source path", err)
	}
}

func TestConfigResolveSecrets(t *testing.T) {
	t.Setenv("SANDBOX_TOKEN", "mcp-secret")
	t.Setenv("WORKER_SECRET", "broker-secret")
	cfg := baseTestConfig(t)
	cfg.AuthToken = ""
	cfg.AuthTokenEnv = "SANDBOX_TOKEN"
	tmpl := cfg.Templates["worker"]
	tmpl.BrokerAgentSecret = ""
	tmpl.BrokerSecretEnv = "WORKER_SECRET"
	cfg.Templates["worker"] = tmpl
	cfg.ResolveSecrets()
	if cfg.AuthToken != "mcp-secret" {
		t.Fatalf("AuthToken = %q", cfg.AuthToken)
	}
	if cfg.Templates["worker"].BrokerAgentSecret != "broker-secret" {
		t.Fatalf("BrokerAgentSecret was not resolved")
	}
}
