package sandbox

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadExampleConfig(t *testing.T) {
	t.Setenv("SANDBOX_MCP_TOKEN", "mcp-secret")
	t.Setenv("SANDBOX_OPERATOR_TIMER_TOKEN", "timer-secret")
	t.Setenv("SANDBOX_OPERATOR_ADMIN_TOKEN", "operator-secret")
	t.Setenv("HERMES_CODER_01_BROKER_SECRET", "broker-secret")
	cfg, err := Load(filepath.Join("..", "..", "configs", "sandbox.example.yaml"))
	if err != nil {
		t.Fatalf("Load(example) error = %v", err)
	}
	if cfg.MCPPath != "/mcp" || cfg.Templates["hermes-task-worker"].BrokerAgentSecret != "broker-secret" {
		t.Fatalf("loaded config = %+v", cfg)
	}
}

func TestConfigVersionIncludesOnlyNonemptySourceVolume(t *testing.T) {
	cfg := baseTestConfig(t)
	bundle := cfg.Bundles["codex"]
	bundle.SourcePath = ""
	cfg.Bundles["codex"] = bundle
	cfg.StampLoaded(time.Unix(1, 0).UTC())
	withoutVolume := cfg.ConfigVersion

	bundle.SourceVolume = "agentd-staging-auth"
	cfg.Bundles["codex"] = bundle
	cfg.StampLoaded(time.Unix(2, 0).UTC())
	if cfg.ConfigVersion == withoutVolume {
		t.Fatal("nonempty source_volume was omitted from config version")
	}

	bundle.SourceVolume = ""
	cfg.Bundles["codex"] = bundle
	cfg.StampLoaded(time.Unix(3, 0).UTC())
	if cfg.ConfigVersion != withoutVolume {
		t.Fatal("empty source_volume changed the legacy canonical config shape")
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

	cfg = baseTestConfig(t)
	tmpl = cfg.Templates["worker"]
	tmpl.ExtraMounts = []ExtraMount{{SourcePath: "/var/run/docker.sock", MountPath: "/data/docker", ReadOnly: true}}
	cfg.Templates["worker"] = tmpl
	err = cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "source_path is not allowed") {
		t.Fatalf("Validate() error = %v, want unsafe extra mount source", err)
	}

	cfg = baseTestConfig(t)
	tmpl = cfg.Templates["worker"]
	tmpl.ExtraMounts = []ExtraMount{{SourcePath: "/tmp/evidence", MountPath: "/input/evidence", ReadOnly: true}}
	cfg.Templates["worker"] = tmpl
	err = cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "conflicts with sandbox-managed paths") {
		t.Fatalf("Validate() error = %v, want unsafe extra mount target", err)
	}

	cfg = baseTestConfig(t)
	tmpl = cfg.Templates["worker"]
	tmpl.CompletionStatusPath = "/data/intake/curator-status.json"
	cfg.Templates["worker"] = tmpl
	err = cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "writable extra_mounts") {
		t.Fatalf("Validate() error = %v, want writable completion status mount requirement", err)
	}
}

func TestConfigResolveSecrets(t *testing.T) {
	t.Setenv("SANDBOX_TOKEN", "mcp-secret")
	t.Setenv("WORKER_SECRET", "broker-secret")
	t.Setenv("OPERATOR_TOKEN", "operator-secret")
	cfg := baseTestConfig(t)
	cfg.AuthToken = ""
	cfg.AuthTokenEnv = "SANDBOX_TOKEN"
	tmpl := cfg.Templates["worker"]
	tmpl.BrokerAgentSecret = ""
	tmpl.BrokerSecretEnv = "WORKER_SECRET"
	cfg.Templates["worker"] = tmpl
	cfg.LaunchProfiles = map[string]LaunchProfile{"nightly": testLaunchProfile()}
	cfg.OperatorPrincipals = map[string]OperatorPrincipal{
		"timer": {
			TokenEnv:        "OPERATOR_TOKEN",
			AllowedProfiles: []string{"nightly"},
			AllowedActions:  []string{"launch", "dry_run"},
		},
	}
	cfg.ResolveSecrets()
	if cfg.AuthToken != "mcp-secret" {
		t.Fatalf("AuthToken = %q", cfg.AuthToken)
	}
	if cfg.Templates["worker"].BrokerAgentSecret != "broker-secret" {
		t.Fatalf("BrokerAgentSecret was not resolved")
	}
	if cfg.OperatorPrincipals["timer"].Token != "operator-secret" {
		t.Fatalf("operator token was not resolved")
	}
}

func TestConfigValidateLaunchProfilesAndOperatorPrincipals(t *testing.T) {
	cfg := baseTestConfig(t)
	cfg.LaunchProfiles = map[string]LaunchProfile{"nightly": testLaunchProfile()}
	cfg.OperatorPrincipals = map[string]OperatorPrincipal{
		"timer": {
			Token:           "timer-secret",
			AllowedProfiles: []string{"nightly"},
			AllowedActions:  []string{"launch", "dry_run"},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	cfg = baseTestConfig(t)
	cfg.LaunchProfiles = map[string]LaunchProfile{"nightly": testLaunchProfile()}
	cfg.OperatorPrincipals = map[string]OperatorPrincipal{
		"timer": {Token: "timer-secret", AllowedProfiles: []string{"missing"}, AllowedActions: []string{"launch"}},
	}
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "unknown launch profile") {
		t.Fatalf("Validate() error = %v, want unknown launch profile", err)
	}

	cfg = baseTestConfig(t)
	cfg.LaunchProfiles = map[string]LaunchProfile{"nightly": testLaunchProfile()}
	cfg.OperatorPrincipals = map[string]OperatorPrincipal{
		"timer": {Token: "timer-secret", AllowedProfiles: []string{"nightly"}, AllowedActions: []string{"shell"}},
	}
	err = cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "unsupported action") {
		t.Fatalf("Validate() error = %v, want unsupported action", err)
	}

	cfg = baseTestConfig(t)
	cfg.LaunchProfiles = map[string]LaunchProfile{"nightly": testLaunchProfile()}
	cfg.OperatorPrincipals = map[string]OperatorPrincipal{
		"timer": {Token: "timer-secret", AllowedProfiles: []string{"nightly"}, AllowedActions: []string{"launch"}, RunScope: "global"},
	}
	err = cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "run_scope must be owned or profile") {
		t.Fatalf("Validate() error = %v, want invalid run scope", err)
	}

	cfg = baseTestConfig(t)
	profile := testLaunchProfile()
	profile.AllowOverrides = []string{"env"}
	cfg.LaunchProfiles = map[string]LaunchProfile{"nightly": profile}
	err = cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "unsupported field") {
		t.Fatalf("Validate() error = %v, want unsupported override field", err)
	}

	cfg = baseTestConfig(t)
	profile = testLaunchProfile()
	profile.MaxRuntimeMinutes = 0
	profile.MaxRuntimeSeconds = 30
	profile.AllowOverrides = []string{"task", "max_runtime_seconds"}
	cfg.LaunchProfiles = map[string]LaunchProfile{"nightly": profile}
	if err = cfg.Validate(); err != nil {
		t.Fatalf("Validate() with second runtime profile error = %v", err)
	}

	cfg = baseTestConfig(t)
	profile = testLaunchProfile()
	profile.MaxConcurrentRuns = -1
	cfg.LaunchProfiles = map[string]LaunchProfile{"nightly": profile}
	err = cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "max_concurrent_runs must not be negative") {
		t.Fatalf("Validate() error = %v, want negative concurrency rejection", err)
	}

	cfg = baseTestConfig(t)
	profile = testLaunchProfile()
	profile.MaxRuntimeSeconds = 30
	cfg.LaunchProfiles = map[string]LaunchProfile{"nightly": profile}
	err = cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "only one") {
		t.Fatalf("Validate() error = %v, want mixed runtime unit rejection", err)
	}

	cfg = baseTestConfig(t)
	cfg.LaunchProfiles = map[string]LaunchProfile{"nightly": testLaunchProfile()}
	cfg.OperatorPrincipals = map[string]OperatorPrincipal{
		"timer": {AllowedProfiles: []string{"nightly"}, AllowedActions: []string{"launch"}},
	}
	err = cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "token or token_env is required") {
		t.Fatalf("Validate() error = %v, want token requirement", err)
	}
}

func TestConfigValidateLaunchProfileParameters(t *testing.T) {
	cfg := baseTestConfig(t)
	profile := testLaunchProfile()
	profile.Parameters = map[string]ParameterDeclaration{
		"upload_ids": {
			Type:      "string_list",
			Required:  true,
			MaxItems:  3,
			MaxLength: 32,
			Pattern:   `^[A-Za-z0-9_.:-]+$`,
		},
		"attempt": {
			Type: "integer",
			Min:  intPtr(1),
			Max:  intPtr(5),
		},
	}
	cfg.LaunchProfiles = map[string]LaunchProfile{"nightly": profile}
	cfg.OperatorPrincipals = map[string]OperatorPrincipal{
		"timer": {Token: "timer-secret", AllowedProfiles: []string{"nightly"}, AllowedActions: []string{"launch", "dry_run"}},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() with parameters error = %v", err)
	}

	profile.Parameters["bad-name!"] = ParameterDeclaration{Type: "string", MaxLength: 16}
	cfg.LaunchProfiles["nightly"] = profile
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "invalid name") {
		t.Fatalf("Validate() error = %v, want invalid parameter name", err)
	}

	cfg = baseTestConfig(t)
	profile = testLaunchProfile()
	profile.Parameters = map[string]ParameterDeclaration{
		"upload_ids": {Type: "string_list", MaxItems: 1, MaxLength: 8, Default: []any{"ok", "too-many"}},
	}
	cfg.LaunchProfiles = map[string]LaunchProfile{"nightly": profile}
	cfg.OperatorPrincipals = map[string]OperatorPrincipal{
		"timer": {Token: "timer-secret", AllowedProfiles: []string{"nightly"}, AllowedActions: []string{"launch", "dry_run"}},
	}
	err = cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "default is invalid") {
		t.Fatalf("Validate() error = %v, want invalid default", err)
	}
}

func intPtr(v int) *int {
	return &v
}
