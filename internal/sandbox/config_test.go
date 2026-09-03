package sandbox

import (
	"path/filepath"
	"strings"
	"testing"
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

func TestCodexIssueWorkflowConfigIsExactAndDenyByDefault(t *testing.T) {
	cfg := codexWorkflowTestConfig(t)
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid secure Codex config: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{name: "lower luna effort", mutate: func(c *Config) {
			policy := c.ModelPolicies["reviewed"]
			policy.Mappings["luna-medium-v1"] = ModelMapping{Model: "gpt-5.6-luna", Effort: "low"}
			c.ModelPolicies["reviewed"] = policy
		}, want: "resolve exactly"},
		{name: "sol xhigh", mutate: func(c *Config) {
			policy := c.ModelPolicies["reviewed"]
			policy.Mappings["sol-high-v1"] = ModelMapping{Model: "gpt-5.6-sol", Effort: "xhigh"}
			c.ModelPolicies["reviewed"] = policy
		}, want: "resolve exactly"},
		{name: "extra fallback", mutate: func(c *Config) {
			policy := c.ModelPolicies["reviewed"]
			policy.Mappings["fallback"] = ModelMapping{Model: "gpt-5.6-terra", Effort: "medium"}
			c.ModelPolicies["reviewed"] = policy
		}, want: "current reviewed Codex policy mappings"},
		{name: "prep egress", mutate: func(c *Config) {
			network := c.Networks["prep"]
			network.EgressProxy = "http://proxy:8080"
			c.Networks["prep"] = network
		}, want: "private broker credentials only"},
		{name: "execution general internet", mutate: func(c *Config) {
			network := c.Networks["execution"]
			network.AllowInternet = true
			c.Networks["execution"] = network
		}, want: "cannot allow general DNS or internet"},
		{name: "execution proxy bypass", mutate: func(c *Config) {
			network := c.Networks["execution"]
			network.EgressProxy = "http://proxy:8080"
			c.Networks["execution"] = network
		}, want: "Codex subscription relay only"},
		{name: "execution relay missing", mutate: func(c *Config) {
			network := c.Networks["execution"]
			network.CodexRelay = false
			c.Networks["execution"] = network
		}, want: "Codex subscription relay only"},
		{name: "execution broker credential", mutate: func(c *Config) {
			template := c.Templates["execution"]
			template.BrokerAgentID = "forbidden"
			template.BrokerAgentSecret = "forbidden"
			c.Templates["execution"] = template
		}, want: "no broker agent credential"},
		{name: "execution private broker route", mutate: func(c *Config) {
			network := c.Networks["execution"]
			network.PrivateBroker = true
			c.Networks["execution"] = network
		}, want: "Codex subscription relay only"},
		{name: "delivery relay", mutate: func(c *Config) {
			network := c.Networks["delivery"]
			network.CodexRelay = true
			c.Networks["delivery"] = network
		}, want: "no Codex holder, relay, or proxy"},
		{name: "delivery missing broker credential", mutate: func(c *Config) {
			template := c.Templates["delivery"]
			template.BrokerAgentSecret = ""
			c.Templates["delivery"] = template
		}, want: "private broker credentials only"},
		{name: "missing tmpfs", mutate: func(c *Config) {
			template := c.Templates["execution"]
			template.Tmpfs = nil
			c.Templates["execution"] = template
		}, want: "bounded /dev/shm tmpfs"},
		{name: "master mounted", mutate: func(c *Config) {
			template := c.Templates["prep"]
			template.ExtraMounts = append(template.ExtraMounts, ExtraMount{
				SourcePath: c.CodexHolder.MasterAuthPath, MountPath: "/data/master", ReadOnly: true,
			})
			c.Templates["prep"] = template
		}, want: "cannot expose Codex holder paths"},
		{name: "prep credential env", mutate: func(c *Config) {
			template := c.Templates["prep"]
			template.Environment = map[string]string{"OPENAI_API_KEY": "forbidden"}
			c.Templates["prep"] = template
		}, want: "cannot configure credential or proxy environment"},
		{name: "recovery broker env", mutate: func(c *Config) {
			template := c.Templates["recovery"]
			template.Environment = map[string]string{"BROKER_AGENT_SECRET": "forbidden"}
			c.Templates["recovery"] = template
		}, want: "cannot configure credential or proxy environment"},
		{name: "recovery extra mount", mutate: func(c *Config) {
			template := c.Templates["recovery"]
			template.ExtraMounts = []ExtraMount{{SourcePath: "/tmp/secret", MountPath: "/data/secret", ReadOnly: true}}
			c.Templates["recovery"] = template
		}, want: "must not configure extra_mounts"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			candidate := codexWorkflowTestConfig(t)
			tt.mutate(&candidate)
			err := candidate.Validate()
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Validate() error=%v, want %q", err, tt.want)
			}
		})
	}
}

func reviewedModelPolicy() ModelPolicy {
	return ModelPolicy{
		Version: "codex-model-policy/v1",
		Mappings: map[string]ModelMapping{
			"luna-medium-v1":  {Model: "gpt-5.6-luna", Effort: "medium"},
			"luna-high-v1":    {Model: "gpt-5.6-luna", Effort: "high"},
			"terra-medium-v1": {Model: "gpt-5.6-terra", Effort: "medium"},
			"terra-high-v1":   {Model: "gpt-5.6-terra", Effort: "high"},
			"sol-high-v1":     {Model: "gpt-5.6-sol", Effort: "high"},
		},
	}
}

func codexWorkflowTestConfig(t *testing.T) Config {
	t.Helper()
	cfg := baseTestConfig(t)
	cfg.Bundles = map[string]CredentialBundle{}
	cfg.Networks = map[string]NetworkPolicy{
		"prep": {
			Network: "prep-net", PrivateBroker: true,
		},
		"execution": {
			Network: "execution-net", CodexRelay: true,
		},
		"delivery": {
			Network: "delivery-net", PrivateBroker: true,
		},
		"recovery": {Network: "recovery-net"},
	}
	prep := testTemplate("example.com/prep@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	prep.NetworkPolicy = "prep"
	prep.CredentialBundle = ""
	prep.Command = []string{"/usr/local/bin/agent-codex-repo-prep-worker"}
	execution := testTemplate("example.com/exec@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	execution.NetworkPolicy = "execution"
	execution.CredentialBundle = ""
	execution.BrokerAgentID = ""
	execution.BrokerAgentSecret = ""
	execution.Command = []string{"/usr/local/bin/agent-codex-repo-task-worker"}
	execution.StorageLimitMB = 8192
	execution.Tmpfs = map[string]int64{"/dev/shm": 64}
	delivery := testTemplate("example.com/delivery@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")
	delivery.NetworkPolicy = "delivery"
	delivery.CredentialBundle = ""
	delivery.Command = []string{"/usr/local/bin/agent-codex-delivery-worker"}
	recovery := testTemplate("example.com/recovery@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd")
	recovery.NetworkPolicy, recovery.CredentialBundle, recovery.BrokerAgentID, recovery.BrokerAgentSecret = "recovery", "", "", ""
	recovery.Command = []string{"/usr/local/bin/agent-codex-recovery-validation-worker"}
	cfg.Templates = map[string]Template{"prep": prep, "execution": execution, "recovery": recovery, "delivery": delivery}
	cfg.ModelPolicies = map[string]ModelPolicy{"reviewed": reviewedModelPolicy()}
	cfg.CodexHolder = CodexHolderConfig{
		MasterAuthPath: filepath.Join(t.TempDir(), "master", "auth.json"),
		IssuanceRoot:   filepath.Join(t.TempDir(), "issuance"),
	}
	cfg.LaunchProfiles = map[string]LaunchProfile{
		"terra-medium-v1": {
			LaunchAgentInput: LaunchAgentInput{
				Template: "execution", Task: "Implement the issue", Repo: "owner/repo",
				BaseBranch: "main", MaxRuntimeMinutes: 5,
				VerificationTask: "verify",
			},
			RequireIdempotencyKey: true,
			MaxConcurrentRuns:     1,
			Parameters: map[string]ParameterDeclaration{
				"issue_number":       {Type: "integer", Required: true, Min: intPtr(1)},
				"source_delivery_id": {Type: "string", Required: true, MaxLength: 128, Pattern: `^[A-Za-z0-9-]+$`},
			},
			CodexIssueWorkflow: &CodexIssueWorkflow{
				PreparationTemplate: "prep", ExecutionTemplate: "execution", RecoveryTemplate: "recovery", DeliveryTemplate: "delivery",
				ModelPolicy: "reviewed", ModelProfile: "terra-medium-v1", PromptRevision: "issue-ready-pr/v1",
			},
		},
	}
	cfg.OperatorPrincipals = map[string]OperatorPrincipal{
		"signal-plane": {
			Token: "signal-secret", AllowedProfiles: []string{"terra-medium-v1"},
			AllowedActions: []string{"launch", "status", "terminal_result"}, RunScope: "owned",
		},
	}
	return cfg
}
