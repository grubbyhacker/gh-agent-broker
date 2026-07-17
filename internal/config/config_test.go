package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadAllowsExplicitLocalSandboxOnlyWithoutGitHubApps(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	writeFile(t, path, `
server:
  local_sandbox_only: true
audit:
  path: audit.jsonl
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !cfg.Server.LocalSandboxOnly || len(cfg.GitHub.AppContexts()) != 0 || len(cfg.Agents) != 0 {
		t.Fatalf("unexpected local sandbox config: %+v", cfg)
	}
}

func TestLocalSandboxOnlyRejectsProductionAndGitHubAuthority(t *testing.T) {
	for name, body := range map[string]string{
		"production": "server:\n  local_sandbox_only: true\n  production: true\n",
		"app":        "server:\n  local_sandbox_only: true\ngithub:\n  app_id: 1\n  private_key_path: key.pem\n  installations: {owner/repo: 2}\n",
		"agent":      "server:\n  local_sandbox_only: true\nagents:\n  - id: agent\n    enabled: false\n",
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			writeFile(t, path, body)
			_, err := Load(path)
			if err == nil || !strings.Contains(err.Error(), "local_sandbox_only") {
				t.Fatalf("Load() error = %v", err)
			}
		})
	}
}

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

func TestPushTripwireRequiresReviewedMaterialAndResponseScope(t *testing.T) {
	cfg := Config{GitHub: GitHubConfig{AppID: 1, PrivateKeyPath: "key.pem", Installations: map[string]int64{"owner/repo": 2}}, PushTripwire: PushTripwireConfig{Enabled: true, ScannerID: "scanner", ScannerSecret: "secret", StatePath: "tripwire.db", Repositories: map[string]PushTripwireRepository{"owner/repo": {BaseRef: "refs/heads/main", RefPatterns: []string{"^refs/heads/agent/.+$"}}}, ResponseProfiles: map[string]PushTripwireResponseProfile{"curator": {Generation: 7, AllowHalt: true, AllowFence: true, Bindings: []PushTripwireBinding{{WorkerID: "worker", LogicalSessionID: "logical", SessionLineageID: "session", WorkerStorageLineageID: "storage", WorkerFenceEpoch: 2}}}}, Bounds: PushTripwireBounds{MaxCommits: 10, MaxPaths: 20, MaxCommitMessageBytes: 1024, MaxBlobBytes: 4096, MaxTotalBytes: 16384}}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid tripwire config rejected: %v", err)
	}
	cfg.PushTripwire.Repositories["owner/repo"] = PushTripwireRepository{}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "base_ref") {
		t.Fatalf("missing reviewed base accepted: %v", err)
	}
	cfg.PushTripwire.Repositories["owner/repo"] = PushTripwireRepository{BaseRef: "refs/heads/main", RefPatterns: []string{"^refs/heads/agent/.+$"}}
	cfg.PushTripwire.ResponseProfiles["curator"] = PushTripwireResponseProfile{Generation: 7, AllowFence: true}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "reviewed bindings") {
		t.Fatalf("unbound fence scope accepted: %v", err)
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

func TestInstallationIDForAppSupportsOwnerWildcard(t *testing.T) {
	cfg := Config{
		GitHub: GitHubConfig{
			Apps: map[string]GitHubAppConfig{
				"reporter": {
					AppID:          1,
					PrivateKeyPath: "reporter.pem",
					Installations: map[string]int64{
						"grubbyhacker/*": 42,
					},
				},
			},
		},
		Agents: []Agent{{
			ID:           "broker-reporter-01",
			Enabled:      true,
			Secret:       "secret",
			GitHubApp:    "reporter",
			Repositories: []string{"grubbyhacker/youknowme", "grubbyhacker/ykmcorpus"},
		}},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if id, ok := cfg.InstallationIDForApp("reporter", "grubbyhacker/youknowme"); !ok || id != 42 {
		t.Fatalf("wildcard installation = %d/%v, want 42/true", id, ok)
	}
	if _, ok := cfg.InstallationIDForApp("reporter", "other/youknowme"); ok {
		t.Fatalf("wildcard unexpectedly matched another owner")
	}
}

func TestValidateRejectsEnabledAgentRepoMissingInstallation(t *testing.T) {
	cfg := Config{
		GitHub: GitHubConfig{
			Apps: map[string]GitHubAppConfig{
				"reporter": {
					AppID:          1,
					PrivateKeyPath: "reporter.pem",
					Installations: map[string]int64{
						"grubbyhacker/gh-agent-broker": 42,
					},
				},
			},
		},
		Agents: []Agent{{
			ID:           "broker-reporter-01",
			Enabled:      true,
			Secret:       "secret",
			GitHubApp:    "reporter",
			Repositories: []string{"grubbyhacker/gh-agent-broker", "grubbyhacker/youknowme"},
		}},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatalf("Validate() error = nil, want missing installation coverage")
	}
	want := `enabled agent "broker-reporter-01" repository "grubbyhacker/youknowme" is not covered by github app "reporter" installations`
	if err.Error() != want {
		t.Fatalf("Validate() error = %q, want %q", err.Error(), want)
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

func TestGitReceivePackPolicyDefaultsAndRejectsUnknownMode(t *testing.T) {
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
    secret: test-secret
    repositories: [owner/repo]
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Agents[0].GitReceivePack != GitReceivePackAllowOpaque {
		t.Fatalf("default git receive-pack policy = %q", cfg.Agents[0].GitReceivePack)
	}
	cfg.Agents[0].GitReceivePack = "caller_selected"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "git_receive_pack_policy") {
		t.Fatalf("invalid git receive-pack policy error = %v", err)
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
