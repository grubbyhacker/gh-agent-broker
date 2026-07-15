// Package config loads and validates broker YAML configuration.
package config

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server         ServerConfig         `yaml:"server"`
	Audit          AuditConfig          `yaml:"audit"`
	GitHub         GitHubConfig         `yaml:"github"`
	MutationLimits MutationLimitsConfig `yaml:"mutation_limits"`
	Idempotency    IdempotencyConfig    `yaml:"idempotency"`
	Agents         []Agent              `yaml:"agents"`
}

type ServerConfig struct {
	Listen         string `yaml:"listen"`
	AdminSecret    string `yaml:"admin_secret"`
	AdminSecretEnv string `yaml:"admin_secret_env"`
	// LocalSandboxOnly is an explicit staging-only escape hatch for the
	// sandbox broker. It disables all broker GitHub authority rather than
	// weakening normal broker validation.
	LocalSandboxOnly bool `yaml:"local_sandbox_only"`
	Production       bool `yaml:"production"`
}

type AuditConfig struct {
	Path string `yaml:"path"`
}

type GitHubConfig struct {
	AppID          int64                      `yaml:"app_id"`
	PrivateKeyPath string                     `yaml:"private_key_path"`
	APIBaseURL     string                     `yaml:"api_base_url"`
	GitBaseURL     string                     `yaml:"git_base_url"`
	Installations  map[string]int64           `yaml:"installations"`
	Apps           map[string]GitHubAppConfig `yaml:"apps"`
}

type GitHubAppConfig struct {
	AppID          int64            `yaml:"app_id"`
	PrivateKeyPath string           `yaml:"private_key_path"`
	Installations  map[string]int64 `yaml:"installations"`
}

type MutationLimitsConfig struct {
	StatePath           string            `yaml:"state_path"`
	RunMetadataField    string            `yaml:"run_metadata_field"`
	ActionMetadataField string            `yaml:"action_metadata_field"`
	MaxNewObjectsPerRun int               `yaml:"max_new_objects_per_run"`
	ClassLimits         map[string]int    `yaml:"class_limits"`
	OperationClasses    map[string]string `yaml:"operation_classes"`
}

type IdempotencyConfig struct {
	StatePath string `yaml:"state_path"`
}

type Agent struct {
	ID                 string                     `yaml:"id"`
	Enabled            bool                       `yaml:"enabled"`
	Secret             string                     `yaml:"secret"`
	SecretEnv          string                     `yaml:"secret_env"`
	GitHubApp          string                     `yaml:"github_app"`
	Repositories       []string                   `yaml:"repositories"`
	Operations         []string                   `yaml:"operations"`
	BranchPatterns     []string                   `yaml:"branch_patterns"`
	BaseBranches       []string                   `yaml:"base_branches"`
	BranchGuard        BranchLifecycleGuard       `yaml:"branch_lifecycle_guard"`
	Permissions        []string                   `yaml:"permissions"`
	MetadataAssertions map[string]AssertionPolicy `yaml:"metadata_assertions"`
}

type BranchLifecycleGuard struct {
	Mode          string   `json:"mode" yaml:"mode"`
	StalePRStates []string `json:"stale_pr_states" yaml:"stale_pr_states"`
	Operations    []string `json:"operations" yaml:"operations"`
}

type AssertionPolicy struct {
	Mode   string           `yaml:"mode"`
	Fields []AssertionField `yaml:"fields"`
}

type AssertionField struct {
	Name      string   `yaml:"name"`
	Required  bool     `yaml:"required"`
	Pattern   string   `yaml:"pattern"`
	Value     string   `yaml:"value"`
	Locations []string `yaml:"locations"`
}

func Load(path string) (*Config, error) {
	// #nosec G304 -- config path is supplied by the operator on broker startup.
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return nil, err
	}
	cfg.applyDefaults()
	if err := cfg.resolveSecrets(); err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) applyDefaults() {
	if c.Server.Listen == "" {
		c.Server.Listen = "127.0.0.1:8080"
	}
	if c.GitHub.APIBaseURL == "" {
		c.GitHub.APIBaseURL = "https://api.github.com"
	}
	if c.GitHub.GitBaseURL == "" {
		c.GitHub.GitBaseURL = "https://github.com"
	}
	for i := range c.Agents {
		c.Agents[i].BranchGuard.applyDefaults()
	}
}

func (c *Config) resolveSecrets() error {
	if c.Server.AdminSecret == "" && c.Server.AdminSecretEnv != "" {
		c.Server.AdminSecret = os.Getenv(c.Server.AdminSecretEnv)
	}
	for i := range c.Agents {
		if c.Agents[i].Secret == "" && c.Agents[i].SecretEnv != "" {
			c.Agents[i].Secret = os.Getenv(c.Agents[i].SecretEnv)
		}
	}
	return nil
}

func (c *Config) Validate() error {
	var errs []string
	apps := c.GitHub.AppContexts()
	if c.Server.LocalSandboxOnly {
		if c.Server.Production {
			errs = append(errs, "local_sandbox_only cannot be enabled in production")
		}
		if len(apps) != 0 {
			errs = append(errs, "local_sandbox_only must not configure github apps")
		}
		if len(c.Agents) != 0 {
			errs = append(errs, "local_sandbox_only must not configure broker agents")
		}
	} else if len(apps) == 0 {
		errs = append(errs, "github app context is required: configure legacy github.app_id/private_key_path/installations or github.apps")
	}
	for name, app := range apps {
		if app.AppID == 0 {
			errs = append(errs, fmt.Sprintf("github app %q app_id is required", name))
		}
		if app.PrivateKeyPath == "" {
			errs = append(errs, fmt.Sprintf("github app %q private_key_path is required", name))
		}
		if len(app.Installations) == 0 {
			errs = append(errs, fmt.Sprintf("github app %q installations must not be empty", name))
		}
	}
	seen := map[string]bool{}
	for _, a := range c.Agents {
		if a.ID == "" {
			errs = append(errs, "agent id is required")
		}
		if seen[a.ID] {
			errs = append(errs, fmt.Sprintf("duplicate agent id %q", a.ID))
		}
		seen[a.ID] = true
		if a.Enabled && a.Secret == "" {
			errs = append(errs, fmt.Sprintf("enabled agent %q has no secret or secret_env value", a.ID))
		}
		appName := GitHubAppName(a)
		if _, ok := apps[appName]; !ok {
			errs = append(errs, fmt.Sprintf("agent %q references unknown github_app %q", a.ID, appName))
		} else if a.Enabled {
			for _, repo := range a.Repositories {
				if repo == "" {
					continue
				}
				if _, ok := c.InstallationIDForApp(appName, repo); !ok {
					errs = append(errs, fmt.Sprintf("enabled agent %q repository %q is not covered by github app %q installations", a.ID, repo, appName))
				}
			}
		}
		if err := a.BranchGuard.Validate(); err != nil {
			errs = append(errs, fmt.Sprintf("agent %q branch_lifecycle_guard: %v", a.ID, err))
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

func (c *Config) AgentByID(id string) (Agent, bool) {
	for _, a := range c.Agents {
		if a.ID == id {
			return a, true
		}
	}
	return Agent{}, false
}

func (c *Config) InstallationID(repo string) (int64, bool) {
	return c.InstallationIDForApp("", repo)
}

func (c *Config) InstallationIDForApp(appName, repo string) (int64, bool) {
	app, ok := c.GitHub.AppContext(appName)
	if !ok {
		return 0, false
	}
	id, ok := app.Installations[strings.ToLower(repo)]
	if ok {
		return id, true
	}
	id, ok = app.Installations[repo]
	if ok {
		return id, true
	}
	for configuredRepo, id := range app.Installations {
		if installationCoversRepo(configuredRepo, repo) {
			return id, true
		}
	}
	return 0, false
}

func installationCoversRepo(configured, repo string) bool {
	configured = strings.TrimSpace(configured)
	repo = strings.TrimSpace(repo)
	if strings.EqualFold(configured, repo) {
		return true
	}
	owner, _, ok := strings.Cut(repo, "/")
	if !ok || owner == "" {
		return false
	}
	wildcardOwner, wildcardSuffix, ok := strings.Cut(configured, "/")
	return ok && wildcardSuffix == "*" && strings.EqualFold(wildcardOwner, owner)
}

func (g GitHubConfig) AppContexts() map[string]GitHubAppConfig {
	out := map[string]GitHubAppConfig{}
	if g.AppID != 0 || g.PrivateKeyPath != "" || len(g.Installations) > 0 {
		out["default"] = GitHubAppConfig{
			AppID:          g.AppID,
			PrivateKeyPath: g.PrivateKeyPath,
			Installations:  g.Installations,
		}
	}
	for name, app := range g.Apps {
		out[name] = app
	}
	return out
}

func (g GitHubConfig) AppContext(name string) (GitHubAppConfig, bool) {
	if name == "" {
		name = "default"
	}
	app, ok := g.AppContexts()[name]
	return app, ok
}

func GitHubAppName(agent Agent) string {
	if agent.GitHubApp != "" {
		return agent.GitHubApp
	}
	return "default"
}

func (g *BranchLifecycleGuard) applyDefaults() {
	if strings.TrimSpace(g.Mode) == "" {
		g.Mode = "off"
	}
	if strings.EqualFold(g.Mode, "off") {
		return
	}
	if len(g.StalePRStates) == 0 {
		g.StalePRStates = []string{"closed"}
	}
	if len(g.Operations) == 0 {
		g.Operations = []string{"git.receive-pack", "pull.create"}
	}
}

func (g BranchLifecycleGuard) Validate() error {
	mode := strings.ToLower(strings.TrimSpace(g.Mode))
	if mode == "" {
		mode = "off"
	}
	switch mode {
	case "off", "warn", "enforce":
	default:
		return fmt.Errorf("mode must be one of off, warn, enforce")
	}
	for _, state := range g.StalePRStates {
		switch strings.ToLower(strings.TrimSpace(state)) {
		case "closed":
		default:
			return fmt.Errorf("stale_pr_states currently supports only closed")
		}
	}
	for _, operation := range g.Operations {
		switch strings.TrimSpace(operation) {
		case "git.receive-pack", "pull.create":
		default:
			return fmt.Errorf("operations currently supports only git.receive-pack and pull.create")
		}
	}
	return nil
}
