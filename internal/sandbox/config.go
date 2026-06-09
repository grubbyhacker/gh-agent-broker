// Package sandbox implements the task-isolated sandbox MCP broker.
package sandbox

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	defaultListen       = "127.0.0.1:8091"
	defaultMCPPath      = "/mcp"
	defaultRunsDir      = "/srv/hermes-sandbox-broker/runs"
	defaultMaxTaskBytes = 64 * 1024
	defaultLogByteLimit = 128 * 1024
)

type Config struct {
	Listen             string                       `yaml:"listen"`
	MCPPath            string                       `yaml:"mcp_path"`
	AuthToken          string                       `yaml:"auth_token"`
	AuthTokenEnv       string                       `yaml:"auth_token_env"`
	RunsDir            string                       `yaml:"runs_dir"`
	BrokerURL          string                       `yaml:"broker_url"`
	Production         bool                         `yaml:"production"`
	Repositories       []string                     `yaml:"repositories"`
	Networks           map[string]NetworkPolicy     `yaml:"network_policies"`
	Bundles            map[string]CredentialBundle  `yaml:"credential_bundles"`
	Templates          map[string]Template          `yaml:"templates"`
	LaunchProfiles     map[string]LaunchProfile     `yaml:"launch_profiles"`
	OperatorPrincipals map[string]OperatorPrincipal `yaml:"operator_principals"`
	Audit              SandboxAuditConfig           `yaml:"audit"`
	MaxTaskBytes       int                          `yaml:"max_task_bytes"`
	LogByteLimit       int                          `yaml:"log_byte_limit"`
	StopGrace          Duration                     `yaml:"stop_grace"`
	ResolvedPaths      map[string]CredentialBundle  `yaml:"-"`
}

type SandboxAuditConfig struct {
	Path string `yaml:"path"`
}

type NetworkPolicy struct {
	Network string `yaml:"network"`
	None    bool   `yaml:"none"`
}

type CredentialBundle struct {
	SourcePath       string   `yaml:"source_path"`
	MountPath        string   `yaml:"mount_path"`
	ReadOnly         bool     `yaml:"readonly"`
	AllowedTemplates []string `yaml:"allowed_templates"`
	SecretFiles      []string `yaml:"secret_files"`
	RedactFiles      []string `yaml:"redact_files"`
}

type Template struct {
	Image              string            `yaml:"image"`
	Command            []string          `yaml:"command"`
	User               string            `yaml:"user"`
	Resources          Resources         `yaml:"resources"`
	NetworkPolicy      string            `yaml:"network_policy"`
	MaxRuntimeMinutes  int               `yaml:"max_runtime_minutes"`
	BrokerAgentID      string            `yaml:"broker_agent_id"`
	BrokerAgentSecret  string            `yaml:"broker_agent_secret"`
	BrokerSecretEnv    string            `yaml:"broker_agent_secret_env"`
	BranchPolicy       BranchPolicy      `yaml:"branch_policy"`
	CredentialBundle   string            `yaml:"credential_bundle"`
	Deliverables       []string          `yaml:"deliverables"`
	KnowledgeSnapshots []string          `yaml:"knowledge_snapshots"`
	Environment        map[string]string `yaml:"environment"`
	ExtraMounts        []ExtraMount      `yaml:"extra_mounts"`
}

type ExtraMount struct {
	SourcePath string `yaml:"source_path"`
	MountPath  string `yaml:"mount_path"`
	ReadOnly   bool   `yaml:"readonly"`
}

type Resources struct {
	CPUShares int   `yaml:"cpu_shares"`
	MemoryMB  int64 `yaml:"memory_mb"`
	PidsLimit int64 `yaml:"pids_limit"`
}

type BranchPolicy struct {
	AllowedPatterns []string `yaml:"allowed_patterns"`
	BaseBranches    []string `yaml:"base_branches"`
	GeneratePrefix  string   `yaml:"generate_prefix"`
}

type LaunchProfile struct {
	LaunchAgentInput `yaml:",inline"`
	AllowOverrides   []string `yaml:"allow_overrides"`
}

type OperatorPrincipal struct {
	Token           string   `yaml:"token"`
	TokenEnv        string   `yaml:"token_env"`
	AllowedProfiles []string `yaml:"allowed_profiles"`
	AllowedActions  []string `yaml:"allowed_actions"`
}

type Duration struct {
	time.Duration
}

func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	if value == nil || value.Value == "" {
		return nil
	}
	if value.Tag == "!!int" {
		var seconds int64
		if err := value.Decode(&seconds); err != nil {
			return err
		}
		d.Duration = time.Duration(seconds) * time.Second
		return nil
	}
	parsed, err := time.ParseDuration(value.Value)
	if err != nil {
		return err
	}
	d.Duration = parsed
	return nil
}

func Load(path string) (Config, error) {
	// #nosec G304 -- config path is supplied by the operator on sandbox startup.
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var cfg Config
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return Config{}, err
	}
	cfg.ApplyDefaults()
	cfg.ResolveSecrets()
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c *Config) ApplyDefaults() {
	if c.Listen == "" {
		c.Listen = defaultListen
	}
	if c.MCPPath == "" {
		c.MCPPath = defaultMCPPath
	}
	if c.RunsDir == "" {
		c.RunsDir = defaultRunsDir
	}
	if c.MaxTaskBytes == 0 {
		c.MaxTaskBytes = defaultMaxTaskBytes
	}
	if c.LogByteLimit == 0 {
		c.LogByteLimit = defaultLogByteLimit
	}
	if c.StopGrace.Duration == 0 {
		c.StopGrace.Duration = 10 * time.Second
	}
}

func (c *Config) ResolveSecrets() {
	if c.AuthToken == "" && c.AuthTokenEnv != "" {
		c.AuthToken = os.Getenv(c.AuthTokenEnv)
	}
	for name, tmpl := range c.Templates {
		if tmpl.BrokerAgentSecret == "" && tmpl.BrokerSecretEnv != "" {
			tmpl.BrokerAgentSecret = os.Getenv(tmpl.BrokerSecretEnv)
			c.Templates[name] = tmpl
		}
	}
	for name, principal := range c.OperatorPrincipals {
		if principal.Token == "" && principal.TokenEnv != "" {
			principal.Token = os.Getenv(principal.TokenEnv)
			c.OperatorPrincipals[name] = principal
		}
	}
}

func (c *Config) Validate() error {
	var errs []string
	if strings.TrimSpace(c.AuthToken) == "" {
		errs = append(errs, "auth_token or auth_token_env is required")
	}
	if strings.TrimSpace(c.BrokerURL) == "" {
		errs = append(errs, "broker_url is required")
	}
	if !filepath.IsAbs(c.RunsDir) {
		errs = append(errs, "runs_dir must be an absolute path")
	}
	if c.MaxTaskBytes < 1 {
		errs = append(errs, "max_task_bytes must be positive")
	}
	if c.LogByteLimit < 1 {
		errs = append(errs, "log_byte_limit must be positive")
	}
	if len(c.Repositories) == 0 {
		errs = append(errs, "repositories must not be empty")
	}
	for _, repo := range c.Repositories {
		if !validRepo(repo) {
			errs = append(errs, fmt.Sprintf("repository %q must be owner/repo", repo))
		}
	}
	if len(c.Networks) == 0 {
		errs = append(errs, "network_policies must not be empty")
	}
	for name, network := range c.Networks {
		if name == "" {
			errs = append(errs, "network policy name is required")
		}
		if network.None && network.Network != "" {
			errs = append(errs, fmt.Sprintf("network policy %q cannot set both none and network", name))
		}
		if !network.None && network.Network == "" {
			errs = append(errs, fmt.Sprintf("network policy %q must set network or none", name))
		}
		if strings.EqualFold(network.Network, "host") || strings.HasPrefix(network.Network, "container:") {
			errs = append(errs, fmt.Sprintf("network policy %q cannot use host or container network namespace", name))
		}
	}
	for name, bundle := range c.Bundles {
		errs = append(errs, validateBundle(name, bundle)...)
	}
	if len(c.Templates) == 0 {
		errs = append(errs, "templates must not be empty")
	}
	for name, tmpl := range c.Templates {
		errs = append(errs, c.validateTemplate(name, tmpl)...)
	}
	for name, profile := range c.LaunchProfiles {
		errs = append(errs, c.validateLaunchProfile(name, profile)...)
	}
	for name, principal := range c.OperatorPrincipals {
		errs = append(errs, c.validateOperatorPrincipal(name, principal)...)
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

func validateBundle(name string, bundle CredentialBundle) []string {
	var errs []string
	if name == "" {
		errs = append(errs, "credential bundle name is required")
	}
	if !filepath.IsAbs(bundle.SourcePath) {
		errs = append(errs, fmt.Sprintf("credential bundle %q source_path must be absolute", name))
	}
	if !filepath.IsAbs(bundle.MountPath) {
		errs = append(errs, fmt.Sprintf("credential bundle %q mount_path must be absolute", name))
	}
	if !bundle.ReadOnly {
		errs = append(errs, fmt.Sprintf("credential bundle %q readonly must be true", name))
	}
	if filepath.Clean(bundle.SourcePath) == "/var/run/docker.sock" || strings.HasPrefix(filepath.Clean(bundle.SourcePath), "/var/run/docker.sock/") {
		errs = append(errs, fmt.Sprintf("credential bundle %q cannot mount Docker socket", name))
	}
	if bundle.MountPath == "/" || strings.HasPrefix(bundle.MountPath, "/input") || strings.HasPrefix(bundle.MountPath, "/work") ||
		strings.HasPrefix(bundle.MountPath, "/output") || strings.HasPrefix(bundle.MountPath, "/lessons") {
		errs = append(errs, fmt.Sprintf("credential bundle %q mount_path conflicts with sandbox paths", name))
	}
	for _, p := range append(bundle.SecretFiles, bundle.RedactFiles...) {
		if !safeRelativePath(p) {
			errs = append(errs, fmt.Sprintf("credential bundle %q redaction path %q is unsafe", name, p))
		}
	}
	return errs
}

func (c Config) validateTemplate(name string, tmpl Template) []string {
	var errs []string
	if name == "" {
		errs = append(errs, "template name is required")
	}
	if strings.TrimSpace(tmpl.Image) == "" {
		errs = append(errs, fmt.Sprintf("template %q image is required", name))
	}
	if c.Production && !strings.Contains(tmpl.Image, "@sha256:") {
		errs = append(errs, fmt.Sprintf("template %q image must be pinned by digest in production mode", name))
	}
	if len(tmpl.Command) == 0 {
		errs = append(errs, fmt.Sprintf("template %q command is required", name))
	}
	if strings.TrimSpace(tmpl.User) == "" || tmpl.User == "0" || tmpl.User == "root" {
		errs = append(errs, fmt.Sprintf("template %q must set a non-root user", name))
	}
	if tmpl.NetworkPolicy == "" {
		errs = append(errs, fmt.Sprintf("template %q network_policy is required", name))
	} else if _, ok := c.Networks[tmpl.NetworkPolicy]; !ok {
		errs = append(errs, fmt.Sprintf("template %q references unknown network_policy %q", name, tmpl.NetworkPolicy))
	}
	if tmpl.MaxRuntimeMinutes < 1 {
		errs = append(errs, fmt.Sprintf("template %q max_runtime_minutes must be positive", name))
	}
	if strings.TrimSpace(tmpl.BrokerAgentID) == "" {
		errs = append(errs, fmt.Sprintf("template %q broker_agent_id is required", name))
	}
	if tmpl.BrokerAgentSecret == "" {
		errs = append(errs, fmt.Sprintf("template %q broker_agent_secret or broker_agent_secret_env is required", name))
	}
	if tmpl.CredentialBundle != "" {
		bundle, ok := c.Bundles[tmpl.CredentialBundle]
		if !ok {
			errs = append(errs, fmt.Sprintf("template %q references unknown credential_bundle %q", name, tmpl.CredentialBundle))
		} else if !contains(bundle.AllowedTemplates, name) {
			errs = append(errs, fmt.Sprintf("credential_bundle %q does not allow template %q", tmpl.CredentialBundle, name))
		}
	}
	for _, pattern := range tmpl.BranchPolicy.AllowedPatterns {
		if _, err := regexp.Compile(pattern); err != nil {
			errs = append(errs, fmt.Sprintf("template %q has invalid branch pattern %q", name, pattern))
		}
	}
	for _, path := range tmpl.KnowledgeSnapshots {
		if !filepath.IsAbs(path) {
			errs = append(errs, fmt.Sprintf("template %q knowledge snapshot %q must be absolute", name, path))
		}
	}
	for i, mount := range tmpl.ExtraMounts {
		errs = append(errs, validateExtraMount(name, i, mount)...)
	}
	return errs
}

func validateExtraMount(template string, idx int, mount ExtraMount) []string {
	var errs []string
	name := fmt.Sprintf("template %q extra_mounts[%d]", template, idx)
	source := filepath.Clean(mount.SourcePath)
	target := filepath.Clean(mount.MountPath)
	if !filepath.IsAbs(mount.SourcePath) {
		errs = append(errs, fmt.Sprintf("%s source_path must be absolute", name))
	}
	if !filepath.IsAbs(mount.MountPath) {
		errs = append(errs, fmt.Sprintf("%s mount_path must be absolute", name))
	}
	if source == "/" || source == "/var/run/docker.sock" || strings.HasPrefix(source, "/var/run/docker.sock/") {
		errs = append(errs, fmt.Sprintf("%s source_path is not allowed", name))
	}
	if target == "/" || target == "/input" || target == "/work" || target == "/output" || target == "/lessons" ||
		strings.HasPrefix(target, "/input/") || strings.HasPrefix(target, "/work/") || strings.HasPrefix(target, "/output/") || strings.HasPrefix(target, "/lessons/") {
		errs = append(errs, fmt.Sprintf("%s mount_path conflicts with sandbox-managed paths", name))
	}
	return errs
}

func (c Config) validateLaunchProfile(name string, profile LaunchProfile) []string {
	var errs []string
	if name == "" {
		errs = append(errs, "launch profile name is required")
	}
	tmpl, ok := c.Templates[profile.Template]
	if strings.TrimSpace(profile.Template) == "" {
		errs = append(errs, fmt.Sprintf("launch profile %q template is required", name))
	} else if !ok {
		errs = append(errs, fmt.Sprintf("launch profile %q references unknown template %q", name, profile.Template))
	}
	if !validRepo(profile.Repo) {
		errs = append(errs, fmt.Sprintf("launch profile %q repo must be owner/repo", name))
	} else if !containsFold(c.Repositories, profile.Repo) {
		errs = append(errs, fmt.Sprintf("launch profile %q repo %q is not allowed", name, profile.Repo))
	}
	if strings.TrimSpace(profile.Task) == "" {
		errs = append(errs, fmt.Sprintf("launch profile %q task is required", name))
	} else if len(profile.Task) > c.MaxTaskBytes {
		errs = append(errs, fmt.Sprintf("launch profile %q task exceeds max_task_bytes", name))
	}
	if strings.TrimSpace(profile.BaseBranch) == "" {
		errs = append(errs, fmt.Sprintf("launch profile %q base_branch is required", name))
	}
	if ok {
		if len(tmpl.BranchPolicy.BaseBranches) > 0 && !contains(tmpl.BranchPolicy.BaseBranches, profile.BaseBranch) {
			errs = append(errs, fmt.Sprintf("launch profile %q base_branch %q is not allowed by template", name, profile.BaseBranch))
		}
		if profile.Branch != "" {
			if !safeBranch(profile.Branch) {
				errs = append(errs, fmt.Sprintf("launch profile %q branch %q is unsafe", name, profile.Branch))
			} else if len(tmpl.BranchPolicy.AllowedPatterns) > 0 && !matchesAny(tmpl.BranchPolicy.AllowedPatterns, profile.Branch) {
				errs = append(errs, fmt.Sprintf("launch profile %q branch %q does not match template branch policy", name, profile.Branch))
			}
		}
		if profile.MaxRuntimeMinutes < 0 || profile.MaxRuntimeMinutes > tmpl.MaxRuntimeMinutes {
			errs = append(errs, fmt.Sprintf("launch profile %q max_runtime_minutes must be between 1 and %d when set", name, tmpl.MaxRuntimeMinutes))
		}
	}
	for _, field := range profile.AllowOverrides {
		if !launchOverrideFieldAllowed(field) {
			errs = append(errs, fmt.Sprintf("launch profile %q allow_overrides contains unsupported field %q", name, field))
		}
	}
	return errs
}

func (c Config) validateOperatorPrincipal(name string, principal OperatorPrincipal) []string {
	var errs []string
	if name == "" {
		errs = append(errs, "operator principal name is required")
	}
	if strings.TrimSpace(principal.Token) == "" {
		errs = append(errs, fmt.Sprintf("operator principal %q token or token_env is required", name))
	}
	if len(principal.AllowedProfiles) == 0 {
		errs = append(errs, fmt.Sprintf("operator principal %q allowed_profiles must not be empty", name))
	}
	for _, profile := range principal.AllowedProfiles {
		if _, ok := c.LaunchProfiles[profile]; !ok {
			errs = append(errs, fmt.Sprintf("operator principal %q references unknown launch profile %q", name, profile))
		}
	}
	if len(principal.AllowedActions) == 0 {
		errs = append(errs, fmt.Sprintf("operator principal %q allowed_actions must not be empty", name))
	}
	for _, action := range principal.AllowedActions {
		if !validOperatorAction(action) {
			errs = append(errs, fmt.Sprintf("operator principal %q has unsupported action %q", name, action))
		}
	}
	return errs
}

func validOperatorAction(action string) bool {
	switch action {
	case "launch", "dry_run", "status", "logs", "artifacts", "stop", "cleanup":
		return true
	default:
		return false
	}
}

func launchOverrideFieldAllowed(field string) bool {
	switch field {
	case "task", "focus", "deliverables", "max_runtime_minutes", "branch", "base_branch", "repo", "template":
		return true
	default:
		return false
	}
}

func contains(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

func containsFold(items []string, want string) bool {
	for _, item := range items {
		if strings.EqualFold(item, want) {
			return true
		}
	}
	return false
}

func safeRelativePath(p string) bool {
	if p == "" || filepath.IsAbs(p) {
		return false
	}
	clean := filepath.Clean(p)
	return clean != "." && clean == p && !strings.HasPrefix(clean, ".."+string(filepath.Separator)) && clean != ".."
}

func validRepo(repo string) bool {
	parts := strings.Split(repo, "/")
	if len(parts) != 2 {
		return false
	}
	for _, part := range parts {
		if part == "" || strings.Contains(part, ".git") || strings.ContainsAny(part, "\\:") {
			return false
		}
		if strings.Contains(part, "..") {
			return false
		}
	}
	return true
}
