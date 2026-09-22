// Package config loads and validates broker YAML configuration.
package config

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server         ServerConfig         `yaml:"server"`
	Audit          AuditConfig          `yaml:"audit"`
	GitHub         GitHubConfig         `yaml:"github"`
	MutationLimits MutationLimitsConfig `yaml:"mutation_limits"`
	Idempotency    IdempotencyConfig    `yaml:"idempotency"`
	PushTripwire   PushTripwireConfig   `yaml:"push_tripwire"`
	Correlation    CorrelationConfig    `yaml:"correlation"`
	Agents         []Agent              `yaml:"agents"`
}

// CorrelationConfig enables authenticated run-to-PR correlation on pull.create.
// It is OPT-IN: when store_path and a capability API (url + token) are all set,
// pull.create requires a verified per-run capability handle, records the
// correlation + outbox event atomically after GitHub returns, and fails closed
// on a missing/invalid/revoked/expired handle. When unset, pull.create keeps its
// legacy behavior and records nothing.
//
// capability_api_url is the broker's PRIVATE capability API base (the sandbox
// broker that mounts /v1/capabilities/*). capability_api_token is the
// deployment-owned token that authenticates the broker to that API — it is held
// ONLY by the broker, is never a run's handle, and is never placed in a launched
// run's environment, metadata, log, or audit.
type CorrelationConfig struct {
	StorePath             string `yaml:"store_path"`
	CapabilityAPIURL      string `yaml:"capability_api_url"`
	CapabilityAPIToken    string `yaml:"capability_api_token"`
	CapabilityAPITokenEnv string `yaml:"capability_api_token_env"`

	// Outbox is the PRODUCTION-ACTIVATION contract for the private outbox
	// claim/ack/reclaim API that Signal Plane consumes. It is a separate,
	// independently-gated surface: correlation RECORDING (above) can be enabled
	// without exposing the outbox API, and the outbox API is inert until its own
	// token is configured. The token here is the deployment-owned bearer secret
	// that Signal Plane PRESENTS TO the broker to drain the outbox — it is NOT
	// the capability_api_token the broker presents to the sandbox broker, and it
	// is NEVER injected into a launched run's env, metadata, log, or response.
	Outbox OutboxAPIConfig `yaml:"outbox"`
}

// OutboxAPIConfig is the deployment-owned contract for the private outbox
// consumer API. It is validated but NEVER auto-enabled: OutboxEnabled reports
// true only when a store and a consumer token are both configured, and even
// then the endpoints are mounted by the server only if correlation recording is
// itself configured (a store with no recorder has nothing to drain).
type OutboxAPIConfig struct {
	// ConsumerToken authenticates the outbox consumer (Signal Plane) to the
	// broker. Empty leaves the outbox API inert (unmounted). It is compared
	// constant-time and never echoed.
	ConsumerToken string `yaml:"consumer_token"`
	// ConsumerTokenEnv names an environment variable the token is read from when
	// ConsumerToken is empty. Deployment-owned; the raw secret stays out of the
	// config file on disk.
	ConsumerTokenEnv string `yaml:"consumer_token_env"`
	// ClaimTTLSeconds bounds how long a claim is held before it is reclaimable by
	// another consumer (crash recovery). Zero applies DefaultOutboxClaimTTL.
	ClaimTTLSeconds int `yaml:"claim_ttl_seconds"`
	// MaxClaimBatch bounds how many events one claim call may take. Zero applies
	// DefaultOutboxMaxClaimBatch. It is a hard backstop against an unbounded
	// claim; the consumer may always ask for fewer.
	MaxClaimBatch int `yaml:"max_claim_batch"`
}

const (
	// DefaultOutboxClaimTTL is the claim lease applied when ClaimTTLSeconds is 0.
	DefaultOutboxClaimTTLSeconds = 300
	// minOutboxClaimTTLSeconds / maxOutboxClaimTTLSeconds bound a configured
	// lease: too short strands in-flight deliveries as reclaimable mid-flight,
	// too long delays crash recovery.
	minOutboxClaimTTLSeconds = 30
	maxOutboxClaimTTLSeconds = 3600
	// DefaultOutboxMaxClaimBatch is the batch cap applied when MaxClaimBatch is 0.
	DefaultOutboxMaxClaimBatch = 100
	// maxOutboxMaxClaimBatch is the hard ceiling on a configured claim batch.
	maxOutboxMaxClaimBatch = 1000
)

// OutboxEnabled reports whether the private outbox consumer API is configured.
// It requires the correlation store (there is nothing to drain otherwise) and a
// consumer token. It is independent of whether correlation RECORDING is enabled;
// the server additionally requires recording before mounting the endpoints.
func (c CorrelationConfig) OutboxEnabled() bool {
	return strings.TrimSpace(c.StorePath) != "" &&
		strings.TrimSpace(c.Outbox.ConsumerToken) != ""
}

// OutboxClaimTTLSeconds returns the effective claim lease, applying the default
// when unset.
func (c CorrelationConfig) OutboxClaimTTLSeconds() int {
	if c.Outbox.ClaimTTLSeconds <= 0 {
		return DefaultOutboxClaimTTLSeconds
	}
	return c.Outbox.ClaimTTLSeconds
}

// OutboxMaxClaimBatch returns the effective claim batch cap, applying the
// default when unset.
func (c CorrelationConfig) OutboxMaxClaimBatch() int {
	if c.Outbox.MaxClaimBatch <= 0 {
		return DefaultOutboxMaxClaimBatch
	}
	return c.Outbox.MaxClaimBatch
}

// Enabled reports whether authenticated correlation is fully configured.
func (c CorrelationConfig) Enabled() bool {
	return strings.TrimSpace(c.StorePath) != "" &&
		strings.TrimSpace(c.CapabilityAPIURL) != "" &&
		strings.TrimSpace(c.CapabilityAPIToken) != ""
}

type PushTripwireConfig struct {
	Enabled          bool                                   `yaml:"enabled"`
	ScannerID        string                                 `yaml:"scanner_id"`
	ScannerSecret    string                                 `yaml:"scanner_secret"`
	ScannerSecretEnv string                                 `yaml:"scanner_secret_env"`
	StatePath        string                                 `yaml:"state_path"`
	Repositories     map[string]PushTripwireRepository      `yaml:"repositories"`
	ResponseProfiles map[string]PushTripwireResponseProfile `yaml:"response_profiles"`
	Bounds           PushTripwireBounds                     `yaml:"bounds"`
}

type PushTripwireRepository struct {
	GitHubApp   string   `yaml:"github_app"`
	BaseRef     string   `yaml:"base_ref"`
	RefPatterns []string `yaml:"ref_patterns"`
}

type PushTripwireResponseProfile struct {
	Generation int64                 `yaml:"generation"`
	AllowHalt  bool                  `yaml:"allow_halt"`
	AllowFence bool                  `yaml:"allow_fence"`
	Bindings   []PushTripwireBinding `yaml:"bindings"`
}

type PushTripwireBinding struct {
	WorkerID               string `yaml:"worker_id"`
	LogicalSessionID       string `yaml:"logical_session_id"`
	SessionLineageID       string `yaml:"session_lineage_id"`
	WorkerStorageLineageID string `yaml:"worker_storage_lineage_id"`
	WorkerFenceEpoch       int64  `yaml:"worker_fence_epoch"`
}

type PushTripwireBounds struct {
	MaxCommits            int   `yaml:"max_commits"`
	MaxPaths              int   `yaml:"max_paths"`
	MaxCommitMessageBytes int64 `yaml:"max_commit_message_bytes"`
	MaxBlobBytes          int64 `yaml:"max_blob_bytes"`
	MaxTotalBytes         int64 `yaml:"max_total_bytes"`
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

type GitReceivePackPolicy string

const (
	GitReceivePackAllowOpaque GitReceivePackPolicy = "allow_opaque"
	GitReceivePackDenyOpaque  GitReceivePackPolicy = "deny_opaque"
)

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
	GitReceivePack     GitReceivePackPolicy       `yaml:"git_receive_pack_policy"`
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
	if c.PushTripwire.Bounds.MaxCommits == 0 {
		c.PushTripwire.Bounds.MaxCommits = 100
	}
	if c.PushTripwire.Bounds.MaxPaths == 0 {
		c.PushTripwire.Bounds.MaxPaths = 300
	}
	if c.PushTripwire.Bounds.MaxCommitMessageBytes == 0 {
		c.PushTripwire.Bounds.MaxCommitMessageBytes = 64 << 10
	}
	if c.PushTripwire.Bounds.MaxBlobBytes == 0 {
		c.PushTripwire.Bounds.MaxBlobBytes = 1 << 20
	}
	if c.PushTripwire.Bounds.MaxTotalBytes == 0 {
		c.PushTripwire.Bounds.MaxTotalBytes = 16 << 20
	}
	for i := range c.Agents {
		c.Agents[i].BranchGuard.applyDefaults()
		if c.Agents[i].GitReceivePack == "" {
			c.Agents[i].GitReceivePack = GitReceivePackAllowOpaque
		}
	}
}

func (c *Config) resolveSecrets() error {
	if c.Server.AdminSecret == "" && c.Server.AdminSecretEnv != "" {
		c.Server.AdminSecret = os.Getenv(c.Server.AdminSecretEnv)
	}
	if c.PushTripwire.ScannerSecret == "" && c.PushTripwire.ScannerSecretEnv != "" {
		c.PushTripwire.ScannerSecret = os.Getenv(c.PushTripwire.ScannerSecretEnv)
	}
	if c.Correlation.CapabilityAPIToken == "" && c.Correlation.CapabilityAPITokenEnv != "" {
		c.Correlation.CapabilityAPIToken = os.Getenv(c.Correlation.CapabilityAPITokenEnv)
	}
	if c.Correlation.Outbox.ConsumerToken == "" && c.Correlation.Outbox.ConsumerTokenEnv != "" {
		c.Correlation.Outbox.ConsumerToken = os.Getenv(c.Correlation.Outbox.ConsumerTokenEnv)
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
	if c.PushTripwire.Enabled {
		if c.PushTripwire.ScannerID == "" {
			errs = append(errs, "push_tripwire scanner_id is required")
		}
		if c.PushTripwire.ScannerSecret == "" {
			errs = append(errs, "push_tripwire scanner_secret or scanner_secret_env is required")
		}
		if c.PushTripwire.StatePath == "" {
			errs = append(errs, "push_tripwire state_path is required")
		}
		if len(c.PushTripwire.Repositories) == 0 {
			errs = append(errs, "push_tripwire repositories must not be empty")
		}
		if len(c.PushTripwire.ResponseProfiles) == 0 {
			errs = append(errs, "push_tripwire response_profiles must not be empty")
		}
		for profile, scope := range c.PushTripwire.ResponseProfiles {
			if profile == "" || scope.Generation < 1 || (!scope.AllowHalt && !scope.AllowFence) {
				errs = append(errs, fmt.Sprintf("push_tripwire response profile %q has invalid generation or no allowed actions", profile))
			}
			if scope.AllowFence && len(scope.Bindings) == 0 {
				errs = append(errs, fmt.Sprintf("push_tripwire response profile %q allows fencing without reviewed bindings", profile))
			}
			for _, binding := range scope.Bindings {
				if binding.WorkerID == "" || binding.LogicalSessionID == "" || binding.SessionLineageID == "" || binding.WorkerStorageLineageID == "" || binding.WorkerFenceEpoch < 1 {
					errs = append(errs, fmt.Sprintf("push_tripwire response profile %q has an incomplete binding", profile))
				}
			}
		}
		b := c.PushTripwire.Bounds
		if b.MaxCommits < 1 || b.MaxCommits > 1000 || b.MaxPaths < 1 || b.MaxPaths > 3000 || b.MaxCommitMessageBytes < 1 || b.MaxCommitMessageBytes > 1<<20 || b.MaxBlobBytes < 1 || b.MaxBlobBytes > 10<<20 || b.MaxTotalBytes < 1 || b.MaxTotalBytes > 64<<20 {
			errs = append(errs, "push_tripwire bounds are outside supported limits")
		}
		for repo, tripwireRepo := range c.PushTripwire.Repositories {
			if strings.Count(repo, "/") != 1 || strings.ToLower(repo) != repo {
				errs = append(errs, fmt.Sprintf("push_tripwire repository %q must be lowercase owner/repo", repo))
				continue
			}
			appName := tripwireRepo.GitHubApp
			if appName == "" {
				appName = "default"
			}
			if _, ok := c.InstallationIDForApp(appName, repo); !ok {
				errs = append(errs, fmt.Sprintf("push_tripwire repository %q is not covered by github app %q", repo, appName))
			}
			if !strings.HasPrefix(tripwireRepo.BaseRef, "refs/heads/") || len(tripwireRepo.BaseRef) > 240 {
				errs = append(errs, fmt.Sprintf("push_tripwire repository %q requires a reviewed refs/heads base_ref", repo))
			}
			if len(tripwireRepo.RefPatterns) == 0 {
				errs = append(errs, fmt.Sprintf("push_tripwire repository %q requires reviewed ref_patterns", repo))
			}
			for _, pattern := range tripwireRepo.RefPatterns {
				if !strings.HasPrefix(pattern, "^") || !strings.HasSuffix(pattern, "$") {
					errs = append(errs, fmt.Sprintf("push_tripwire repository %q ref pattern must be anchored", repo))
					continue
				}
				if _, err := regexp.Compile(pattern); err != nil {
					errs = append(errs, fmt.Sprintf("push_tripwire repository %q has invalid ref pattern", repo))
				}
			}
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
		if a.GitReceivePack != "" && a.GitReceivePack != GitReceivePackAllowOpaque && a.GitReceivePack != GitReceivePackDenyOpaque {
			errs = append(errs, fmt.Sprintf("agent %q git_receive_pack_policy must be allow_opaque or deny_opaque", a.ID))
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
	errs = append(errs, c.Correlation.validationErrors()...)
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

// validationErrors reports correlation misconfiguration. Correlation is all or
// nothing: a store without a capability API (or vice versa) would silently
// fail to enforce authenticated identity, so a partial configuration is
// rejected rather than half-enabled.
func (c CorrelationConfig) validationErrors() []string {
	store := strings.TrimSpace(c.StorePath)
	url := strings.TrimSpace(c.CapabilityAPIURL)
	token := strings.TrimSpace(c.CapabilityAPIToken)
	tokenEnv := strings.TrimSpace(c.CapabilityAPITokenEnv)
	var errs []string
	anySet := store != "" || url != "" || token != "" || tokenEnv != ""
	if !anySet {
		return nil
	}
	if store != "" && !isAbsPath(store) {
		errs = append(errs, "correlation.store_path must be an absolute path")
	}
	if store == "" {
		errs = append(errs, "correlation.capability_api_* is set without correlation.store_path")
	}
	if url == "" {
		errs = append(errs, "correlation requires correlation.capability_api_url")
	} else if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		errs = append(errs, "correlation.capability_api_url must be an http(s) URL")
	}
	if token == "" {
		errs = append(errs, "correlation requires correlation.capability_api_token or capability_api_token_env")
	}
	errs = append(errs, c.outboxValidationErrors()...)
	return errs
}

// outboxValidationErrors validates the outbox consumer-API activation contract.
// The API is INERT by default: with no outbox fields set it contributes no
// errors and mounts nothing. Once any outbox field is set the contract is
// checked as a whole so a partial/misbounded activation is rejected rather than
// half-enabled: a consumer token requires a store to drain, and the claim TTL /
// batch bounds must sit inside supported limits. Validation NEVER enables or
// deploys the API; it only refuses an incoherent configuration.
func (c CorrelationConfig) outboxValidationErrors() []string {
	store := strings.TrimSpace(c.StorePath)
	consumerToken := strings.TrimSpace(c.Outbox.ConsumerToken)
	consumerTokenEnv := strings.TrimSpace(c.Outbox.ConsumerTokenEnv)
	ttl := c.Outbox.ClaimTTLSeconds
	batch := c.Outbox.MaxClaimBatch

	anySet := consumerToken != "" || consumerTokenEnv != "" || ttl != 0 || batch != 0
	if !anySet {
		return nil
	}
	var errs []string
	if consumerToken == "" {
		errs = append(errs, "correlation.outbox requires correlation.outbox.consumer_token or consumer_token_env")
	}
	if store == "" {
		errs = append(errs, "correlation.outbox is set without correlation.store_path")
	}
	if ttl != 0 && (ttl < minOutboxClaimTTLSeconds || ttl > maxOutboxClaimTTLSeconds) {
		errs = append(errs, fmt.Sprintf("correlation.outbox.claim_ttl_seconds must be between %d and %d", minOutboxClaimTTLSeconds, maxOutboxClaimTTLSeconds))
	}
	if batch != 0 && (batch < 1 || batch > maxOutboxMaxClaimBatch) {
		errs = append(errs, fmt.Sprintf("correlation.outbox.max_claim_batch must be between 1 and %d", maxOutboxMaxClaimBatch))
	}
	return errs
}

func isAbsPath(p string) bool { return strings.HasPrefix(p, "/") }

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
