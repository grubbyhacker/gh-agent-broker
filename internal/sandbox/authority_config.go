package sandbox

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// AuthorityProfile is an operator-reviewed, immutable authority boundary.
// The agentd command and session-isolation primitive are intentionally absent
// until those production contracts are versioned; callers can only select a
// registered profile.
type AuthorityProfile struct {
	Image string `json:"image" yaml:"image"`
	// Platform is a reviewed runtime constraint, not a caller preference. The
	// first authority-worker release is published only for linux/amd64.
	Platform string `json:"platform" yaml:"platform"`
	// Command is deliberately not configurable by callers.  The only accepted
	// authority worker process is the agentd bootstrap command from agentd's
	// immutable OCI contract.
	Command             []string         `json:"command" yaml:"command"`
	Resources           Resources        `json:"resources" yaml:"resources"`
	NetworkPolicy       string           `json:"network_policy" yaml:"network_policy"`
	BrokerAgentID       string           `json:"broker_agent_id" yaml:"broker_agent_id"`
	BrokerSecretEnv     string           `json:"broker_agent_secret_env" yaml:"broker_agent_secret_env"`
	CoordinatorTokenEnv string           `json:"coordinator_token_env" yaml:"coordinator_token_env"`
	CredentialBundle    string           `json:"credential_bundle,omitempty" yaml:"credential_bundle"`
	Repositories        []string         `json:"repositories" yaml:"repositories"`
	BranchPolicy        BranchPolicy     `json:"branch_policy" yaml:"branch_policy"`
	Operations          []string         `json:"operations" yaml:"operations"`
	ExtraMounts         []ExtraMount     `json:"extra_mounts,omitempty" yaml:"extra_mounts"`
	SessionIsolation    SessionIsolation `json:"session_isolation" yaml:"session_isolation"`
	Checkpoint          CheckpointPolicy `json:"checkpoint" yaml:"checkpoint"`
	Storage             AuthorityStorage `json:"storage" yaml:"storage"`
	MaxWorkers          int              `json:"max_workers" yaml:"max_workers"`
	SessionCapacity     int              `json:"session_capacity" yaml:"session_capacity"`
}

// SessionIsolation is immutable worker policy. PR 8 intentionally allocates
// the UID/GID range but does not create logical sessions; PR 9 consumes it.
type SessionIsolation struct {
	Primitive     string `json:"primitive" yaml:"primitive"`
	WorkspaceRoot string `json:"workspace_root" yaml:"workspace_root"`
	UIDStart      int    `json:"uid_start" yaml:"uid_start"`
	GIDStart      int    `json:"gid_start" yaml:"gid_start"`
}

type CheckpointPolicy struct {
	Directory string `json:"directory" yaml:"directory"`
	KeyEnv    string `json:"key_env" yaml:"key_env"`
}
type AuthorityStorage struct {
	SessionVolume    string `json:"session_volume" yaml:"session_volume"`
	CheckpointVolume string `json:"checkpoint_volume" yaml:"checkpoint_volume"`
	EvidenceVolume   string `json:"evidence_volume" yaml:"evidence_volume"`
}

var fixedAgentdCommand = []string{"bun", "run", "src/cli.ts", "serve"}

type AuthorityPrincipal struct {
	Token           string   `json:"-" yaml:"token"`
	TokenEnv        string   `json:"-" yaml:"token_env"`
	AllowedProfiles []string `json:"allowed_profiles" yaml:"allowed_profiles"`
	AllowedActions  []string `json:"allowed_actions" yaml:"allowed_actions"`
}

func (c Config) validateAuthorityProfile(name string, profile AuthorityProfile) []string {
	var errs []string
	if !safeAuthorityName(name) {
		errs = append(errs, fmt.Sprintf("authority profile %q has an invalid name", name))
	}
	if strings.TrimSpace(profile.Image) == "" {
		errs = append(errs, fmt.Sprintf("authority profile %q image is required", name))
	} else if c.Production && !regexp.MustCompile(`@sha256:[0-9a-f]{64}$`).MatchString(profile.Image) {
		errs = append(errs, fmt.Sprintf("authority profile %q image must be pinned by digest in production mode", name))
	}
	if profile.Platform != "linux/amd64" {
		errs = append(errs, fmt.Sprintf("authority profile %q platform must be linux/amd64", name))
	}
	if !equalStrings(profile.Command, fixedAgentdCommand) {
		errs = append(errs, fmt.Sprintf("authority profile %q command must be the fixed agentd command", name))
	}
	if _, ok := c.Networks[profile.NetworkPolicy]; !ok {
		errs = append(errs, fmt.Sprintf("authority profile %q references unknown network_policy %q", name, profile.NetworkPolicy))
	}
	if strings.TrimSpace(profile.BrokerAgentID) == "" {
		errs = append(errs, fmt.Sprintf("authority profile %q broker_agent_id is required", name))
	}
	if !regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`).MatchString(profile.BrokerSecretEnv) {
		errs = append(errs, fmt.Sprintf("authority profile %q broker_agent_secret_env is required and must be an environment variable name", name))
	}
	if !regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`).MatchString(profile.CoordinatorTokenEnv) {
		errs = append(errs, fmt.Sprintf("authority profile %q coordinator_token_env is required and must be an environment variable name", name))
	}
	if profile.MaxWorkers < 1 {
		errs = append(errs, fmt.Sprintf("authority profile %q max_workers must be positive", name))
	}
	if profile.SessionCapacity < 1 {
		errs = append(errs, fmt.Sprintf("authority profile %q session_capacity must be positive", name))
	}
	if profile.Resources.CPUShares < 1 || profile.Resources.MemoryMB < 1 || profile.Resources.PidsLimit < 1 {
		errs = append(errs, fmt.Sprintf("authority profile %q resources must set positive cpu_shares, memory_mb, and pids_limit", name))
	}
	if len(profile.Repositories) == 0 {
		errs = append(errs, fmt.Sprintf("authority profile %q repositories must not be empty", name))
	}
	for _, repo := range profile.Repositories {
		if !validRepo(repo) || !containsFold(c.Repositories, repo) {
			errs = append(errs, fmt.Sprintf("authority profile %q repository %q is not in the global repository allowlist", name, repo))
		}
	}
	if len(profile.Operations) == 0 {
		errs = append(errs, fmt.Sprintf("authority profile %q operations must not be empty", name))
	}
	for _, operation := range profile.Operations {
		if !regexp.MustCompile(`^[a-z][a-z0-9_.-]{1,63}$`).MatchString(operation) {
			errs = append(errs, fmt.Sprintf("authority profile %q operation %q is invalid", name, operation))
		}
	}
	for _, pattern := range profile.BranchPolicy.AllowedPatterns {
		if _, err := regexp.Compile(pattern); err != nil {
			errs = append(errs, fmt.Sprintf("authority profile %q has invalid branch pattern %q", name, pattern))
		}
	}
	if len(profile.BranchPolicy.AllowedPatterns) == 0 || len(profile.BranchPolicy.BaseBranches) == 0 {
		errs = append(errs, fmt.Sprintf("authority profile %q branch policy must set allowed_patterns and base_branches", name))
	}
	for i, mount := range profile.ExtraMounts {
		errs = append(errs, validateAuthorityMount(name, i, mount)...)
	}
	if profile.SessionIsolation.Primitive != "uid_gid_0700" || !filepath.IsAbs(profile.SessionIsolation.WorkspaceRoot) || profile.SessionIsolation.UIDStart < 10000 || profile.SessionIsolation.GIDStart < 10000 {
		errs = append(errs, fmt.Sprintf("authority profile %q must use uid_gid_0700 with an absolute workspace root and non-system UID/GID range", name))
	}
	if !safeAuthorityName(profile.Storage.SessionVolume) || !safeAuthorityName(profile.Storage.CheckpointVolume) || !safeAuthorityName(profile.Storage.EvidenceVolume) {
		errs = append(errs, fmt.Sprintf("authority profile %q storage must name managed session, checkpoint, and evidence volumes", name))
	}
	if !filepath.IsAbs(profile.Checkpoint.Directory) || !regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`).MatchString(profile.Checkpoint.KeyEnv) {
		errs = append(errs, fmt.Sprintf("authority profile %q checkpoint must set absolute directory and key_env", name))
	}
	if profile.CredentialBundle != "" {
		bundle, ok := c.Bundles[profile.CredentialBundle]
		if !ok {
			errs = append(errs, fmt.Sprintf("authority profile %q references unknown credential_bundle %q", name, profile.CredentialBundle))
		} else if !contains(bundle.AllowedAuthorityProfiles, name) {
			errs = append(errs, fmt.Sprintf("credential_bundle %q does not allow authority profile %q", profile.CredentialBundle, name))
		}
	}
	return errs
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func validateAuthorityMount(profile string, index int, mount ExtraMount) []string {
	var errs []string
	label := fmt.Sprintf("authority profile %q extra_mounts[%d]", profile, index)
	if !filepath.IsAbs(mount.SourcePath) || filepath.Clean(mount.SourcePath) == "/" {
		errs = append(errs, label+" source_path must be an absolute non-root path")
	}
	if !filepath.IsAbs(mount.MountPath) || filepath.Clean(mount.MountPath) == "/" {
		errs = append(errs, label+" mount_path must be an absolute non-root path")
	}
	source := filepath.Clean(mount.SourcePath)
	if source == "/var/run/docker.sock" || strings.HasPrefix(source, "/var/run/docker.sock/") {
		errs = append(errs, label+" cannot mount the Docker socket")
	}
	return errs
}

func (c Config) validateAuthorityPrincipal(name string, principal AuthorityPrincipal) []string {
	var errs []string
	if !safeAuthorityName(name) {
		errs = append(errs, fmt.Sprintf("authority principal %q has an invalid name", name))
	}
	if strings.TrimSpace(principal.Token) == "" {
		errs = append(errs, fmt.Sprintf("authority principal %q token or token_env is required", name))
	}
	if len(principal.AllowedProfiles) == 0 {
		errs = append(errs, fmt.Sprintf("authority principal %q allowed_profiles must not be empty", name))
	}
	for _, profile := range principal.AllowedProfiles {
		if _, ok := c.AuthorityProfiles[profile]; !ok {
			errs = append(errs, fmt.Sprintf("authority principal %q references unknown authority profile %q", name, profile))
		}
	}
	if len(principal.AllowedActions) == 0 {
		errs = append(errs, fmt.Sprintf("authority principal %q allowed_actions must not be empty", name))
	}
	for _, action := range principal.AllowedActions {
		if !validAuthorityAction(action) {
			errs = append(errs, fmt.Sprintf("authority principal %q has unsupported action %q", name, action))
		}
	}
	return errs
}

func validAuthorityAction(action string) bool {
	switch action {
	case "provision", "health", "acquire", "release", "drain", "replace", "reassign":
		return true
	default:
		return false
	}
}

func safeAuthorityName(value string) bool {
	return regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,79}$`).MatchString(value)
}

func authorityProfileDigest(name string, profile AuthorityProfile) (string, string, error) {
	canonical := profile
	canonical.Repositories = sortedCopy(profile.Repositories)
	canonical.Operations = sortedCopy(profile.Operations)
	canonical.BranchPolicy.AllowedPatterns = sortedCopy(profile.BranchPolicy.AllowedPatterns)
	canonical.BranchPolicy.BaseBranches = sortedCopy(profile.BranchPolicy.BaseBranches)
	b, err := json.Marshal(struct {
		Name    string           `json:"name"`
		Profile AuthorityProfile `json:"profile"`
	}{Name: name, Profile: canonical})
	if err != nil {
		return "", "", err
	}
	profileSum := sha256.Sum256(b)
	policyBytes, err := json.Marshal(struct {
		BrokerAgentID string       `json:"broker_agent_id"`
		Repositories  []string     `json:"repositories"`
		BranchPolicy  BranchPolicy `json:"branch_policy"`
		Operations    []string     `json:"operations"`
	}{canonical.BrokerAgentID, canonical.Repositories, canonical.BranchPolicy, canonical.Operations})
	if err != nil {
		return "", "", err
	}
	policySum := sha256.Sum256(policyBytes)
	return hex.EncodeToString(profileSum[:]), hex.EncodeToString(policySum[:]), nil
}

func sortedCopy(values []string) []string {
	out := append([]string(nil), values...)
	sort.Strings(out)
	return out
}
