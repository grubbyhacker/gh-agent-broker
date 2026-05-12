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
	Server ServerConfig `yaml:"server"`
	Audit  AuditConfig  `yaml:"audit"`
	GitHub GitHubConfig `yaml:"github"`
	Agents []Agent      `yaml:"agents"`
}

type ServerConfig struct {
	Listen         string `yaml:"listen"`
	AdminSecret    string `yaml:"admin_secret"`
	AdminSecretEnv string `yaml:"admin_secret_env"`
}

type AuditConfig struct {
	Path string `yaml:"path"`
}

type GitHubConfig struct {
	AppID          int64            `yaml:"app_id"`
	PrivateKeyPath string           `yaml:"private_key_path"`
	APIBaseURL     string           `yaml:"api_base_url"`
	GitBaseURL     string           `yaml:"git_base_url"`
	Installations  map[string]int64 `yaml:"installations"`
}

type Agent struct {
	ID                 string                     `yaml:"id"`
	Enabled            bool                       `yaml:"enabled"`
	Secret             string                     `yaml:"secret"`
	SecretEnv          string                     `yaml:"secret_env"`
	Repositories       []string                   `yaml:"repositories"`
	Operations         []string                   `yaml:"operations"`
	BranchPatterns     []string                   `yaml:"branch_patterns"`
	BaseBranches       []string                   `yaml:"base_branches"`
	Permissions        []string                   `yaml:"permissions"`
	MetadataAssertions map[string]AssertionPolicy `yaml:"metadata_assertions"`
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
	if c.GitHub.AppID == 0 {
		errs = append(errs, "github.app_id is required")
	}
	if c.GitHub.PrivateKeyPath == "" {
		errs = append(errs, "github.private_key_path is required")
	}
	if len(c.GitHub.Installations) == 0 {
		errs = append(errs, "github.installations must not be empty")
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
	id, ok := c.GitHub.Installations[strings.ToLower(repo)]
	if ok {
		return id, true
	}
	id, ok = c.GitHub.Installations[repo]
	return id, ok
}
