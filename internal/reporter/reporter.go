// Package reporter implements the narrow issue-reporting service used by MCP.
package reporter

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"gh-agent-broker/internal/api"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Listen               string   `yaml:"listen"`
	MCPPath              string   `yaml:"mcp_path"`
	BrokerURL            string   `yaml:"broker_url"`
	BrokerAgentID        string   `yaml:"broker_agent_id"`
	BrokerAgentSecret    string   `yaml:"broker_agent_secret"`
	BrokerAgentSecretEnv string   `yaml:"broker_agent_secret_env"`
	Repositories         []string `yaml:"repositories"`
	DefaultLabel         string   `yaml:"default_label"`
	AllowedLabels        []string `yaml:"allowed_labels"`
	MaxTitleLength       int      `yaml:"max_title_length"`
	MaxBodyLength        int      `yaml:"max_body_length"`
}

type Service struct {
	cfg  Config
	http *http.Client
}

type ReportIssueInput struct {
	Repo          string   `json:"repo" jsonschema:"owner/repo repository to report against"`
	Title         string   `json:"title" jsonschema:"issue title"`
	Body          string   `json:"body" jsonschema:"issue body with observed behavior and useful context"`
	DedupeKey     string   `json:"dedupe_key" jsonschema:"stable caller-provided key for future duplicate suppression"`
	Labels        []string `json:"labels,omitempty" jsonschema:"optional extra labels from the service allowlist"`
	SourceAgentID string   `json:"source_agent_id,omitempty" jsonschema:"optional originating agent identity"`
	SourceRunID   string   `json:"source_run_id,omitempty" jsonschema:"optional originating run or session id"`
}

type ReportIssueOutput struct {
	URL     string `json:"url,omitempty"`
	HTMLURL string `json:"html_url,omitempty"`
	Number  int    `json:"number,omitempty"`
	ID      int64  `json:"id,omitempty"`
}

type CapabilitiesOutput struct {
	AllowedRepositories   []string `json:"allowed_repositories"`
	AllowedOptionalLabels []string `json:"allowed_optional_labels"`
	ForcedLabels          []string `json:"forced_labels"`
	MaxTitleLength        int      `json:"max_title_length"`
	MaxBodyLength         int      `json:"max_body_length"`
	DedupeKeyRequired     bool     `json:"dedupe_key_required"`
	DedupeBehavior        string   `json:"dedupe_behavior"`
	ReadSupport           []string `json:"read_support"`
}

type GetIssueInput struct {
	Repo   string `json:"repo" jsonschema:"owner/repo repository"`
	Number int    `json:"number" jsonschema:"issue number"`
}

type SearchIssuesInput struct {
	Repo       string   `json:"repo" jsonschema:"owner/repo repository"`
	State      string   `json:"state,omitempty" jsonschema:"issue state, defaults to open"`
	Labels     []string `json:"labels,omitempty" jsonschema:"labels to filter by"`
	Assignee   string   `json:"assignee,omitempty" jsonschema:"assignee to filter by"`
	BodyMarker string   `json:"body_marker,omitempty" jsonschema:"optional body marker or dedupe key to filter returned issues"`
}

type ListIssueCommentsInput struct {
	Repo   string `json:"repo" jsonschema:"owner/repo repository"`
	Number int    `json:"number" jsonschema:"issue number"`
}

func Load(path string) (Config, error) {
	// #nosec G304 -- config path is supplied by the operator on reporter startup.
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
		c.Listen = "127.0.0.1:8090"
	}
	if c.MCPPath == "" {
		c.MCPPath = "/mcp"
	}
	if c.DefaultLabel == "" {
		c.DefaultLabel = "agent-reported"
	}
	if c.MaxTitleLength == 0 {
		c.MaxTitleLength = 256
	}
	if c.MaxBodyLength == 0 {
		c.MaxBodyLength = 20000
	}
}

func (c *Config) ResolveSecrets() {
	if c.BrokerAgentSecret == "" && c.BrokerAgentSecretEnv != "" {
		c.BrokerAgentSecret = os.Getenv(c.BrokerAgentSecretEnv)
	}
}

func (c Config) Validate() error {
	var errs []string
	if strings.TrimSpace(c.BrokerURL) == "" {
		errs = append(errs, "broker_url is required")
	}
	if strings.TrimSpace(c.BrokerAgentID) == "" {
		errs = append(errs, "broker_agent_id is required")
	}
	if c.BrokerAgentSecret == "" {
		errs = append(errs, "broker_agent_secret or broker_agent_secret_env is required")
	}
	if len(c.Repositories) == 0 {
		errs = append(errs, "repositories must not be empty")
	}
	if c.MaxTitleLength < 1 {
		errs = append(errs, "max_title_length must be positive")
	}
	if c.MaxBodyLength < 1 {
		errs = append(errs, "max_body_length must be positive")
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

func NewService(cfg Config) *Service {
	return &Service{
		cfg:  cfg,
		http: &http.Client{Timeout: 30 * time.Second},
	}
}

func (s *Service) Capabilities() CapabilitiesOutput {
	forcedLabels := []string{}
	if strings.TrimSpace(s.cfg.DefaultLabel) != "" {
		forcedLabels = append(forcedLabels, strings.TrimSpace(s.cfg.DefaultLabel))
	}
	return CapabilitiesOutput{
		AllowedRepositories:   append([]string(nil), s.cfg.Repositories...),
		AllowedOptionalLabels: append([]string(nil), s.cfg.AllowedLabels...),
		ForcedLabels:          forcedLabels,
		MaxTitleLength:        s.cfg.MaxTitleLength,
		MaxBodyLength:         s.cfg.MaxBodyLength,
		DedupeKeyRequired:     true,
		DedupeBehavior:        "dedupe_key is passed to the broker as issue metadata; the reporter does not suppress duplicate reports",
		ReadSupport:           []string{"broker_get_issue", "broker_search_issues", "broker_list_issue_comments"},
	}
}

func (s *Service) ReportIssue(in ReportIssueInput) (ReportIssueOutput, error) {
	repo := strings.TrimSpace(in.Repo)
	title := strings.TrimSpace(in.Title)
	body := strings.TrimSpace(in.Body)
	dedupeKey := strings.TrimSpace(in.DedupeKey)
	if !allowedRepo(s.cfg.Repositories, repo) {
		return ReportIssueOutput{}, fmt.Errorf("repo %q is not in reporter allowlist", repo)
	}
	if title == "" {
		return ReportIssueOutput{}, fmt.Errorf("title is required")
	}
	if len(title) > s.cfg.MaxTitleLength {
		return ReportIssueOutput{}, fmt.Errorf("title exceeds max length %d", s.cfg.MaxTitleLength)
	}
	if body == "" {
		return ReportIssueOutput{}, fmt.Errorf("body is required")
	}
	if len(body) > s.cfg.MaxBodyLength {
		return ReportIssueOutput{}, fmt.Errorf("body exceeds max length %d", s.cfg.MaxBodyLength)
	}
	if dedupeKey == "" {
		return ReportIssueOutput{}, fmt.Errorf("dedupe_key is required")
	}
	labels, err := s.labels(in.Labels)
	if err != nil {
		return ReportIssueOutput{}, err
	}
	reqBody := api.IssueCreateRequest{
		Title:  title,
		Body:   body,
		Labels: labels,
		Metadata: api.Metadata{
			"Agent-Id":   s.cfg.BrokerAgentID,
			"Dedupe-Key": dedupeKey,
		},
		Permissions: []string{"issues:write"},
	}
	if in.SourceAgentID != "" {
		reqBody.Metadata["Source-Agent-Id"] = in.SourceAgentID
	}
	if in.SourceRunID != "" {
		reqBody.Metadata["Source-Run-Id"] = in.SourceRunID
	}
	var out api.GitHubResult
	if err := s.postIssue(repo, reqBody, &out); err != nil {
		return ReportIssueOutput{}, err
	}
	return ReportIssueOutput{URL: out.URL, HTMLURL: out.HTMLURL, Number: out.Number, ID: out.ID}, nil
}

func (s *Service) GetIssue(in GetIssueInput) (api.IssueSummary, error) {
	repo := strings.TrimSpace(in.Repo)
	if !allowedRepo(s.cfg.Repositories, repo) {
		return api.IssueSummary{}, fmt.Errorf("repo %q is not in reporter allowlist", repo)
	}
	if in.Number < 1 {
		return api.IssueSummary{}, fmt.Errorf("number must be positive")
	}
	var out api.IssueSummary
	if err := s.getJSON(issueNumberPath(repo, in.Number), &out); err != nil {
		return api.IssueSummary{}, err
	}
	return out, nil
}

func (s *Service) SearchIssues(in SearchIssuesInput) ([]api.IssueSummary, error) {
	repo := strings.TrimSpace(in.Repo)
	if !allowedRepo(s.cfg.Repositories, repo) {
		return nil, fmt.Errorf("repo %q is not in reporter allowlist", repo)
	}
	q := url.Values{}
	if in.State == "" {
		q.Set("state", "open")
	} else {
		q.Set("state", in.State)
	}
	if len(in.Labels) > 0 {
		for _, label := range in.Labels {
			if strings.TrimSpace(label) == "" {
				continue
			}
			if label != s.cfg.DefaultLabel && !containsString(s.cfg.AllowedLabels, label) {
				return nil, fmt.Errorf("label %q is not in reporter label allowlist", label)
			}
		}
		q.Set("labels", strings.Join(in.Labels, ","))
	}
	if in.Assignee != "" {
		q.Set("assignee", in.Assignee)
	}
	if in.BodyMarker != "" {
		q.Set("body_marker", in.BodyMarker)
	}
	var out []api.IssueSummary
	if err := s.getJSON(issueListPath(repo)+"?"+q.Encode(), &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Service) ListIssueComments(in ListIssueCommentsInput) ([]api.IssueComment, error) {
	repo := strings.TrimSpace(in.Repo)
	if !allowedRepo(s.cfg.Repositories, repo) {
		return nil, fmt.Errorf("repo %q is not in reporter allowlist", repo)
	}
	if in.Number < 1 {
		return nil, fmt.Errorf("number must be positive")
	}
	var out []api.IssueComment
	if err := s.getJSON(issueNumberPath(repo, in.Number)+"/comments", &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Service) labels(requested []string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	add := func(label string) {
		label = strings.TrimSpace(label)
		if label == "" || seen[label] {
			return
		}
		seen[label] = true
		out = append(out, label)
	}
	add(s.cfg.DefaultLabel)
	allowed := map[string]bool{}
	for _, label := range s.cfg.AllowedLabels {
		allowed[label] = true
	}
	for _, label := range requested {
		label = strings.TrimSpace(label)
		if label == "" || label == s.cfg.DefaultLabel {
			continue
		}
		if !allowed[label] {
			return nil, fmt.Errorf("label %q is not in reporter label allowlist", label)
		}
		add(label)
	}
	return out, nil
}

func (s *Service) postIssue(repo string, body api.IssueCreateRequest, out *api.GitHubResult) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	path, err := issuePath(repo)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(s.cfg.BrokerURL, "/")+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.SetBasicAuth(s.cfg.BrokerAgentID, s.cfg.BrokerAgentSecret)
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.http.Do(req)
	if err != nil {
		return err
	}
	defer closeBody(resp.Body)
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("broker issue.create failed: status %d: %s", resp.StatusCode, string(respBody))
	}
	return json.Unmarshal(respBody, out)
}

func (s *Service) getJSON(path string, out interface{}) error {
	req, err := http.NewRequest(http.MethodGet, strings.TrimRight(s.cfg.BrokerURL, "/")+path, nil)
	if err != nil {
		return err
	}
	req.SetBasicAuth(s.cfg.BrokerAgentID, s.cfg.BrokerAgentSecret)
	resp, err := s.http.Do(req)
	if err != nil {
		return err
	}
	defer closeBody(resp.Body)
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("broker read failed: status %d: %s", resp.StatusCode, string(respBody))
	}
	return json.Unmarshal(respBody, out)
}

func issuePath(repo string) (string, error) {
	if err := validateRepo(repo); err != nil {
		return "", err
	}
	return issueListPath(repo), nil
}

func issueListPath(repo string) string {
	owner, name, ok := strings.Cut(repo, "/")
	if !ok {
		return "/v1/repos//issues"
	}
	return "/v1/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(name) + "/issues"
}

func issueNumberPath(repo string, number int) string {
	return issueListPath(repo) + fmt.Sprintf("/%d", number)
}

func validateRepo(repo string) error {
	owner, name, ok := strings.Cut(repo, "/")
	if !ok || owner == "" || name == "" || strings.Contains(name, "/") {
		return fmt.Errorf("repo must be owner/repo")
	}
	return nil
}

func allowedRepo(allowed []string, repo string) bool {
	for _, item := range allowed {
		if strings.EqualFold(item, repo) {
			return true
		}
	}
	return false
}

func containsString(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

func closeBody(body io.Closer) {
	if err := body.Close(); err != nil {
		return
	}
}
