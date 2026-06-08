// Package proxy implements a narrow model-call facade for sandboxed agents.
package proxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Listen           string   `yaml:"listen"`
	AuthToken        string   `yaml:"auth_token"`
	AuthTokenEnv     string   `yaml:"auth_token_env"`
	UpstreamURL      string   `yaml:"upstream_url"`
	UpstreamKey      string   `yaml:"upstream_key"`
	UpstreamKeyEnv   string   `yaml:"upstream_key_env"`
	AllowedModels    []string `yaml:"allowed_models"`
	StatePath        string   `yaml:"state_path"`
	AuditPath        string   `yaml:"audit_path"`
	MaxCallsPerRun   int      `yaml:"max_calls_per_run"`
	MaxTokensPerRun  int      `yaml:"max_tokens_per_run"`
	MaxRequestBytes  int64    `yaml:"max_request_bytes"`
	MaxResponseBytes int64    `yaml:"max_response_bytes"`
	Timeout          Duration `yaml:"timeout"`
	LogPrompts       bool     `yaml:"log_prompts"`
}

type Duration struct {
	time.Duration
}

func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	if value == nil || value.Value == "" {
		return nil
	}
	parsed, err := time.ParseDuration(value.Value)
	if err != nil {
		return err
	}
	d.Duration = parsed
	return nil
}

type Service struct {
	cfg   Config
	http  *http.Client
	audit *auditLogger
	mu    sync.Mutex
}

type ModelCallRequest struct {
	RunID          string            `json:"run_id"`
	Model          string            `json:"model"`
	Messages       []json.RawMessage `json:"messages"`
	ResponseFormat json.RawMessage   `json:"response_format,omitempty"`
	Temperature    *float64          `json:"temperature,omitempty"`
	MaxTokens      int               `json:"max_tokens,omitempty"`
	Metadata       map[string]string `json:"metadata,omitempty"`
}

type ModelCallResponse struct {
	ID      string          `json:"id,omitempty"`
	Model   string          `json:"model,omitempty"`
	Content json.RawMessage `json:"content,omitempty"`
	Usage   Usage           `json:"usage,omitempty"`
	Raw     json.RawMessage `json:"raw,omitempty"`
}

type Usage struct {
	PromptTokens     int `json:"prompt_tokens,omitempty"`
	CompletionTokens int `json:"completion_tokens,omitempty"`
	TotalTokens      int `json:"total_tokens,omitempty"`
}

func Load(path string) (Config, error) {
	// #nosec G304 -- config path is supplied by the operator on proxy startup.
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
		c.Listen = "127.0.0.1:8092"
	}
	if c.MaxRequestBytes == 0 {
		c.MaxRequestBytes = 256 * 1024
	}
	if c.MaxResponseBytes == 0 {
		c.MaxResponseBytes = 512 * 1024
	}
	if c.MaxCallsPerRun == 0 {
		c.MaxCallsPerRun = 20
	}
	if c.MaxTokensPerRun == 0 {
		c.MaxTokensPerRun = 200000
	}
	if c.Timeout.Duration == 0 {
		c.Timeout.Duration = 2 * time.Minute
	}
}

func (c *Config) ResolveSecrets() {
	if c.AuthToken == "" && c.AuthTokenEnv != "" {
		c.AuthToken = os.Getenv(c.AuthTokenEnv)
	}
	if c.UpstreamKey == "" && c.UpstreamKeyEnv != "" {
		c.UpstreamKey = os.Getenv(c.UpstreamKeyEnv)
	}
}

func (c Config) Validate() error {
	var errs []string
	if strings.TrimSpace(c.AuthToken) == "" {
		errs = append(errs, "auth_token or auth_token_env is required")
	}
	if strings.TrimSpace(c.UpstreamURL) == "" {
		errs = append(errs, "upstream_url is required")
	}
	if len(c.AllowedModels) == 0 {
		errs = append(errs, "allowed_models must not be empty")
	}
	if c.StatePath == "" {
		errs = append(errs, "state_path is required")
	}
	if c.MaxCallsPerRun < 1 {
		errs = append(errs, "max_calls_per_run must be positive")
	}
	if c.MaxTokensPerRun < 1 {
		errs = append(errs, "max_tokens_per_run must be positive")
	}
	if c.MaxRequestBytes < 1 || c.MaxResponseBytes < 1 {
		errs = append(errs, "request and response byte limits must be positive")
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

func NewService(cfg Config) (*Service, error) {
	audit, err := newAuditLogger(cfg.AuditPath)
	if err != nil {
		return nil, err
	}
	return &Service{cfg: cfg, http: &http.Client{Timeout: cfg.Timeout.Duration}, audit: audit}, nil
}

func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/healthz" && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	case r.URL.Path == "/v1/model/call" && r.Method == http.MethodPost:
		s.handleModelCall(w, r)
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
	}
}

func (s *Service) handleModelCall(w http.ResponseWriter, r *http.Request) {
	if !s.authOK(r) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="gh-agent-proxy"`)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	var in ModelCallRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, s.cfg.MaxRequestBytes)).Decode(&in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json", "message": err.Error()})
		return
	}
	if err := s.validateCall(in); err != nil {
		s.audit.Log(auditEvent{RunID: in.RunID, Model: in.Model, Decision: "deny", Error: err.Error()})
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "policy_denied", "message": err.Error()})
		return
	}
	if err := s.reserve(in.RunID, 0); err != nil {
		s.audit.Log(auditEvent{RunID: in.RunID, Model: in.Model, Decision: "deny", Error: err.Error()})
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "budget_exhausted", "message": err.Error()})
		return
	}
	out, usage, err := s.forward(in)
	if err != nil {
		s.audit.Log(auditEvent{RunID: in.RunID, Model: in.Model, Decision: "deny", Error: err.Error()})
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "upstream_error", "message": err.Error()})
		return
	}
	if err := s.reserve(in.RunID, usage.TotalTokens); err != nil {
		s.audit.Log(auditEvent{RunID: in.RunID, Model: in.Model, Decision: "deny", Tokens: usage.TotalTokens, Error: err.Error()})
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "budget_exhausted", "message": err.Error()})
		return
	}
	s.audit.Log(auditEvent{RunID: in.RunID, Model: in.Model, Decision: "allow", Tokens: usage.TotalTokens})
	writeJSON(w, http.StatusOK, out)
}

func (s *Service) authOK(r *http.Request) bool {
	got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	return got != "" && got == s.cfg.AuthToken
}

func (s *Service) validateCall(in ModelCallRequest) error {
	if in.RunID == "" {
		return fmt.Errorf("run_id is required")
	}
	if !contains(s.cfg.AllowedModels, in.Model) {
		return fmt.Errorf("model %q is not allowed", in.Model)
	}
	if len(in.Messages) == 0 {
		return fmt.Errorf("messages are required")
	}
	return nil
}

func (s *Service) forward(in ModelCallRequest) (ModelCallResponse, Usage, error) {
	body := map[string]interface{}{
		"model":    in.Model,
		"messages": in.Messages,
	}
	if len(in.ResponseFormat) > 0 {
		var rf interface{}
		if err := json.Unmarshal(in.ResponseFormat, &rf); err != nil {
			return ModelCallResponse{}, Usage{}, err
		}
		body["response_format"] = rf
	}
	if in.Temperature != nil {
		body["temperature"] = *in.Temperature
	}
	if in.MaxTokens > 0 {
		body["max_tokens"] = in.MaxTokens
	}
	b, err := json.Marshal(body)
	if err != nil {
		return ModelCallResponse{}, Usage{}, err
	}
	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(s.cfg.UpstreamURL, "/")+"/chat/completions", bytes.NewReader(b))
	if err != nil {
		return ModelCallResponse{}, Usage{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	if s.cfg.UpstreamKey != "" {
		req.Header.Set("Authorization", "Bearer "+s.cfg.UpstreamKey)
	}
	resp, err := s.http.Do(req)
	if err != nil {
		return ModelCallResponse{}, Usage{}, err
	}
	defer closeBody(resp.Body)
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, s.cfg.MaxResponseBytes))
	if err != nil {
		return ModelCallResponse{}, Usage{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return ModelCallResponse{}, Usage{}, fmt.Errorf("upstream status %d", resp.StatusCode)
	}
	var raw struct {
		ID      string `json:"id"`
		Model   string `json:"model"`
		Choices []struct {
			Message struct {
				Content json.RawMessage `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Usage Usage `json:"usage"`
	}
	if err := json.Unmarshal(respBody, &raw); err != nil {
		return ModelCallResponse{}, Usage{}, err
	}
	var content json.RawMessage
	if len(raw.Choices) > 0 {
		content = raw.Choices[0].Message.Content
	}
	return ModelCallResponse{ID: raw.ID, Model: raw.Model, Content: content, Usage: raw.Usage, Raw: respBody}, raw.Usage, nil
}

type budgetState struct {
	Runs map[string]runBudget `json:"runs"`
}

type runBudget struct {
	Calls  int `json:"calls"`
	Tokens int `json:"tokens"`
}

func (s *Service) reserve(runID string, tokens int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.readBudget()
	if err != nil {
		return err
	}
	rb := st.Runs[runID]
	if tokens == 0 {
		if rb.Calls >= s.cfg.MaxCallsPerRun {
			return fmt.Errorf("model call budget exhausted for run %s", runID)
		}
		rb.Calls++
	} else {
		if rb.Tokens+tokens > s.cfg.MaxTokensPerRun {
			return fmt.Errorf("model token budget exhausted for run %s", runID)
		}
		rb.Tokens += tokens
	}
	st.Runs[runID] = rb
	return s.writeBudget(st)
}

func (s *Service) readBudget() (budgetState, error) {
	st := budgetState{Runs: map[string]runBudget{}}
	b, err := os.ReadFile(s.cfg.StatePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return st, nil
		}
		return st, err
	}
	if len(b) == 0 {
		return st, nil
	}
	if err := json.Unmarshal(b, &st); err != nil {
		return st, err
	}
	if st.Runs == nil {
		st.Runs = map[string]runBudget{}
	}
	return st, nil
}

func (s *Service) writeBudget(st budgetState) error {
	if err := os.MkdirAll(filepath.Dir(s.cfg.StatePath), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.cfg.StatePath + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.cfg.StatePath)
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		return
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

func closeBody(body io.Closer) {
	if err := body.Close(); err != nil {
		return
	}
}
