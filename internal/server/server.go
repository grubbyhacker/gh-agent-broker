// Package server exposes the broker HTTP API and Git smart-HTTP proxy.
package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"gh-agent-broker/internal/api"
	"gh-agent-broker/internal/audit"
	"gh-agent-broker/internal/auth"
	"gh-agent-broker/internal/config"
	"gh-agent-broker/internal/githubapp"
	"gh-agent-broker/internal/ids"
	"gh-agent-broker/internal/metadata"
	"gh-agent-broker/internal/policy"
)

type Server struct {
	configPath string
	mu         sync.RWMutex
	cfg        *config.Config
	gh         *githubapp.Client
	audit      *audit.Logger
	http       *http.Client
}

func New(configPath string, cfg *config.Config, gh *githubapp.Client, auditLog *audit.Logger) *Server {
	return &Server{
		configPath: configPath,
		cfg:        cfg,
		gh:         gh,
		audit:      auditLog,
		http:       &http.Client{Timeout: 10 * time.Minute},
	}
}

func (s *Server) InstallSignalReload() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	go func() {
		for range ch {
			if err := s.Reload(); err != nil {
				log.Printf("reload failed: %v", err)
			}
		}
	}()
}

func (s *Server) Reload() error {
	cfg, err := config.Load(s.configPath)
	if err != nil {
		return err
	}
	gh, err := githubapp.New(cfg.GitHub)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.cfg = cfg
	s.gh = gh
	s.mu.Unlock()
	return nil
}

func (s *Server) snapshot() (*config.Config, *githubapp.Client) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg, s.gh
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/healthz":
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	case r.URL.Path == "/readyz":
		writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
	case r.URL.Path == "/v1/admin/reload":
		s.handleReload(w, r)
	case r.URL.Path == "/v1/policy/dry-run":
		s.handleDryRun(w, r)
	case strings.HasPrefix(r.URL.Path, "/v1/repos/"):
		s.handleRepoAPI(w, r)
	case strings.HasPrefix(r.URL.Path, "/git/"):
		s.handleGit(w, r)
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
	}
}

func (s *Server) handleReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	cfg, _ := s.snapshot()
	if !auth.AuthenticateAdmin(r, cfg) {
		writeJSON(w, http.StatusUnauthorized, api.ErrorResponse{Code: "unauthorized", Message: "admin authentication failed", Decision: policy.DecisionDeny})
		return
	}
	if err := s.Reload(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "reloaded"})
}

func (s *Server) handleDryRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	opID := ids.NewOperationID()
	cfg, _ := s.snapshot()
	principal, ok := auth.AuthenticateAgent(r, cfg)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, api.ErrorResponse{Code: "unauthorized", Message: "agent authentication failed", OperationID: opID, Decision: policy.DecisionDeny})
		return
	}
	var req api.DryRunRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, api.ErrorResponse{Code: "invalid_json", Message: err.Error(), OperationID: opID, Decision: policy.DecisionDeny})
		return
	}
	if req.AgentID != "" && req.AgentID != principal.ID {
		writeJSON(w, http.StatusForbidden, api.ErrorResponse{Code: "agent_mismatch", Message: "request agent_id must match authenticated agent", OperationID: opID, Decision: policy.DecisionDeny})
		return
	}
	var installationID int64
	if id, ok := cfg.InstallationID(req.Repo); ok {
		installationID = id
	}
	enriched := metadata.WithBrokerFields(req.Metadata, principal.ID, opID, installationID)
	result := policy.Check(policy.Request{
		Agent:       principal.Agent,
		AgentID:     principal.ID,
		Repo:        req.Repo,
		Operation:   req.Operation,
		Branch:      req.Branch,
		BaseBranch:  req.BaseBranch,
		Permissions: req.Permissions,
		Metadata:    req.Metadata,
		Locations: map[string]map[string]string{
			"request":      req.Metadata,
			"pr_body":      enriched,
			"comment_body": enriched,
		},
	})
	s.audit.Log(audit.Event{OperationID: opID, AgentID: principal.ID, Operation: "policy.dry-run", Repo: req.Repo, Branch: req.Branch, RequestedPermissions: req.Permissions, Decision: result.Decision})
	writeJSON(w, statusFor(result), api.DryRunResponse{
		OperationID:     opID,
		Allowed:         result.Allowed,
		Decision:        result.Decision,
		FailedChecks:    result.FailedChecks,
		Warnings:        result.Warnings,
		RequiredChanges: result.RequiredChanges,
	})
}

func (s *Server) handleRepoAPI(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/repos/"), "/")
	if len(parts) < 3 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	repo := parts[0] + "/" + parts[1]
	switch {
	case len(parts) == 3 && parts[2] == "probe" && r.Method == http.MethodGet:
		s.handleProbe(w, r, repo)
	case len(parts) == 3 && parts[2] == "pulls" && r.Method == http.MethodPost:
		s.handlePullCreate(w, r, repo)
	case len(parts) == 5 && parts[2] == "issues" && parts[4] == "comments" && r.Method == http.MethodPost:
		s.handleCommentCreate(w, r, repo, parts[3])
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
	}
}

func (s *Server) handleProbe(w http.ResponseWriter, r *http.Request, repo string) {
	opID := ids.NewOperationID()
	cfg, gh := s.snapshot()
	principal, ok := auth.AuthenticateAgent(r, cfg)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, api.ErrorResponse{Code: "unauthorized", Message: "agent authentication failed", OperationID: opID, Decision: policy.DecisionDeny})
		return
	}
	inst, ok := cfg.InstallationID(repo)
	if !ok {
		writeJSON(w, http.StatusForbidden, s.errorResponse(opID, "installation_not_configured", "repository has no configured GitHub App installation", nil))
		return
	}
	result := policy.Check(policy.Request{Agent: principal.Agent, AgentID: principal.ID, Repo: repo, Operation: "repo.probe"})
	if !result.Allowed {
		writeJSON(w, http.StatusForbidden, s.errorResponse(opID, "policy_denied", "repo probe denied by policy", &result))
		s.audit.Log(audit.Event{OperationID: opID, AgentID: principal.ID, Operation: "repo.probe", Repo: repo, Decision: result.Decision})
		return
	}
	ghResult, err := gh.GetRepo(repo, inst)
	if err != nil {
		s.audit.Log(audit.Event{OperationID: opID, AgentID: principal.ID, Operation: "repo.probe", Repo: repo, Decision: result.Decision, Error: err.Error()})
		writeJSON(w, http.StatusBadGateway, api.ErrorResponse{Code: "github_error", Message: audit.Redact(err.Error()), OperationID: opID, Decision: result.Decision})
		return
	}
	s.audit.Log(audit.Event{OperationID: opID, AgentID: principal.ID, Operation: "repo.probe", Repo: repo, Decision: result.Decision, GitHubURL: ghResult.HTMLURL, Result: "ok"})
	writeJSON(w, http.StatusOK, ghResult)
}

func (s *Server) handlePullCreate(w http.ResponseWriter, r *http.Request, repo string) {
	opID := ids.NewOperationID()
	cfg, gh := s.snapshot()
	principal, ok := auth.AuthenticateAgent(r, cfg)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, api.ErrorResponse{Code: "unauthorized", Message: "agent authentication failed", OperationID: opID, Decision: policy.DecisionDeny})
		return
	}
	var req api.PullCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, api.ErrorResponse{Code: "invalid_json", Message: err.Error(), OperationID: opID, Decision: policy.DecisionDeny})
		return
	}
	inst, ok := cfg.InstallationID(repo)
	if !ok {
		writeJSON(w, http.StatusForbidden, s.errorResponse(opID, "installation_not_configured", "repository has no configured GitHub App installation", nil))
		return
	}
	enriched := metadata.WithBrokerFields(req.Metadata, principal.ID, opID, inst)
	result := policy.Check(policy.Request{
		Agent:       principal.Agent,
		AgentID:     principal.ID,
		Repo:        repo,
		Operation:   "pull.create",
		Branch:      req.Head,
		BaseBranch:  req.Base,
		Permissions: req.Permissions,
		Metadata:    req.Metadata,
		Locations: map[string]map[string]string{
			"request": req.Metadata,
			"pr_body": enriched,
		},
	})
	if !result.Allowed {
		s.audit.Log(audit.Event{OperationID: opID, AgentID: principal.ID, Operation: "pull.create", Repo: repo, Branch: req.Head, RequestedPermissions: req.Permissions, Decision: result.Decision})
		writeJSON(w, http.StatusForbidden, s.errorResponse(opID, "policy_denied", "pull request creation denied by policy", &result))
		return
	}
	body := req.Body + metadata.RenderBlock(enriched)
	ghResult, err := gh.CreatePull(repo, inst, req.Title, req.Head, req.Base, body, req.Draft)
	if err != nil {
		s.audit.Log(audit.Event{OperationID: opID, AgentID: principal.ID, Operation: "pull.create", Repo: repo, Branch: req.Head, RequestedPermissions: req.Permissions, Decision: result.Decision, Error: err.Error()})
		writeJSON(w, http.StatusBadGateway, api.ErrorResponse{Code: "github_error", Message: audit.Redact(err.Error()), OperationID: opID, Decision: result.Decision, Warnings: result.Warnings})
		return
	}
	s.audit.Log(audit.Event{OperationID: opID, AgentID: principal.ID, Operation: "pull.create", Repo: repo, Branch: req.Head, RequestedPermissions: req.Permissions, Decision: result.Decision, GitHubURL: ghResult.HTMLURL, Result: "ok"})
	writeJSON(w, http.StatusCreated, ghResult)
}

func (s *Server) handleCommentCreate(w http.ResponseWriter, r *http.Request, repo, issueNumber string) {
	opID := ids.NewOperationID()
	cfg, gh := s.snapshot()
	principal, ok := auth.AuthenticateAgent(r, cfg)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, api.ErrorResponse{Code: "unauthorized", Message: "agent authentication failed", OperationID: opID, Decision: policy.DecisionDeny})
		return
	}
	var req api.CommentCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, api.ErrorResponse{Code: "invalid_json", Message: err.Error(), OperationID: opID, Decision: policy.DecisionDeny})
		return
	}
	inst, ok := cfg.InstallationID(repo)
	if !ok {
		writeJSON(w, http.StatusForbidden, s.errorResponse(opID, "installation_not_configured", "repository has no configured GitHub App installation", nil))
		return
	}
	enriched := metadata.WithBrokerFields(req.Metadata, principal.ID, opID, inst)
	result := policy.Check(policy.Request{
		Agent:       principal.Agent,
		AgentID:     principal.ID,
		Repo:        repo,
		Operation:   "issue.comment",
		Permissions: req.Permissions,
		Metadata:    req.Metadata,
		Locations: map[string]map[string]string{
			"request":      req.Metadata,
			"comment_body": enriched,
		},
	})
	if !result.Allowed {
		s.audit.Log(audit.Event{OperationID: opID, AgentID: principal.ID, Operation: "issue.comment", Repo: repo, RequestedPermissions: req.Permissions, Decision: result.Decision})
		writeJSON(w, http.StatusForbidden, s.errorResponse(opID, "policy_denied", "comment creation denied by policy", &result))
		return
	}
	body := req.Body + metadata.RenderBlock(enriched)
	ghResult, err := gh.CreateIssueComment(repo, issueNumber, inst, body)
	if err != nil {
		s.audit.Log(audit.Event{OperationID: opID, AgentID: principal.ID, Operation: "issue.comment", Repo: repo, RequestedPermissions: req.Permissions, Decision: result.Decision, Error: err.Error()})
		writeJSON(w, http.StatusBadGateway, api.ErrorResponse{Code: "github_error", Message: audit.Redact(err.Error()), OperationID: opID, Decision: result.Decision, Warnings: result.Warnings})
		return
	}
	s.audit.Log(audit.Event{OperationID: opID, AgentID: principal.ID, Operation: "issue.comment", Repo: repo, RequestedPermissions: req.Permissions, Decision: result.Decision, GitHubURL: ghResult.HTMLURL, Result: "ok"})
	writeJSON(w, http.StatusCreated, ghResult)
}

func (s *Server) handleGit(w http.ResponseWriter, r *http.Request) {
	opID := ids.NewOperationID()
	cfg, gh := s.snapshot()
	principal, ok := auth.AuthenticateAgent(r, cfg)
	if !ok {
		http.Error(w, "agent authentication failed", http.StatusUnauthorized)
		return
	}
	repo, suffix, ok := parseGitPath(r.URL.Path)
	if !ok {
		http.Error(w, "invalid git path", http.StatusNotFound)
		return
	}
	operation := gitOperation(r, suffix)
	if operation == "" {
		http.Error(w, "unsupported git operation", http.StatusBadRequest)
		return
	}
	inst, ok := cfg.InstallationID(repo)
	if !ok {
		http.Error(w, "repository has no configured GitHub App installation", http.StatusForbidden)
		return
	}
	var body []byte
	var bodyReader io.Reader
	branch := ""
	if r.Body != nil {
		var err error
		body, err = io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read git request body failed", http.StatusBadRequest)
			return
		}
		bodyReader = bytes.NewReader(body)
	}
	if operation == "git.receive-pack" && len(body) > 0 {
		branch = receivePackBranch(body)
	}
	if operation == "git.receive-pack" && r.Method == http.MethodPost && branch == "" {
		result := policy.Result{
			Allowed:  false,
			Decision: policy.DecisionDeny,
			FailedChecks: []api.FailedCheck{{
				Dimension:     "branch",
				Location:      "git.receive-pack",
				Expected:      "parseable refs/heads/* update",
				SafeToDisplay: true,
				Message:       "broker could not determine the pushed branch, so branch policy cannot be enforced",
			}},
			RequiredChanges: []api.RequiredChange{{
				Location: "branch",
				Action:   "push a named branch ref that the broker can parse and policy allows",
			}},
		}
		s.audit.Log(audit.Event{OperationID: opID, AgentID: principal.ID, Operation: operation, Repo: repo, Decision: result.Decision})
		writeGitPolicyError(w, r, s.errorResponse(opID, "policy_denied", "git operation denied by policy", &result))
		return
	}
	result := policy.Check(policy.Request{
		Agent:     principal.Agent,
		AgentID:   principal.ID,
		Repo:      repo,
		Operation: operation,
		Branch:    branch,
	})
	if !result.Allowed {
		s.audit.Log(audit.Event{OperationID: opID, AgentID: principal.ID, Operation: operation, Repo: repo, Branch: branch, Decision: result.Decision})
		writeGitPolicyError(w, r, s.errorResponse(opID, "policy_denied", "git operation denied by policy", &result))
		return
	}
	token, err := gh.InstallationToken(inst)
	if err != nil {
		s.audit.Log(audit.Event{OperationID: opID, AgentID: principal.ID, Operation: operation, Repo: repo, Branch: branch, Decision: result.Decision, Error: err.Error()})
		http.Error(w, "github token exchange failed", http.StatusBadGateway)
		return
	}
	upstream, err := gitUpstreamURL(cfg.GitHub.GitBaseURL, repo, suffix, r.URL.RawQuery)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	//nolint:gosec // upstream is constructed from validated repo path and configured Git base URL.
	req, err := http.NewRequest(r.Method, upstream, bodyReader)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	copyGitHeaders(req.Header, r.Header)
	req.SetBasicAuth("x-access-token", token)
	// #nosec G704 -- outbound Git proxy target is constrained by broker config and repo policy.
	resp, err := s.http.Do(req)
	if err != nil {
		s.audit.Log(audit.Event{OperationID: opID, AgentID: principal.ID, Operation: operation, Repo: repo, Branch: branch, Decision: result.Decision, Error: err.Error()})
		http.Error(w, "github git upstream failed", http.StatusBadGateway)
		return
	}
	defer closeBody(resp.Body)
	copyGitHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil {
		s.audit.Log(audit.Event{OperationID: opID, AgentID: principal.ID, Operation: operation, Repo: repo, Branch: branch, Decision: result.Decision, Error: err.Error()})
		return
	}
	s.audit.Log(audit.Event{OperationID: opID, AgentID: principal.ID, Operation: operation, Repo: repo, Branch: branch, Decision: result.Decision, Result: "status " + strconv.Itoa(resp.StatusCode)})
}

func (s *Server) errorResponse(operationID, code, message string, result *policy.Result) api.ErrorResponse {
	out := api.ErrorResponse{Code: code, Message: message, OperationID: operationID, Decision: policy.DecisionDeny}
	if result != nil {
		out.Decision = result.Decision
		out.FailedChecks = result.FailedChecks
		out.RequiredChanges = result.RequiredChanges
		out.Warnings = result.Warnings
	}
	return out
}

func parseGitPath(path string) (repo, suffix string, ok bool) {
	trimmed := strings.TrimPrefix(path, "/git/")
	idx := strings.Index(trimmed, ".git")
	if idx < 0 {
		return "", "", false
	}
	repo = trimmed[:idx]
	suffix = trimmed[idx+len(".git"):]
	if strings.Count(repo, "/") != 1 {
		return "", "", false
	}
	return repo, suffix, true
}

func gitOperation(r *http.Request, suffix string) string {
	if r.Method == http.MethodGet && suffix == "/info/refs" {
		switch r.URL.Query().Get("service") {
		case "git-upload-pack":
			return "git.upload-pack"
		case "git-receive-pack":
			return "git.receive-pack"
		}
	}
	if r.Method == http.MethodPost && suffix == "/git-upload-pack" {
		return "git.upload-pack"
	}
	if r.Method == http.MethodPost && suffix == "/git-receive-pack" {
		return "git.receive-pack"
	}
	return ""
}

func gitUpstreamURL(base, repo, suffix, rawQuery string) (string, error) {
	u, err := url.Parse(strings.TrimRight(base, "/") + "/" + repo + ".git" + suffix)
	if err != nil {
		return "", err
	}
	u.RawQuery = rawQuery
	return u.String(), nil
}

func copyGitHeaders(dst, src http.Header) {
	for k, vals := range src {
		lk := strings.ToLower(k)
		if lk == "authorization" || lk == "host" || strings.HasPrefix(lk, "x-agent-") || strings.HasPrefix(lk, "x-admin-") {
			continue
		}
		for _, v := range vals {
			dst.Add(k, v)
		}
	}
}

func receivePackBranch(body []byte) string {
	i := 0
	for i+4 <= len(body) {
		n, err := strconv.ParseInt(string(body[i:i+4]), 16, 32)
		if err != nil || n < 0 {
			return ""
		}
		i += 4
		if n == 0 {
			return ""
		}
		if int(n) < 4 || i+int(n)-4 > len(body) {
			return ""
		}
		line := string(body[i : i+int(n)-4])
		if nul := strings.IndexByte(line, 0); nul >= 0 {
			line = line[:nul]
		}
		fields := strings.Fields(line)
		if len(fields) >= 3 && strings.HasPrefix(fields[2], "refs/heads/") {
			return fields[2]
		}
		i += int(n) - 4
	}
	return ""
}

func writeGitPolicyError(w http.ResponseWriter, r *http.Request, errResp api.ErrorResponse) {
	if !wantsJSON(r) {
		writeGitPolicyTextError(w, errResp)
		return
	}
	b, err := json.Marshal(errResp)
	if err != nil {
		http.Error(w, "encode policy error failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	if _, err := w.Write(b); err != nil {
		return
	}
}

func wantsJSON(r *http.Request) bool {
	return strings.Contains(strings.ToLower(r.Header.Get("Accept")), "application/json")
}

func writeGitPolicyTextError(w http.ResponseWriter, errResp api.ErrorResponse) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	var b strings.Builder
	b.WriteString("Git operation denied by gh-agent-broker policy\n")
	if errResp.OperationID != "" {
		fmt.Fprintf(&b, "operation_id: %s\n", errResp.OperationID)
	}
	if errResp.Code != "" {
		fmt.Fprintf(&b, "code: %s\n", errResp.Code)
	}
	if errResp.Decision != "" {
		fmt.Fprintf(&b, "decision: %s\n", errResp.Decision)
	}
	if errResp.Message != "" {
		fmt.Fprintf(&b, "message: %s\n", errResp.Message)
	}
	if len(errResp.FailedChecks) > 0 {
		b.WriteString("failed_checks:\n")
		for _, check := range errResp.FailedChecks {
			fmt.Fprintf(&b, "- %s", check.Dimension)
			if check.Field != "" {
				fmt.Fprintf(&b, ".%s", check.Field)
			}
			if check.Location != "" {
				fmt.Fprintf(&b, " at %s", check.Location)
			}
			if check.Message != "" {
				fmt.Fprintf(&b, ": %s", check.Message)
			}
			b.WriteByte('\n')
			if check.SafeToDisplay {
				if check.Expected != "" {
					fmt.Fprintf(&b, "  expected: %s\n", check.Expected)
				}
				if check.Actual != "" {
					fmt.Fprintf(&b, "  actual: %s\n", check.Actual)
				}
			}
		}
	}
	if len(errResp.RequiredChanges) > 0 {
		b.WriteString("required_changes:\n")
		for _, change := range errResp.RequiredChanges {
			label := change.Location
			if label == "" {
				label = change.Field
			}
			if label == "" {
				label = "request"
			}
			fmt.Fprintf(&b, "- %s: %s\n", label, change.Action)
		}
	}
	if _, err := w.Write([]byte(b.String())); err != nil {
		return
	}
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		return
	}
}

func closeBody(body io.Closer) {
	if err := body.Close(); err != nil {
		return
	}
}

func statusFor(result policy.Result) int {
	if result.Allowed {
		return http.StatusOK
	}
	return http.StatusForbidden
}

func ValidateListenAddress(addr string) error {
	if strings.HasPrefix(addr, "0.0.0.0:") || strings.HasPrefix(addr, ":") {
		return fmt.Errorf("listen address %q is publicly reachable; bind to localhost or a Docker-internal address unless intentionally changed", addr)
	}
	return nil
}
