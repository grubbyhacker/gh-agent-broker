// Package server exposes the broker HTTP API and Git smart-HTTP proxy.
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
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
	"gh-agent-broker/internal/idempotency"
	"gh-agent-broker/internal/ids"
	"gh-agent-broker/internal/limits"
	"gh-agent-broker/internal/metadata"
	"gh-agent-broker/internal/policy"
	"gh-agent-broker/internal/pushtripwire"
	"gh-agent-broker/internal/repositoryroutepolicy"
	"gh-agent-broker/internal/sandbox"
	"gh-agent-broker/internal/securityscan"
)

type Server struct {
	configPath        string
	mu                sync.RWMutex
	cfg               *config.Config
	gh                *githubapp.Client
	audit             *audit.Logger
	http              *http.Client
	tripwire          *pushtripwire.Store
	fence             pushtripwire.FenceAdapter
	transport         *sandbox.TransportObserver
	transportProfiles map[string]string
	credentialStore   *sandbox.AuthorityWorkerStore
}

func New(configPath string, cfg *config.Config, gh *githubapp.Client, auditLog *audit.Logger) (*Server, error) {
	var tripwire *pushtripwire.Store
	var err error
	if cfg.PushTripwire.Enabled {
		tripwire, err = pushtripwire.Open(cfg.PushTripwire.StatePath)
		if err != nil {
			return nil, err
		}
	}
	var transport *sandbox.TransportObserver
	if cfg.TransportObservation.Enabled {
		transport, err = sandbox.OpenTransportObserver(context.Background(), cfg.TransportObservation.AuthorityStorePath)
		if err != nil {
			return nil, fmt.Errorf("open transport observer: %w", err)
		}
	}
	var credentialStore *sandbox.AuthorityWorkerStore
	if cfg.TransportObservation.AuthorityStorePath != "" {
		credentialStore, err = sandbox.OpenAuthorityWorkerStore(context.Background(), cfg.TransportObservation.AuthorityStorePath)
		if err != nil {
			return nil, fmt.Errorf("open credential custody store: %w", err)
		}
	}
	return &Server{
		configPath:        configPath,
		cfg:               cfg,
		gh:                gh,
		audit:             auditLog,
		http:              &http.Client{Timeout: 10 * time.Minute},
		tripwire:          tripwire,
		transport:         transport,
		transportProfiles: cfg.TransportObservation.ProfileAgentIDs,
		credentialStore:   credentialStore,
	}, nil
}

func (s *Server) beginTransport(ctx context.Context, principal auth.Principal, transportContext, method, service, repo, path string, credentialHeader bool) (*sandbox.TransportOperation, error) {
	authority, err := s.transport.ResolveAuthority(ctx, transportContext)
	if err != nil {
		return nil, err
	}
	if authority.Principal != principal.ID {
		return nil, errors.New("transport authority context principal mismatch")
	}
	op := &sandbox.TransportOperation{OperationID: ids.NewOperationID(), Method: method, Service: service, Repository: repo, RequestPath: path, RequestedRefs: []string{}, RefUpdates: []any{}, CredentialHeaderPresent: credentialHeader, Authority: authority}
	if err := s.transport.Received(ctx, op); err != nil {
		return nil, err
	}
	return op, nil
}

func (s *Server) denyTransport(ctx context.Context, op *sandbox.TransportOperation, code string, status int) bool {
	if op == nil {
		return true
	}
	return s.transport.Terminal(ctx, op, "denied", "denied", code, status, 0) == nil
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
	s.mu.RLock()
	oldTripwireEnabled := s.cfg.PushTripwire.Enabled
	oldTripwirePath := s.cfg.PushTripwire.StatePath
	s.mu.RUnlock()
	cfg, err := config.Load(s.configPath)
	if err != nil {
		return err
	}
	gh, err := githubapp.New(cfg.GitHub)
	if err != nil {
		return err
	}
	if cfg.PushTripwire.Enabled != oldTripwireEnabled || cfg.PushTripwire.StatePath != oldTripwirePath {
		return errors.New("push_tripwire enabled state and state_path cannot change on reload; restart is required")
	}
	s.mu.Lock()
	s.cfg = cfg
	s.gh = gh
	s.mu.Unlock()
	return nil
}

func (s *Server) pushTripwireSnapshot() (*config.Config, *githubapp.Client, *pushtripwire.Store, pushtripwire.FenceAdapter) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg, s.gh, s.tripwire, s.fence
}

func (s *Server) handlePushTripwireMaterial(w http.ResponseWriter, r *http.Request) {
	cfg, gh, store, _ := s.pushTripwireSnapshot()
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !cfg.PushTripwire.Enabled || store == nil {
		http.NotFound(w, r)
		return
	}
	if !pushtripwire.Authenticate(r.Header.Get("Authorization"), cfg.PushTripwire.ScannerSecret) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "scanner authentication failed"})
		return
	}
	var req pushtripwire.MaterialRequest
	if err := decodeStrictJSON(r.Body, &req); err != nil || req.Validate() != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid push tripwire material request"})
		return
	}
	repoCfg, ok := cfg.PushTripwire.Repositories[req.Repository]
	if !ok {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "repository is not configured for scanning"})
		return
	}
	if !tripwireRefAllowed(repoCfg, req.Ref) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "ref is not configured for scanning"})
		return
	}
	appName := repoCfg.GitHubApp
	if appName == "" {
		appName = "default"
	}
	inst, ok := cfg.InstallationIDForApp(appName, req.Repository)
	if !ok {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "repository installation is not configured"})
		return
	}
	out, err := gh.PushTripwireMaterial(appName, inst, req, repoCfg.BaseRef, cfg.PushTripwire.Bounds)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "scan material unavailable"})
		return
	}
	s.audit.Log(audit.Event{OperationID: ids.NewOperationID(), AgentID: cfg.PushTripwire.ScannerID, Operation: "push_tripwire.material", Repo: req.Repository, Branch: req.Ref, Decision: policy.DecisionAllow, Result: map[bool]string{true: "complete", false: "incomplete"}[out.Complete], Extra: map[string]interface{}{"delivery_id": req.DeliveryID, "reason_code": out.ReasonCode}})
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handlePushTripwireResponse(w http.ResponseWriter, r *http.Request) {
	cfg, _, store, fence := s.pushTripwireSnapshot()
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !cfg.PushTripwire.Enabled || store == nil {
		http.NotFound(w, r)
		return
	}
	if !pushtripwire.Authenticate(r.Header.Get("Authorization"), cfg.PushTripwire.ScannerSecret) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "scanner authentication failed"})
		return
	}
	var req pushtripwire.ResponseRequest
	if err := decodeStrictJSON(r.Body, &req); err != nil || req.Validate() != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid push tripwire response request"})
		return
	}
	if req.Severity != "high" {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "response controls require high severity"})
		return
	}
	repoCfg, ok := cfg.PushTripwire.Repositories[req.Repository]
	if !ok || !tripwireRefAllowed(repoCfg, req.Ref) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "response repository or ref is outside reviewed broker scope"})
		return
	}
	if !responseWithinReviewedScope(cfg.PushTripwire, req) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "response attribution is outside reviewed broker scope"})
		return
	}
	out, err := store.Apply(r.Context(), strings.TrimSpace(r.Header.Get("Idempotency-Key")), req, fence)
	if err != nil {
		status := http.StatusInternalServerError
		if strings.Contains(err.Error(), "Idempotency-Key") {
			status = http.StatusBadRequest
		}
		if strings.Contains(err.Error(), "reused") {
			status = http.StatusConflict
		}
		writeJSON(w, status, map[string]string{"error": audit.Redact(err.Error())})
		return
	}
	s.audit.Log(audit.Event{OperationID: ids.NewOperationID(), AgentID: cfg.PushTripwire.ScannerID, Operation: "push_tripwire.respond", Repo: req.Repository, Branch: req.Ref, Decision: policy.DecisionAllow, Result: "recorded", Extra: map[string]interface{}{"finding_id": req.FindingID, "delivery_id": req.DeliveryID, "fingerprint_id": req.FingerprintID, "severity": req.Severity, "reason_code": req.ReasonCode, "before": req.Before, "after": req.After, "profile": req.Profile, "profile_generation": req.ProfileGeneration, "idempotent_replay": out.IdempotentReplay, "actions": out.Actions}})
	writeJSON(w, http.StatusOK, out)
}

func tripwireRefAllowed(repo config.PushTripwireRepository, ref string) bool {
	for _, pattern := range repo.RefPatterns {
		if matched, err := regexp.MatchString(pattern, ref); err == nil && matched {
			return true
		}
	}
	return false
}

func responseWithinReviewedScope(cfg config.PushTripwireConfig, req pushtripwire.ResponseRequest) bool {
	scope, ok := cfg.ResponseProfiles[req.Profile]
	if !ok || scope.Generation != req.ProfileGeneration {
		return false
	}
	for _, action := range req.Actions {
		if action == "halt_issuance" && !scope.AllowHalt {
			return false
		}
		if action == "fence_worker_session" && !scope.AllowFence {
			return false
		}
	}
	if req.Binding == nil {
		return true
	}
	for _, binding := range scope.Bindings {
		if binding.WorkerID == req.Binding.WorkerID && binding.LogicalSessionID == req.Binding.LogicalSessionID && binding.SessionLineageID == req.Binding.SessionLineageID && binding.WorkerStorageLineageID == req.Binding.WorkerStorageLineageID && binding.WorkerFenceEpoch == req.Binding.WorkerFenceEpoch {
			return true
		}
	}
	return false
}

func decodeStrictJSON(body io.Reader, out interface{}) error {
	b, err := io.ReadAll(io.LimitReader(body, (64<<10)+1))
	if err != nil {
		return err
	}
	if len(b) > 64<<10 {
		return errors.New("request body exceeds limit")
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return err
	}
	var extra interface{}
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("request must contain one JSON value")
	}
	return nil
}

func (s *Server) snapshot() (*config.Config, *githubapp.Client) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg, s.gh
}

// blockUnsafeEgress is deliberately called after authentication/policy but
// before any GitHub client mutation. A finding therefore halts installation
// token issuance and the external write for this operation.
func (s *Server) blockUnsafeEgress(w http.ResponseWriter, operationID, agentID, repo, operation string, fields []securityscan.Segment) bool {
	finding := securityscan.Sequence(fields)
	if finding == nil {
		return false
	}
	if finding.Fingerprint != "" && s.credentialStore != nil {
		if err := s.credentialStore.HandleEffectTokenLeak(context.Background(), finding.Fingerprint); err != nil {
			s.audit.Log(audit.Event{OperationID: operationID, AgentID: agentID, Operation: "security.fence_failed", Repo: repo, Decision: policy.DecisionDeny, Result: "effect_token_fingerprint"})
		}
	}
	s.audit.Log(audit.Event{
		OperationID: operationID,
		AgentID:     agentID,
		Operation:   "security.egress_blocked",
		Repo:        repo,
		Decision:    policy.DecisionDeny,
		Result:      finding.Code,
		Extra: map[string]interface{}{
			"attempted_operation": operation,
			"field":               finding.Field,
			"surface":             "github_mutation",
		},
	})
	writeJSON(w, http.StatusUnprocessableEntity, api.ErrorResponse{
		Code:        "security_egress_blocked",
		Message:     "credential-shaped material is not allowed in broker-controlled output",
		OperationID: operationID,
		Decision:    policy.DecisionDeny,
	})
	return true
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/":
		handleDiscovery(w, r)
	case r.URL.Path == "/docs":
		handleDocs(w, r)
	case r.URL.Path == "/operations" || r.URL.Path == "/api/operations":
		handleOperations(w, r)
	case r.URL.Path == "/openapi.json":
		handleOpenAPI(w, r)
	case r.URL.Path == "/whoami" || r.URL.Path == "/api/whoami":
		s.handleWhoami(w, r)
	case r.URL.Path == "/healthz":
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	case r.URL.Path == "/readyz":
		writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
	case r.URL.Path == "/v1/admin/reload":
		s.handleReload(w, r)
	case r.URL.Path == "/v1/security/push-tripwire/material":
		s.handlePushTripwireMaterial(w, r)
	case r.URL.Path == "/v1/security/push-tripwire/respond":
		s.handlePushTripwireResponse(w, r)
	case r.URL.Path == "/v1/registered/github-green-pr/observe":
		s.handleRegisteredGreenPRObservation(w, r)
	case r.URL.Path == "/v1/registered/github-green-pr/create":
		s.handleRegisteredGreenPRCreate(w, r)
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

// handleRegisteredGreenPRObservation has an intentionally empty request
// surface: every completion fact is derived from durable admission, the
// broker's recorded smart-HTTP push, and authenticated GitHub reads.
func (s *Server) handleRegisteredGreenPRObservation(w http.ResponseWriter, r *http.Request) {
	principal, appName, admission, installation, gh, ok := s.registeredGreenPRAdmission(w, r, "observation")
	if !ok {
		return
	}
	observation, err := gh.ObserveGreenPR(appName, greenPRRequest(admission, appName, installation))
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "GitHub green PR observation failed"})
		return
	}
	s.audit.Log(audit.Event{OperationID: admission.OperationID, AgentID: principal.ID, Operation: "github_green_pr.observe", Repo: admission.Task.Parameters.Repository, Branch: admission.Task.Parameters.BranchRef, Decision: policy.DecisionAllow, Result: observation.Verdict})
	writeJSON(w, http.StatusOK, observation)
}

// handleRegisteredGreenPRCreate has the same empty request surface and
// durable admission source as observation. The fixed App installation creates
// the ready PR; callers cannot select its title, refs, body, or draft state.
func (s *Server) handleRegisteredGreenPRCreate(w http.ResponseWriter, r *http.Request) {
	principal, appName, admission, installation, gh, ok := s.registeredGreenPRAdmission(w, r, "creation")
	if !ok {
		return
	}
	pull, err := gh.CreateReadyGreenPR(appName, greenPRRequest(admission, appName, installation))
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "GitHub green PR creation was refused"})
		return
	}
	s.audit.Log(audit.Event{OperationID: admission.OperationID, AgentID: principal.ID, Operation: "github_green_pr.create", Repo: admission.Task.Parameters.Repository, Branch: admission.Task.Parameters.BranchRef, Decision: policy.DecisionAllow, GitHubURL: pull.URL, Result: "ok"})
	writeJSON(w, http.StatusCreated, pull)
}

func greenPRRequest(admission sandbox.GreenPRTransportAdmission, appName string, installation int64) githubapp.GreenPRRequest {
	return githubapp.GreenPRRequest{RegisteredTaskDigest: admission.TaskDigest, BrokerOperationID: admission.OperationID, AppSlug: appName, InstallationID: installation, Repository: admission.Task.Parameters.Repository, BaseRef: admission.Task.Parameters.BaseBranch, WorkerRef: "refs/heads/" + admission.Task.Parameters.BranchRef, PushedHeadSHA: admission.PushedSHA}
}

// registeredGreenPRAdmission authenticates the registered principal, rejects
// every caller-supplied completion fact, and derives all mutable PR inputs
// from the one durable task and completed broker push.
func (s *Server) registeredGreenPRAdmission(w http.ResponseWriter, r *http.Request, action string) (auth.Principal, string, sandbox.GreenPRTransportAdmission, int64, *githubapp.Client, bool) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return auth.Principal{}, "", sandbox.GreenPRTransportAdmission{}, 0, nil, false
	}
	if body, err := io.ReadAll(io.LimitReader(r.Body, 2)); err != nil || len(bytes.TrimSpace(body)) != 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "github green PR " + action + " accepts no caller facts"})
		return auth.Principal{}, "", sandbox.GreenPRTransportAdmission{}, 0, nil, false
	}
	cfg, gh := s.snapshot()
	if s.transport == nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "registered transport authority is unavailable"})
		return auth.Principal{}, "", sandbox.GreenPRTransportAdmission{}, 0, nil, false
	}
	transportContext := bearerTransportContext(r)
	authority, err := s.transport.ResolveAuthority(r.Context(), transportContext)
	if err != nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "registered transport authority is unavailable"})
		return auth.Principal{}, "", sandbox.GreenPRTransportAdmission{}, 0, nil, false
	}
	agent, found := configuredAgent(cfg, authority.Principal)
	if !found || s.transportProfiles[authority.Profile] != authority.Principal {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "registered transport authority is unavailable"})
		return auth.Principal{}, "", sandbox.GreenPRTransportAdmission{}, 0, nil, false
	}
	principal := auth.Principal{ID: authority.Principal, Agent: agent}
	admission, err := s.transport.GreenPRAdmission(r.Context(), transportContext)
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "registered green PR " + action + " is unavailable"})
		return auth.Principal{}, "", sandbox.GreenPRTransportAdmission{}, 0, nil, false
	}
	appName := config.GitHubAppName(principal.Agent)
	installation, ok := cfg.InstallationIDForApp(appName, admission.Task.Parameters.Repository)
	if !ok {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "repository installation is not configured"})
		return auth.Principal{}, "", sandbox.GreenPRTransportAdmission{}, 0, nil, false
	}
	result := registeredGreenPRPolicyCheck(principal, admission, action)
	if !result.Allowed {
		writeJSON(w, http.StatusForbidden, s.errorResponse(admission.OperationID, "policy_denied", "registered green PR "+action+" denied by policy", &result))
		return auth.Principal{}, "", sandbox.GreenPRTransportAdmission{}, 0, nil, false
	}
	return principal, appName, admission, installation, gh, true
}

func bearerTransportContext(r *http.Request) string {
	value := strings.TrimSpace(r.Header.Get("Authorization"))
	if strings.HasPrefix(strings.ToLower(value), "bearer ") {
		return strings.TrimSpace(value[len("bearer "):])
	}
	return ""
}

func configuredAgent(cfg *config.Config, id string) (config.Agent, bool) {
	for _, agent := range cfg.Agents {
		if agent.ID == id && agent.Enabled {
			return agent, true
		}
	}
	return config.Agent{}, false
}

// registeredGreenPRPolicyCheck requires the registered principal to authorize
// every broker operation performed by the selected fixed endpoint.
func registeredGreenPRPolicyCheck(principal auth.Principal, admission sandbox.GreenPRTransportAdmission, action string) policy.Result {
	var operations []string
	switch action {
	case "creation":
		operations = []string{"repo.probe", "pull.read", "pull.create"}
	case "observation":
		operations = []string{"repo.probe", "pull.read", "checks.read", "status.read"}
	default:
		return policy.Result{Allowed: false, Decision: policy.DecisionDeny}
	}
	for _, operation := range operations {
		result := policy.Check(policy.Request{
			Agent:      principal.Agent,
			AgentID:    principal.ID,
			Repo:       admission.Task.Parameters.Repository,
			Operation:  operation,
			Branch:     admission.Task.Parameters.BranchRef,
			BaseBranch: admission.Task.Parameters.BaseBranch,
		})
		if !result.Allowed {
			return result
		}
	}
	return policy.Result{Allowed: true, Decision: policy.DecisionAllow}
}

func handleDiscovery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"name":        "gh-agent-broker",
		"description": "GitHub Agent Access Broker",
		"version":     "v1",
		"links": map[string]string{
			"health":     "/healthz",
			"ready":      "/readyz",
			"operations": "/operations",
			"openapi":    "/openapi.json",
		},
		"git_remote_template": "/git/{owner}/{repo}.git",
		"auth":                "agent operations use HTTP basic auth with broker agent ID and broker agent secret",
	})
}

func handleOperations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"version": "v1",
		"operations": []map[string]interface{}{
			{
				"name":        "registered.github-green-pr.create",
				"method":      http.MethodPost,
				"path":        "/v1/registered/github-green-pr/create",
				"auth":        "registered agent",
				"description": "Create or return the exact ready PR derived from the registered task and completed broker push. This endpoint accepts no request body.",
			},
			{
				"name":        "registered.github-green-pr.observe",
				"method":      http.MethodPost,
				"path":        "/v1/registered/github-green-pr/observe",
				"auth":        "registered agent",
				"description": "Observe the exact ready PR derived from the registered task and completed broker push. This endpoint accepts no request body.",
			},
			{
				"name":        "repo.probe",
				"method":      http.MethodGet,
				"path":        "/v1/repos/{owner}/{repo}/probe",
				"auth":        "agent",
				"description": "Probe configured repository access through the broker.",
			},
			{
				"name":        "pull.create",
				"method":      http.MethodPost,
				"path":        "/v1/repos/{owner}/{repo}/pulls",
				"auth":        "agent",
				"description": "Create a pull request through the broker.",
				"metadata":    "send configured metadata fields in request body metadata",
			},
			{
				"name":        "pull.read",
				"method":      http.MethodGet,
				"path":        "/v1/repos/{owner}/{repo}/pulls",
				"auth":        "agent",
				"description": "List or get pull requests through the broker.",
			},
			{
				"name":        "pull.files.read",
				"method":      http.MethodGet,
				"path":        "/v1/repos/{owner}/{repo}/pulls/{number}/files",
				"auth":        "agent",
				"description": "List files changed by a pull request.",
			},
			{
				"name":        "pull.reviews.read",
				"method":      http.MethodGet,
				"path":        "/v1/repos/{owner}/{repo}/pulls/{number}/reviews",
				"auth":        "agent",
				"description": "List pull request reviews, review comments, or review threads.",
			},
			{
				"name":        "pull.review.dismiss",
				"method":      http.MethodPut,
				"path":        "/v1/repos/{owner}/{repo}/pulls/{number}/reviews/{review_id}/dismissal",
				"auth":        "agent",
				"description": "Dismiss a pull request review through the broker.",
				"metadata":    "send configured metadata fields in request body metadata",
			},
			{
				"name":        "pull.review_thread.resolve",
				"method":      http.MethodPut,
				"path":        "/v1/repos/{owner}/{repo}/pulls/{number}/review-threads/{thread_id}/resolve",
				"auth":        "agent",
				"description": "Resolve a pull request review thread through the broker.",
				"metadata":    "send configured metadata fields in request body metadata",
			},
			{
				"name":        "issue.comment",
				"method":      http.MethodPost,
				"path":        "/v1/repos/{owner}/{repo}/issues/{number}/comments",
				"auth":        "agent",
				"description": "Create an issue or pull request comment through the broker.",
				"metadata":    "send configured metadata fields in request body metadata",
			},
			{
				"name":        "issue.label.add",
				"method":      http.MethodPost,
				"path":        "/v1/repos/{owner}/{repo}/issues/{number}/labels",
				"auth":        "agent",
				"description": "Add labels to an issue or pull request through the broker.",
				"metadata":    "send configured metadata fields in request body metadata",
			},
			{
				"name":        "issue.label.remove",
				"method":      http.MethodDelete,
				"path":        "/v1/repos/{owner}/{repo}/issues/{number}/labels/{label}",
				"auth":        "agent",
				"description": "Remove a label from an issue or pull request through the broker.",
				"metadata":    "send configured metadata fields in request body metadata",
			},
			{
				"name":        "issue.read",
				"method":      http.MethodGet,
				"path":        "/v1/repos/{owner}/{repo}/issues",
				"auth":        "agent",
				"description": "List or get issues through the broker.",
			},
			{
				"name":        "issue.comments.read",
				"method":      http.MethodGet,
				"path":        "/v1/repos/{owner}/{repo}/issues/{number}/comments",
				"auth":        "agent",
				"description": "List issue or pull request conversation comments through the broker.",
			},
			{
				"name":        "status.read",
				"method":      http.MethodGet,
				"path":        "/v1/repos/{owner}/{repo}/commits/{sha}/status",
				"auth":        "agent",
				"description": "Read combined commit status through the broker.",
			},
			{
				"name":        "checks.read",
				"method":      http.MethodGet,
				"path":        "/v1/repos/{owner}/{repo}/commits/{sha}/check-runs",
				"auth":        "agent",
				"description": "Read commit check runs through the broker.",
			},
			{
				"name":        "issue.create",
				"method":      http.MethodPost,
				"path":        "/v1/repos/{owner}/{repo}/issues",
				"auth":        "agent",
				"description": "Create an issue through the broker.",
				"metadata":    "send configured metadata fields in request body metadata",
			},
			{
				"name":        "policy.dry-run",
				"method":      http.MethodPost,
				"path":        "/v1/policy/dry-run",
				"auth":        "agent",
				"description": "Evaluate broker policy without performing the requested operation.",
			},
			{
				"name":        "git.upload-pack",
				"method":      "GET/POST",
				"path":        "/git/{owner}/{repo}.git",
				"auth":        "git basic auth",
				"description": "Brokered Git clone/fetch smart-HTTP endpoint.",
			},
			{
				"name":        "git.receive-pack",
				"method":      "GET/POST",
				"path":        "/git/{owner}/{repo}.git",
				"auth":        "git basic auth",
				"description": "Brokered Git push smart-HTTP endpoint.",
			},
		},
	})
}

func handleDocs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte(`gh-agent-broker REST routes

Authentication:
- Agent operations use HTTP basic auth with broker agent ID and broker agent secret.
- Do not use GitHub tokens with the broker.

Discovery:
- GET /operations
- GET /openapi.json
- GET /whoami

Operations:
- POST /v1/registered/github-green-pr/create
- POST /v1/registered/github-green-pr/observe
- GET  /v1/repos/{owner}/{repo}/probe
- POST /v1/policy/dry-run
- GET  /v1/repos/{owner}/{repo}/pulls
- GET  /v1/repos/{owner}/{repo}/pulls/{number}
- GET  /v1/repos/{owner}/{repo}/pulls/{number}/files
- GET  /v1/repos/{owner}/{repo}/pulls/{number}/comments
- GET  /v1/repos/{owner}/{repo}/pulls/{number}/reviews
- GET  /v1/repos/{owner}/{repo}/pulls/{number}/review-comments
- GET  /v1/repos/{owner}/{repo}/pulls/{number}/review-threads
- PUT  /v1/repos/{owner}/{repo}/pulls/{number}/reviews/{review_id}/dismissal
- PUT  /v1/repos/{owner}/{repo}/pulls/{number}/review-threads/{thread_id}/resolve
- POST /v1/repos/{owner}/{repo}/pulls
- GET  /v1/repos/{owner}/{repo}/issues
- GET  /v1/repos/{owner}/{repo}/issues/{number}
- GET  /v1/repos/{owner}/{repo}/issues/{number}/comments
- POST /v1/repos/{owner}/{repo}/issues
- POST /v1/repos/{owner}/{repo}/issues/{number}/comments
- POST /v1/repos/{owner}/{repo}/issues/{number}/labels
- DELETE /v1/repos/{owner}/{repo}/issues/{number}/labels/{label}
- GET  /v1/repos/{owner}/{repo}/commits/{sha}/status
- GET  /v1/repos/{owner}/{repo}/commits/{sha}/check-runs

Git smart HTTP:
- /git/{owner}/{repo}.git
`)); err != nil {
		return
	}
}

func handleOpenAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, openAPISpec())
}

func (s *Server) handleWhoami(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	cfg, _ := s.snapshot()
	principal, ok := auth.AuthenticateAgent(r, cfg)
	if !ok {
		writeAuthJSON(w, api.ErrorResponse{Code: "unauthorized", Message: "agent authentication failed", Decision: policy.DecisionDeny})
		return
	}
	agent := principal.Agent
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"agent_id":               principal.ID,
		"enabled":                agent.Enabled,
		"repositories":           agent.Repositories,
		"operations":             agent.Operations,
		"branch_patterns":        agent.BranchPatterns,
		"base_branches":          agent.BaseBranches,
		"branch_lifecycle_guard": agent.BranchGuard,
		"permissions":            agent.Permissions,
		"metadata_assertions":    agent.MetadataAssertions,
	})
}

func openAPISpec() map[string]interface{} {
	errorResponse := map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"code":             map[string]string{"type": "string"},
			"message":          map[string]string{"type": "string"},
			"operation_id":     map[string]string{"type": "string"},
			"decision":         map[string]string{"type": "string"},
			"failed_checks":    map[string]interface{}{"type": "array", "items": map[string]string{"type": "object"}},
			"required_changes": map[string]interface{}{"type": "array", "items": map[string]string{"type": "object"}},
			"warnings":         map[string]interface{}{"type": "array", "items": map[string]string{"type": "object"}},
		},
	}
	return map[string]interface{}{
		"openapi": "3.1.0",
		"info": map[string]string{
			"title":   "GitHub Agent Access Broker",
			"version": "v1",
		},
		"security": []map[string][]string{{"agentBasicAuth": []string{}}},
		"components": map[string]interface{}{
			"securitySchemes": map[string]interface{}{
				"agentBasicAuth": map[string]string{
					"type":   "http",
					"scheme": "basic",
				},
			},
			"schemas": map[string]interface{}{
				"Metadata": map[string]interface{}{
					"type":                 "object",
					"additionalProperties": map[string]string{"type": "string"},
					"example": map[string]string{
						"Agent-Id":      "hermes-coder-01",
						"Hermes-Run-Id": "run-123",
					},
				},
				"DryRunRequest": map[string]interface{}{
					"type":     "object",
					"required": []string{"operation"},
					"properties": map[string]interface{}{
						"agent_id":    map[string]string{"type": "string"},
						"repo":        map[string]string{"type": "string", "description": "owner/repo, or repo name when owner is also supplied"},
						"repository":  map[string]string{"type": "string", "description": "owner/repo alias accepted for dry-run"},
						"owner":       map[string]string{"type": "string", "description": "repository owner, used with repo name"},
						"operation":   map[string]string{"type": "string"},
						"branch":      map[string]string{"type": "string"},
						"base_branch": map[string]string{"type": "string"},
						"permissions": map[string]interface{}{"type": "array", "items": map[string]string{"type": "string"}},
						"metadata":    map[string]interface{}{"$ref": "#/components/schemas/Metadata"},
					},
					"examples": map[string]interface{}{
						"pullCreate": map[string]interface{}{
							"value": map[string]interface{}{
								"repo":        "OWNER/REPO",
								"operation":   "pull.create",
								"branch":      "agent/hermes-coder-01/run-123",
								"base_branch": "main",
								"metadata": map[string]string{
									"Agent-Id":      "hermes-coder-01",
									"Hermes-Run-Id": "run-123",
								},
							},
						},
					},
				},
				"DryRunResponse": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"operation_id":     map[string]string{"type": "string"},
						"allowed":          map[string]string{"type": "boolean"},
						"decision":         map[string]string{"type": "string"},
						"failed_checks":    map[string]interface{}{"type": "array", "items": map[string]string{"type": "object"}},
						"warnings":         map[string]interface{}{"type": "array", "items": map[string]string{"type": "object"}},
						"required_changes": map[string]interface{}{"type": "array", "items": map[string]string{"type": "object"}},
					},
				},
				"PullCreateRequest": map[string]interface{}{
					"type":     "object",
					"required": []string{"title", "head", "base"},
					"properties": map[string]interface{}{
						"title":       map[string]string{"type": "string"},
						"head":        map[string]string{"type": "string"},
						"base":        map[string]string{"type": "string"},
						"body":        map[string]string{"type": "string"},
						"draft":       map[string]string{"type": "boolean"},
						"metadata":    map[string]interface{}{"$ref": "#/components/schemas/Metadata"},
						"permissions": map[string]interface{}{"type": "array", "items": map[string]string{"type": "string"}},
					},
					"example": map[string]interface{}{
						"title": "Hermes agent change",
						"head":  "agent/hermes-coder-01/run-123",
						"base":  "main",
						"body":  "Implemented requested change.",
						"metadata": map[string]string{
							"Agent-Id":      "hermes-coder-01",
							"Hermes-Run-Id": "run-123",
						},
					},
				},
				"CommentCreateRequest": map[string]interface{}{
					"type":     "object",
					"required": []string{"body"},
					"properties": map[string]interface{}{
						"body":        map[string]string{"type": "string"},
						"metadata":    map[string]interface{}{"$ref": "#/components/schemas/Metadata"},
						"permissions": map[string]interface{}{"type": "array", "items": map[string]string{"type": "string"}},
					},
					"example": map[string]interface{}{
						"body": "Hermes finished this run.",
						"metadata": map[string]string{
							"Agent-Id":      "hermes-coder-01",
							"Hermes-Run-Id": "run-123",
						},
					},
				},
				"IssueCreateRequest": map[string]interface{}{
					"type":     "object",
					"required": []string{"title", "body"},
					"properties": map[string]interface{}{
						"title":       map[string]string{"type": "string"},
						"body":        map[string]string{"type": "string"},
						"labels":      map[string]interface{}{"type": "array", "items": map[string]string{"type": "string"}},
						"metadata":    map[string]interface{}{"$ref": "#/components/schemas/Metadata"},
						"permissions": map[string]interface{}{"type": "array", "items": map[string]string{"type": "string"}},
					},
					"example": map[string]interface{}{
						"title":  "Agent-reported issue",
						"body":   "Observed behavior...",
						"labels": []string{"agent-reported"},
						"metadata": map[string]string{
							"Agent-Id":   "broker-reporter-01",
							"Dedupe-Key": "repo:path:summary",
						},
					},
				},
				"IssueLabelsRequest": map[string]interface{}{
					"type":     "object",
					"required": []string{"labels"},
					"properties": map[string]interface{}{
						"labels":      map[string]interface{}{"type": "array", "items": map[string]string{"type": "string"}},
						"metadata":    map[string]interface{}{"$ref": "#/components/schemas/Metadata"},
						"permissions": map[string]interface{}{"type": "array", "items": map[string]string{"type": "string"}},
					},
				},
				"PullReviewDismissRequest": map[string]interface{}{
					"type":     "object",
					"required": []string{"message"},
					"properties": map[string]interface{}{
						"message":     map[string]string{"type": "string"},
						"metadata":    map[string]interface{}{"$ref": "#/components/schemas/Metadata"},
						"permissions": map[string]interface{}{"type": "array", "items": map[string]string{"type": "string"}},
					},
				},
				"PullReviewThreadResolveRequest": map[string]interface{}{
					"type":     "object",
					"required": []string{"message"},
					"properties": map[string]interface{}{
						"message":     map[string]string{"type": "string"},
						"metadata":    map[string]interface{}{"$ref": "#/components/schemas/Metadata"},
						"permissions": map[string]interface{}{"type": "array", "items": map[string]string{"type": "string"}},
					},
				},
				"GitHubResult": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"url":      map[string]string{"type": "string"},
						"html_url": map[string]string{"type": "string"},
						"number":   map[string]string{"type": "integer"},
						"id":       map[string]string{"type": "integer"},
					},
				},
				"ErrorResponse": errorResponse,
			},
		},
		"paths": map[string]interface{}{
			"/healthz": map[string]interface{}{
				"get": map[string]interface{}{
					"summary":  "Health check",
					"security": []map[string][]string{},
					"responses": map[string]interface{}{
						"200": map[string]string{"description": "healthy"},
					},
				},
			},
			"/readyz": map[string]interface{}{
				"get": map[string]interface{}{
					"summary":  "Readiness check",
					"security": []map[string][]string{},
					"responses": map[string]interface{}{
						"200": map[string]string{"description": "ready"},
					},
				},
			},
			"/v1/policy/dry-run": map[string]interface{}{
				"post": map[string]interface{}{
					"summary":     "Evaluate policy without performing an operation",
					"requestBody": jsonRequestRef("#/components/schemas/DryRunRequest"),
					"responses": map[string]interface{}{
						"200": map[string]interface{}{"description": "allowed or warning decision", "content": jsonContentRef("#/components/schemas/DryRunResponse")},
						"403": map[string]interface{}{"description": "denied", "content": jsonContentRef("#/components/schemas/ErrorResponse")},
					},
				},
			},
			"/v1/repos/{owner}/{repo}/probe": map[string]interface{}{
				"get": map[string]interface{}{
					"summary":    "Probe repository access",
					"parameters": repoPathParams(),
					"responses": map[string]interface{}{
						"200": map[string]interface{}{"description": "repository probe result", "content": jsonContentRef("#/components/schemas/GitHubResult")},
						"403": map[string]interface{}{"description": "denied", "content": jsonContentRef("#/components/schemas/ErrorResponse")},
					},
				},
			},
			"/v1/repos/{owner}/{repo}/pulls": map[string]interface{}{
				"post": map[string]interface{}{
					"summary":     "Create pull request",
					"parameters":  repoPathParams(),
					"requestBody": jsonRequestRef("#/components/schemas/PullCreateRequest"),
					"responses": map[string]interface{}{
						"201": map[string]interface{}{"description": "pull request created", "content": jsonContentRef("#/components/schemas/GitHubResult")},
						"403": map[string]interface{}{"description": "denied", "content": jsonContentRef("#/components/schemas/ErrorResponse")},
					},
				},
			},
			"/v1/repos/{owner}/{repo}/issues/{number}/comments": map[string]interface{}{
				"post": map[string]interface{}{
					"summary": "Create issue or pull request comment",
					"parameters": append(repoPathParams(), map[string]interface{}{
						"name": "number", "in": "path", "required": true, "schema": map[string]string{"type": "string"},
					}),
					"requestBody": jsonRequestRef("#/components/schemas/CommentCreateRequest"),
					"responses": map[string]interface{}{
						"201": map[string]interface{}{"description": "comment created", "content": jsonContentRef("#/components/schemas/GitHubResult")},
						"403": map[string]interface{}{"description": "denied", "content": jsonContentRef("#/components/schemas/ErrorResponse")},
					},
				},
			},
			"/v1/repos/{owner}/{repo}/issues/{number}/labels": map[string]interface{}{
				"post": map[string]interface{}{
					"summary": "Add issue or pull request labels",
					"parameters": append(repoPathParams(), map[string]interface{}{
						"name": "number", "in": "path", "required": true, "schema": map[string]string{"type": "string"},
					}),
					"requestBody": jsonRequestRef("#/components/schemas/IssueLabelsRequest"),
					"responses": map[string]interface{}{
						"200": map[string]interface{}{"description": "resulting labels"},
						"403": map[string]interface{}{"description": "denied", "content": jsonContentRef("#/components/schemas/ErrorResponse")},
					},
				},
			},
			"/v1/repos/{owner}/{repo}/issues/{number}/labels/{label}": map[string]interface{}{
				"delete": map[string]interface{}{
					"summary": "Remove issue or pull request label",
					"parameters": append(repoPathParams(),
						map[string]interface{}{"name": "number", "in": "path", "required": true, "schema": map[string]string{"type": "string"}},
						map[string]interface{}{"name": "label", "in": "path", "required": true, "schema": map[string]string{"type": "string"}},
					),
					"responses": map[string]interface{}{
						"200": map[string]interface{}{"description": "resulting labels"},
						"403": map[string]interface{}{"description": "denied", "content": jsonContentRef("#/components/schemas/ErrorResponse")},
					},
				},
			},
			"/v1/repos/{owner}/{repo}/issues": map[string]interface{}{
				"post": map[string]interface{}{
					"summary":     "Create issue",
					"parameters":  repoPathParams(),
					"requestBody": jsonRequestRef("#/components/schemas/IssueCreateRequest"),
					"responses": map[string]interface{}{
						"201": map[string]interface{}{"description": "issue created", "content": jsonContentRef("#/components/schemas/GitHubResult")},
						"403": map[string]interface{}{"description": "denied", "content": jsonContentRef("#/components/schemas/ErrorResponse")},
					},
				},
			},
			"/v1/repos/{owner}/{repo}/pulls/{number}/reviews/{review_id}/dismissal": map[string]interface{}{
				"put": map[string]interface{}{
					"summary": "Dismiss pull request review",
					"parameters": append(repoPathParams(),
						map[string]interface{}{"name": "number", "in": "path", "required": true, "schema": map[string]string{"type": "integer"}},
						map[string]interface{}{"name": "review_id", "in": "path", "required": true, "schema": map[string]string{"type": "integer"}},
					),
					"requestBody": jsonRequestRef("#/components/schemas/PullReviewDismissRequest"),
					"responses": map[string]interface{}{
						"200": map[string]interface{}{"description": "review dismissed"},
						"403": map[string]interface{}{"description": "denied", "content": jsonContentRef("#/components/schemas/ErrorResponse")},
					},
				},
			},
			"/v1/repos/{owner}/{repo}/pulls/{number}/review-threads/{thread_id}/resolve": map[string]interface{}{
				"put": map[string]interface{}{
					"summary": "Resolve pull request review thread",
					"parameters": append(repoPathParams(),
						map[string]interface{}{"name": "number", "in": "path", "required": true, "schema": map[string]string{"type": "integer"}},
						map[string]interface{}{"name": "thread_id", "in": "path", "required": true, "schema": map[string]string{"type": "string"}},
					),
					"requestBody": jsonRequestRef("#/components/schemas/PullReviewThreadResolveRequest"),
					"responses": map[string]interface{}{
						"200": map[string]interface{}{"description": "thread resolved"},
						"403": map[string]interface{}{"description": "denied", "content": jsonContentRef("#/components/schemas/ErrorResponse")},
					},
				},
			},
		},
	}
}

func repoPathParams() []map[string]interface{} {
	return []map[string]interface{}{
		{"name": "owner", "in": "path", "required": true, "schema": map[string]string{"type": "string"}},
		{"name": "repo", "in": "path", "required": true, "schema": map[string]string{"type": "string"}},
	}
}

func jsonContentRef(ref string) map[string]interface{} {
	return map[string]interface{}{
		"application/json": map[string]interface{}{
			"schema": map[string]string{"$ref": ref},
		},
	}
}

func jsonRequestRef(ref string) map[string]interface{} {
	return map[string]interface{}{
		"required": true,
		"content":  jsonContentRef(ref),
	}
}

func (s *Server) handleReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	cfg, _ := s.snapshot()
	if !auth.AuthenticateAdmin(r, cfg) {
		writeAuthJSON(w, api.ErrorResponse{Code: "unauthorized", Message: "admin authentication failed", Decision: policy.DecisionDeny})
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
		writeAuthJSON(w, api.ErrorResponse{Code: "unauthorized", Message: "agent authentication failed", OperationID: opID, Decision: policy.DecisionDeny})
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
	repo := dryRunRepo(req)
	var installationID int64
	if id, ok := cfg.InstallationIDForApp(config.GitHubAppName(principal.Agent), repo); ok {
		installationID = id
	}
	enriched := metadata.WithBrokerFields(req.Metadata, principal.ID, opID, installationID)
	prBody := enriched
	commentBody := enriched
	result := policy.Check(policy.Request{
		Agent:       principal.Agent,
		AgentID:     principal.ID,
		Repo:        repo,
		Operation:   req.Operation,
		Branch:      req.Branch,
		BaseBranch:  req.BaseBranch,
		Permissions: req.Permissions,
		Metadata:    req.Metadata,
		Locations: map[string]map[string]string{
			"request":      req.Metadata,
			"pr_body":      prBody,
			"comment_body": commentBody,
		},
	})
	s.audit.Log(audit.Event{OperationID: opID, AgentID: principal.ID, Operation: "policy.dry-run", Repo: repo, Branch: req.Branch, RequestedPermissions: req.Permissions, Decision: result.Decision})
	writeJSON(w, statusFor(result), api.DryRunResponse{
		OperationID:     opID,
		Allowed:         result.Allowed,
		Decision:        result.Decision,
		FailedChecks:    result.FailedChecks,
		Warnings:        result.Warnings,
		RequiredChanges: result.RequiredChanges,
	})
}

func dryRunRepo(req api.DryRunRequest) string {
	if req.Repository != "" {
		return req.Repository
	}
	if req.Owner != "" && req.Repo != "" && !strings.Contains(req.Repo, "/") {
		return req.Owner + "/" + req.Repo
	}
	return req.Repo
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
	case len(parts) == 3 && parts[2] == "pulls" && r.Method == http.MethodGet:
		s.handlePullList(w, r, repo)
	case len(parts) == 3 && parts[2] == "pulls" && r.Method == http.MethodPost:
		s.handlePullCreate(w, r, repo)
	case len(parts) == 4 && parts[2] == "pulls" && r.Method == http.MethodGet:
		s.handlePullGet(w, r, repo, parts[3])
	case len(parts) == 5 && parts[2] == "pulls" && parts[4] == "files" && r.Method == http.MethodGet:
		s.handlePullFiles(w, r, repo, parts[3])
	case len(parts) == 5 && parts[2] == "pulls" && parts[4] == "comments" && r.Method == http.MethodGet:
		s.handlePullIssueComments(w, r, repo, parts[3])
	case len(parts) == 5 && parts[2] == "pulls" && parts[4] == "reviews" && r.Method == http.MethodGet:
		s.handlePullReviews(w, r, repo, parts[3])
	case len(parts) == 5 && parts[2] == "pulls" && parts[4] == "review-comments" && r.Method == http.MethodGet:
		s.handlePullReviewComments(w, r, repo, parts[3])
	case len(parts) == 5 && parts[2] == "pulls" && parts[4] == "review-threads" && r.Method == http.MethodGet:
		s.handlePullReviewThreads(w, r, repo, parts[3])
	case len(parts) == 7 && parts[2] == "pulls" && parts[4] == "reviews" && parts[6] == "dismissal" && r.Method == http.MethodPut:
		s.handlePullReviewDismiss(w, r, repo, parts[3], parts[5])
	case len(parts) == 7 && parts[2] == "pulls" && parts[4] == "review-threads" && parts[6] == "resolve" && r.Method == http.MethodPut:
		s.handlePullReviewThreadResolve(w, r, repo, parts[3], parts[5])
	case len(parts) == 3 && parts[2] == "issues" && r.Method == http.MethodPost:
		s.handleIssueCreate(w, r, repo)
	case len(parts) == 3 && parts[2] == "issues" && r.Method == http.MethodGet:
		s.handleIssueList(w, r, repo)
	case len(parts) == 4 && parts[2] == "issues" && r.Method == http.MethodGet:
		s.handleIssueGet(w, r, repo, parts[3])
	case len(parts) == 5 && parts[2] == "issues" && parts[4] == "comments" && r.Method == http.MethodGet:
		s.handleIssueComments(w, r, repo, parts[3])
	case len(parts) == 5 && parts[2] == "issues" && parts[4] == "comments" && r.Method == http.MethodPost:
		s.handleCommentCreate(w, r, repo, parts[3])
	case len(parts) == 5 && parts[2] == "issues" && parts[4] == "labels" && r.Method == http.MethodPost:
		s.handleIssueLabelsAdd(w, r, repo, parts[3])
	case len(parts) == 6 && parts[2] == "issues" && parts[4] == "labels" && r.Method == http.MethodDelete:
		s.handleIssueLabelRemove(w, r, repo, parts[3], parts[5])
	case len(parts) == 5 && parts[2] == "commits" && parts[4] == "status" && r.Method == http.MethodGet:
		s.handleCommitStatus(w, r, repo, parts[3])
	case len(parts) == 5 && parts[2] == "commits" && parts[4] == "check-runs" && r.Method == http.MethodGet:
		s.handleCheckRuns(w, r, repo, parts[3])
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
	}
}

func (s *Server) handlePullList(w http.ResponseWriter, r *http.Request, repo string) {
	s.withReadAccess(w, r, repo, "pull.read", "", func(_ string, gh *githubapp.Client, appName string, inst int64) (interface{}, error) {
		pulls, err := gh.ListPulls(appName, repo, inst, githubListQuery(r, []string{"state", "head", "base", "sort", "direction"}))
		if err != nil {
			return nil, err
		}
		if marker := strings.TrimSpace(r.URL.Query().Get("body_marker")); marker != "" {
			filtered := pulls[:0]
			for _, pull := range pulls {
				if strings.Contains(pull.Body, marker) {
					filtered = append(filtered, pull)
				}
			}
			pulls = filtered
		}
		if prefix := strings.TrimSpace(r.URL.Query().Get("head_prefix")); prefix != "" {
			filtered := pulls[:0]
			for _, pull := range pulls {
				if strings.HasPrefix(pull.HeadRef, prefix) {
					filtered = append(filtered, pull)
				}
			}
			pulls = filtered
		}
		return pulls, nil
	})
}

func (s *Server) handlePullGet(w http.ResponseWriter, r *http.Request, repo, rawNumber string) {
	number, ok := parsePositiveInt(w, rawNumber)
	if !ok {
		return
	}
	s.withReadAccess(w, r, repo, "pull.read", "", func(_ string, gh *githubapp.Client, appName string, inst int64) (interface{}, error) {
		return gh.GetPull(appName, repo, inst, number)
	})
}

func (s *Server) handlePullFiles(w http.ResponseWriter, r *http.Request, repo, rawNumber string) {
	number, ok := parsePositiveInt(w, rawNumber)
	if !ok {
		return
	}
	s.withReadAccess(w, r, repo, "pull.files.read", "", func(_ string, gh *githubapp.Client, appName string, inst int64) (interface{}, error) {
		return gh.ListPullFiles(appName, repo, inst, number, githubListQuery(r, nil))
	})
}

func (s *Server) handlePullIssueComments(w http.ResponseWriter, r *http.Request, repo, rawNumber string) {
	number, ok := parsePositiveInt(w, rawNumber)
	if !ok {
		return
	}
	s.withReadAccess(w, r, repo, "issue.comments.read", "", func(_ string, gh *githubapp.Client, appName string, inst int64) (interface{}, error) {
		return gh.ListIssueComments(appName, repo, inst, number, githubListQuery(r, []string{"since"}))
	})
}

func (s *Server) handlePullReviews(w http.ResponseWriter, r *http.Request, repo, rawNumber string) {
	number, ok := parsePositiveInt(w, rawNumber)
	if !ok {
		return
	}
	s.withReadAccess(w, r, repo, "pull.reviews.read", "", func(_ string, gh *githubapp.Client, appName string, inst int64) (interface{}, error) {
		return gh.ListPullReviews(appName, repo, inst, number, githubListQuery(r, nil))
	})
}

func (s *Server) handlePullReviewComments(w http.ResponseWriter, r *http.Request, repo, rawNumber string) {
	number, ok := parsePositiveInt(w, rawNumber)
	if !ok {
		return
	}
	s.withReadAccess(w, r, repo, "pull.reviews.read", "", func(_ string, gh *githubapp.Client, appName string, inst int64) (interface{}, error) {
		return gh.ListPullReviewComments(appName, repo, inst, number, githubListQuery(r, nil))
	})
}

func (s *Server) handlePullReviewThreads(w http.ResponseWriter, r *http.Request, repo, rawNumber string) {
	number, ok := parsePositiveInt(w, rawNumber)
	if !ok {
		return
	}
	s.withReadAccess(w, r, repo, "pull.reviews.read", "", func(_ string, gh *githubapp.Client, appName string, inst int64) (interface{}, error) {
		return gh.ListPullReviewThreads(appName, repo, inst, number, githubListQuery(r, nil))
	})
}

func (s *Server) handlePullReviewDismiss(w http.ResponseWriter, r *http.Request, repo, rawNumber, rawReviewID string) {
	opID := ids.NewOperationID()
	number, ok := parsePositiveInt(w, rawNumber)
	if !ok {
		return
	}
	reviewID := strings.TrimSpace(rawReviewID)
	if reviewID == "" {
		writeJSON(w, http.StatusBadRequest, api.ErrorResponse{Code: "invalid_request", Message: "review_id is required", OperationID: opID, Decision: policy.DecisionDeny})
		return
	}
	cfg, gh := s.snapshot()
	principal, ok := auth.AuthenticateAgent(r, cfg)
	if !ok {
		writeAuthJSON(w, api.ErrorResponse{Code: "unauthorized", Message: "agent authentication failed", OperationID: opID, Decision: policy.DecisionDeny})
		return
	}
	var req api.PullReviewDismissRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, api.ErrorResponse{Code: "invalid_json", Message: err.Error(), OperationID: opID, Decision: policy.DecisionDeny})
		return
	}
	if strings.TrimSpace(req.Message) == "" {
		writeJSON(w, http.StatusBadRequest, api.ErrorResponse{Code: "invalid_request", Message: "message is required", OperationID: opID, Decision: policy.DecisionDeny})
		return
	}
	appName := config.GitHubAppName(principal.Agent)
	inst, ok := cfg.InstallationIDForApp(appName, repo)
	if !ok {
		writeJSON(w, http.StatusForbidden, s.errorResponse(opID, "installation_not_configured", "repository has no configured GitHub App installation", nil))
		return
	}
	result := policy.Check(policy.Request{
		Agent:       principal.Agent,
		AgentID:     principal.ID,
		Repo:        repo,
		Operation:   "pull.review.dismiss",
		Permissions: req.Permissions,
		Metadata:    req.Metadata,
		Locations: map[string]map[string]string{
			"request": req.Metadata,
		},
	})
	if !result.Allowed {
		s.audit.Log(audit.Event{OperationID: opID, AgentID: principal.ID, Operation: "pull.review.dismiss", Repo: repo, RequestedPermissions: req.Permissions, Decision: result.Decision, Extra: map[string]interface{}{"pull_number": number, "review_id": reviewID}})
		writeJSON(w, http.StatusForbidden, s.errorResponse(opID, "policy_denied", "pull review dismissal denied by policy", &result))
		return
	}
	if s.blockUnsafeEgress(w, opID, principal.ID, repo, "pull.review.dismiss", []securityscan.Segment{{Name: "message", Value: req.Message}}) {
		return
	}
	key := idempotencyKey(r, fmt.Sprintf("pull.review.dismiss:%s:%d:%s", repo, number, reviewID))
	extra := map[string]interface{}{"pull_number": number, "review_id": reviewID, "idempotency_key": key}
	if replayed, err := replayIdempotent(w, cfg.Idempotency, key); err != nil {
		s.audit.Log(audit.Event{OperationID: opID, AgentID: principal.ID, Operation: "pull.review.dismiss", Repo: repo, RequestedPermissions: req.Permissions, Decision: policy.DecisionDeny, Error: err.Error(), Extra: extra})
		writeJSON(w, http.StatusInternalServerError, api.ErrorResponse{Code: "idempotency_error", Message: audit.Redact(err.Error()), OperationID: opID, Decision: policy.DecisionDeny})
		return
	} else if replayed {
		s.audit.Log(audit.Event{OperationID: opID, AgentID: principal.ID, Operation: "pull.review.dismiss", Repo: repo, RequestedPermissions: req.Permissions, Decision: result.Decision, Result: "idempotent_replay", Extra: extra})
		return
	}
	var out api.PullReview
	var err error
	if numericReviewID, parseErr := strconv.ParseInt(reviewID, 10, 64); parseErr == nil && numericReviewID > 0 {
		out, err = gh.DismissPullReview(appName, repo, inst, number, numericReviewID, req.Message)
	} else {
		out, err = gh.DismissPullReviewNode(appName, inst, reviewID, req.Message)
	}
	if err != nil {
		s.audit.Log(audit.Event{OperationID: opID, AgentID: principal.ID, Operation: "pull.review.dismiss", Repo: repo, RequestedPermissions: req.Permissions, Decision: result.Decision, Error: err.Error(), Extra: extra})
		writeJSON(w, http.StatusBadGateway, api.ErrorResponse{Code: "github_error", Message: audit.Redact(err.Error()), OperationID: opID, Decision: result.Decision, Warnings: result.Warnings})
		return
	}
	if err := writeIdempotentJSON(w, cfg.Idempotency, key, "pull.review.dismiss", http.StatusOK, out); err != nil {
		s.audit.Log(audit.Event{OperationID: opID, AgentID: principal.ID, Operation: "pull.review.dismiss", Repo: repo, RequestedPermissions: req.Permissions, Decision: result.Decision, Error: err.Error(), Extra: extra})
		writeJSON(w, http.StatusInternalServerError, api.ErrorResponse{Code: "idempotency_error", Message: audit.Redact(err.Error()), OperationID: opID, Decision: result.Decision})
		return
	}
	s.audit.Log(audit.Event{OperationID: opID, AgentID: principal.ID, Operation: "pull.review.dismiss", Repo: repo, RequestedPermissions: req.Permissions, Decision: result.Decision, GitHubURL: out.HTMLURL, Result: "ok", Extra: extra})
}

func (s *Server) handlePullReviewThreadResolve(w http.ResponseWriter, r *http.Request, repo, rawNumber, threadID string) {
	opID := ids.NewOperationID()
	number, ok := parsePositiveInt(w, rawNumber)
	if !ok {
		return
	}
	if strings.TrimSpace(threadID) == "" {
		writeJSON(w, http.StatusBadRequest, api.ErrorResponse{Code: "invalid_request", Message: "thread_id is required", OperationID: opID, Decision: policy.DecisionDeny})
		return
	}
	cfg, gh := s.snapshot()
	principal, ok := auth.AuthenticateAgent(r, cfg)
	if !ok {
		writeAuthJSON(w, api.ErrorResponse{Code: "unauthorized", Message: "agent authentication failed", OperationID: opID, Decision: policy.DecisionDeny})
		return
	}
	var req api.PullReviewThreadResolveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, api.ErrorResponse{Code: "invalid_json", Message: err.Error(), OperationID: opID, Decision: policy.DecisionDeny})
		return
	}
	if strings.TrimSpace(req.Message) == "" {
		writeJSON(w, http.StatusBadRequest, api.ErrorResponse{Code: "invalid_request", Message: "message is required", OperationID: opID, Decision: policy.DecisionDeny})
		return
	}
	appName := config.GitHubAppName(principal.Agent)
	inst, ok := cfg.InstallationIDForApp(appName, repo)
	if !ok {
		writeJSON(w, http.StatusForbidden, s.errorResponse(opID, "installation_not_configured", "repository has no configured GitHub App installation", nil))
		return
	}
	result := policy.Check(policy.Request{
		Agent:       principal.Agent,
		AgentID:     principal.ID,
		Repo:        repo,
		Operation:   "pull.review_thread.resolve",
		Permissions: req.Permissions,
		Metadata:    req.Metadata,
		Locations: map[string]map[string]string{
			"request": req.Metadata,
		},
	})
	if !result.Allowed {
		s.audit.Log(audit.Event{OperationID: opID, AgentID: principal.ID, Operation: "pull.review_thread.resolve", Repo: repo, RequestedPermissions: req.Permissions, Decision: result.Decision, Extra: map[string]interface{}{"pull_number": number, "thread_id": threadID}})
		writeJSON(w, http.StatusForbidden, s.errorResponse(opID, "policy_denied", "pull review thread resolution denied by policy", &result))
		return
	}
	if s.blockUnsafeEgress(w, opID, principal.ID, repo, "pull.review_thread.resolve", []securityscan.Segment{{Name: "message", Value: req.Message}}) {
		return
	}
	key := idempotencyKey(r, fmt.Sprintf("pull.review_thread.resolve:%s:%d:%s", repo, number, threadID))
	extra := map[string]interface{}{"pull_number": number, "thread_id": threadID, "idempotency_key": key}
	if replayed, err := replayIdempotent(w, cfg.Idempotency, key); err != nil {
		s.audit.Log(audit.Event{OperationID: opID, AgentID: principal.ID, Operation: "pull.review_thread.resolve", Repo: repo, RequestedPermissions: req.Permissions, Decision: policy.DecisionDeny, Error: err.Error(), Extra: extra})
		writeJSON(w, http.StatusInternalServerError, api.ErrorResponse{Code: "idempotency_error", Message: audit.Redact(err.Error()), OperationID: opID, Decision: policy.DecisionDeny})
		return
	} else if replayed {
		s.audit.Log(audit.Event{OperationID: opID, AgentID: principal.ID, Operation: "pull.review_thread.resolve", Repo: repo, RequestedPermissions: req.Permissions, Decision: result.Decision, Result: "idempotent_replay", Extra: extra})
		return
	}
	out, err := gh.ResolvePullReviewThread(appName, inst, threadID, req.Message)
	if err != nil {
		s.audit.Log(audit.Event{OperationID: opID, AgentID: principal.ID, Operation: "pull.review_thread.resolve", Repo: repo, RequestedPermissions: req.Permissions, Decision: result.Decision, Error: err.Error(), Extra: extra})
		writeJSON(w, http.StatusBadGateway, api.ErrorResponse{Code: "github_error", Message: audit.Redact(err.Error()), OperationID: opID, Decision: result.Decision, Warnings: result.Warnings})
		return
	}
	extra["resolved"] = out.IsResolved
	if err := writeIdempotentJSON(w, cfg.Idempotency, key, "pull.review_thread.resolve", http.StatusOK, out); err != nil {
		s.audit.Log(audit.Event{OperationID: opID, AgentID: principal.ID, Operation: "pull.review_thread.resolve", Repo: repo, RequestedPermissions: req.Permissions, Decision: result.Decision, Error: err.Error(), Extra: extra})
		writeJSON(w, http.StatusInternalServerError, api.ErrorResponse{Code: "idempotency_error", Message: audit.Redact(err.Error()), OperationID: opID, Decision: result.Decision})
		return
	}
	s.audit.Log(audit.Event{OperationID: opID, AgentID: principal.ID, Operation: "pull.review_thread.resolve", Repo: repo, RequestedPermissions: req.Permissions, Decision: result.Decision, Result: "ok", Extra: extra})
}

func (s *Server) handleIssueList(w http.ResponseWriter, r *http.Request, repo string) {
	s.withReadAccess(w, r, repo, "issue.read", "", func(_ string, gh *githubapp.Client, appName string, inst int64) (interface{}, error) {
		issues, err := gh.ListIssues(appName, repo, inst, githubListQuery(r, []string{"state", "labels", "assignee", "creator", "mentioned", "since", "sort", "direction"}))
		if err != nil {
			return nil, err
		}
		if marker := strings.TrimSpace(r.URL.Query().Get("body_marker")); marker != "" {
			filtered := issues[:0]
			for _, issue := range issues {
				if strings.Contains(issue.Body, marker) {
					filtered = append(filtered, issue)
				}
			}
			issues = filtered
		}
		return issues, nil
	})
}

func (s *Server) handleIssueGet(w http.ResponseWriter, r *http.Request, repo, rawNumber string) {
	number, ok := parsePositiveInt(w, rawNumber)
	if !ok {
		return
	}
	s.withReadAccess(w, r, repo, "issue.read", "", func(_ string, gh *githubapp.Client, appName string, inst int64) (interface{}, error) {
		return gh.GetIssue(appName, repo, inst, number)
	})
}

func (s *Server) handleIssueComments(w http.ResponseWriter, r *http.Request, repo, rawNumber string) {
	number, ok := parsePositiveInt(w, rawNumber)
	if !ok {
		return
	}
	s.withReadAccess(w, r, repo, "issue.comments.read", "", func(_ string, gh *githubapp.Client, appName string, inst int64) (interface{}, error) {
		return gh.ListIssueComments(appName, repo, inst, number, githubListQuery(r, []string{"since"}))
	})
}

func (s *Server) handleCommitStatus(w http.ResponseWriter, r *http.Request, repo, sha string) {
	s.withReadAccess(w, r, repo, "status.read", "", func(_ string, gh *githubapp.Client, appName string, inst int64) (interface{}, error) {
		return gh.GetCommitStatus(appName, repo, inst, sha)
	})
}

func (s *Server) handleCheckRuns(w http.ResponseWriter, r *http.Request, repo, sha string) {
	s.withReadAccess(w, r, repo, "checks.read", "", func(_ string, gh *githubapp.Client, appName string, inst int64) (interface{}, error) {
		return gh.ListCheckRuns(appName, repo, inst, sha, githubListQuery(r, []string{"check_name", "status", "filter"}))
	})
}

func (s *Server) withReadAccess(w http.ResponseWriter, r *http.Request, repo, operation, branch string, fn func(opID string, gh *githubapp.Client, appName string, inst int64) (interface{}, error)) {
	opID := ids.NewOperationID()
	cfg, gh := s.snapshot()
	principal, ok := auth.AuthenticateAgent(r, cfg)
	if !ok {
		writeAuthJSON(w, api.ErrorResponse{Code: "unauthorized", Message: "agent authentication failed", OperationID: opID, Decision: policy.DecisionDeny})
		return
	}
	appName := config.GitHubAppName(principal.Agent)
	inst, ok := cfg.InstallationIDForApp(appName, repo)
	if !ok {
		writeJSON(w, http.StatusForbidden, s.errorResponse(opID, "installation_not_configured", "repository has no configured GitHub App installation", nil))
		return
	}
	result := policy.Check(policy.Request{Agent: principal.Agent, AgentID: principal.ID, Repo: repo, Operation: operation, Branch: branch})
	if !result.Allowed {
		s.audit.Log(audit.Event{OperationID: opID, AgentID: principal.ID, Operation: operation, Repo: repo, Branch: branch, Decision: result.Decision})
		writeJSON(w, http.StatusForbidden, s.errorResponse(opID, "policy_denied", "read denied by policy", &result))
		return
	}
	out, err := fn(opID, gh, appName, inst)
	if err != nil {
		brokerStatus, code, _, extra := classifyGitHubReadError(err)
		s.audit.Log(audit.Event{OperationID: opID, AgentID: principal.ID, Operation: operation, Repo: repo, Branch: branch, Decision: result.Decision, Error: err.Error(), Extra: extra})
		writeJSON(w, brokerStatus, api.ErrorResponse{Code: code, Message: audit.Redact(err.Error()), OperationID: opID, Decision: result.Decision, Warnings: result.Warnings})
		return
	}
	s.audit.Log(audit.Event{OperationID: opID, AgentID: principal.ID, Operation: operation, Repo: repo, Branch: branch, Decision: result.Decision, Result: "ok"})
	writeJSON(w, http.StatusOK, out)
}

func classifyGitHubReadError(err error) (int, string, string, map[string]interface{}) {
	extra := map[string]interface{}{
		"upstream": "github",
	}
	var apiErr githubapp.APIError
	if errors.As(err, &apiErr) {
		extra["github_status"] = apiErr.StatusCode
		switch {
		case apiErr.StatusCode == http.StatusNotFound:
			extra["github_error_code"] = "github_not_found"
			extra["github_error_category"] = "not_found"
			extra["broker_status"] = http.StatusNotFound
			return http.StatusNotFound, "github_not_found", "not_found", extra
		case apiErr.RateLimited():
			extra["github_error_code"] = "github_rate_limited"
			extra["github_error_category"] = "rate_limited"
			extra["broker_status"] = http.StatusTooManyRequests
			return http.StatusTooManyRequests, "github_rate_limited", "rate_limited", extra
		case apiErr.StatusCode == http.StatusForbidden:
			extra["github_error_code"] = "github_forbidden"
			extra["github_error_category"] = "forbidden"
			extra["broker_status"] = http.StatusForbidden
			return http.StatusForbidden, "github_forbidden", "forbidden", extra
		default:
			extra["github_error_code"] = "github_error"
			extra["github_error_category"] = "upstream_error"
			extra["broker_status"] = http.StatusBadGateway
			return http.StatusBadGateway, "github_error", "upstream_error", extra
		}
	}
	if isTimeoutError(err) {
		extra["github_error_code"] = "github_timeout"
		extra["github_error_category"] = "timeout"
		extra["broker_status"] = http.StatusGatewayTimeout
		return http.StatusGatewayTimeout, "github_timeout", "timeout", extra
	}
	extra["github_error_code"] = "github_error"
	extra["github_error_category"] = "transport_error"
	extra["broker_status"] = http.StatusBadGateway
	return http.StatusBadGateway, "github_error", "transport_error", extra
}

func isTimeoutError(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) || os.IsTimeout(err) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func replayIdempotent(w http.ResponseWriter, cfg config.IdempotencyConfig, key string) (bool, error) {
	rec, ok, err := idempotency.Load(cfg, key)
	if err != nil || !ok {
		return false, err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(rec.Status)
	if _, err := w.Write(rec.Body); err != nil {
		return true, err
	}
	return true, nil
}

func writeIdempotentJSON(w http.ResponseWriter, cfg config.IdempotencyConfig, key, operation string, status int, out interface{}) error {
	body, err := json.Marshal(out)
	if err != nil {
		return err
	}
	if err := idempotency.Store(cfg, key, idempotency.Record{Operation: operation, Status: status, Body: body}); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if _, err := w.Write(body); err != nil {
		return err
	}
	return nil
}

func idempotencyHeader(r *http.Request) string {
	return strings.TrimSpace(r.Header.Get("Idempotency-Key"))
}

func idempotencyKey(r *http.Request, fallback string) string {
	if key := idempotencyHeader(r); key != "" {
		return key
	}
	return fallback
}

func cleanLabels(labels []string) []string {
	out := make([]string, 0, len(labels))
	seen := map[string]bool{}
	for _, label := range labels {
		label = strings.TrimSpace(label)
		if label == "" || seen[label] {
			continue
		}
		seen[label] = true
		out = append(out, label)
	}
	return out
}

func parsePositiveInt(w http.ResponseWriter, raw string) (int, bool) {
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 {
		writeJSON(w, http.StatusBadRequest, api.ErrorResponse{Code: "invalid_request", Message: "number must be a positive integer", Decision: policy.DecisionDeny})
		return 0, false
	}
	return n, true
}

func githubListQuery(r *http.Request, passthrough []string) url.Values {
	out := url.Values{}
	perPage := 30
	if raw := r.URL.Query().Get("per_page"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			perPage = n
		}
	}
	if perPage > 100 {
		perPage = 100
	}
	out.Set("per_page", strconv.Itoa(perPage))
	page := 1
	if raw := r.URL.Query().Get("page"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			page = n
		}
	}
	out.Set("page", strconv.Itoa(page))
	for _, key := range passthrough {
		if value := strings.TrimSpace(r.URL.Query().Get(key)); value != "" {
			out.Set(key, value)
		}
	}
	return out
}

func (s *Server) handleProbe(w http.ResponseWriter, r *http.Request, repo string) {
	opID := ids.NewOperationID()
	cfg, gh := s.snapshot()
	principal, ok := auth.AuthenticateAgent(r, cfg)
	if !ok {
		writeAuthJSON(w, api.ErrorResponse{Code: "unauthorized", Message: "agent authentication failed", OperationID: opID, Decision: policy.DecisionDeny})
		return
	}
	appName := config.GitHubAppName(principal.Agent)
	inst, ok := cfg.InstallationIDForApp(appName, repo)
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
	ghResult, err := gh.GetRepo(appName, repo, inst)
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
		writeAuthJSON(w, api.ErrorResponse{Code: "unauthorized", Message: "agent authentication failed", OperationID: opID, Decision: policy.DecisionDeny})
		return
	}
	var req api.PullCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, api.ErrorResponse{Code: "invalid_json", Message: err.Error(), OperationID: opID, Decision: policy.DecisionDeny})
		return
	}
	appName := config.GitHubAppName(principal.Agent)
	inst, ok := cfg.InstallationIDForApp(appName, repo)
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
	if s.blockUnsafeEgress(w, opID, principal.ID, repo, "pull.create", []securityscan.Segment{
		{Name: "title", Value: req.Title}, {Name: "body", Value: body}, {Name: "head", Value: req.Head}, {Name: "base", Value: req.Base},
	}) {
		return
	}
	guardResult := s.checkBranchLifecycle(opID, gh, appName, inst, repo, req.Head, "pull.create", principal.Agent)
	if guardResult != nil {
		result.Warnings = append(result.Warnings, guardResult.Warnings...)
		if !guardResult.Allowed {
			s.audit.Log(audit.Event{OperationID: opID, AgentID: principal.ID, Operation: "pull.create", Repo: repo, Branch: req.Head, RequestedPermissions: req.Permissions, Decision: guardResult.Decision})
			writeJSON(w, http.StatusForbidden, s.errorResponse(opID, "policy_denied", "pull request creation denied by policy", guardResult))
			return
		}
		if guardResult.Decision == policy.DecisionWarn {
			result.Decision = policy.DecisionWarn
			s.audit.Log(audit.Event{OperationID: opID, AgentID: principal.ID, Operation: "pull.create", Repo: repo, Branch: req.Head, RequestedPermissions: req.Permissions, Decision: result.Decision, Result: "branch_lifecycle_warning"})
		}
	}
	if !s.reserveMutation(w, opID, principal.ID, "pull.create", repo, req.Head, req.Metadata) {
		return
	}
	ghResult, err := gh.CreatePull(appName, repo, inst, req.Title, req.Head, req.Base, body, req.Draft)
	if err != nil {
		s.audit.Log(audit.Event{OperationID: opID, AgentID: principal.ID, Operation: "pull.create", Repo: repo, Branch: req.Head, RequestedPermissions: req.Permissions, Decision: result.Decision, Error: err.Error()})
		writeJSON(w, http.StatusBadGateway, api.ErrorResponse{Code: "github_error", Message: audit.Redact(err.Error()), OperationID: opID, Decision: result.Decision, Warnings: result.Warnings})
		return
	}
	s.audit.Log(audit.Event{OperationID: opID, AgentID: principal.ID, Operation: "pull.create", Repo: repo, Branch: req.Head, RequestedPermissions: req.Permissions, Decision: result.Decision, GitHubURL: ghResult.HTMLURL, Result: "ok"})
	writeJSON(w, http.StatusCreated, ghResult)
}

func (s *Server) handleIssueCreate(w http.ResponseWriter, r *http.Request, repo string) {
	opID := ids.NewOperationID()
	cfg, gh := s.snapshot()
	principal, ok := auth.AuthenticateAgent(r, cfg)
	if !ok {
		writeAuthJSON(w, api.ErrorResponse{Code: "unauthorized", Message: "agent authentication failed", OperationID: opID, Decision: policy.DecisionDeny})
		return
	}
	var req api.IssueCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, api.ErrorResponse{Code: "invalid_json", Message: err.Error(), OperationID: opID, Decision: policy.DecisionDeny})
		return
	}
	if strings.TrimSpace(req.Title) == "" {
		writeJSON(w, http.StatusBadRequest, api.ErrorResponse{Code: "invalid_request", Message: "title is required", OperationID: opID, Decision: policy.DecisionDeny})
		return
	}
	if strings.TrimSpace(req.Body) == "" {
		writeJSON(w, http.StatusBadRequest, api.ErrorResponse{Code: "invalid_request", Message: "body is required", OperationID: opID, Decision: policy.DecisionDeny})
		return
	}
	appName := config.GitHubAppName(principal.Agent)
	inst, ok := cfg.InstallationIDForApp(appName, repo)
	if !ok {
		writeJSON(w, http.StatusForbidden, s.errorResponse(opID, "installation_not_configured", "repository has no configured GitHub App installation", nil))
		return
	}
	enriched := metadata.WithBrokerFields(req.Metadata, principal.ID, opID, inst)
	result := policy.Check(policy.Request{
		Agent:       principal.Agent,
		AgentID:     principal.ID,
		Repo:        repo,
		Operation:   "issue.create",
		Permissions: req.Permissions,
		Metadata:    req.Metadata,
		Locations: map[string]map[string]string{
			"request":    req.Metadata,
			"issue_body": enriched,
		},
	})
	if !result.Allowed {
		s.audit.Log(audit.Event{OperationID: opID, AgentID: principal.ID, Operation: "issue.create", Repo: repo, RequestedPermissions: req.Permissions, Decision: result.Decision})
		writeJSON(w, http.StatusForbidden, s.errorResponse(opID, "policy_denied", "issue creation denied by policy", &result))
		return
	}
	body := req.Body + metadata.RenderBlock(enriched)
	fields := []securityscan.Segment{{Name: "title", Value: req.Title}, {Name: "body", Value: body}}
	for i, label := range req.Labels {
		fields = append(fields, securityscan.Segment{Name: fmt.Sprintf("labels[%d]", i), Value: label})
	}
	if s.blockUnsafeEgress(w, opID, principal.ID, repo, "issue.create", fields) {
		return
	}
	if !s.reserveMutation(w, opID, principal.ID, "issue.create", repo, "", req.Metadata) {
		return
	}
	ghResult, err := gh.CreateIssue(appName, repo, inst, req.Title, body, req.Labels)
	if err != nil {
		s.audit.Log(audit.Event{OperationID: opID, AgentID: principal.ID, Operation: "issue.create", Repo: repo, RequestedPermissions: req.Permissions, Decision: result.Decision, Error: err.Error()})
		writeJSON(w, http.StatusBadGateway, api.ErrorResponse{Code: "github_error", Message: audit.Redact(err.Error()), OperationID: opID, Decision: result.Decision, Warnings: result.Warnings})
		return
	}
	s.audit.Log(audit.Event{OperationID: opID, AgentID: principal.ID, Operation: "issue.create", Repo: repo, RequestedPermissions: req.Permissions, Decision: result.Decision, GitHubURL: ghResult.HTMLURL, Result: "ok"})
	writeJSON(w, http.StatusCreated, ghResult)
}

func (s *Server) handleCommentCreate(w http.ResponseWriter, r *http.Request, repo, issueNumber string) {
	opID := ids.NewOperationID()
	cfg, gh := s.snapshot()
	principal, ok := auth.AuthenticateAgent(r, cfg)
	if !ok {
		writeAuthJSON(w, api.ErrorResponse{Code: "unauthorized", Message: "agent authentication failed", OperationID: opID, Decision: policy.DecisionDeny})
		return
	}
	var req api.CommentCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, api.ErrorResponse{Code: "invalid_json", Message: err.Error(), OperationID: opID, Decision: policy.DecisionDeny})
		return
	}
	appName := config.GitHubAppName(principal.Agent)
	inst, ok := cfg.InstallationIDForApp(appName, repo)
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
	if s.blockUnsafeEgress(w, opID, principal.ID, repo, "issue.comment", []securityscan.Segment{{Name: "body", Value: body}}) {
		return
	}
	key := idempotencyHeader(r)
	extra := map[string]interface{}{"issue_number": issueNumber, "idempotency_key": key}
	if replayed, err := replayIdempotent(w, cfg.Idempotency, key); err != nil {
		s.audit.Log(audit.Event{OperationID: opID, AgentID: principal.ID, Operation: "issue.comment", Repo: repo, RequestedPermissions: req.Permissions, Decision: policy.DecisionDeny, Error: err.Error(), Extra: extra})
		writeJSON(w, http.StatusInternalServerError, api.ErrorResponse{Code: "idempotency_error", Message: audit.Redact(err.Error()), OperationID: opID, Decision: policy.DecisionDeny})
		return
	} else if replayed {
		s.audit.Log(audit.Event{OperationID: opID, AgentID: principal.ID, Operation: "issue.comment", Repo: repo, RequestedPermissions: req.Permissions, Decision: result.Decision, Result: "idempotent_replay", Extra: extra})
		return
	}
	ghResult, err := gh.CreateIssueComment(appName, repo, issueNumber, inst, body)
	if err != nil {
		s.audit.Log(audit.Event{OperationID: opID, AgentID: principal.ID, Operation: "issue.comment", Repo: repo, RequestedPermissions: req.Permissions, Decision: result.Decision, Error: err.Error(), Extra: extra})
		writeJSON(w, http.StatusBadGateway, api.ErrorResponse{Code: "github_error", Message: audit.Redact(err.Error()), OperationID: opID, Decision: result.Decision, Warnings: result.Warnings})
		return
	}
	extra["comment_id"] = ghResult.ID
	if err := writeIdempotentJSON(w, cfg.Idempotency, key, "issue.comment", http.StatusCreated, ghResult); err != nil {
		s.audit.Log(audit.Event{OperationID: opID, AgentID: principal.ID, Operation: "issue.comment", Repo: repo, RequestedPermissions: req.Permissions, Decision: result.Decision, Error: err.Error(), Extra: extra})
		writeJSON(w, http.StatusInternalServerError, api.ErrorResponse{Code: "idempotency_error", Message: audit.Redact(err.Error()), OperationID: opID, Decision: result.Decision})
		return
	}
	s.audit.Log(audit.Event{OperationID: opID, AgentID: principal.ID, Operation: "issue.comment", Repo: repo, RequestedPermissions: req.Permissions, Decision: result.Decision, GitHubURL: ghResult.HTMLURL, Result: "ok", Extra: extra})
}

func (s *Server) handleIssueLabelsAdd(w http.ResponseWriter, r *http.Request, repo, rawNumber string) {
	opID := ids.NewOperationID()
	number, ok := parsePositiveInt(w, rawNumber)
	if !ok {
		return
	}
	cfg, gh := s.snapshot()
	principal, ok := auth.AuthenticateAgent(r, cfg)
	if !ok {
		writeAuthJSON(w, api.ErrorResponse{Code: "unauthorized", Message: "agent authentication failed", OperationID: opID, Decision: policy.DecisionDeny})
		return
	}
	var req api.IssueLabelsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, api.ErrorResponse{Code: "invalid_json", Message: err.Error(), OperationID: opID, Decision: policy.DecisionDeny})
		return
	}
	labels := cleanLabels(req.Labels)
	if len(labels) == 0 {
		writeJSON(w, http.StatusBadRequest, api.ErrorResponse{Code: "invalid_request", Message: "labels are required", OperationID: opID, Decision: policy.DecisionDeny})
		return
	}
	appName := config.GitHubAppName(principal.Agent)
	inst, ok := cfg.InstallationIDForApp(appName, repo)
	if !ok {
		writeJSON(w, http.StatusForbidden, s.errorResponse(opID, "installation_not_configured", "repository has no configured GitHub App installation", nil))
		return
	}
	result := policy.Check(policy.Request{
		Agent:       principal.Agent,
		AgentID:     principal.ID,
		Repo:        repo,
		Operation:   "issue.label.add",
		Permissions: req.Permissions,
		Metadata:    req.Metadata,
		Locations:   map[string]map[string]string{"request": req.Metadata},
	})
	if !result.Allowed {
		s.audit.Log(audit.Event{OperationID: opID, AgentID: principal.ID, Operation: "issue.label.add", Repo: repo, RequestedPermissions: req.Permissions, Decision: result.Decision, Extra: map[string]interface{}{"issue_number": number, "labels": labels}})
		writeJSON(w, http.StatusForbidden, s.errorResponse(opID, "policy_denied", "label add denied by policy", &result))
		return
	}
	key := idempotencyKey(r, fmt.Sprintf("issue.label.add:%s:%d:%s", repo, number, strings.Join(labels, ",")))
	extra := map[string]interface{}{"issue_number": number, "labels": labels, "idempotency_key": key}
	if replayed, err := replayIdempotent(w, cfg.Idempotency, key); err != nil {
		s.audit.Log(audit.Event{OperationID: opID, AgentID: principal.ID, Operation: "issue.label.add", Repo: repo, RequestedPermissions: req.Permissions, Decision: policy.DecisionDeny, Error: err.Error(), Extra: extra})
		writeJSON(w, http.StatusInternalServerError, api.ErrorResponse{Code: "idempotency_error", Message: audit.Redact(err.Error()), OperationID: opID, Decision: policy.DecisionDeny})
		return
	} else if replayed {
		s.audit.Log(audit.Event{OperationID: opID, AgentID: principal.ID, Operation: "issue.label.add", Repo: repo, RequestedPermissions: req.Permissions, Decision: result.Decision, Result: "idempotent_replay", Extra: extra})
		return
	}
	out, err := gh.AddIssueLabels(appName, repo, inst, number, labels)
	if err != nil {
		s.audit.Log(audit.Event{OperationID: opID, AgentID: principal.ID, Operation: "issue.label.add", Repo: repo, RequestedPermissions: req.Permissions, Decision: result.Decision, Error: err.Error(), Extra: extra})
		writeJSON(w, http.StatusBadGateway, api.ErrorResponse{Code: "github_error", Message: audit.Redact(err.Error()), OperationID: opID, Decision: result.Decision, Warnings: result.Warnings})
		return
	}
	body := map[string]interface{}{"labels": out}
	if err := writeIdempotentJSON(w, cfg.Idempotency, key, "issue.label.add", http.StatusOK, body); err != nil {
		s.audit.Log(audit.Event{OperationID: opID, AgentID: principal.ID, Operation: "issue.label.add", Repo: repo, RequestedPermissions: req.Permissions, Decision: result.Decision, Error: err.Error(), Extra: extra})
		writeJSON(w, http.StatusInternalServerError, api.ErrorResponse{Code: "idempotency_error", Message: audit.Redact(err.Error()), OperationID: opID, Decision: result.Decision})
		return
	}
	s.audit.Log(audit.Event{OperationID: opID, AgentID: principal.ID, Operation: "issue.label.add", Repo: repo, RequestedPermissions: req.Permissions, Decision: result.Decision, Result: "ok", Extra: extra})
}

func (s *Server) handleIssueLabelRemove(w http.ResponseWriter, r *http.Request, repo, rawNumber, rawLabel string) {
	opID := ids.NewOperationID()
	number, ok := parsePositiveInt(w, rawNumber)
	if !ok {
		return
	}
	label, err := url.PathUnescape(rawLabel)
	if err != nil || strings.TrimSpace(label) == "" {
		writeJSON(w, http.StatusBadRequest, api.ErrorResponse{Code: "invalid_request", Message: "label is required", OperationID: opID, Decision: policy.DecisionDeny})
		return
	}
	label = strings.TrimSpace(label)
	cfg, gh := s.snapshot()
	principal, ok := auth.AuthenticateAgent(r, cfg)
	if !ok {
		writeAuthJSON(w, api.ErrorResponse{Code: "unauthorized", Message: "agent authentication failed", OperationID: opID, Decision: policy.DecisionDeny})
		return
	}
	appName := config.GitHubAppName(principal.Agent)
	inst, ok := cfg.InstallationIDForApp(appName, repo)
	if !ok {
		writeJSON(w, http.StatusForbidden, s.errorResponse(opID, "installation_not_configured", "repository has no configured GitHub App installation", nil))
		return
	}
	result := policy.Check(policy.Request{Agent: principal.Agent, AgentID: principal.ID, Repo: repo, Operation: "issue.label.remove"})
	if !result.Allowed {
		s.audit.Log(audit.Event{OperationID: opID, AgentID: principal.ID, Operation: "issue.label.remove", Repo: repo, Decision: result.Decision, Extra: map[string]interface{}{"issue_number": number, "label": label}})
		writeJSON(w, http.StatusForbidden, s.errorResponse(opID, "policy_denied", "label removal denied by policy", &result))
		return
	}
	key := idempotencyKey(r, fmt.Sprintf("issue.label.remove:%s:%d:%s", repo, number, label))
	extra := map[string]interface{}{"issue_number": number, "label": label, "idempotency_key": key}
	if replayed, err := replayIdempotent(w, cfg.Idempotency, key); err != nil {
		s.audit.Log(audit.Event{OperationID: opID, AgentID: principal.ID, Operation: "issue.label.remove", Repo: repo, Decision: policy.DecisionDeny, Error: err.Error(), Extra: extra})
		writeJSON(w, http.StatusInternalServerError, api.ErrorResponse{Code: "idempotency_error", Message: audit.Redact(err.Error()), OperationID: opID, Decision: policy.DecisionDeny})
		return
	} else if replayed {
		s.audit.Log(audit.Event{OperationID: opID, AgentID: principal.ID, Operation: "issue.label.remove", Repo: repo, Decision: result.Decision, Result: "idempotent_replay", Extra: extra})
		return
	}
	out, err := gh.RemoveIssueLabel(appName, repo, inst, number, label)
	if err != nil {
		s.audit.Log(audit.Event{OperationID: opID, AgentID: principal.ID, Operation: "issue.label.remove", Repo: repo, Decision: result.Decision, Error: err.Error(), Extra: extra})
		writeJSON(w, http.StatusBadGateway, api.ErrorResponse{Code: "github_error", Message: audit.Redact(err.Error()), OperationID: opID, Decision: result.Decision, Warnings: result.Warnings})
		return
	}
	body := map[string]interface{}{"labels": out}
	if err := writeIdempotentJSON(w, cfg.Idempotency, key, "issue.label.remove", http.StatusOK, body); err != nil {
		s.audit.Log(audit.Event{OperationID: opID, AgentID: principal.ID, Operation: "issue.label.remove", Repo: repo, Decision: result.Decision, Error: err.Error(), Extra: extra})
		writeJSON(w, http.StatusInternalServerError, api.ErrorResponse{Code: "idempotency_error", Message: audit.Redact(err.Error()), OperationID: opID, Decision: result.Decision})
		return
	}
	s.audit.Log(audit.Event{OperationID: opID, AgentID: principal.ID, Operation: "issue.label.remove", Repo: repo, Decision: result.Decision, Result: "ok", Extra: extra})
}

func (s *Server) handleGit(w http.ResponseWriter, r *http.Request) {
	opID := ids.NewOperationID()
	cfg, gh := s.snapshot()
	repo, suffix, ok := parseGitPath(r.URL.Path)
	if !ok {
		http.Error(w, "invalid git path", http.StatusNotFound)
		return
	}
	principal, ok := auth.AuthenticateAgent(r, cfg)
	if !ok && s.credentialStore != nil {
		id, secret, basic := r.BasicAuth()
		if basic {
			if custody, valid, err := s.credentialStore.AuthenticateGitCredential(r.Context(), id, secret, repo); err == nil && valid {
				if parent, found := cfg.AgentByID(custody.Principal); found {
					parent.ID = custody.AgentID
					parent.Secret = ""
					parent.Repositories = []string{custody.Repository}
					principal, ok = auth.Principal{Agent: parent, ID: custody.AgentID}, true
				}
			}
		}
	}
	if !ok {
		writeAuthText(w, "agent authentication failed")
		return
	}
	operation := gitOperation(r, suffix)
	if operation == "" {
		http.Error(w, "unsupported git operation", http.StatusBadRequest)
		return
	}
	var transport *sandbox.TransportOperation
	if s.transport != nil {
		var err error
		transport, err = s.beginTransport(r.Context(), principal, r.Header.Get("X-GH-Agent-Broker-Transport-Context"), r.Method, strings.ReplaceAll(operation, ".", "-"), repo, r.URL.Path, r.Header.Get("Authorization") != "")
		if err != nil {
			http.Error(w, "transport authority observation unavailable", http.StatusServiceUnavailable)
			return
		}
	}
	var bodyReader io.Reader = r.Body
	branch := ""
	var updates []receivePackUpdate
	if operation == "git.receive-pack" && r.Method == http.MethodPost && r.Body != nil {
		prefix, parsedUpdates, parseErr := readReceivePackCommandPrefix(r.Body)
		if parseErr != nil {
			status := http.StatusBadRequest
			if errors.Is(parseErr, errReceivePackCommandPrefixLimit) {
				status = http.StatusRequestEntityTooLarge
			}
			s.audit.Log(audit.Event{OperationID: opID, AgentID: principal.ID, Operation: operation, Repo: repo, Decision: policy.DecisionDeny, Result: "receive_pack_command_prefix_rejected"})
			if !s.denyTransport(r.Context(), transport, "receive_pack_command_prefix_rejected", status) {
				http.Error(w, "transport event persistence failed", http.StatusServiceUnavailable)
				return
			}
			http.Error(w, "invalid receive-pack command prefix", status)
			return
		}
		updates = parsedUpdates
		if transport != nil {
			transport.RefUpdates = parsedUpdates
		}
		bodyReader = io.MultiReader(bytes.NewReader(prefix), r.Body)
		if len(parsedUpdates) > 0 {
			branch = parsedUpdates[0].Ref
		}
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
		if !s.denyTransport(r.Context(), transport, "branch_unparseable", http.StatusForbidden) {
			http.Error(w, "transport event persistence failed", http.StatusServiceUnavailable)
			return
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
		if !s.denyTransport(r.Context(), transport, "policy_denied", http.StatusForbidden) {
			http.Error(w, "transport event persistence failed", http.StatusServiceUnavailable)
			return
		}
		s.audit.Log(audit.Event{OperationID: opID, AgentID: principal.ID, Operation: operation, Repo: repo, Branch: branch, Decision: result.Decision})
		writeGitPolicyError(w, r, s.errorResponse(opID, "policy_denied", "git operation denied by policy", &result))
		return
	}
	for i := 1; i < len(updates); i++ {
		update := updates[i]
		additional := policy.Check(policy.Request{Agent: principal.Agent, AgentID: principal.ID, Repo: repo, Operation: operation, Branch: update.Ref})
		if !additional.Allowed {
			s.audit.Log(audit.Event{OperationID: opID, AgentID: principal.ID, Operation: operation, Repo: repo, Branch: update.Ref, Decision: additional.Decision})
			writeGitPolicyError(w, r, s.errorResponse(opID, "policy_denied", "git operation denied by policy", &additional))
			return
		}
	}
	if operation == "git.receive-pack" && r.Method == http.MethodPost && principal.Agent.GitReceivePack == config.GitReceivePackDenyOpaque {
		result = policy.Result{
			Allowed:  false,
			Decision: policy.DecisionDeny,
			FailedChecks: []api.FailedCheck{{
				Dimension:     "security_egress",
				Location:      "git.receive-pack",
				Expected:      "semantic packfile inspection before forwarding",
				SafeToDisplay: true,
				Message:       "opaque Git pushes are disabled for this broker identity until semantic packfile inspection is available",
			}},
			RequiredChanges: []api.RequiredChange{{
				Location: "git.receive-pack",
				Action:   "use broker-controlled textual mutation paths or an identity explicitly allowed to forward opaque packfiles",
			}},
		}
		s.audit.Log(audit.Event{
			OperationID: opID,
			AgentID:     principal.ID,
			Operation:   "security.egress_blocked",
			Repo:        repo,
			Branch:      branch,
			Decision:    policy.DecisionDeny,
			Result:      "semantic_pack_inspection_unavailable",
			Extra:       map[string]interface{}{"attempted_operation": operation, "surface": "git_receive_pack"},
		})
		if !s.denyTransport(r.Context(), transport, "security_egress_blocked", http.StatusForbidden) {
			http.Error(w, "transport event persistence failed", http.StatusServiceUnavailable)
			return
		}
		writeGitPolicyError(w, r, s.errorResponse(opID, "security_egress_blocked", "opaque Git push denied by security policy", &result))
		return
	}
	if operation == "git.receive-pack" && r.Method == http.MethodPost && s.credentialStore != nil {
		// Effect credentials are exact, broker-known values.  Scan the bounded
		// receive-pack stream before forwarding so a matching token cannot be
		// committed through the opaque transport path.
		pack, err := io.ReadAll(io.LimitReader(bodyReader, securityscan.MaxStreamBytes+1))
		if err != nil || len(pack) > securityscan.MaxStreamBytes {
			if !s.denyTransport(r.Context(), transport, "security_scan_limit", http.StatusRequestEntityTooLarge) {
				http.Error(w, "transport event persistence failed", http.StatusServiceUnavailable)
				return
			}
			http.Error(w, "receive-pack exceeds security scan bound", http.StatusRequestEntityTooLarge)
			return
		}
		bodyReader = bytes.NewReader(pack)
		if finding := securityscan.Reader("receive_pack", bytes.NewReader(pack), securityscan.MaxStreamBytes); finding != nil {
			if finding.Fingerprint != "" && s.credentialStore.HandleEffectTokenLeak(r.Context(), finding.Fingerprint) != nil {
				http.Error(w, "credential fence unavailable", http.StatusServiceUnavailable)
				return
			}
			s.audit.Log(audit.Event{OperationID: opID, AgentID: principal.ID, Operation: "security.egress_blocked", Repo: repo, Decision: policy.DecisionDeny, Result: finding.Code, Extra: map[string]interface{}{"fingerprint": finding.Fingerprint, "surface": "git_receive_pack"}})
			if !s.denyTransport(r.Context(), transport, "security_egress_blocked", http.StatusForbidden) {
				http.Error(w, "transport event persistence failed", http.StatusServiceUnavailable)
				return
			}
			http.Error(w, "receive-pack blocked by security policy", http.StatusForbidden)
			return
		}
	}
	if strings.HasPrefix(repo, "local/") {
		route, found := localRepositoryRoute(cfg, repo)
		if !found {
			if !s.denyTransport(r.Context(), transport, "local_repository_not_configured", http.StatusForbidden) {
				http.Error(w, "transport event persistence failed", http.StatusServiceUnavailable)
				return
			}
			http.Error(w, "local repository is not configured", http.StatusForbidden)
			return
		}
		if operation == "git.receive-pack" && r.Method == http.MethodPost {
			for _, update := range updates {
				if update.After == strings.Repeat("0", 40) || !route.AllowsWrite(update.Ref) {
					if !s.denyTransport(r.Context(), transport, "local_ref_policy_denied", http.StatusForbidden) {
						http.Error(w, "transport event persistence failed", http.StatusServiceUnavailable)
						return
					}
					s.writeGitPreflightDenial(w, r, opID, principal.ID, repo, update.Ref, "local_ref_policy_denied", "local pushes must be non-deleting updates in the configured writable namespace")
					return
				}
			}
			if !s.localReceivePackBeforeMatches(r.Context(), route, repo, updates) {
				if !s.denyTransport(r.Context(), transport, "ref_before_mismatch", http.StatusForbidden) {
					http.Error(w, "transport event persistence failed", http.StatusServiceUnavailable)
					return
				}
				s.writeGitPreflightDenial(w, r, opID, principal.ID, repo, branch, "ref_before_mismatch", "advertised ref state no longer matches the repository backend")
				return
			}
		}
		s.forwardLocalGit(w, r, opID, principal.ID, repo, branch, operation, result, route, suffix, bodyReader, transport)
		return
	}
	appName := config.GitHubAppName(principal.Agent)
	inst, ok := cfg.InstallationIDForApp(appName, repo)
	if !ok {
		if !s.denyTransport(r.Context(), transport, "installation_not_configured", http.StatusForbidden) {
			http.Error(w, "transport event persistence failed", http.StatusServiceUnavailable)
			return
		}
		http.Error(w, "repository has no configured GitHub App installation", http.StatusForbidden)
		return
	}
	guardResult := s.checkBranchLifecycle(opID, gh, appName, inst, repo, branch, operation, principal.Agent)
	if guardResult != nil {
		result.Warnings = append(result.Warnings, guardResult.Warnings...)
		if !guardResult.Allowed {
			if !s.denyTransport(r.Context(), transport, "policy_denied", http.StatusForbidden) {
				http.Error(w, "transport event persistence failed", http.StatusServiceUnavailable)
				return
			}
			s.audit.Log(audit.Event{OperationID: opID, AgentID: principal.ID, Operation: operation, Repo: repo, Branch: branch, Decision: guardResult.Decision})
			writeGitPolicyError(w, r, s.errorResponse(opID, "policy_denied", "git operation denied by policy", guardResult))
			return
		}
		if guardResult.Decision == policy.DecisionWarn {
			result.Decision = policy.DecisionWarn
			s.audit.Log(audit.Event{OperationID: opID, AgentID: principal.ID, Operation: operation, Repo: repo, Branch: branch, Decision: result.Decision, Result: "branch_lifecycle_warning"})
		}
	}
	if operation == "git.receive-pack" && r.Method == http.MethodPost {
		for _, update := range updates {
			if update.After == strings.Repeat("0", 40) {
				if !s.denyTransport(r.Context(), transport, "ref_deletion_rejected", http.StatusForbidden) {
					http.Error(w, "transport event persistence failed", http.StatusServiceUnavailable)
					return
				}
				s.writeGitPreflightDenial(w, r, opID, principal.ID, repo, update.Ref, "ref_deletion_rejected", "ref deletion is not allowed through opaque receive-pack")
				return
			}
			current, found, err := gh.GetRef(appName, repo, update.Ref, inst)
			if err != nil {
				if !s.denyTransport(r.Context(), transport, "ref_preflight_unavailable", http.StatusBadGateway) {
					http.Error(w, "transport event persistence failed", http.StatusServiceUnavailable)
					return
				}
				s.audit.Log(audit.Event{OperationID: opID, AgentID: principal.ID, Operation: operation, Repo: repo, Branch: update.Ref, Decision: policy.DecisionDeny, Result: "ref_preflight_unavailable", Error: err.Error()})
				http.Error(w, "GitHub ref preflight failed", http.StatusBadGateway)
				return
			}
			zeroBefore := update.Before == strings.Repeat("0", 40)
			if (zeroBefore && found) || (!zeroBefore && (!found || current != update.Before)) {
				if !s.denyTransport(r.Context(), transport, "ref_before_mismatch", http.StatusForbidden) {
					http.Error(w, "transport event persistence failed", http.StatusServiceUnavailable)
					return
				}
				s.writeGitPreflightDenial(w, r, opID, principal.ID, repo, update.Ref, "ref_before_mismatch", "advertised ref state no longer matches GitHub")
				return
			}
		}
	}
	token, err := gh.InstallationToken(appName, inst)
	if err != nil {
		if !s.denyTransport(r.Context(), transport, "token_exchange_failed", http.StatusBadGateway) {
			http.Error(w, "transport event persistence failed", http.StatusServiceUnavailable)
			return
		}
		s.audit.Log(audit.Event{OperationID: opID, AgentID: principal.ID, Operation: operation, Repo: repo, Branch: branch, Decision: result.Decision, Error: err.Error()})
		http.Error(w, "github token exchange failed", http.StatusBadGateway)
		return
	}
	upstream, err := gitUpstreamURL(cfg.GitHub.GitBaseURL, repo, suffix, r.URL.RawQuery)
	if err != nil {
		if !s.denyTransport(r.Context(), transport, "upstream_url_invalid", http.StatusBadRequest) {
			http.Error(w, "transport event persistence failed", http.StatusServiceUnavailable)
			return
		}
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	//nolint:gosec // upstream is constructed from validated repo path and configured Git base URL.
	req, err := http.NewRequest(r.Method, upstream, bodyReader)
	if err != nil {
		if !s.denyTransport(r.Context(), transport, "upstream_request_invalid", http.StatusBadRequest) {
			http.Error(w, "transport event persistence failed", http.StatusServiceUnavailable)
			return
		}
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	req.ContentLength = r.ContentLength
	copyGitHeaders(req.Header, r.Header)
	req.SetBasicAuth("x-access-token", token)
	if transport != nil && s.transport.Forwarded(r.Context(), transport) != nil {
		http.Error(w, "transport event persistence failed", http.StatusServiceUnavailable)
		return
	}
	// #nosec G704 -- outbound Git proxy target is constrained by broker config and repo policy.
	resp, err := s.http.Do(req)
	if err != nil {
		if transport != nil {
			if terminalErr := s.transport.Terminal(r.Context(), transport, "failed", "failed", "github_git_upstream_failed", http.StatusBadGateway, 0); terminalErr != nil {
				http.Error(w, "transport event persistence failed", http.StatusServiceUnavailable)
				return
			}
		}
		s.audit.Log(audit.Event{OperationID: opID, AgentID: principal.ID, Operation: operation, Repo: repo, Branch: branch, Decision: result.Decision, Error: err.Error()})
		http.Error(w, "github git upstream failed", http.StatusBadGateway)
		return
	}
	defer closeBody(resp.Body)
	if transport != nil && s.transport.Terminal(r.Context(), transport, "completed", "allowed", "", resp.StatusCode, resp.StatusCode) != nil {
		http.Error(w, "transport event persistence failed", http.StatusServiceUnavailable)
		return
	}
	if operation != "git.receive-pack" {
		copyGitHeaders(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)
		if _, err := io.Copy(w, resp.Body); err != nil {
			s.audit.Log(audit.Event{OperationID: opID, AgentID: principal.ID, Operation: operation, Repo: repo, Branch: branch, Decision: result.Decision, Error: err.Error()})
			return
		}
		s.audit.Log(audit.Event{OperationID: opID, AgentID: principal.ID, Operation: operation, Repo: repo, Branch: branch, Decision: result.Decision, Result: "status " + strconv.Itoa(resp.StatusCode)})
		return
	}
	responseBody, err := io.ReadAll(io.LimitReader(resp.Body, (4<<20)+1))
	if err != nil || len(responseBody) > 4<<20 {
		s.audit.Log(audit.Event{OperationID: opID, AgentID: principal.ID, Operation: operation, Repo: repo, Branch: branch, Decision: policy.DecisionDeny, Result: "receive_pack_status_limit_exceeded"})
		http.Error(w, "GitHub receive-pack status exceeded broker limit", http.StatusBadGateway)
		return
	}
	copyGitHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	if _, err := w.Write(responseBody); err != nil {
		return
	}
	resultCode := "status " + strconv.Itoa(resp.StatusCode)
	if operation == "git.receive-pack" && receivePackRejected(responseBody) {
		resultCode = "github_ref_update_rejected"
	}
	s.audit.Log(audit.Event{OperationID: opID, AgentID: principal.ID, Operation: operation, Repo: repo, Branch: branch, Decision: result.Decision, Result: resultCode})
}

func (s *Server) writeGitPreflightDenial(w http.ResponseWriter, r *http.Request, opID, agentID, repo, ref, code, message string) {
	result := policy.Result{Allowed: false, Decision: policy.DecisionDeny, FailedChecks: []api.FailedCheck{{Dimension: "git_ref_preflight", Location: ref, Expected: "advertised before SHA equals current GitHub ref and update is not a deletion", SafeToDisplay: true, Message: message}}, RequiredChanges: []api.RequiredChange{{Location: ref, Action: "fetch the current ref and retry a non-deleting update"}}}
	s.audit.Log(audit.Event{OperationID: opID, AgentID: agentID, Operation: "git.receive_pack_preflight", Repo: repo, Branch: ref, Decision: policy.DecisionDeny, Result: code})
	writeGitPolicyError(w, r, s.errorResponse(opID, code, message, &result))
}

func receivePackRejected(body []byte) bool {
	i := 0
	for i+4 <= len(body) {
		n, err := strconv.ParseInt(string(body[i:i+4]), 16, 32)
		if err != nil || n < 4 || i+int(n) > len(body) {
			return false
		}
		if n == 0 {
			i += 4
			continue
		}
		line := body[i+4 : i+int(n)]
		if len(line) > 0 && (line[0] == 1 || line[0] == 2 || line[0] == 3) {
			line = line[1:]
		}
		if bytes.HasPrefix(line, []byte("ng ")) {
			return true
		}
		i += int(n)
	}
	return false
}

func (s *Server) reserveMutation(w http.ResponseWriter, opID, agentID, operation, repo, branch string, metadata map[string]string) bool {
	cfg, _ := s.snapshot()
	decision, err := limits.CheckAndReserve(cfg.MutationLimits, operation, metadata)
	if err != nil {
		s.audit.Log(audit.Event{OperationID: opID, AgentID: agentID, Operation: operation, Repo: repo, Branch: branch, Decision: policy.DecisionDeny, Error: err.Error()})
		writeJSON(w, http.StatusInternalServerError, api.ErrorResponse{Code: "mutation_limit_error", Message: audit.Redact(err.Error()), OperationID: opID, Decision: policy.DecisionDeny})
		return false
	}
	if decision.Allowed {
		return true
	}
	s.audit.Log(audit.Event{
		OperationID: opID,
		AgentID:     agentID,
		Operation:   operation,
		Repo:        repo,
		Branch:      branch,
		RunID:       decision.RunID,
		Decision:    policy.DecisionDeny,
		Result:      "capacity_deferred",
		Extra:       map[string]interface{}{"class": decision.Class, "reason": decision.Reason},
	})
	writeJSON(w, http.StatusTooManyRequests, api.ErrorResponse{
		Code:        "capacity_deferred",
		Message:     decision.Reason + "; retry on the next Curator run",
		OperationID: opID,
		Decision:    policy.DecisionDeny,
		FailedChecks: []api.FailedCheck{{
			Dimension:     "mutation_budget",
			Expected:      "available per-run GitHub object budget",
			Actual:        "exhausted",
			SafeToDisplay: true,
			Message:       decision.Reason,
		}},
		RequiredChanges: []api.RequiredChange{{
			Action: "defer this valid action to the next Curator run",
		}},
	})
	return false
}

func (s *Server) checkBranchLifecycle(opID string, gh *githubapp.Client, appName string, inst int64, repo, branch, operation string, agent config.Agent) *policy.Result {
	guard := agent.BranchGuard
	mode := strings.ToLower(strings.TrimSpace(guard.Mode))
	operations := guard.Operations
	if len(operations) == 0 {
		operations = []string{"git.receive-pack", "pull.create"}
	}
	staleStates := guard.StalePRStates
	if len(staleStates) == 0 {
		staleStates = []string{"closed"}
	}
	if mode == "" || mode == "off" || !containsString(operations, operation) {
		return nil
	}
	branchName := strings.TrimPrefix(branch, "refs/heads/")
	if branchName == "" {
		return nil
	}
	owner, _, ok := strings.Cut(repo, "/")
	if !ok || owner == "" {
		return nil
	}
	query := url.Values{}
	query.Set("state", "all")
	query.Set("head", owner+":"+branchName)
	query.Set("sort", "updated")
	query.Set("direction", "desc")
	query.Set("per_page", "100")
	pulls, err := gh.ListPulls(appName, repo, inst, query)
	if err != nil {
		check := api.FailedCheck{
			Dimension:     "branch_lifecycle",
			Location:      "github",
			Expected:      "verifiable pull request state for branch",
			Actual:        "lookup failed",
			SafeToDisplay: true,
			Message:       "broker could not verify whether this branch has already backed a closed pull request",
		}
		if mode == "warn" {
			return &policy.Result{Allowed: true, Decision: policy.DecisionWarn, Warnings: []api.FailedCheck{check}}
		}
		return &policy.Result{
			Allowed:      false,
			Decision:     policy.DecisionDeny,
			FailedChecks: []api.FailedCheck{check},
			RequiredChanges: []api.RequiredChange{{
				Location: "branch",
				Action:   "retry after branch lifecycle state can be verified or use a fresh agent branch",
			}},
		}
	}
	for _, pull := range pulls {
		if pull.HeadRef != branchName || !containsFoldString(staleStates, pull.State) {
			continue
		}
		merged := "not merged"
		if pull.Merged {
			merged = "merged"
		} else if pull.MergedAt == "" {
			merged = "merged status unavailable"
		}
		check := api.FailedCheck{
			Dimension:     "branch_lifecycle",
			Location:      "branch",
			Expected:      "branch with no closed pull request history",
			Actual:        fmt.Sprintf("PR #%d is %s (%s): %s", pull.Number, pull.State, merged, pull.HTMLURL),
			SafeToDisplay: true,
			Message:       "branch has already backed a closed pull request; create a fresh agent branch for follow-up work",
		}
		if mode == "warn" {
			return &policy.Result{Allowed: true, Decision: policy.DecisionWarn, Warnings: []api.FailedCheck{check}}
		}
		return &policy.Result{
			Allowed:      false,
			Decision:     policy.DecisionDeny,
			FailedChecks: []api.FailedCheck{check},
			RequiredChanges: []api.RequiredChange{{
				Location: "branch",
				Action:   "create and push a fresh branch matching the agent branch policy",
			}},
		}
	}
	return nil
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

func containsString(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

func containsFoldString(items []string, want string) bool {
	for _, item := range items {
		if strings.EqualFold(item, want) {
			return true
		}
	}
	return false
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
		service, ok := gitDiscoveryService(r.URL.RawQuery)
		if !ok {
			return ""
		}
		switch service {
		case "git-upload-pack":
			return "git.upload-pack"
		case "git-receive-pack":
			return "git.receive-pack"
		}
	}
	if r.Method == http.MethodPost && r.URL.RawQuery == "" && suffix == "/git-upload-pack" {
		return "git.upload-pack"
	}
	if r.Method == http.MethodPost && r.URL.RawQuery == "" && suffix == "/git-receive-pack" {
		return "git.receive-pack"
	}
	return ""
}

func gitDiscoveryService(rawQuery string) (string, bool) {
	query, err := url.ParseQuery(rawQuery)
	if err != nil || len(query) != 1 || len(query["service"]) != 1 {
		return "", false
	}
	return query["service"][0], true
}

func gitUpstreamURL(base, repo, suffix, rawQuery string) (string, error) {
	u, err := url.Parse(strings.TrimRight(base, "/") + "/" + repo + ".git" + suffix)
	if err != nil {
		return "", err
	}
	u.RawQuery = rawQuery
	return u.String(), nil
}

func localRepositoryRoute(cfg *config.Config, repo string) (repositoryroutepolicy.Route, bool) {
	if cfg.RepositoryRoutePolicy == nil {
		return repositoryroutepolicy.Route{}, false
	}
	return cfg.RepositoryRoutePolicy.Route(repo)
}

func localGitURL(route repositoryroutepolicy.Route, repo, suffix, rawQuery string) (string, error) {
	name := strings.TrimPrefix(repo, "local/")
	u, err := url.Parse(strings.TrimRight(route.BackendURL, "/") + "/" + name + ".git" + suffix)
	if err != nil {
		return "", err
	}
	u.RawQuery = rawQuery
	return u.String(), nil
}

// localReceivePackBeforeMatches obtains the backend's advertised receive refs immediately
// before the push is forwarded. The backend owns the final transaction check as well.
func (s *Server) localReceivePackBeforeMatches(ctx context.Context, route repositoryroutepolicy.Route, repo string, updates []receivePackUpdate) bool {
	u, err := localGitURL(route, repo, "/info/refs", "service=git-receive-pack")
	if err != nil {
		return false
	}
	//nolint:gosec // URL is constructed solely from the reviewed route manifest.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return false
	}
	//nolint:gosec // request target is constrained by the reviewed route manifest.
	resp, err := s.http.Do(req)
	if err != nil {
		return false
	}
	defer closeBody(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return false
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return false
	}
	refs := advertisedRefs(b)
	zero := strings.Repeat("0", 40)
	for _, update := range updates {
		current, found := refs[update.Ref]
		if (update.Before == zero && found) || (update.Before != zero && (!found || current != update.Before)) {
			return false
		}
	}
	return true
}

func advertisedRefs(body []byte) map[string]string {
	refs := map[string]string{}
	for i := 0; i+4 <= len(body); {
		n, err := strconv.ParseInt(string(body[i:i+4]), 16, 32)
		if err != nil || n < 4 || i+int(n) > len(body) {
			break
		}
		if n == 0 {
			i += 4
			continue
		}
		line := string(body[i+4 : i+int(n)])
		fields := strings.Fields(strings.TrimPrefix(line, "\x01"))
		if len(fields) >= 2 && githubSHA.MatchString(fields[0]) {
			refs[fields[1]] = fields[0]
		}
		i += int(n)
	}
	return refs
}

func (s *Server) forwardLocalGit(w http.ResponseWriter, r *http.Request, opID, agentID, repo, branch, operation string, result policy.Result, route repositoryroutepolicy.Route, suffix string, body io.Reader, transport *sandbox.TransportOperation) {
	u, err := localGitURL(route, repo, suffix, r.URL.RawQuery)
	if err != nil {
		if !s.denyTransport(r.Context(), transport, "local_backend_url_invalid", http.StatusBadGateway) {
			http.Error(w, "transport event persistence failed", http.StatusServiceUnavailable)
			return
		}
		http.Error(w, "invalid local backend URL", http.StatusBadGateway)
		return
	}
	//nolint:gosec // URL is constructed solely from the reviewed route manifest.
	req, err := http.NewRequestWithContext(r.Context(), r.Method, u, body)
	if err != nil {
		if !s.denyTransport(r.Context(), transport, "local_backend_request_invalid", http.StatusBadGateway) {
			http.Error(w, "transport event persistence failed", http.StatusServiceUnavailable)
			return
		}
		http.Error(w, "invalid local backend request", http.StatusBadGateway)
		return
	}
	req.ContentLength = r.ContentLength
	copyGitHeaders(req.Header, r.Header)
	if transport != nil && s.transport.Forwarded(r.Context(), transport) != nil {
		http.Error(w, "transport event persistence failed", http.StatusServiceUnavailable)
		return
	}
	//nolint:gosec // request target is constrained by the reviewed route manifest.
	resp, err := s.http.Do(req)
	if err != nil {
		if transport != nil {
			if terminalErr := s.transport.Terminal(r.Context(), transport, "failed", "failed", "backend_unavailable", http.StatusBadGateway, 0); terminalErr != nil {
				http.Error(w, "transport event persistence failed", http.StatusServiceUnavailable)
				return
			}
		}
		http.Error(w, "repository backend unavailable", http.StatusBadGateway)
		return
	}
	defer closeBody(resp.Body)
	if transport != nil && s.transport.Terminal(r.Context(), transport, "completed", "allowed", "", resp.StatusCode, resp.StatusCode) != nil {
		http.Error(w, "transport event persistence failed", http.StatusServiceUnavailable)
		return
	}
	copyGitHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil {
		return
	}
	s.audit.Log(audit.Event{OperationID: opID, AgentID: agentID, Operation: operation, Repo: repo, Branch: branch, Decision: result.Decision, Result: "local backend status " + strconv.Itoa(resp.StatusCode)})
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

type receivePackUpdate struct{ Before, After, Ref string }

const maxReceivePackCommandPrefixBytes = 256 << 10

var errReceivePackCommandPrefixLimit = errors.New("receive-pack command prefix exceeds limit")

func readReceivePackCommandPrefix(body io.Reader) ([]byte, []receivePackUpdate, error) {
	var prefix bytes.Buffer
	updates := make([]receivePackUpdate, 0, 1)
	for {
		var header [4]byte
		if _, err := io.ReadFull(body, header[:]); err != nil {
			return nil, nil, fmt.Errorf("read receive-pack pkt-line header: %w", err)
		}
		if prefix.Len()+len(header) > maxReceivePackCommandPrefixBytes {
			return nil, nil, errReceivePackCommandPrefixLimit
		}
		prefix.Write(header[:])
		n, err := strconv.ParseInt(string(header[:]), 16, 32)
		if err != nil || n < 0 {
			return nil, nil, errors.New("invalid pkt-line length")
		}
		if n == 0 {
			if len(updates) == 0 {
				return nil, nil, errors.New("no receive-pack updates")
			}
			return prefix.Bytes(), updates, nil
		}
		if n < 4 {
			return nil, nil, errors.New("invalid receive-pack command length")
		}
		payloadSize := int(n) - 4
		if prefix.Len()+payloadSize > maxReceivePackCommandPrefixBytes {
			return nil, nil, errReceivePackCommandPrefixLimit
		}
		payload := make([]byte, payloadSize)
		if _, err := io.ReadFull(body, payload); err != nil {
			return nil, nil, fmt.Errorf("read receive-pack command: %w", err)
		}
		prefix.Write(payload)
		line := string(payload)
		if nul := strings.IndexByte(line, 0); nul >= 0 {
			line = line[:nul]
		}
		fields := strings.Fields(line)
		if len(fields) != 3 || !strings.HasPrefix(fields[2], "refs/heads/") || !githubSHA.MatchString(fields[0]) || !githubSHA.MatchString(fields[1]) {
			return nil, nil, errors.New("invalid receive-pack update")
		}
		updates = append(updates, receivePackUpdate{Before: fields[0], After: fields[1], Ref: fields[2]})
		if len(updates) > 64 {
			return nil, nil, errors.New("too many receive-pack updates")
		}
	}
}

func receivePackUpdates(body []byte) ([]receivePackUpdate, error) {
	_, updates, err := readReceivePackCommandPrefix(bytes.NewReader(body))
	return updates, err
}

var githubSHA = regexp.MustCompile(`^[0-9a-f]{40}$`)

func receivePackBranch(body []byte) string {
	updates, err := receivePackUpdates(body)
	if err != nil {
		return ""
	}
	return updates[0].Ref
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

func writeAuthJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("WWW-Authenticate", `Basic realm="gh-agent-broker"`)
	writeJSON(w, http.StatusUnauthorized, v)
}

func writeAuthText(w http.ResponseWriter, message string) {
	w.Header().Set("WWW-Authenticate", `Basic realm="gh-agent-broker"`)
	http.Error(w, message, http.StatusUnauthorized)
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
