package sandbox

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

type restHandler struct {
	service *Service
}

type operatorIdentity struct {
	Name      string
	Principal OperatorPrincipal
}

type launchProfileSummary struct {
	Name                  string                          `json:"name"`
	Request               LaunchAgentInput                `json:"request"`
	AllowOverrides        []string                        `json:"allow_overrides,omitempty"`
	Parameters            map[string]ParameterDeclaration `json:"parameters,omitempty"`
	MaxConcurrentRuns     int                             `json:"max_concurrent_runs,omitempty"`
	RequireIdempotencyKey bool                            `json:"require_idempotency_key"`
}

type launchProfilesOutput struct {
	Profiles []launchProfileSummary `json:"profiles"`
}

type restError struct {
	Error string `json:"error"`
	Code  string `json:"code,omitempty"`
}

func NewRESTHandler(service *Service) http.Handler {
	return &restHandler{service: service}
}

func (h *restHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.Trim(strings.TrimPrefix(r.URL.Path, "/v1/"), "/")
	switch {
	case path == "launch-profiles":
		h.handleLaunchProfiles(w, r)
	case strings.HasPrefix(path, "launch-profiles/"):
		h.handleLaunchProfileAction(w, r, strings.TrimPrefix(path, "launch-profiles/"))
	case path == "runs":
		h.handleRuns(w, r)
	case strings.HasPrefix(path, "runs/"):
		h.handleRunAction(w, r, strings.TrimPrefix(path, "runs/"))
	default:
		writeRESTError(w, http.StatusNotFound, "not_found")
	}
}

func (h *restHandler) handleLaunchProfiles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeRESTError(w, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	identity, ok := h.authenticate(w, r, "launch_profiles.list")
	if !ok {
		return
	}
	profiles := make([]launchProfileSummary, 0, len(identity.Principal.AllowedProfiles))
	for _, name := range identity.Principal.AllowedProfiles {
		profile, ok := h.service.cfg.LaunchProfiles[name]
		if !ok {
			continue
		}
		profiles = append(profiles, launchProfileSummary{
			Name:                  name,
			Request:               profile.LaunchAgentInput,
			AllowOverrides:        append([]string(nil), profile.AllowOverrides...),
			Parameters:            profile.Parameters,
			MaxConcurrentRuns:     profile.MaxConcurrentRuns,
			RequireIdempotencyKey: profile.RequireIdempotencyKey,
		})
	}
	h.audit("launch_profiles.list", identity.Name, "", "", "", "", "", "allow", nil, nil)
	writeJSON(w, http.StatusOK, launchProfilesOutput{Profiles: profiles})
}

func (h *restHandler) handleLaunchProfileAction(w http.ResponseWriter, r *http.Request, rest string) {
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	if len(parts) != 2 {
		writeRESTError(w, http.StatusNotFound, "not_found")
		return
	}
	name, action := parts[0], parts[1]
	if action != "launch" && action != "dry-run" && action != "preview" {
		writeRESTError(w, http.StatusNotFound, "not_found")
		return
	}
	if r.Method != http.MethodPost {
		writeRESTError(w, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	operatorAction := "launch"
	operation := "launch_profiles.launch"
	switch action {
	case "dry-run":
		operatorAction = "dry_run"
		operation = "launch_profiles.dry_run"
	case "preview":
		operatorAction = "dry_run"
		operation = "launch_profiles.preview"
	}
	identity, ok := h.authenticate(w, r, operation)
	if !ok {
		return
	}
	profile, ok := h.authorizeProfile(w, identity, name, operatorAction, operation)
	if !ok {
		return
	}
	fingerprint := ""
	idempotencyKey := ""
	if action == "launch" {
		var keyErr error
		idempotencyKey, keyErr = parseIdempotencyKey(r, profile.RequireIdempotencyKey)
		if keyErr != nil {
			status := http.StatusBadRequest
			code := "invalid_idempotency_key"
			if errors.Is(keyErr, errMissingIdempotencyKey) {
				status = http.StatusPreconditionRequired
				code = "idempotency_key_required"
			}
			h.audit(operation, identity.Name, name, "", profile.Template, profile.Repo, profile.Branch, "deny", keyErr, nil)
			writeRESTCodeError(w, status, code, keyErr.Error())
			return
		}
		if idempotencyKey != "" {
			canonical, canonicalErr := canonicalizeRequestBody(r, h.service.cfg.MaxParameterBytes)
			if canonicalErr != nil {
				h.audit(operation, identity.Name, name, "", profile.Template, profile.Repo, profile.Branch, "deny", canonicalErr, nil)
				writeRESTCodeError(w, http.StatusBadRequest, "validation_error", canonicalErr.Error())
				return
			}
			fingerprint = requestFingerprint(canonical)
		}
	}
	in, params, err := resolveLaunchProfileRequest(profile, r, h.service.cfg.MaxParameterBytes)
	if err != nil {
		h.audit(operation, identity.Name, name, "", profile.Template, profile.Repo, profile.Branch, "deny", err, params)
		writeRESTError(w, http.StatusBadRequest, err.Error())
		return
	}
	if action == "preview" {
		in.Profile = name
		out, err := h.service.PreviewLaunch(r.Context(), in)
		if err != nil {
			h.audit(operation, identity.Name, name, "", in.Template, in.Repo, in.Branch, "deny", err, params)
			writeRESTError(w, http.StatusForbidden, err.Error())
			return
		}
		out.Profile = name
		out.Principal = identity.Name
		out.AllowedActions = append([]string(nil), identity.Principal.AllowedActions...)
		h.audit(operation, identity.Name, name, "", in.Template, in.Repo, out.TaskContract.Branch, "allow", nil, params)
		writeJSON(w, http.StatusOK, out)
		return
	}
	var out LaunchAgentOutput
	if action == "dry-run" {
		in.Profile = name
		out, err = h.service.DryRunLaunch(r.Context(), in)
	} else {
		in.Profile = name
		out, err = h.service.LaunchProfile(r.Context(), identity.Name, name, idempotencyKey, fingerprint, in)
	}
	if err != nil {
		var conflict *intentConflictError
		if errors.As(err, &conflict) {
			h.audit(operation, identity.Name, name, "", in.Template, in.Repo, in.Branch, "deny", conflict, params)
			writeRESTCodeError(w, http.StatusConflict, conflict.Code, conflict.Message)
			return
		}
		var validation *launchValidationError
		if action != "launch" || errors.As(err, &validation) {
			h.audit(operation, identity.Name, name, "", in.Template, in.Repo, in.Branch, "deny", err, params)
			writeRESTCodeError(w, http.StatusBadRequest, "validation_error", err.Error())
			return
		}
		h.audit(operation, identity.Name, name, "", in.Template, in.Repo, in.Branch, "deny", errors.New("launch failed"), params)
		writeRESTCodeError(w, http.StatusInternalServerError, "launch_failed", "launch failed")
		return
	}
	h.audit(operation, identity.Name, name, out.RunID, in.Template, in.Repo, out.Branch, "allow", nil, params)
	writeJSON(w, http.StatusOK, out)
}

func (h *restHandler) handleRuns(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeRESTError(w, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	identity, ok := h.authenticate(w, r, "runs.list")
	if !ok {
		return
	}
	if !h.authorizeAction(w, identity, "status", "runs.list") {
		return
	}
	out, err := h.service.listAgentsForPrincipal(r.Context(), identity.Name, identity.Principal.AllowedProfiles, identity.Principal.RunScope == "profile")
	if err != nil {
		h.audit("runs.list", identity.Name, "", "", "", "", "", "deny", err, nil)
		writeRESTError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.audit("runs.list", identity.Name, "", "", "", "", "", "allow", nil, nil)
	writeJSON(w, http.StatusOK, out)
}

func (h *restHandler) handleRunAction(w http.ResponseWriter, r *http.Request, rest string) {
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		writeRESTError(w, http.StatusNotFound, "not_found")
		return
	}
	runID := parts[0]
	if len(parts) == 1 {
		if r.Method != http.MethodGet {
			writeRESTError(w, http.StatusMethodNotAllowed, "method_not_allowed")
			return
		}
		h.runStatus(w, r, runID)
		return
	}
	if len(parts) != 2 {
		writeRESTError(w, http.StatusNotFound, "not_found")
		return
	}
	switch parts[1] {
	case "logs":
		h.runLogs(w, r, runID)
	case "artifacts":
		h.runCollection(w, r, runID, "artifacts")
	case "lessons":
		h.runCollection(w, r, runID, "lessons")
	case "stop":
		h.runMutation(w, r, runID, "stop")
	case "cleanup":
		h.runMutation(w, r, runID, "cleanup")
	default:
		writeRESTError(w, http.StatusNotFound, "not_found")
	}
}

func (h *restHandler) runStatus(w http.ResponseWriter, r *http.Request, runID string) {
	identity, ok := h.authenticate(w, r, "runs.status")
	if !ok {
		return
	}
	if !h.authorizeAction(w, identity, "status", "runs.status") {
		return
	}
	if !h.authorizeRunProfile(w, identity, runID, "runs.status") {
		return
	}
	out, err := h.service.GetAgentStatus(r.Context(), RunInput{RunID: runID})
	if err != nil {
		h.audit("runs.status", identity.Name, "", runID, "", "", "", "deny", err, nil)
		writeRESTError(w, http.StatusNotFound, err.Error())
		return
	}
	h.audit("runs.status", identity.Name, "", runID, "", out.Repo, out.Branch, "allow", nil, nil)
	writeJSON(w, http.StatusOK, out)
}

func (h *restHandler) runLogs(w http.ResponseWriter, r *http.Request, runID string) {
	if r.Method != http.MethodGet {
		writeRESTError(w, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	identity, ok := h.authenticate(w, r, "runs.logs")
	if !ok {
		return
	}
	if !h.authorizeAction(w, identity, "logs", "runs.logs") {
		return
	}
	if !h.authorizeRunProfile(w, identity, runID, "runs.logs") {
		return
	}
	maxBytes := 0
	if raw := r.URL.Query().Get("max_bytes"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 0 {
			writeRESTError(w, http.StatusBadRequest, "max_bytes must be a non-negative integer")
			return
		}
		maxBytes = parsed
	}
	out, err := h.service.GetAgentLogs(r.Context(), LogsInput{RunID: runID, MaxBytes: maxBytes})
	if err != nil {
		h.audit("runs.logs", identity.Name, "", runID, "", "", "", "deny", err, nil)
		writeRESTError(w, http.StatusNotFound, err.Error())
		return
	}
	h.audit("runs.logs", identity.Name, "", runID, "", "", "", "allow", nil, nil)
	writeJSON(w, http.StatusOK, out)
}

func (h *restHandler) runCollection(w http.ResponseWriter, r *http.Request, runID, kind string) {
	if r.Method != http.MethodGet {
		writeRESTError(w, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	operation := "runs." + kind
	identity, ok := h.authenticate(w, r, operation)
	if !ok {
		return
	}
	if !h.authorizeAction(w, identity, "artifacts", operation) {
		return
	}
	if !h.authorizeRunProfile(w, identity, runID, operation) {
		return
	}
	var (
		out CollectionOutput
		err error
	)
	if kind == "lessons" {
		out, err = h.service.CollectLessons(r.Context(), RunInput{RunID: runID})
	} else {
		out, err = h.service.CollectArtifacts(r.Context(), RunInput{RunID: runID})
	}
	if err != nil {
		h.audit(operation, identity.Name, "", runID, "", "", "", "deny", err, nil)
		writeRESTError(w, http.StatusNotFound, err.Error())
		return
	}
	h.audit(operation, identity.Name, "", runID, "", "", "", "allow", nil, nil)
	writeJSON(w, http.StatusOK, out)
}

func (h *restHandler) runMutation(w http.ResponseWriter, r *http.Request, runID, action string) {
	if r.Method != http.MethodPost {
		writeRESTError(w, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	operation := "runs." + action
	identity, ok := h.authenticate(w, r, operation)
	if !ok {
		return
	}
	if !h.authorizeAction(w, identity, action, operation) {
		return
	}
	if !h.authorizeRunProfile(w, identity, runID, operation) {
		return
	}
	var (
		out StatusOutput
		err error
	)
	if action == "cleanup" {
		out, err = h.service.CleanupRun(r.Context(), RunInput{RunID: runID})
	} else {
		out, err = h.service.StopAgent(r.Context(), RunInput{RunID: runID})
	}
	if err != nil {
		h.audit(operation, identity.Name, "", runID, "", "", "", "deny", err, nil)
		writeRESTError(w, http.StatusNotFound, err.Error())
		return
	}
	h.audit(operation, identity.Name, "", runID, "", out.Repo, out.Branch, "allow", nil, nil)
	writeJSON(w, http.StatusOK, out)
}

func (h *restHandler) authenticate(w http.ResponseWriter, r *http.Request, operation string) (operatorIdentity, bool) {
	token := bearerToken(r)
	for name, principal := range h.service.cfg.OperatorPrincipals {
		if secureTokenEqual(token, principal.Token) {
			return operatorIdentity{Name: name, Principal: principal}, true
		}
	}
	h.audit(operation, "", "", "", "", "", "", "deny", fmt.Errorf("unauthorized"), nil)
	writeRESTError(w, http.StatusUnauthorized, "unauthorized")
	return operatorIdentity{}, false
}

func (h *restHandler) authorizeProfile(w http.ResponseWriter, identity operatorIdentity, profile, action, operation string) (LaunchProfile, bool) {
	if !contains(identity.Principal.AllowedActions, action) || !contains(identity.Principal.AllowedProfiles, profile) {
		err := fmt.Errorf("forbidden")
		h.audit(operation, identity.Name, profile, "", "", "", "", "deny", err, nil)
		writeRESTError(w, http.StatusForbidden, "forbidden")
		return LaunchProfile{}, false
	}
	launchProfile, ok := h.service.cfg.LaunchProfiles[profile]
	if !ok {
		err := fmt.Errorf("unknown launch profile")
		h.audit(operation, identity.Name, profile, "", "", "", "", "deny", err, nil)
		writeRESTError(w, http.StatusNotFound, "unknown launch profile")
		return LaunchProfile{}, false
	}
	return launchProfile, true
}

func (h *restHandler) authorizeAction(w http.ResponseWriter, identity operatorIdentity, action, operation string) bool {
	if contains(identity.Principal.AllowedActions, action) {
		return true
	}
	err := fmt.Errorf("forbidden")
	h.audit(operation, identity.Name, "", "", "", "", "", "deny", err, nil)
	writeRESTError(w, http.StatusForbidden, "forbidden")
	return false
}

func (h *restHandler) authorizeRunProfile(w http.ResponseWriter, identity operatorIdentity, runID, operation string) bool {
	meta, err := h.service.lookupRun(runID)
	if err != nil {
		h.audit(operation, identity.Name, "", runID, "", "", "", "deny", err, nil)
		writeRESTError(w, http.StatusNotFound, err.Error())
		return false
	}
	profileAllowed := contains(identity.Principal.AllowedProfiles, meta.Profile)
	ownerAllowed := identity.Principal.RunScope == "profile" || meta.Principal == identity.Name
	if profileAllowed && ownerAllowed {
		return true
	}
	err = fmt.Errorf("run not found")
	h.audit(operation, identity.Name, meta.Profile, runID, meta.Template, meta.Repo, meta.Branch, "deny", err, nil)
	writeRESTCodeError(w, http.StatusNotFound, "not_found", "run not found")
	return false
}

func (h *restHandler) audit(operation, principal, profile, runID, template, repo, branch, decision string, err error, params map[string]any) {
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	h.service.audit.Log(AuditEvent{
		Operation:  operation,
		Principal:  principal,
		Profile:    profile,
		RunID:      runID,
		Template:   template,
		Repo:       repo,
		Branch:     branch,
		Parameters: cloneParameters(params),
		Decision:   decision,
		Error:      msg,
	}, NewRedactor(nil))
}

func resolveLaunchProfileRequest(profile LaunchProfile, r *http.Request, maxBytes int) (LaunchAgentInput, map[string]any, error) {
	params := map[string]any(nil)
	defer closeBody(r.Body)
	if r.Body == nil || r.ContentLength == 0 {
		resolved, err := resolveProfileParameters(profile, nil)
		in := profile.LaunchAgentInput
		in.Parameters = resolved
		return in, resolved, err
	}
	if maxBytes < 1 {
		maxBytes = defaultMaxParamBytes
	}
	b, err := io.ReadAll(io.LimitReader(r.Body, int64(maxBytes)+1))
	if err != nil {
		return LaunchAgentInput{}, nil, err
	}
	if len(b) > maxBytes {
		return LaunchAgentInput{}, nil, fmt.Errorf("request body exceeds max_parameter_bytes %d", maxBytes)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return LaunchAgentInput{}, nil, err
	}
	if len(raw) == 0 {
		resolved, err := resolveProfileParameters(profile, nil)
		in := profile.LaunchAgentInput
		in.Parameters = resolved
		return in, resolved, err
	}
	if rawParams, ok := raw["parameters"]; ok {
		if len(raw) != 1 {
			return LaunchAgentInput{}, nil, fmt.Errorf("request body must contain only parameters")
		}
		var submitted map[string]any
		if err := json.Unmarshal(rawParams, &submitted); err != nil {
			return LaunchAgentInput{}, nil, fmt.Errorf("parameters must be an object")
		}
		resolved, err := resolveProfileParameters(profile, submitted)
		if err != nil {
			return LaunchAgentInput{}, resolved, err
		}
		in := profile.LaunchAgentInput
		in.Parameters = resolved
		return in, resolved, nil
	}
	if len(profile.Parameters) > 0 {
		return LaunchAgentInput{}, nil, fmt.Errorf("parameterized profile requests must contain only parameters")
	}
	if overrides, ok := raw["overrides"]; ok {
		if len(raw) != 1 {
			return LaunchAgentInput{}, nil, fmt.Errorf("request body must contain only overrides")
		}
		raw = map[string]json.RawMessage{}
		if err := json.Unmarshal(overrides, &raw); err != nil {
			return LaunchAgentInput{}, nil, fmt.Errorf("overrides must be an object")
		}
	}
	allowed := map[string]bool{}
	for _, field := range profile.AllowOverrides {
		allowed[field] = true
	}
	for field := range raw {
		if !launchOverrideFieldAllowed(field) {
			return LaunchAgentInput{}, nil, fmt.Errorf("unsupported override field %q", field)
		}
		if !allowed[field] {
			return LaunchAgentInput{}, nil, fmt.Errorf("override field %q is not allowed for this profile", field)
		}
	}
	mergedBytes, err := json.Marshal(profile.LaunchAgentInput)
	if err != nil {
		return LaunchAgentInput{}, nil, err
	}
	var merged map[string]json.RawMessage
	if err := json.Unmarshal(mergedBytes, &merged); err != nil {
		return LaunchAgentInput{}, nil, err
	}
	for field, value := range raw {
		merged[field] = value
	}
	finalBytes, err := json.Marshal(merged)
	if err != nil {
		return LaunchAgentInput{}, nil, err
	}
	var out LaunchAgentInput
	if err := json.Unmarshal(finalBytes, &out); err != nil {
		return LaunchAgentInput{}, nil, err
	}
	params, err = resolveProfileParameters(profile, nil)
	out.Parameters = params
	return out, params, err
}

func bearerToken(r *http.Request) string {
	if got := strings.TrimSpace(r.Header.Get("X-Sandbox-Token")); got != "" {
		return got
	}
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		return strings.TrimSpace(auth[len("bearer "):])
	}
	return ""
}

func secureTokenEqual(got, want string) bool {
	if got == "" || want == "" {
		return false
	}
	gotSum := sha256.Sum256([]byte(got))
	wantSum := sha256.Sum256([]byte(want))
	return subtle.ConstantTimeCompare(gotSum[:], wantSum[:]) == 1
}

func writeRESTError(w http.ResponseWriter, status int, message string) {
	code := "request_failed"
	switch status {
	case http.StatusBadRequest:
		code = "validation_error"
	case http.StatusUnauthorized:
		code = "authentication_required"
	case http.StatusForbidden:
		code = "authorization_denied"
	case http.StatusNotFound:
		code = "not_found"
	case http.StatusMethodNotAllowed:
		code = "method_not_allowed"
	case http.StatusInternalServerError:
		code = "internal_error"
	}
	writeRESTCodeError(w, status, code, message)
}

func writeRESTCodeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, restError{Error: message, Code: code})
}

var errMissingIdempotencyKey = errors.New("Idempotency-Key header is required")

func parseIdempotencyKey(r *http.Request, required bool) (string, error) {
	values := r.Header.Values("Idempotency-Key")
	if len(values) == 0 {
		if required {
			return "", errMissingIdempotencyKey
		}
		return "", nil
	}
	if len(values) != 1 || len(values[0]) < 1 || len(values[0]) > 255 {
		return "", fmt.Errorf("Idempotency-Key must be a single value of 1 to 255 visible ASCII characters")
	}
	for _, char := range []byte(values[0]) {
		if char < 0x21 || char > 0x7e {
			return "", fmt.Errorf("Idempotency-Key must contain only visible ASCII characters")
		}
	}
	return values[0], nil
}

func canonicalizeRequestBody(r *http.Request, maxBytes int) ([]byte, error) {
	if r.Body == nil || r.ContentLength == 0 {
		r.Body = io.NopCloser(bytes.NewReader(nil))
		r.ContentLength = 0
		return []byte("{}"), nil
	}
	if maxBytes < 1 {
		maxBytes = defaultMaxParamBytes
	}
	b, err := io.ReadAll(io.LimitReader(r.Body, int64(maxBytes)+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxBytes {
		return nil, fmt.Errorf("request body exceeds max_parameter_bytes %d", maxBytes)
	}
	r.Body = io.NopCloser(bytes.NewReader(b))
	r.ContentLength = int64(len(b))
	if len(b) == 0 {
		return []byte("{}"), nil
	}
	decoder := json.NewDecoder(bytes.NewReader(b))
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, fmt.Errorf("request body must contain exactly one JSON value")
		}
		return nil, err
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("request body must be a JSON object")
	}
	return json.Marshal(object)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		return
	}
}
