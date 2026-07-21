package sandbox

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"gh-agent-broker/internal/securityscan"
)

const coordinatorProtocolVersion = "broker/coordinator/v1"

type CoordinatorSessionRequest struct {
	SessionBinding string `json:"session_binding"`
	IdempotencyKey string `json:"idempotency_key,omitempty"`
	Prompt         string `json:"prompt,omitempty"`
	TurnID         string `json:"turn_id,omitempty"`
	CheckpointRef  string `json:"checkpoint_ref,omitempty"`
	After          int64  `json:"after,omitempty"`
}

type CoordinatorSessionResponse struct {
	Version string          `json:"version"`
	Lease   AuthorityLease  `json:"lease"`
	Result  json.RawMessage `json:"result"`
}

type CoordinatorLeaseAdmission struct {
	Version   string                    `json:"version"`
	Admission AuthoritySessionAdmission `json:"admission"`
}

type CoordinatorReassignmentStatus struct {
	Version          string              `json:"version"`
	SessionBinding   string              `json:"session_binding"`
	SessionLineageID string              `json:"session_lineage_id"`
	AuthorityProfile string              `json:"authority_profile"`
	ProfileVersion   string              `json:"profile_version"`
	PolicyDigest     string              `json:"policy_digest"`
	Predecessor      agentdWorkerBinding `json:"predecessor"`
	Successor        agentdWorkerBinding `json:"successor"`
	IdempotencyKey   string              `json:"rebind_idempotency_key"`
	State            string              `json:"state"`
	ErrorCode        string              `json:"error_code,omitempty"`
}

func (s *AuthorityWorkerService) CoordinatorSessionCommand(ctx context.Context, principal, operation string, request CoordinatorSessionRequest) (CoordinatorSessionResponse, error) {
	if strings.TrimSpace(request.SessionBinding) == "" || len(request.SessionBinding) > 256 || request.After < 0 {
		return CoordinatorSessionResponse{}, fmt.Errorf("bounded session_binding and cursor are required")
	}
	lease, err := s.store.GetLease(ctx, principal, request.SessionBinding)
	if err != nil || !lease.ReleasedAt.IsZero() {
		return CoordinatorSessionResponse{}, fmt.Errorf("active coordinator session binding is required")
	}
	if _, err := s.authorize(principal, lease.Profile, "acquire"); err != nil {
		return CoordinatorSessionResponse{}, err
	}
	registered, admissionErr := s.store.RegisteredAdmission(ctx, principal, request.SessionBinding)
	isRegistered := admissionErr == nil
	if admissionErr != nil && !errors.Is(admissionErr, sql.ErrNoRows) {
		return CoordinatorSessionResponse{}, admissionErr
	}
	if err := validateCoordinatorSessionRequestForBinding(operation, request, isRegistered); err != nil {
		return CoordinatorSessionResponse{}, err
	}
	if err := s.store.RequireConfirmedCoordinatorRouting(ctx, request.SessionBinding, lease); err != nil {
		return CoordinatorSessionResponse{}, err
	}
	workspace, err := s.store.SessionWorkspace(ctx, request.SessionBinding)
	if err != nil || !validAgentdID(workspace.AgentdSessionID) {
		return CoordinatorSessionResponse{}, fmt.Errorf("coordinator session has no durable agentd identity")
	}
	worker, err := s.store.GetWorker(ctx, lease.WorkerID)
	if err != nil || worker.ProfileVersion != lease.ProfileVersion || worker.PolicyDigest != lease.PolicyDigest || worker.WorkerStorageLineageID != lease.WorkerStorageLineageID || worker.WorkerFenceEpoch != lease.WorkerFenceEpoch {
		return CoordinatorSessionResponse{}, fmt.Errorf("coordinator session lease identity changed")
	}
	transport, ok := s.runtime.(AuthorityAgentdSessionTransport)
	if !ok {
		return CoordinatorSessionResponse{}, fmt.Errorf("agentd session transport is unavailable")
	}
	method, path, payload := coordinatorAgentdRequest(operation, workspace.AgentdSessionID, request)
	if isRegistered {
		method, path, payload = coordinatorRegisteredAgentdRequest(operation, workspace.AgentdSessionID, request, registered)
	}
	status, result, err := transport.AgentdSessionRequest(ctx, worker, method, path, payload)
	if err != nil {
		return CoordinatorSessionResponse{}, err
	}
	if finding := securityscan.Fields(map[string]string{"agentd_result": string(result)}); finding != nil {
		s.audit.Log(AuditEvent{
			Operation:         "security.egress_blocked",
			Principal:         principal,
			Profile:           lease.Profile,
			AuthorityWorkerID: lease.WorkerID,
			ProfileVersion:    lease.ProfileVersion,
			PolicyDigest:      lease.PolicyDigest,
			Decision:          "deny",
			Status:            finding.Code,
			Parameters: map[string]any{
				"surface": "coordinator_agentd_result",
				"field":   finding.Field,
			},
		}, NewRedactor(nil))
		return CoordinatorSessionResponse{}, &securityscan.DetectionError{Finding: *finding}
	}
	if status < 200 || status >= 300 {
		var denied struct {
			Error string `json:"error"`
		}
		if err := json.Unmarshal(result, &denied); err != nil {
			denied.Error = "agentd_session_rejected"
		}
		return CoordinatorSessionResponse{}, &CoordinatorAgentdError{Status: status, Code: safeAgentdErrorCode(denied.Error)}
	}
	if operation == "status" || operation == "checkpoint" || operation == "resume" || (isRegistered && operation == "cancel") {
		if err := validateCoordinatorAgentdSessionStatus(result, workspace, request.SessionBinding, lease); err != nil {
			return CoordinatorSessionResponse{}, err
		}
	} else if err := validateCoordinatorAgentdResult(operation, workspace.AgentdSessionID, request.After, result); err != nil {
		return CoordinatorSessionResponse{}, err
	}
	return CoordinatorSessionResponse{Version: coordinatorProtocolVersion, Lease: lease, Result: result}, nil
}

func validateCoordinatorAgentdSessionStatus(result json.RawMessage, workspace SessionWorkspace, sessionBinding string, lease AuthorityLease) error {
	decoded, err := decodeAgentdSessionStatus(strings.NewReader(string(result)))
	if err != nil || !exactAgentdSessionStatus(decoded, workspace.AgentdSessionID, sessionBinding, lease.Profile, lease.SessionLineageID, agentdSessionWorkspace{WorkspaceRef: workspace.Path, UID: workspace.UID, GID: workspace.GID, BranchRef: decoded.Workspace.BranchRef, CheckpointRef: decoded.Workspace.CheckpointRef}, agentdWorkerBinding{WorkerID: lease.WorkerID, StorageLineageID: lease.WorkerStorageLineageID, FenceEpoch: lease.WorkerFenceEpoch}) {
		return fmt.Errorf("agentd returned mismatched session status")
	}
	return nil
}

func coordinatorRegisteredAgentdRequest(operation, sessionID string, request CoordinatorSessionRequest, admission registeredAdmission) (string, string, json.RawMessage) {
	path := "/v1/registered-sessions/" + url.PathEscape(sessionID)
	versionQuery := "?version=agentd%2Fregistered-lifecycle%2Fv1"
	if operation != "submit" {
		method := http.MethodPost
		payload := map[string]any{}
		switch operation {
		case "events":
			method, payload, path = http.MethodGet, nil, path+"/events"+versionQuery+"&after="+strconv.FormatInt(request.After, 10)
		case "status":
			method, payload, path = http.MethodGet, nil, path+"/status"+versionQuery
		case "cancel":
			path, payload = path+"/cancel", map[string]any{"version": "agentd/registered-lifecycle/v1", "idempotencyKey": request.IdempotencyKey}
		case "checkpoint":
			path, payload = path+"/checkpoint", map[string]any{"version": "agentd/registered-lifecycle/v1", "checkpointRef": request.CheckpointRef}
		}
		encoded, err := json.Marshal(payload)
		if err != nil {
			return method, path, nil
		}
		return method, path, encoded
	}
	payload, err := json.Marshal(struct {
		Version             string                   `json:"version"`
		IdempotencyKey      string                   `json:"idempotencyKey"`
		TaskKind            string                   `json:"taskKind"`
		TaskEvidenceDigest  string                   `json:"taskEvidenceDigest"`
		AdmissionTaskDigest string                   `json:"admissionTaskDigest"`
		Source              RegisteredTaskSource     `json:"registeredTaskSource"`
		Parameters          RegisteredTaskParameters `json:"parameters"`
	}{"agentd/registered-lifecycle/v1", request.IdempotencyKey, admission.Task.TaskKind, admission.Task.TaskEvidenceDigest, admission.Digest, admission.Source, admission.Task.Parameters})
	if err != nil {
		return http.MethodPost, "/v1/registered-sessions/" + url.PathEscape(sessionID) + "/turns", nil
	}
	return http.MethodPost, "/v1/registered-sessions/" + url.PathEscape(sessionID) + "/turns", payload
}

func validateCoordinatorAgentdResult(operation, sessionID string, after int64, result json.RawMessage) error {
	switch operation {
	case "submit", "cancel":
		var turn struct {
			SessionID string `json:"sessionId"`
			TurnID    string `json:"turnId"`
			Phase     string `json:"phase"`
		}
		if json.Unmarshal(result, &turn) != nil || turn.SessionID != sessionID || !validAgentdID(turn.TurnID) || turn.Phase == "" {
			return fmt.Errorf("agentd returned mismatched turn status")
		}
	case "events":
		var events []struct {
			Version   string `json:"version"`
			Cursor    int64  `json:"cursor"`
			Kind      string `json:"kind"`
			SessionID string `json:"sessionId"`
		}
		if json.Unmarshal(result, &events) != nil {
			return fmt.Errorf("agentd returned invalid event stream")
		}
		previous := after
		for _, event := range events {
			if event.Version != agentdSessionProtocolVersion || event.SessionID != sessionID || event.Cursor <= previous || event.Kind == "" {
				return fmt.Errorf("agentd returned mismatched event stream")
			}
			previous = event.Cursor
		}
	}
	return nil
}

type CoordinatorAgentdError struct {
	Status int
	Code   string
}

func (e *CoordinatorAgentdError) Error() string { return "agentd session command was rejected" }

func safeAgentdErrorCode(code string) string {
	switch code {
	case "unauthorized", "invalid_request", "not_found", "method_not_allowed",
		"session_fenced", "broker_validator_unavailable", "session_storage_unavailable",
		"rebind_required", "rebind_conflict", "invalid_command":
		return code
	default:
		return "agentd_session_rejected"
	}
}

func validateCoordinatorSessionRequest(operation string, request CoordinatorSessionRequest) error {
	return validateCoordinatorSessionRequestForBinding(operation, request, false)
}

func validateCoordinatorSessionRequestForBinding(operation string, request CoordinatorSessionRequest, registered bool) error {
	if strings.TrimSpace(request.SessionBinding) == "" || len(request.SessionBinding) > 256 || request.After < 0 {
		return fmt.Errorf("bounded session_binding and cursor are required")
	}
	switch operation {
	case "submit":
		if !validAgentdID(request.IdempotencyKey) || request.TurnID != "" || request.CheckpointRef != "" || request.After != 0 || (registered && request.Prompt != "") || (!registered && (request.Prompt == "" || len(request.Prompt) > 256*1024)) {
			return fmt.Errorf("submit requires only bounded prompt and idempotency_key")
		}
	case "cancel":
		if registered {
			if !validAgentdID(request.IdempotencyKey) || request.TurnID != "" || request.Prompt != "" || request.CheckpointRef != "" || request.After != 0 {
				return fmt.Errorf("registered cancel requires only idempotency_key")
			}
		} else if !validAgentdID(request.TurnID) || request.IdempotencyKey != "" || request.Prompt != "" || request.CheckpointRef != "" || request.After != 0 {
			return fmt.Errorf("cancel requires only turn_id")
		}
	case "checkpoint":
		if !validAgentdOpaque(request.CheckpointRef) || request.IdempotencyKey != "" || request.Prompt != "" || request.TurnID != "" || request.After != 0 {
			return fmt.Errorf("checkpoint requires only checkpoint_ref")
		}
	case "events":
		if request.IdempotencyKey != "" || request.Prompt != "" || request.TurnID != "" || request.CheckpointRef != "" {
			return fmt.Errorf("events accepts only after")
		}
	case "resume":
		if registered {
			return fmt.Errorf("registered session resume is unsupported")
		}
		fallthrough
	case "status":
		if request.IdempotencyKey != "" || request.Prompt != "" || request.TurnID != "" || request.CheckpointRef != "" || request.After != 0 {
			return fmt.Errorf("session command has forbidden fields")
		}
	default:
		return fmt.Errorf("unsupported coordinator session operation")
	}
	return nil
}

func coordinatorAgentdRequest(operation, sessionID string, request CoordinatorSessionRequest) (string, string, json.RawMessage) {
	path := "/v1/sessions/" + url.PathEscape(sessionID) + "/" + operation
	payload := map[string]any{}
	method := http.MethodPost
	switch operation {
	case "submit":
		path = "/v1/sessions/" + url.PathEscape(sessionID) + "/turns"
		payload = map[string]any{"prompt": request.Prompt, "idempotencyKey": request.IdempotencyKey}
	case "cancel":
		payload = map[string]any{"turnId": request.TurnID}
	case "checkpoint":
		payload = map[string]any{"checkpointRef": request.CheckpointRef}
	case "events":
		method, payload = http.MethodGet, nil
		path += "?after=" + strconv.FormatInt(request.After, 10)
	case "status":
		method, payload = http.MethodGet, nil
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return method, path, nil
	}
	return method, path, encoded
}

func (s *AuthorityWorkerService) CoordinatorReassignmentStatus(ctx context.Context, principal, binding string, predecessorEpoch int64) (CoordinatorReassignmentStatus, error) {
	if strings.TrimSpace(binding) == "" || len(binding) > 256 || predecessorEpoch < 1 {
		return CoordinatorReassignmentStatus{}, fmt.Errorf("binding and predecessor epoch are required")
	}
	adoption, err := s.store.AgentdAdoptionForPrincipalAtEpoch(ctx, principal, s.store.requestDigest(binding), predecessorEpoch)
	if err != nil {
		return CoordinatorReassignmentStatus{}, err
	}
	if _, err := s.authorize(principal, adoption.AuthorityBinding, "reassign"); err != nil {
		return CoordinatorReassignmentStatus{}, err
	}
	return CoordinatorReassignmentStatus{Version: coordinatorProtocolVersion, SessionBinding: adoption.CoordinatorBinding, SessionLineageID: adoption.SessionLineageID, AuthorityProfile: adoption.AuthorityBinding, ProfileVersion: adoption.ProfileVersion, PolicyDigest: adoption.PolicyDigest, Predecessor: adoption.Predecessor, Successor: adoption.Successor, IdempotencyKey: adoption.RebindIdempotencyKey, State: adoption.State, ErrorCode: adoption.ErrorCode}, nil
}
