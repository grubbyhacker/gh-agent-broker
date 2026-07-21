package sandbox

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
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

type CoordinatorRegisteredTurnRequest struct {
	Version             string                   `json:"version"`
	SessionBinding      string                   `json:"sessionBinding"`
	IdempotencyKey      string                   `json:"idempotencyKey"`
	TaskKind            string                   `json:"taskKind"`
	AdmissionTaskDigest string                   `json:"admissionTaskDigest"`
	TaskEvidenceDigest  string                   `json:"taskEvidenceDigest"`
	Parameters          RegisteredTaskParameters `json:"parameters"`
}

func (r *CoordinatorRegisteredTurnRequest) UnmarshalJSON(data []byte) error {
	type request CoordinatorRegisteredTurnRequest
	var decoded request
	if err := decodeRegisteredResponse(data, &decoded); err != nil {
		return err
	}
	*r = CoordinatorRegisteredTurnRequest(decoded)
	return nil
}

type CoordinatorRegisteredEventsRequest struct {
	SessionBinding string `json:"sessionBinding"`
	After          int64  `json:"after"`
}

func (r *CoordinatorRegisteredEventsRequest) UnmarshalJSON(data []byte) error {
	type request CoordinatorRegisteredEventsRequest
	var decoded request
	if err := decodeRegisteredResponse(data, &decoded); err != nil {
		return err
	}
	*r = CoordinatorRegisteredEventsRequest(decoded)
	return nil
}

type CoordinatorRegisteredTurnResponse struct {
	Lease         AuthorityLease `json:"lease"`
	Version       string         `json:"version"`
	SessionID     string         `json:"sessionId"`
	TurnID        string         `json:"turnId"`
	ModelEffectID string         `json:"modelEffectId"`
	Phase         string         `json:"phase"`
	Cursor        int64          `json:"cursor"`
}

type CoordinatorRegisteredEventsResponse struct {
	Lease      AuthorityLease              `json:"lease"`
	Version    string                      `json:"version"`
	Events     []registeredEventProjection `json:"events"`
	NextCursor int64                       `json:"nextCursor"`
}

func (s *AuthorityWorkerService) SubmitRegisteredTurn(ctx context.Context, principal string, request CoordinatorRegisteredTurnRequest) (CoordinatorRegisteredTurnResponse, error) {
	admission, err := s.store.RegisteredAdmission(ctx, principal, request.SessionBinding)
	if err != nil {
		return CoordinatorRegisteredTurnResponse{}, err
	}
	wantKey := "agentd:registered-turn:v1:" + admission.Source.WorkItemID
	if request.Version != "agentd/registered-lifecycle/v1" || request.IdempotencyKey != wantKey || request.TaskKind != admission.Task.TaskKind || request.AdmissionTaskDigest != admission.Digest || request.TaskEvidenceDigest != admission.Task.TaskEvidenceDigest || request.Parameters != admission.Task.Parameters {
		return CoordinatorRegisteredTurnResponse{}, fmt.Errorf("registered turn does not match durable admission")
	}
	workspace, err := s.store.SessionWorkspace(ctx, request.SessionBinding)
	if err != nil {
		return CoordinatorRegisteredTurnResponse{}, err
	}
	if workspace.AgentdSessionID == "" {
		if _, err := s.CreateSession(ctx, principal, request.SessionBinding); err != nil {
			return CoordinatorRegisteredTurnResponse{}, err
		}
		workspace, err = s.store.SessionWorkspace(ctx, request.SessionBinding)
		if err != nil || workspace.AgentdSessionID == "" {
			return CoordinatorRegisteredTurnResponse{}, fmt.Errorf("registered session identity was not persisted")
		}
	}
	out, err := s.CoordinatorSessionCommand(ctx, principal, "submit", CoordinatorSessionRequest{SessionBinding: request.SessionBinding, IdempotencyKey: request.IdempotencyKey})
	if err != nil {
		return CoordinatorRegisteredTurnResponse{}, err
	}
	turn, err := validateRegisteredTurnResponse(out.Result, workspace.AgentdSessionID, request.IdempotencyKey)
	if err != nil {
		return CoordinatorRegisteredTurnResponse{}, err
	}
	return CoordinatorRegisteredTurnResponse{Lease: out.Lease, Version: turn.Version, SessionID: turn.SessionID, TurnID: turn.TurnID, ModelEffectID: turn.ModelEffectID, Phase: turn.Phase, Cursor: turn.Cursor}, nil
}

func (s *AuthorityWorkerService) StreamRegisteredEvents(ctx context.Context, principal string, request CoordinatorRegisteredEventsRequest) (CoordinatorRegisteredEventsResponse, error) {
	if request.After < 0 {
		return CoordinatorRegisteredEventsResponse{}, fmt.Errorf("registered event cursor is invalid")
	}
	out, err := s.CoordinatorSessionCommand(ctx, principal, "events", CoordinatorSessionRequest{SessionBinding: request.SessionBinding, After: request.After})
	if err != nil {
		return CoordinatorRegisteredEventsResponse{}, err
	}
	var events registeredEventsResponse
	if err := decodeRegisteredResponse(out.Result, &events); err != nil {
		return CoordinatorRegisteredEventsResponse{}, err
	}
	return CoordinatorRegisteredEventsResponse{Lease: out.Lease, Version: events.Version, Events: events.Events, NextCursor: events.NextCursor}, nil
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
	var registeredTurn registeredTurnState
	if isRegistered {
		if operation == "submit" {
			registeredTurn, err = s.store.RegisteredTurn(ctx, principal, request.SessionBinding)
			if err == nil {
				if registeredTurn.IdempotencyDigest != s.store.requestDigest(request.IdempotencyKey) {
					return CoordinatorSessionResponse{}, fmt.Errorf("registered turn idempotency key conflicts with durable turn")
				}
				result, marshalErr := json.Marshal(registeredTurnResponse{Version: registeredTurnResponseVersion, SessionID: registeredTurn.SessionID, TurnID: registeredTurn.TurnID, ModelEffectID: registeredTurn.ModelEffectID, Phase: "queued", Cursor: registeredTurn.SubmitCursor})
				if marshalErr != nil {
					return CoordinatorSessionResponse{}, marshalErr
				}
				return CoordinatorSessionResponse{Version: coordinatorProtocolVersion, Lease: lease, Result: result}, nil
			}
			if !errors.Is(err, sql.ErrNoRows) {
				return CoordinatorSessionResponse{}, err
			}
		}
		if operation == "events" {
			registeredTurn, err = s.store.RegisteredTurn(ctx, principal, request.SessionBinding)
			if err != nil {
				return CoordinatorSessionResponse{}, fmt.Errorf("registered turn is not durably accepted")
			}
			if request.After != registeredTurn.EventsAfter {
				return CoordinatorSessionResponse{}, fmt.Errorf("registered event cursor does not match durable cursor")
			}
		}
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
	if isRegistered && ((operation == "submit" && status != http.StatusAccepted) || (operation == "events" && status != http.StatusOK)) {
		return CoordinatorSessionResponse{}, &CoordinatorAgentdError{Status: status, Code: "agentd_session_rejected"}
	}
	if isRegistered && operation == "submit" {
		turn, validateErr := validateRegisteredTurnResponse(result, workspace.AgentdSessionID, request.IdempotencyKey)
		if validateErr != nil {
			return CoordinatorSessionResponse{}, validateErr
		}
		if err := s.store.RecordRegisteredTurn(ctx, principal, request.SessionBinding, request.IdempotencyKey, registeredTurnState{SessionID: turn.SessionID, TurnID: turn.TurnID, ModelEffectID: turn.ModelEffectID, SubmitCursor: turn.Cursor}); err != nil {
			return CoordinatorSessionResponse{}, err
		}
	}
	if isRegistered && operation == "events" {
		events, validateErr := validateRegisteredEventsResponse(result, registeredTurn, request.After, registered.Digest, registered.Task.ContractDigest, registered.Task.TaskEvidenceDigest)
		if validateErr != nil {
			return CoordinatorSessionResponse{}, validateErr
		}
		if err := s.store.RecordRegisteredEvents(ctx, principal, request.SessionBinding, request.After, events.NextCursor, events.Events); err != nil {
			return CoordinatorSessionResponse{}, err
		}
	}
	if operation == "status" || operation == "checkpoint" || operation == "resume" || (isRegistered && operation == "cancel") {
		if err := validateCoordinatorAgentdSessionStatus(result, workspace, request.SessionBinding, lease); err != nil {
			return CoordinatorSessionResponse{}, err
		}
	} else if !isRegistered {
		if err := validateCoordinatorAgentdResult(operation, workspace.AgentdSessionID, request.After, result); err != nil {
			return CoordinatorSessionResponse{}, err
		}
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
			method, payload, path = http.MethodGet, nil, path+"/events?version=agentd%2Fregistered-events%2Fv2&after="+strconv.FormatInt(request.After, 10)
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
		AdmissionTaskDigest string                   `json:"admissionTaskDigest"`
		TaskEvidenceDigest  string                   `json:"taskEvidenceDigest"`
		Parameters          RegisteredTaskParameters `json:"parameters"`
	}{"agentd/registered-lifecycle/v1", request.IdempotencyKey, admission.Task.TaskKind, admission.Digest, admission.Task.TaskEvidenceDigest, admission.Task.Parameters})
	if err != nil {
		return http.MethodPost, "/v1/registered-sessions/" + url.PathEscape(sessionID) + "/turns", nil
	}
	return http.MethodPost, "/v1/registered-sessions/" + url.PathEscape(sessionID) + "/turns", payload
}

const (
	registeredTurnResponseVersion   = "agentd/registered-turn/v2"
	registeredEventsResponseVersion = "agentd/registered-events/v2"
)

type registeredTurnResponse struct {
	Version       string `json:"version"`
	SessionID     string `json:"sessionId"`
	TurnID        string `json:"turnId"`
	ModelEffectID string `json:"modelEffectId"`
	Phase         string `json:"phase"`
	Cursor        int64  `json:"cursor"`
}

func (r *registeredTurnResponse) UnmarshalJSON(data []byte) error {
	type response registeredTurnResponse
	var decoded response
	if err := decodeRegisteredResponse(data, &decoded); err != nil {
		return err
	}
	if _, err := requireRegisteredFields(data, "version", "sessionId", "turnId", "modelEffectId", "phase", "cursor"); err != nil {
		return err
	}
	*r = registeredTurnResponse(decoded)
	return nil
}

type registeredVerifierProjection struct {
	Phase              string                     `json:"phase"`
	Outcome            string                     `json:"outcome"`
	ContractDigest     string                     `json:"contractDigest"`
	TaskEvidenceDigest string                     `json:"taskEvidenceDigest"`
	HeadRevision       string                     `json:"headRevision"`
	Reasons            []registeredVerifierReason `json:"reasons"`
	EvidenceRefs       []string                   `json:"evidenceRefs"`
}

// registeredVerifierReason is the exact session-supervisor v2.2.0 reason
// projection. It intentionally keeps evidence references opaque.
type registeredVerifierReason struct {
	Code        string `json:"code"`
	EvidenceRef string `json:"evidenceRef,omitempty"`
}

func (r *registeredVerifierReason) UnmarshalJSON(data []byte) error {
	type reason registeredVerifierReason
	var decoded reason
	if err := decodeRegisteredResponse(data, &decoded); err != nil {
		return err
	}
	if fields, err := requireRegisteredFields(data, "code"); err != nil {
		return err
	} else if value, ok := fields["evidenceRef"]; ok && string(value) == "null" {
		return fmt.Errorf("evidenceRef cannot be null")
	}
	*r = registeredVerifierReason(decoded)
	return nil
}

type registeredEventProjection struct {
	Cursor              int64                         `json:"cursor"`
	SessionID           string                        `json:"sessionId"`
	TurnID              string                        `json:"turnId"`
	ModelEffectID       string                        `json:"modelEffectId"`
	Attempt             int64                         `json:"attempt"`
	Phase               string                        `json:"phase"`
	WorkerID            string                        `json:"workerId"`
	StorageLineageID    string                        `json:"storageLineageId"`
	FenceEpoch          int64                         `json:"fenceEpoch"`
	AdmissionTaskDigest string                        `json:"admissionTaskDigest"`
	TaskEvidenceDigest  string                        `json:"taskEvidenceDigest"`
	Verifier            *registeredVerifierProjection `json:"verifier,omitempty"`
	Failure             string                        `json:"failure,omitempty"`
}

func (e *registeredEventProjection) UnmarshalJSON(data []byte) error {
	type projection registeredEventProjection
	var decoded projection
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("trailing JSON value")
	}
	fields, err := requireRegisteredFields(data, "cursor", "sessionId", "turnId", "modelEffectId", "attempt", "phase", "workerId", "storageLineageId", "fenceEpoch", "admissionTaskDigest", "taskEvidenceDigest")
	if err != nil {
		return err
	}
	for _, name := range []string{"verifier", "failure"} {
		if value, ok := fields[name]; ok && string(value) == "null" {
			return fmt.Errorf("%s cannot be null", name)
		}
	}
	*e = registeredEventProjection(decoded)
	return nil
}

type registeredEventsResponse struct {
	Version    string                      `json:"version"`
	Events     []registeredEventProjection `json:"events"`
	NextCursor int64                       `json:"nextCursor"`
}

func (r *registeredEventsResponse) UnmarshalJSON(data []byte) error {
	type response registeredEventsResponse
	var decoded response
	if err := decodeRegisteredResponse(data, &decoded); err != nil {
		return err
	}
	if _, err := requireRegisteredFields(data, "version", "events", "nextCursor"); err != nil {
		return err
	}
	*r = registeredEventsResponse(decoded)
	return nil
}

func decodeRegisteredResponse(data json.RawMessage, target any) error {
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("trailing JSON value")
	}
	return nil
}

func requireRegisteredFields(data []byte, required ...string) (map[string]json.RawMessage, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return nil, err
	}
	for _, name := range required {
		value, ok := fields[name]
		if !ok {
			return nil, fmt.Errorf("%s is required", name)
		}
		if string(value) == "null" {
			return nil, fmt.Errorf("%s cannot be null", name)
		}
	}
	return fields, nil
}

func validateRegisteredTurnResponse(result json.RawMessage, sessionID, idempotencyKey string) (registeredTurnResponse, error) {
	var turn registeredTurnResponse
	if err := decodeRegisteredResponse(result, &turn); err != nil || turn.Version != registeredTurnResponseVersion || turn.SessionID != sessionID || !registeredOpaqueID.MatchString(turn.TurnID) || turn.TurnID != "turn:"+idempotencyKey || !registeredOpaqueID.MatchString(turn.ModelEffectID) || turn.ModelEffectID != "model:"+idempotencyKey || turn.Phase != "queued" || turn.Cursor < 1 {
		return registeredTurnResponse{}, fmt.Errorf("agentd returned invalid registered turn acknowledgement")
	}
	return turn, nil
}

func validateRegisteredEventsResponse(result json.RawMessage, turn registeredTurnState, after int64, admissionDigest, contractDigest, taskEvidenceDigest string) (registeredEventsResponse, error) {
	var response registeredEventsResponse
	if err := decodeRegisteredResponse(result, &response); err != nil || response.Version != registeredEventsResponseVersion || response.Events == nil || response.NextCursor < after {
		return registeredEventsResponse{}, fmt.Errorf("agentd returned invalid registered event stream")
	}
	previous := after
	for _, event := range response.Events {
		// The root turn identity never changes, but agentd gives each authorized
		// continuation a distinct model effect identity. Durable projection
		// verifies that identity and its worker custody atomically.
		if event.Cursor <= previous || event.SessionID != turn.SessionID || event.TurnID != turn.TurnID || !registeredOpaqueID.MatchString(event.ModelEffectID) || event.Attempt < 0 || !registeredOpaqueID.MatchString(event.WorkerID) || event.StorageLineageID == "" || len(event.StorageLineageID) > 128 || event.FenceEpoch < 0 || event.AdmissionTaskDigest != admissionDigest || event.TaskEvidenceDigest != taskEvidenceDigest || !validRegisteredEventPhaseFailureVerifier(event, contractDigest, taskEvidenceDigest) {
			return registeredEventsResponse{}, fmt.Errorf("agentd returned invalid registered event stream")
		}
		previous = event.Cursor
	}
	if response.NextCursor != previous {
		return registeredEventsResponse{}, fmt.Errorf("agentd returned invalid registered event cursor")
	}
	return response, nil
}

func validRegisteredEventPhaseFailureVerifier(event registeredEventProjection, contractDigest, taskEvidenceDigest string) bool {
	if !validRegisteredVerifier(event.Verifier, contractDigest, taskEvidenceDigest) {
		return false
	}

	switch event.Failure {
	case "":
		if event.Verifier == nil {
			switch event.Phase {
			case "queued", "authorized", "running", "completed":
				return true
			}
			return false
		}
		return event.Phase == event.Verifier.Phase
	case "credential_mint_failed":
		return event.Phase == "authorized" && event.Verifier == nil
	case "runtime_failed":
		return event.Phase == "failed" && event.Verifier == nil
	case "credential_expired":
		return event.Phase == "escalated" && event.Verifier == nil
	case "runtime_outcome_uncertain":
		return event.Phase == "escalated" && event.Verifier != nil && event.Verifier.Phase == "escalated"
	default:
		return false
	}
}

var registeredVerifierReasonCode = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$`)

func validRegisteredVerifier(verifier *registeredVerifierProjection, contractDigest, taskEvidenceDigest string) bool {
	if verifier == nil {
		return true
	}
	if !registeredVerifierPhaseOutcome(verifier.Phase, verifier.Outcome) || verifier.ContractDigest != contractDigest || verifier.TaskEvidenceDigest != taskEvidenceDigest || !sha256Digest.MatchString(verifier.ContractDigest) || !sha256Digest.MatchString(verifier.TaskEvidenceDigest) || !registeredOpaqueReference(verifier.HeadRevision) || verifier.Reasons == nil || len(verifier.Reasons) > 32 || len(verifier.EvidenceRefs) < 1 || len(verifier.EvidenceRefs) > 64 {
		return false
	}
	if (verifier.Outcome == "satisfied" && len(verifier.Reasons) != 0) || (verifier.Outcome != "satisfied" && len(verifier.Reasons) == 0) {
		return false
	}
	for _, reason := range verifier.Reasons {
		if !registeredVerifierReasonCode.MatchString(reason.Code) || (reason.EvidenceRef != "" && !registeredOpaqueReference(reason.EvidenceRef)) {
			return false
		}
	}
	for _, evidenceRef := range verifier.EvidenceRefs {
		if !registeredOpaqueReference(evidenceRef) {
			return false
		}
	}
	return true
}

func registeredVerifierPhaseOutcome(phase, outcome string) bool {
	switch outcome {
	case "waiting":
		return phase == "pending"
	case "satisfied":
		return phase == "green"
	case "missing_or_stale", "continuation":
		return phase == "red"
	case "escalated":
		return phase == "refused" || phase == "escalated"
	default:
		return false
	}
}

func registeredOpaqueReference(value string) bool {
	return len(value) >= 1 && len(value) <= 512
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
