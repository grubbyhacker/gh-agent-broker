package sandbox

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const agentdSessionProtocolVersion = "agentd/v1"

type agentdWorkerBinding struct {
	WorkerID         string `json:"workerId"`
	StorageLineageID string `json:"storageLineageId"`
	FenceEpoch       int64  `json:"fenceEpoch"`
}

type agentdRebindRequest struct {
	IdempotencyKey string              `json:"idempotencyKey"`
	Predecessor    agentdWorkerBinding `json:"predecessor"`
	Successor      agentdWorkerBinding `json:"successor"`
}

type agentdRegisteredAdoptRequest struct {
	Version           string `json:"version"`
	IdempotencyKey    string `json:"idempotencyKey"`
	PredecessorWorker string `json:"predecessorWorker"`
	PredecessorEpoch  int64  `json:"predecessorEpoch"`
}

type agentdConversationRef struct {
	AdapterKind      string `json:"adapterKind"`
	AdapterVersion   string `json:"adapterVersion"`
	BackendThreadRef string `json:"backendThreadRef"`
}

type agentdSessionStatus struct {
	Version            string                 `json:"version"`
	SessionID          string                 `json:"sessionId"`
	CoordinatorBinding string                 `json:"coordinatorBinding"`
	AuthorityBinding   string                 `json:"authorityBinding"`
	WorkerID           string                 `json:"workerId"`
	StorageLineageID   string                 `json:"storageLineageId"`
	FenceEpoch         int64                  `json:"fenceEpoch"`
	SessionLineageID   string                 `json:"sessionLineageId"`
	Workspace          agentdSessionWorkspace `json:"workspace"`
	Phase              string                 `json:"phase"`
	Conversation       *agentdConversationRef `json:"conversation,omitempty"`
	ActiveTurnID       string                 `json:"activeTurnId,omitempty"`
	TurnIDs            []string               `json:"turnIds"`
	NextCursor         int64                  `json:"nextCursor"`
}

func decodeAgentdSessionStatus(body io.Reader) (agentdSessionStatus, error) {
	var status agentdSessionStatus
	decoder := json.NewDecoder(io.LimitReader(body, 32*1024))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&status); err != nil {
		return agentdSessionStatus{}, fmt.Errorf("decode agentd session status: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return agentdSessionStatus{}, fmt.Errorf("decode agentd session status: trailing JSON value")
	}
	if status.Version != agentdSessionProtocolVersion || !validAgentdID(status.SessionID) || !validAgentdOpaque(status.CoordinatorBinding) || !validAgentdOpaque(status.AuthorityBinding) || !validAgentdOpaque(status.WorkerID) || !validAgentdOpaque(status.StorageLineageID) || !validAgentdID(status.SessionLineageID) || status.FenceEpoch < 1 || (status.Phase != "active" && status.Phase != "terminated") || status.TurnIDs == nil || status.NextCursor < 1 || !validAgentdOpaque(status.Workspace.WorkspaceRef) || status.Workspace.UID < 0 || status.Workspace.GID < 0 || (status.Workspace.BranchRef != "" && !validAgentdOpaque(status.Workspace.BranchRef)) || (status.Workspace.CheckpointRef != "" && !validAgentdOpaque(status.Workspace.CheckpointRef)) || (status.ActiveTurnID != "" && !validAgentdID(status.ActiveTurnID)) {
		return agentdSessionStatus{}, fmt.Errorf("agentd session status failed schema validation")
	}
	for _, turnID := range status.TurnIDs {
		if !validAgentdID(turnID) {
			return agentdSessionStatus{}, fmt.Errorf("agentd session status failed schema validation")
		}
	}
	if status.Conversation != nil && (!validAgentdID(status.Conversation.AdapterKind) || !validAgentdID(status.Conversation.AdapterVersion) || !validAgentdOpaque(status.Conversation.BackendThreadRef)) {
		return agentdSessionStatus{}, fmt.Errorf("agentd session status failed schema validation")
	}
	return status, nil
}

func validAgentdID(value string) bool {
	return value != "" && len(value) <= 128
}

func validAgentdOpaque(value string) bool {
	return value != "" && len(value) <= 512
}

func marshalAgentdSessionStatus(status agentdSessionStatus) (json.RawMessage, error) {
	payload, err := json.Marshal(status)
	if err != nil {
		return nil, err
	}
	return bytes.Clone(payload), nil
}

func exactAgentdSessionStatus(status agentdSessionStatus, sessionID, coordinatorBinding, authorityBinding, sessionLineageID string, workspace agentdSessionWorkspace, binding agentdWorkerBinding) bool {
	return status.SessionID == sessionID && status.CoordinatorBinding == coordinatorBinding && status.AuthorityBinding == authorityBinding && status.WorkerID == binding.WorkerID && status.StorageLineageID == binding.StorageLineageID && status.FenceEpoch == binding.FenceEpoch && status.SessionLineageID == sessionLineageID && status.Workspace == workspace
}

type agentdRebindError struct {
	retryable bool
	code      string
}

func (e *agentdRebindError) Error() string {
	if e.retryable {
		return "agentd rebind is temporarily unavailable"
	}
	if e.code != "" {
		return "agentd rebind rejected: " + e.code
	}
	return "agentd rebind rejected"
}
