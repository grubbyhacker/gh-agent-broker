package sandbox

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

const agentdTransportContextProtocolVersion = "broker/agentd-transport-context/v1"

var (
	authorityTransportDigest        = regexp.MustCompile(`^[0-9a-f]{64}$`)
	errAgentdTransportContextDenied = errors.New("transport context denied")
)

// AgentdTransportContextRequest contains only equality constraints for an
// agentd-parent capability exchange. It carries no principal, lease binding,
// repository, task, push, PR, SHA, or completion authority.
type AgentdTransportContextRequest struct {
	Version                 string `json:"version"`
	SessionID               string `json:"sessionId"`
	CoordinatorBinding      string `json:"coordinatorBinding"`
	SessionLineageID        string `json:"sessionLineageId"`
	WorkerID                string `json:"workerId"`
	WorkerStorageLineageID  string `json:"workerStorageLineageId"`
	WorkerFenceEpoch        int64  `json:"workerFenceEpoch"`
	AuthorityProfile        string `json:"authorityProfile"`
	AuthorityProfileVersion string `json:"authorityProfileVersion"`
	PolicyDigest            string `json:"policyDigest"`
}

func (r *AgentdTransportContextRequest) UnmarshalJSON(data []byte) error {
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	type request AgentdTransportContextRequest
	var decoded request
	if err := decoder.Decode(&decoded); err != nil {
		return fmt.Errorf("invalid agentd transport context request: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("invalid agentd transport context request: trailing JSON value")
	}
	*r = AgentdTransportContextRequest(decoded)
	return nil
}

type AgentdTransportContextResponse struct {
	Version          string `json:"version"`
	TransportContext string `json:"transportContext"`
}

type agentdTransportContextSnapshot struct {
	Authority          TransportAuthority
	SessionID          string
	CoordinatorBinding string
	WorkerState        AuthorityWorkerState
	Adoption           authorityAgentdAdoption
	HasAdoption        bool
}

func (r AgentdTransportContextRequest) valid() bool {
	return r.Version == agentdTransportContextProtocolVersion && validAgentdID(r.SessionID) &&
		validAgentdOpaque(r.CoordinatorBinding) && validOpaqueLineageID(r.SessionLineageID) &&
		safeAuthorityName(r.WorkerID) && validOpaqueLineageID(r.WorkerStorageLineageID) && r.WorkerFenceEpoch >= 1 &&
		safeAuthorityName(r.AuthorityProfile) && authorityTransportDigest.MatchString(r.AuthorityProfileVersion) && authorityTransportDigest.MatchString(r.PolicyDigest)
}

func (s agentdTransportContextSnapshot) matches(request AgentdTransportContextRequest) bool {
	return request.SessionID == s.SessionID && request.CoordinatorBinding == s.CoordinatorBinding &&
		request.SessionLineageID == s.Authority.SessionLineageID && request.WorkerID == s.Authority.WorkerID &&
		request.WorkerStorageLineageID == s.Authority.WorkerStorageLineageID && request.WorkerFenceEpoch == s.Authority.WorkerFenceEpoch &&
		request.AuthorityProfile == s.Authority.Profile && request.AuthorityProfileVersion == s.Authority.ProfileVersion &&
		request.PolicyDigest == s.Authority.PolicyDigest && s.WorkerState == AuthorityWorkerReady
}

func (s agentdTransportContextSnapshot) routingConfirmed() bool {
	if !s.HasAdoption {
		return true
	}
	a := s.Adoption
	return a.State == authorityAdoptionConfirmed && a.Principal == s.Authority.Principal &&
		a.BindingDigest == s.Authority.SessionBindingDigest && a.CoordinatorBinding == s.CoordinatorBinding &&
		a.AuthorityBinding == s.Authority.Profile && a.ProfileVersion == s.Authority.ProfileVersion &&
		a.PolicyDigest == s.Authority.PolicyDigest && a.SessionLineageID == s.Authority.SessionLineageID &&
		a.AgentdSessionID == s.SessionID && a.Successor.WorkerID == s.Authority.WorkerID &&
		a.Successor.StorageLineageID == s.Authority.WorkerStorageLineageID && a.Successor.FenceEpoch == s.Authority.WorkerFenceEpoch
}

// AgentdTransportContext returns a child capability only after one durable
// snapshot proves the authenticated agentd parent and every session coordinate
// describe the same active registered lease.
func (s *AuthorityWorkerService) AgentdTransportContext(ctx context.Context, credential string, request AgentdTransportContextRequest) (AgentdTransportContextResponse, error) {
	if !request.valid() {
		return AgentdTransportContextResponse{}, errAgentdTransportContextDenied
	}
	snapshot, err := s.store.agentdTransportContextSnapshot(ctx, request.SessionID)
	if err != nil || !snapshot.matches(request) || !snapshot.routingConfirmed() {
		return AgentdTransportContextResponse{}, errAgentdTransportContextDenied
	}
	profile, ok := s.cfg.AuthorityProfiles[snapshot.Authority.Profile]
	if !ok {
		return AgentdTransportContextResponse{}, errAgentdTransportContextDenied
	}
	secret := strings.TrimSpace(os.Getenv(profile.BrokerSecretEnv))
	expected := deriveAgentdValidationToken(secret, snapshot.Authority.WorkerID, snapshot.Authority.WorkerStorageLineageID, snapshot.Authority.WorkerFenceEpoch)
	if secret == "" || !secureTokenEqual(credential, expected) {
		return AgentdTransportContextResponse{}, errAgentdTransportContextDenied
	}
	return AgentdTransportContextResponse{Version: agentdTransportContextProtocolVersion, TransportContext: deriveTransportContext(s.store.salt, snapshot.Authority)}, nil
}

func (s *AuthorityWorkerStore) agentdTransportContextSnapshot(ctx context.Context, sessionID string) (agentdTransportContextSnapshot, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT
		l.principal,l.profile,l.worker_id,l.session_lineage_id,l.binding_digest,
		w.worker_storage_lineage_id,w.worker_fence_epoch,w.profile_version,w.policy_digest,w.state,
		a.protocol_version,a.work_item_id,a.route_snapshot_id,a.canonical_task_json,a.admission_task_digest,
		sw.agentd_session_id,
		COALESCE(r.principal,''),COALESCE(r.binding_digest,''),COALESCE(r.coordinator_binding,''),COALESCE(r.authority_binding,''),
		COALESCE(r.profile_version,''),COALESCE(r.policy_digest,''),COALESCE(r.session_lineage_id,''),COALESCE(r.agentd_session_id,''),
		COALESCE(r.predecessor_worker_id,''),COALESCE(r.predecessor_storage_lineage_id,''),COALESCE(r.predecessor_fence_epoch,0),
		COALESCE(r.replacement_worker_id,''),COALESCE(r.replacement_storage_lineage_id,''),COALESCE(r.replacement_fence_epoch,0),
		COALESCE(r.rebind_idempotency_key,''),COALESCE(r.workspace_ref,''),COALESCE(r.workspace_uid,0),COALESCE(r.workspace_gid,0),
		COALESCE(r.adoption_state,''),COALESCE(r.adoption_error_code,'')
	FROM authority_session_leases l
	JOIN authority_workers w ON w.worker_id=l.worker_id
	JOIN authority_registered_admissions a ON a.principal=l.principal AND a.binding_digest=l.binding_digest
	JOIN authority_session_workspaces sw ON sw.binding_digest=l.binding_digest AND sw.worker_id=l.worker_id
	LEFT JOIN authority_session_reassignments r ON r.binding_digest=l.binding_digest AND r.predecessor_fence_epoch=(
		SELECT max(latest.predecessor_fence_epoch) FROM authority_session_reassignments latest WHERE latest.binding_digest=l.binding_digest)
	WHERE sw.agentd_session_id=? AND l.released_at=''`, sessionID)
	if err != nil {
		return agentdTransportContextSnapshot{}, err
	}
	defer closeTransportRows(rows)
	var snapshot agentdTransportContextSnapshot
	var protocol, workItemID, routeSnapshotID, canonical, digest string
	matches := 0
	for rows.Next() {
		matches++
		if matches > 1 {
			return agentdTransportContextSnapshot{}, fmt.Errorf("agentd transport context identity is ambiguous")
		}
		if err := rows.Scan(
			&snapshot.Authority.Principal, &snapshot.Authority.Profile, &snapshot.Authority.WorkerID, &snapshot.Authority.SessionLineageID, &snapshot.Authority.SessionBindingDigest,
			&snapshot.Authority.WorkerStorageLineageID, &snapshot.Authority.WorkerFenceEpoch, &snapshot.Authority.ProfileVersion, &snapshot.Authority.PolicyDigest, &snapshot.WorkerState,
			&protocol, &workItemID, &routeSnapshotID, &canonical, &digest, &snapshot.SessionID,
			&snapshot.Adoption.Principal, &snapshot.Adoption.BindingDigest, &snapshot.Adoption.CoordinatorBinding, &snapshot.Adoption.AuthorityBinding,
			&snapshot.Adoption.ProfileVersion, &snapshot.Adoption.PolicyDigest, &snapshot.Adoption.SessionLineageID, &snapshot.Adoption.AgentdSessionID,
			&snapshot.Adoption.Predecessor.WorkerID, &snapshot.Adoption.Predecessor.StorageLineageID, &snapshot.Adoption.Predecessor.FenceEpoch,
			&snapshot.Adoption.Successor.WorkerID, &snapshot.Adoption.Successor.StorageLineageID, &snapshot.Adoption.Successor.FenceEpoch,
			&snapshot.Adoption.RebindIdempotencyKey, &snapshot.Adoption.Workspace.WorkspaceRef, &snapshot.Adoption.Workspace.UID, &snapshot.Adoption.Workspace.GID,
			&snapshot.Adoption.State, &snapshot.Adoption.ErrorCode,
		); err != nil {
			return agentdTransportContextSnapshot{}, err
		}
	}
	if err := rows.Err(); err != nil {
		return agentdTransportContextSnapshot{}, err
	}
	if matches != 1 {
		return agentdTransportContextSnapshot{}, sql.ErrNoRows
	}
	admission, err := validateDurableRegisteredAdmission(protocol, snapshot.Authority.Profile, workItemID, routeSnapshotID, canonical, digest)
	if err != nil {
		return agentdTransportContextSnapshot{}, err
	}
	snapshot.CoordinatorBinding = "session:" + admission.Source.WorkItemID
	snapshot.HasAdoption = snapshot.Adoption.State != ""
	return snapshot, nil
}
