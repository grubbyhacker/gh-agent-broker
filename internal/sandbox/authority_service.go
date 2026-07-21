package sandbox

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// AuthorityWorkerRequest is intentionally narrower than LaunchAgentInput. It
// cannot carry any authority-bearing runtime or repository fields.
type AuthorityWorkerRequest struct {
	Profile        string `json:"profile"`
	IdempotencyKey string `json:"idempotency_key"`
	SessionBinding string `json:"session_binding"`
}

// AuthoritySessionReassignmentRequest intentionally identifies only the
// session and its observed predecessor. The broker derives the replacement
// from its durable lifecycle record.
type AuthoritySessionReassignmentRequest struct {
	SessionBinding              string `json:"session_binding"`
	SessionLineageID            string `json:"session_lineage_id"`
	PredecessorWorkerID         string `json:"predecessor_worker_id"`
	PredecessorWorkerFenceEpoch int64  `json:"predecessor_worker_fence_epoch"`
	IdempotencyKey              string `json:"idempotency_key"`
}

type agentdCreateSessionRequest struct {
	Version            string                 `json:"version"`
	CoordinatorBinding string                 `json:"coordinatorBinding"`
	AuthorityBinding   string                 `json:"authorityBinding"`
	WorkerID           string                 `json:"workerId"`
	StorageLineageID   string                 `json:"storageLineageId"`
	FenceEpoch         int64                  `json:"fenceEpoch"`
	SessionLineageID   string                 `json:"sessionLineageId"`
	Workspace          agentdSessionWorkspace `json:"workspace"`
}

type agentdRegisteredSessionOpenRequest struct {
	Version                 string                   `json:"version"`
	SessionID               string                   `json:"sessionId"`
	CoordinatorBinding      string                   `json:"coordinatorBinding"`
	SessionLineageID        string                   `json:"sessionLineageId"`
	AuthorityProfile        string                   `json:"authorityProfile"`
	AuthorityProfileVersion string                   `json:"authorityProfileVersion"`
	PolicyDigest            string                   `json:"policyDigest"`
	TaskKind                string                   `json:"taskKind"`
	TaskEvidenceDigest      string                   `json:"taskEvidenceDigest"`
	AdmissionTaskDigest     string                   `json:"admissionTaskDigest"`
	Parameters              RegisteredTaskParameters `json:"parameters"`
	Workspace               agentdSessionWorkspace   `json:"workspace"`
}

type agentdSessionWorkspace struct {
	WorkspaceRef  string `json:"workspaceRef"`
	UID           int    `json:"uid"`
	GID           int    `json:"gid"`
	BranchRef     string `json:"branchRef,omitempty"`
	CheckpointRef string `json:"checkpointRef,omitempty"`
}

func (s *AuthorityWorkerService) CreateSession(ctx context.Context, principal, binding string) (json.RawMessage, error) {
	lease, err := s.store.GetLease(ctx, principal, binding)
	if err != nil {
		return nil, err
	}
	profile, err := s.authorize(principal, lease.Profile, "acquire")
	if err != nil {
		return nil, err
	}
	if err := s.checkIssuance(ctx, lease.Profile, profile); err != nil {
		return nil, err
	}
	if err := s.store.RequireConfirmedCoordinatorRouting(ctx, binding, lease); err != nil {
		return nil, err
	}
	registered, admissionErr := s.store.RegisteredAdmission(ctx, principal, binding)
	isRegistered := admissionErr == nil
	if admissionErr != nil && !errors.Is(admissionErr, sql.ErrNoRows) {
		return nil, admissionErr
	}
	workspace, err := s.store.SessionWorkspace(ctx, binding)
	if err != nil {
		return nil, err
	}
	worker, err := s.store.GetWorker(ctx, lease.WorkerID)
	if err != nil {
		return nil, err
	}
	transport, ok := s.runtime.(AuthorityAgentdSessionTransport)
	if !ok {
		return nil, fmt.Errorf("agentd session transport is unavailable")
	}
	derivedSessionID := "agentd-" + lease.SessionLineageID
	var createPayload any = agentdCreateSessionRequest{Version: "agentd/v1", CoordinatorBinding: binding, AuthorityBinding: lease.Profile, WorkerID: lease.WorkerID, StorageLineageID: lease.WorkerStorageLineageID, FenceEpoch: lease.WorkerFenceEpoch, SessionLineageID: lease.SessionLineageID, Workspace: agentdSessionWorkspace{WorkspaceRef: workspace.Path, UID: workspace.UID, GID: workspace.GID}}
	if isRegistered {
		createPayload = agentdRegisteredSessionOpenRequest{Version: "agentd/registered-lifecycle/v1", SessionID: derivedSessionID, CoordinatorBinding: binding, SessionLineageID: lease.SessionLineageID, AuthorityProfile: lease.Profile, AuthorityProfileVersion: lease.ProfileVersion, PolicyDigest: lease.PolicyDigest, TaskKind: registered.Task.TaskKind, TaskEvidenceDigest: registered.Task.TaskEvidenceDigest, AdmissionTaskDigest: registered.Digest, Parameters: registered.Task.Parameters, Workspace: agentdSessionWorkspace{WorkspaceRef: workspace.Path, UID: workspace.UID, GID: workspace.GID}}
	}
	payload, err := json.Marshal(createPayload)
	if err != nil {
		return nil, err
	}
	path := "/v1/sessions"
	if isRegistered {
		path = "/v1/registered-sessions"
	}
	var encoded json.RawMessage
	err = s.store.IssueAgentdSession(ctx, binding, lease.Profile, profile.IssuanceGeneration, func() (string, error) {
		statusCode, result, err := transport.AgentdSessionRequest(ctx, worker, http.MethodPost, path, payload)
		if err != nil {
			return "", fmt.Errorf("agentd session create: %w", err)
		}
		if statusCode != http.StatusCreated {
			return "", fmt.Errorf("agentd session create rejected: status=%d body=%s", statusCode, string(result))
		}
		status, err := decodeAgentdSessionStatus(bytes.NewReader(result))
		if err != nil {
			return "", fmt.Errorf("agentd session create returned an invalid status")
		}
		expectedBinding := agentdWorkerBinding{WorkerID: lease.WorkerID, StorageLineageID: lease.WorkerStorageLineageID, FenceEpoch: lease.WorkerFenceEpoch}
		expectedWorkspace := agentdSessionWorkspace{WorkspaceRef: workspace.Path, UID: workspace.UID, GID: workspace.GID}
		expectedSessionID := status.SessionID
		if isRegistered {
			expectedSessionID = derivedSessionID
		}
		if !exactAgentdSessionStatus(status, expectedSessionID, binding, lease.Profile, lease.SessionLineageID, expectedWorkspace, expectedBinding) {
			return "", fmt.Errorf("agentd session create returned a mismatched status")
		}
		encoded, err = marshalAgentdSessionStatus(status)
		return status.SessionID, err
	})
	if err != nil || encoded != nil {
		return encoded, err
	}
	workspace, err = s.store.SessionWorkspace(ctx, binding)
	if err != nil || !validAgentdID(workspace.AgentdSessionID) {
		return nil, fmt.Errorf("durable agentd session identity is unavailable")
	}
	statusPath := "/v1/sessions/" + url.PathEscape(workspace.AgentdSessionID) + "/status"
	if isRegistered {
		statusPath = "/v1/registered-sessions/" + url.PathEscape(workspace.AgentdSessionID) + "/status?version=agentd%2Fregistered-lifecycle%2Fv1"
	}
	statusCode, result, err := transport.AgentdSessionRequest(ctx, worker, http.MethodGet, statusPath, nil)
	if err != nil || statusCode != http.StatusOK {
		return nil, fmt.Errorf("agentd session replay status is unavailable")
	}
	status, err := decodeAgentdSessionStatus(bytes.NewReader(result))
	if err != nil {
		return nil, fmt.Errorf("agentd session replay returned an invalid status")
	}
	expectedBinding := agentdWorkerBinding{WorkerID: lease.WorkerID, StorageLineageID: lease.WorkerStorageLineageID, FenceEpoch: lease.WorkerFenceEpoch}
	expectedWorkspace := agentdSessionWorkspace{WorkspaceRef: workspace.Path, UID: workspace.UID, GID: workspace.GID}
	if !exactAgentdSessionStatus(status, workspace.AgentdSessionID, binding, lease.Profile, lease.SessionLineageID, expectedWorkspace, expectedBinding) {
		return nil, fmt.Errorf("agentd session replay returned a mismatched status")
	}
	return marshalAgentdSessionStatus(status)
}

func (r *AuthorityWorkerRequest) UnmarshalJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	type request AuthorityWorkerRequest
	var decoded request
	if err := decoder.Decode(&decoded); err != nil {
		return fmt.Errorf("invalid authority worker request: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("invalid authority worker request: trailing JSON value")
	}
	*r = AuthorityWorkerRequest(decoded)
	return nil
}

func (r *AuthoritySessionReassignmentRequest) UnmarshalJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	type request AuthoritySessionReassignmentRequest
	var decoded request
	if err := decoder.Decode(&decoded); err != nil {
		return fmt.Errorf("invalid authority session reassignment request: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("invalid authority session reassignment request: trailing JSON value")
	}
	*r = AuthoritySessionReassignmentRequest(decoded)
	return nil
}

type AuthorityWorkerSpec struct {
	WorkerID               string
	Profile                string
	ProfileVersion         string
	PolicyDigest           string
	Image                  string
	Platform               string
	Command                []string
	Resources              Resources
	Network                NetworkPolicy
	BrokerAgentID          string
	BrokerSecretEnv        string
	CoordinatorTokenEnv    string
	CredentialBundle       string
	CredentialMount        Mount
	Repositories           []string
	BranchPolicy           BranchPolicy
	Operations             []string
	ExtraMounts            []ExtraMount
	SessionIsolation       SessionIsolation
	Checkpoint             CheckpointPolicy
	Storage                AuthorityStorage
	SessionCapacity        int
	WorkerStorageLineageID string
	WorkerFenceEpoch       int64
	AgentdReadiness        AgentdReadiness
}

type AuthorityRuntimeResult struct {
	ContainerID string
	ImageDigest string
}

// AuthorityWorkerRuntime is separate from the run-oriented RuntimeBackend.
// A real agentd implementation will satisfy it only after that contract is
// versioned; PR 8A uses synthetic test runtimes exclusively. Create must be
// idempotent by WorkerID so a persisted provisioning record can be reconciled
// after broker interruption without creating duplicate containers.
type AuthorityWorkerRuntime interface {
	Create(context.Context, AuthorityWorkerSpec) (AuthorityRuntimeResult, error)
	Stop(context.Context, string) error
	Healthy(context.Context, string) (bool, string, error)
}

// AuthorityAgentdReadiness is intentionally separate from container liveness.
// Reconciliation only promotes workers after agentd attests its journal,
// runtime, launcher and fencing-validator configuration.
type AuthorityAgentdReadiness interface {
	AgentdReady(context.Context, AuthorityWorker) (bool, string, error)
}

// AuthorityAgentdRebinder addresses agentd only through the runtime-owned
// endpoint for the broker-recorded successor worker.
type AuthorityAgentdRebinder interface {
	RebindAgentdSession(context.Context, AuthorityWorker, string, agentdRebindRequest) (agentdSessionStatus, error)
}

// AuthorityAgentdRegisteredAdopter is the registered-lifecycle counterpart to
// legacy rebind. The successor remains entirely broker-derived.
type AuthorityAgentdRegisteredAdopter interface {
	AdoptRegisteredAgentdSession(context.Context, AuthorityWorker, string, agentdRegisteredAdoptRequest) (agentdSessionStatus, error)
}

type AgentdSessionValidationRequest struct {
	WorkerID               string `json:"worker_id"`
	WorkerStorageLineageID string `json:"worker_storage_lineage_id"`
	WorkerFenceEpoch       int64  `json:"worker_fence_epoch"`
	SessionLineageID       string `json:"session_lineage_id"`
}

type AgentdSessionValidation struct {
	Authorized bool   `json:"authorized"`
	Code       string `json:"code"`
}

type AuthorityWorkerService struct {
	cfg              Config
	store            *AuthorityWorkerStore
	runtime          AuthorityWorkerRuntime
	audit            *AuditLogger
	now              func() time.Time
	newID            func() (string, error)
	checkpoints      *CheckpointStore
	issuance         AuthorityIssuanceGuard
	retirementMu     sync.Mutex
	registeredTurnMu sync.Mutex
}

type AuthorityIssuanceGuard interface {
	CheckIssuance(context.Context, string, int64) error
}

type AuthoritySessionAdmission struct {
	Lease     AuthorityLease   `json:"lease"`
	Workspace SessionWorkspace `json:"workspace"`
}

func (s *AuthorityWorkerService) AcquireSession(ctx context.Context, principal string, request AuthorityWorkerRequest) (AuthoritySessionAdmission, error) {
	profile, err := s.authorize(principal, request.Profile, "acquire")
	if err != nil {
		return AuthoritySessionAdmission{}, err
	}
	if err := validateAuthorityRequest(request); err != nil {
		return AuthoritySessionAdmission{}, err
	}
	lease, err := s.store.Acquire(ctx, principal, request, profile.IssuanceGeneration)
	if err != nil {
		return AuthoritySessionAdmission{}, err
	}
	workspace, err := s.store.AllocateSessionWorkspace(ctx, lease, profile.SessionIsolation)
	if err != nil {
		return AuthoritySessionAdmission{}, err
	}
	return AuthoritySessionAdmission{Lease: lease, Workspace: workspace}, nil
}

// AcquireRegisteredSession is the sole registered-task admission seam.  It is
// intentionally unavailable unless configuration names the Signal principal.
func (s *AuthorityWorkerService) AcquireRegisteredSession(ctx context.Context, principal string, request RegisteredAdmissionRequest) (AuthoritySessionAdmission, error) {
	if s.cfg.RegisteredCoordinatorPrincipal == "" || principal != s.cfg.RegisteredCoordinatorPrincipal {
		return AuthoritySessionAdmission{}, fmt.Errorf("policy denial: registered admission principal is not configured")
	}
	profile, err := s.authorize(principal, request.Profile, "acquire")
	if err != nil {
		return AuthoritySessionAdmission{}, err
	}
	lease, err := s.store.AcquireRegistered(ctx, principal, request, profile.IssuanceGeneration)
	if err != nil {
		return AuthoritySessionAdmission{}, err
	}
	workspace, err := s.store.AllocateSessionWorkspace(ctx, lease, profile.SessionIsolation)
	if err != nil {
		return AuthoritySessionAdmission{}, err
	}
	return AuthoritySessionAdmission{Lease: lease, Workspace: workspace}, nil
}

func NewAuthorityWorkerService(cfg Config, store *AuthorityWorkerStore, runtime AuthorityWorkerRuntime, audit *AuditLogger, issuance AuthorityIssuanceGuard) *AuthorityWorkerService {
	return &AuthorityWorkerService{
		cfg: cfg, store: store, runtime: runtime, audit: audit, issuance: issuance,
		now:   func() time.Time { return time.Now().UTC() },
		newID: newRunID,
	}
}

func (s *AuthorityWorkerService) checkIssuance(ctx context.Context, name string, profile AuthorityProfile) error {
	if s.issuance == nil {
		return errors.New("authority issuance guard is unavailable")
	}
	if err := s.issuance.CheckIssuance(ctx, name, profile.IssuanceGeneration); err != nil {
		return fmt.Errorf("authority issuance denied: %w", err)
	}
	return nil
}

func (s *AuthorityWorkerService) WithCheckpointStore(store *CheckpointStore) *AuthorityWorkerService {
	s.checkpoints = store
	return s
}

func (s *AuthorityWorkerService) Reconcile(ctx context.Context, principal string) error {
	workers, err := s.store.ListLiveWorkers(ctx)
	if err != nil {
		return err
	}
	var reconcileErr error
	for _, worker := range workers {
		if _, err := s.authorize(principal, worker.Profile, "health"); err != nil {
			reconcileErr = errors.Join(reconcileErr, err)
			continue
		}
		if worker.ContainerID == "" {
			continue
		}
		healthy, evidence, inspectErr := s.runtime.Healthy(ctx, worker.ContainerID)
		if inspectErr != nil {
			healthy, evidence = false, "runtime_inspect_failed"
		}
		if healthy {
			profile := s.cfg.AuthorityProfiles[worker.Profile]
			if configuredAgentdReadiness(profile).ContractVersion == "" {
				if _, err := s.SetHealth(ctx, principal, worker.WorkerID, evidence, true); err != nil {
					reconcileErr = errors.Join(reconcileErr, err)
				}
				continue
			}
			probe, ok := s.runtime.(AuthorityAgentdReadiness)
			ready, readinessEvidence, readinessErr := false, "agentd_authenticated_readiness_contract_unavailable", error(nil)
			if ok {
				ready, readinessEvidence, readinessErr = probe.AgentdReady(ctx, worker)
			}
			if readinessErr != nil || !ready {
				continue
			}
			if _, err := s.SetHealth(ctx, principal, worker.WorkerID, readinessEvidence, true); err != nil {
				reconcileErr = errors.Join(reconcileErr, err)
			}
			continue
		}
		if s.checkpoints != nil {
			if err := s.checkpoints.CheckpointWorker(ctx, worker); err != nil {
				reconcileErr = errors.Join(reconcileErr, err)
				continue
			}
		}
		if _, err := s.SetHealth(ctx, principal, worker.WorkerID, evidence, false); err != nil {
			reconcileErr = errors.Join(reconcileErr, err)
			continue
		}
		if _, err := s.Replace(ctx, principal, worker.WorkerID, "runtime_unhealthy"); err != nil {
			reconcileErr = errors.Join(reconcileErr, err)
		}
	}
	adoptions, err := s.store.UnconfirmedAgentdAdoptions(ctx)
	if err != nil {
		reconcileErr = errors.Join(reconcileErr, err)
	} else {
		for _, adoption := range adoptions {
			if _, authErr := s.authorize(principal, adoption.AuthorityBinding, "reassign"); authErr != nil {
				reconcileErr = errors.Join(reconcileErr, authErr)
				continue
			}
			if adoptionErr := s.confirmAgentdAdoption(ctx, adoption); adoptionErr != nil {
				reconcileErr = errors.Join(reconcileErr, adoptionErr)
			}
		}
	}
	replacements, err := s.store.ReadyReplacementWorkersWithDrainedPredecessors(ctx)
	if err != nil {
		reconcileErr = errors.Join(reconcileErr, err)
	} else {
		for _, replacementWorkerID := range replacements {
			if retireErr := s.retireDrainedPredecessor(ctx, replacementWorkerID); retireErr != nil {
				reconcileErr = errors.Join(reconcileErr, retireErr)
			}
		}
	}
	return reconcileErr
}

// ValidateAgentdSession is the authenticated, fail-closed fencing contract
// agentd calls before accessing any lineage-scoped journal or workspace state.
func (s *AuthorityWorkerService) ValidateAgentdSession(ctx context.Context, credential string, request AgentdSessionValidationRequest) (AgentdSessionValidation, error) {
	worker, err := s.store.agentdValidationWorker(ctx, request.WorkerID)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return AgentdSessionValidation{}, err
		}
	}
	validationKey := string(make([]byte, sha256.Size))
	knownWorker := err == nil
	profile, knownProfile := s.cfg.AuthorityProfiles[worker.Profile]
	if knownWorker && knownProfile {
		if configuredSecret := strings.TrimSpace(os.Getenv(profile.BrokerSecretEnv)); configuredSecret != "" {
			validationKey = configuredSecret
		} else {
			knownProfile = false
		}
	}
	expected := deriveAgentdValidationToken(validationKey, request.WorkerID, request.WorkerStorageLineageID, request.WorkerFenceEpoch)
	if !knownWorker || !knownProfile || !secureTokenEqual(credential, expected) {
		return AgentdSessionValidation{Code: "unauthorized"}, nil
	}
	if !safeAuthorityName(request.WorkerID) || !validOpaqueLineageID(request.WorkerStorageLineageID) || !validOpaqueLineageID(request.SessionLineageID) || request.WorkerFenceEpoch < 1 {
		return AgentdSessionValidation{Code: "invalid_request"}, nil
	}
	if worker.WorkerStorageLineageID != request.WorkerStorageLineageID || worker.WorkerFenceEpoch != request.WorkerFenceEpoch {
		return AgentdSessionValidation{Code: "fenced"}, nil
	}
	valid, err := s.store.validateAgentdSessionFence(ctx, request.WorkerID, request.SessionLineageID, request.WorkerFenceEpoch)
	if err != nil {
		return AgentdSessionValidation{}, err
	}
	if !valid {
		return AgentdSessionValidation{Code: "fenced"}, nil
	}
	return AgentdSessionValidation{Authorized: true, Code: "authorized"}, nil
}

func (s *AuthorityWorkerService) GetWorker(ctx context.Context, principal, workerID string) (AuthorityWorker, error) {
	worker, err := s.store.GetWorker(ctx, workerID)
	if err != nil {
		return AuthorityWorker{}, err
	}
	if _, err := s.authorize(principal, worker.Profile, "health"); err != nil {
		return AuthorityWorker{}, err
	}
	return worker, nil
}

func (s *AuthorityWorkerService) Provision(ctx context.Context, principal, profileName string) (AuthorityWorker, error) {
	profile, err := s.authorize(principal, profileName, "provision")
	if err != nil {
		s.log("authority_worker.provision", principal, profileName, AuthorityWorker{}, "deny", err)
		return AuthorityWorker{}, err
	}
	if err := s.checkIssuance(ctx, profileName, profile); err != nil {
		return AuthorityWorker{}, err
	}
	profileVersion, policyDigest, err := authorityProfileDigest(profileName, profile)
	if err != nil {
		return AuthorityWorker{}, err
	}
	workerID, err := s.newID()
	if err != nil {
		return AuthorityWorker{}, err
	}
	worker := AuthorityWorker{WorkerID: workerID, Profile: profileName, ProfileVersion: profileVersion, PolicyDigest: policyDigest, ImageReference: profile.Image, Generation: 1, State: AuthorityWorkerProvisioning, Capacity: profile.SessionCapacity}
	worker, err = s.store.CreateWorker(ctx, worker, profile.MaxWorkers, profile.IssuanceGeneration)
	if err != nil {
		s.log("authority_worker.provision", principal, profileName, worker, "deny", err)
		return AuthorityWorker{}, err
	}
	result, err := s.runtime.Create(ctx, authoritySpec(worker, profile, s.cfg))
	if err != nil {
		markErr := s.store.MarkFailed(context.WithoutCancel(ctx), worker.WorkerID, "runtime_create_failed")
		s.log("authority_worker.provision", principal, profileName, worker, "deny", fmt.Errorf("runtime create failed"))
		return AuthorityWorker{}, errors.Join(fmt.Errorf("create authority worker: %w", err), markErr)
	}
	if !validAuthorityImageDigest(result.ImageDigest) {
		return AuthorityWorker{}, s.compensateCreatedWorker(ctx, "", worker.WorkerID, result.ContainerID, "runtime_image_digest_invalid", fmt.Errorf("authority runtime returned an invalid image digest"))
	}
	updated, err := s.store.UpdateWorkerRuntime(ctx, worker.WorkerID, result.ContainerID, result.ImageDigest)
	if err != nil {
		err = s.compensateCreatedWorker(ctx, "", worker.WorkerID, result.ContainerID, "runtime_state_persist_failed", err)
	} else {
		worker = updated
	}
	s.log("authority_worker.provision", principal, profileName, worker, decision(err), err)
	return worker, err
}

func (s *AuthorityWorkerService) SetHealth(ctx context.Context, principal, workerID, health string, ready bool) (AuthorityWorker, error) {
	worker, err := s.store.GetWorker(ctx, workerID)
	if err != nil {
		return AuthorityWorker{}, err
	}
	if _, err := s.authorize(principal, worker.Profile, "health"); err != nil {
		s.log("authority_worker.health", principal, worker.Profile, worker, "deny", err)
		return AuthorityWorker{}, err
	}
	if strings.TrimSpace(health) == "" || len(health) > 256 {
		return AuthorityWorker{}, fmt.Errorf("bounded health evidence is required")
	}
	worker, err = s.store.SetWorkerHealth(ctx, workerID, health, ready)
	if err == nil && ready {
		if retireErr := s.retireDrainedPredecessor(ctx, worker.WorkerID); retireErr != nil {
			err = retireErr
		}
	}
	s.log("authority_worker.health", principal, worker.Profile, worker, decision(err), err)
	return worker, err
}

func (s *AuthorityWorkerService) retireDrainedPredecessor(ctx context.Context, replacementWorkerID string) error {
	s.retirementMu.Lock()
	defer s.retirementMu.Unlock()
	predecessor, found, err := s.store.DrainedPredecessor(ctx, replacementWorkerID)
	if err != nil || !found {
		return err
	}
	if predecessor.ContainerID != "" {
		if err := s.runtime.Stop(ctx, predecessor.ContainerID); err != nil {
			return fmt.Errorf("stop drained predecessor %q: %w", predecessor.WorkerID, err)
		}
	}
	return s.store.MarkDrainedStopped(ctx, predecessor.WorkerID)
}

func (s *AuthorityWorkerService) Acquire(ctx context.Context, principal string, request AuthorityWorkerRequest) (AuthorityLease, error) {
	profile, err := s.authorize(principal, request.Profile, "acquire")
	if err != nil {
		s.log("authority_worker.acquire", principal, request.Profile, AuthorityWorker{}, "deny", err)
		return AuthorityLease{}, err
	}
	if err := validateAuthorityRequest(request); err != nil {
		s.log("authority_worker.acquire", principal, request.Profile, AuthorityWorker{}, "deny", err)
		return AuthorityLease{}, err
	}
	lease, err := s.store.Acquire(ctx, principal, request, profile.IssuanceGeneration)
	worker := AuthorityWorker{WorkerID: lease.WorkerID, Profile: request.Profile}
	s.log("authority_worker.acquire", principal, request.Profile, worker, decision(err), err)
	return lease, err
}

func (s *AuthorityWorkerService) ReassignSession(ctx context.Context, principal string, request AuthoritySessionReassignmentRequest) (AuthoritySessionReassignment, error) {
	if err := validateReassignmentRequest(request); err != nil {
		return AuthoritySessionReassignment{}, err
	}
	lease, err := s.store.GetLease(ctx, principal, request.SessionBinding)
	if err != nil {
		return AuthoritySessionReassignment{}, reassignmentError(ReassignmentStalePredecessor, "session binding is not visible to this principal")
	}
	if _, err := s.authorize(principal, lease.Profile, "reassign"); err != nil {
		s.log("authority_worker.reassign", principal, lease.Profile, AuthorityWorker{WorkerID: request.PredecessorWorkerID, Profile: lease.Profile}, "deny", err)
		return AuthoritySessionReassignment{}, err
	}
	predecessor, err := s.store.GetWorker(ctx, request.PredecessorWorkerID)
	if err != nil {
		return AuthoritySessionReassignment{}, reassignmentError(ReassignmentStalePredecessor, "supplied predecessor is unavailable")
	}
	profile := s.cfg.AuthorityProfiles[lease.Profile]
	profileVersion, policyDigest, digestErr := authorityProfileDigest(lease.Profile, profile)
	if digestErr != nil || predecessor.Profile != lease.Profile || predecessor.ProfileVersion != profileVersion || predecessor.PolicyDigest != policyDigest || predecessor.ImageReference != profile.Image || predecessor.Capacity != profile.SessionCapacity {
		return AuthoritySessionReassignment{}, reassignmentError(ReassignmentConflictingReplacement, "immutable profile/policy/storage identity no longer matches predecessor")
	}
	workspace, err := s.store.SessionWorkspace(ctx, request.SessionBinding)
	if err != nil || !validAgentdID(workspace.AgentdSessionID) {
		return AuthoritySessionReassignment{}, reassignmentError(ReassignmentConflictingReplacement, "session has no durable agentd identity")
	}
	_, admissionErr := s.store.RegisteredAdmission(ctx, principal, request.SessionBinding)
	isRegistered := admissionErr == nil
	if admissionErr != nil && !errors.Is(admissionErr, sql.ErrNoRows) {
		return AuthoritySessionReassignment{}, reassignmentError(ReassignmentRebindConflict, "registered admission state is unavailable")
	}
	if isRegistered {
		if _, ok := s.runtime.(AuthorityAgentdRegisteredAdopter); !ok {
			return AuthoritySessionReassignment{}, reassignmentError(ReassignmentRebindRetryable, "agentd registered adoption transport is unavailable")
		}
	} else if _, ok := s.runtime.(AuthorityAgentdRebinder); !ok {
		return AuthoritySessionReassignment{}, reassignmentError(ReassignmentRebindRetryable, "agentd rebind transport is unavailable")
	}
	reassignment, err := s.store.Reassign(ctx, principal, request.SessionBinding, request.SessionLineageID, request.PredecessorWorkerID, request.PredecessorWorkerFenceEpoch, request.IdempotencyKey, workspace, profile.IssuanceGeneration)
	if err != nil {
		worker := AuthorityWorker{WorkerID: reassignment.ReplacementWorkerID, Profile: lease.Profile}
		s.log("authority_worker.reassign", principal, lease.Profile, worker, decision(err), err)
		return reassignment, err
	}
	replacement, err := s.store.GetWorker(ctx, reassignment.ReplacementWorkerID)
	if err != nil {
		err = reassignmentError(ReassignmentRebindRetryable, "broker-recorded replacement is temporarily unavailable after lease cutover")
		s.log("authority_worker.reassign", principal, lease.Profile, AuthorityWorker{WorkerID: reassignment.ReplacementWorkerID, Profile: lease.Profile}, "deny", err)
		return reassignment, err
	}
	adoption, err := s.store.AgentdAdoption(ctx, reassignment.Lease.BindingDigest)
	if err != nil {
		err = reassignmentError(ReassignmentRebindRetryable, "durable agentd adoption transition is temporarily unavailable")
		s.log("authority_worker.reassign", principal, lease.Profile, replacement, "deny", err)
		return reassignment, err
	}
	if err = s.confirmAgentdAdoption(ctx, adoption); err != nil {
		s.log("authority_worker.reassign", principal, lease.Profile, replacement, "deny", err)
		return reassignment, err
	}
	// Retirement is intentionally after the exact agentd status is durably
	// confirmed. Every retirement query repeats that durable gate.
	if retireErr := s.retireDrainedPredecessor(ctx, reassignment.ReplacementWorkerID); retireErr != nil {
		err = reassignmentError(ReassignmentRebindRetryable, "predecessor retirement is temporarily unavailable")
		s.log("authority_worker.reassign", principal, lease.Profile, replacement, "deny", err)
		return reassignment, err
	}
	worker := replacement
	s.log("authority_worker.reassign", principal, lease.Profile, worker, decision(err), err)
	return reassignment, err
}

func (s *AuthorityWorkerService) confirmAgentdAdoption(ctx context.Context, adoption authorityAgentdAdoption) error {
	switch adoption.State {
	case authorityAdoptionConfirmed:
		return nil
	case authorityAdoptionConflict:
		return reassignmentError(ReassignmentRebindConflict, "agentd adoption has terminal conflict %s", adoption.ErrorCode)
	case authorityAdoptionLegacyUnresolved:
		return reassignmentError(ReassignmentRebindConflict, "agentd adoption transition predates replayable recovery state and requires operator resolution")
	case authorityAdoptionPending:
	default:
		return reassignmentError(ReassignmentRebindConflict, "agentd adoption transition has invalid durable state")
	}
	if !validAgentdID(adoption.AgentdSessionID) || !validAgentdID(adoption.SessionLineageID) ||
		adoption.RebindIdempotencyKey != s.store.rebindIdempotencyKey(adoption.AgentdSessionID, adoption.Predecessor, adoption.Successor) {
		return reassignmentError(ReassignmentRebindConflict, "agentd adoption transition identity is invalid")
	}
	replacement, err := s.store.GetWorker(ctx, adoption.Successor.WorkerID)
	if err != nil || replacement.Profile != adoption.AuthorityBinding || replacement.WorkerStorageLineageID != adoption.Successor.StorageLineageID || replacement.WorkerFenceEpoch != adoption.Successor.FenceEpoch {
		return reassignmentError(ReassignmentRebindRetryable, "broker-recorded adoption successor is temporarily unavailable")
	}
	_, admissionErr := s.store.RegisteredAdmission(ctx, adoption.Principal, adoption.CoordinatorBinding)
	isRegistered := admissionErr == nil
	if admissionErr != nil && !errors.Is(admissionErr, sql.ErrNoRows) {
		return reassignmentError(ReassignmentRebindRetryable, "registered admission state is unavailable")
	}
	var status agentdSessionStatus
	var rebindErr error
	if isRegistered {
		adopter, ok := s.runtime.(AuthorityAgentdRegisteredAdopter)
		if !ok {
			return reassignmentError(ReassignmentRebindRetryable, "agentd registered adoption transport is unavailable")
		}
		request := agentdRegisteredAdoptRequest{Version: "agentd/registered-lifecycle/v1", IdempotencyKey: adoption.RebindIdempotencyKey, PredecessorWorker: adoption.Predecessor.WorkerID, PredecessorEpoch: adoption.Predecessor.FenceEpoch}
		status, rebindErr = adopter.AdoptRegisteredAgentdSession(ctx, replacement, adoption.AgentdSessionID, request)
	} else {
		rebinder, ok := s.runtime.(AuthorityAgentdRebinder)
		if !ok {
			return reassignmentError(ReassignmentRebindRetryable, "agentd rebind transport is unavailable")
		}
		request := agentdRebindRequest{IdempotencyKey: adoption.RebindIdempotencyKey, Predecessor: adoption.Predecessor, Successor: adoption.Successor}
		status, rebindErr = rebinder.RebindAgentdSession(ctx, replacement, adoption.AgentdSessionID, request)
	}
	if rebindErr != nil {
		var typed *agentdRebindError
		if errors.As(rebindErr, &typed) && !typed.retryable {
			code := typed.code
			if code == "" {
				code = "agentd_rebind_rejected"
			}
			if recordErr := s.store.RecordAgentdAdoptionConflict(context.WithoutCancel(ctx), adoption, code); recordErr != nil {
				return reassignmentError(ReassignmentRebindRetryable, "agentd adoption conflict could not be recorded")
			}
			return reassignmentError(ReassignmentRebindConflict, "%s", typed.Error())
		}
		return reassignmentError(ReassignmentRebindRetryable, "agentd rebind is temporarily unavailable")
	}
	expectedWorkspace := adoption.Workspace
	expectedWorkspace.BranchRef = status.Workspace.BranchRef
	expectedWorkspace.CheckpointRef = status.Workspace.CheckpointRef
	if !exactAgentdSessionStatus(status, adoption.AgentdSessionID, adoption.CoordinatorBinding, adoption.AuthorityBinding, adoption.SessionLineageID, expectedWorkspace, adoption.Successor) {
		return reassignmentError(ReassignmentRebindRetryable, "agentd rebind returned an invalid successor status")
	}
	if err := s.store.ConfirmAgentdAdoption(context.WithoutCancel(ctx), adoption); err != nil {
		return reassignmentError(ReassignmentRebindRetryable, "agentd adoption confirmation is temporarily unavailable")
	}
	return nil
}

func (s *AuthorityWorkerService) Release(ctx context.Context, principal, sessionBinding string) (AuthorityLease, error) {
	if strings.TrimSpace(sessionBinding) == "" || len(sessionBinding) > 256 {
		return AuthorityLease{}, fmt.Errorf("session_binding is required and must be at most 256 bytes")
	}
	lease, err := s.store.GetLease(ctx, principal, sessionBinding)
	if err == nil {
		_, err = s.authorize(principal, lease.Profile, "release")
	}
	if err == nil {
		lease, err = s.store.Release(ctx, principal, sessionBinding)
	}
	worker := AuthorityWorker{WorkerID: lease.WorkerID, Profile: lease.Profile}
	s.log("authority_worker.release", principal, lease.Profile, worker, decision(err), err)
	return lease, err
}

func (s *AuthorityWorkerService) Drain(ctx context.Context, principal, workerID, reason string) (AuthorityWorker, error) {
	worker, err := s.store.GetWorker(ctx, workerID)
	if err != nil {
		return AuthorityWorker{}, err
	}
	if _, err := s.authorize(principal, worker.Profile, "drain"); err != nil {
		s.log("authority_worker.drain", principal, worker.Profile, worker, "deny", err)
		return AuthorityWorker{}, err
	}
	if strings.TrimSpace(reason) == "" || len(reason) > 256 {
		return AuthorityWorker{}, fmt.Errorf("bounded drain reason is required")
	}
	// A drain never abandons a lease. Each extant lease receives an encrypted
	// broker-owned checkpoint evidence record before the worker leaves admission.
	if s.checkpoints != nil {
		if err := s.checkpoints.CheckpointWorker(ctx, worker); err != nil {
			return AuthorityWorker{}, err
		}
	}
	worker, err = s.store.Drain(ctx, workerID, reason)
	s.log("authority_worker.drain", principal, worker.Profile, worker, decision(err), err)
	return worker, err
}

func (s *AuthorityWorkerService) Replace(ctx context.Context, principal, workerID, reason string) (AuthorityWorker, error) {
	old, err := s.store.GetWorker(ctx, workerID)
	if err != nil {
		return AuthorityWorker{}, err
	}
	profile, err := s.authorize(principal, old.Profile, "replace")
	if err != nil {
		s.log("authority_worker.replace", principal, old.Profile, old, "deny", err)
		return AuthorityWorker{}, err
	}
	if strings.TrimSpace(reason) == "" || len(reason) > 256 {
		return AuthorityWorker{}, fmt.Errorf("bounded replacement reason is required")
	}
	profileVersion, policyDigest, err := authorityProfileDigest(old.Profile, profile)
	if err != nil {
		return AuthorityWorker{}, err
	}
	// A generation change may not silently change its profile, policy, image or
	// storage identity. ProfileVersion hashes the complete reviewed profile,
	// including AuthorityStorage; PolicyDigest is asserted separately.
	if profileVersion != old.ProfileVersion || policyDigest != old.PolicyDigest || profile.Image != old.ImageReference || profile.SessionCapacity != old.Capacity {
		return AuthorityWorker{}, fmt.Errorf("replacement immutable profile/policy/storage identity differs from predecessor")
	}
	newID, err := s.newID()
	if err != nil {
		return AuthorityWorker{}, err
	}
	replacement := AuthorityWorker{WorkerID: newID, Profile: old.Profile, ProfileVersion: old.ProfileVersion, PolicyDigest: old.PolicyDigest, ImageReference: old.ImageReference, Generation: old.Generation + 1, State: AuthorityWorkerProvisioning, Capacity: old.Capacity, DrainReason: reason}
	replacement, created, err := s.store.LinkReplacement(ctx, old.WorkerID, replacement, profile.MaxWorkers, profile.IssuanceGeneration)
	if err != nil {
		s.log("authority_worker.replace", principal, old.Profile, old, "deny", err)
		return AuthorityWorker{}, err
	}
	if replacement.ProfileVersion != profileVersion || replacement.PolicyDigest != policyDigest || replacement.ImageReference != profile.Image {
		failErr := s.store.FailReplacement(context.WithoutCancel(ctx), old.WorkerID, replacement.WorkerID, "profile_changed_before_runtime_create")
		return AuthorityWorker{}, errors.Join(fmt.Errorf("replacement profile changed before runtime creation; retry with the current profile"), failErr)
	}
	if !created && replacement.State != AuthorityWorkerProvisioning {
		s.log("authority_worker.replace", principal, old.Profile, replacement, "allow", nil)
		return replacement, nil
	}
	result, err := s.runtime.Create(ctx, authoritySpec(replacement, profile, s.cfg))
	if err != nil {
		markErr := s.store.FailReplacement(context.WithoutCancel(ctx), old.WorkerID, replacement.WorkerID, "runtime_create_failed")
		s.log("authority_worker.replace", principal, old.Profile, replacement, "deny", fmt.Errorf("runtime create failed"))
		return AuthorityWorker{}, errors.Join(fmt.Errorf("create replacement authority worker: %w", err), markErr)
	}
	if !validAuthorityImageDigest(result.ImageDigest) {
		return AuthorityWorker{}, s.compensateCreatedWorker(ctx, old.WorkerID, replacement.WorkerID, result.ContainerID, "runtime_image_digest_invalid", fmt.Errorf("authority runtime returned an invalid image digest"))
	}
	updated, err := s.store.UpdateWorkerRuntime(ctx, replacement.WorkerID, result.ContainerID, result.ImageDigest)
	if err != nil {
		err = s.compensateCreatedWorker(ctx, old.WorkerID, replacement.WorkerID, result.ContainerID, "runtime_state_persist_failed", err)
	} else {
		replacement = updated
	}
	s.log("authority_worker.replace", principal, old.Profile, replacement, decision(err), err)
	return replacement, err
}

func (s *AuthorityWorkerService) authorize(principal, profile, action string) (AuthorityProfile, error) {
	configured, ok := s.cfg.AuthorityPrincipals[principal]
	if !ok || !contains(configured.AllowedProfiles, profile) || !contains(configured.AllowedActions, action) {
		return AuthorityProfile{}, fmt.Errorf("policy denial: principal is not allowed to %s authority profile %q", action, profile)
	}
	configuredProfile, ok := s.cfg.AuthorityProfiles[profile]
	if !ok {
		return AuthorityProfile{}, fmt.Errorf("policy denial: unknown authority profile %q", profile)
	}
	return configuredProfile, nil
}

func validateAuthorityRequest(request AuthorityWorkerRequest) error {
	if !safeAuthorityName(request.Profile) {
		return fmt.Errorf("profile is required")
	}
	if strings.TrimSpace(request.IdempotencyKey) == "" || len(request.IdempotencyKey) > 256 {
		return fmt.Errorf("idempotency_key is required and must be at most 256 bytes")
	}
	if strings.TrimSpace(request.SessionBinding) == "" || len(request.SessionBinding) > 256 {
		return fmt.Errorf("session_binding is required and must be at most 256 bytes")
	}
	return nil
}

func validateReassignmentRequest(request AuthoritySessionReassignmentRequest) error {
	if strings.TrimSpace(request.SessionBinding) == "" || len(request.SessionBinding) > 256 {
		return fmt.Errorf("session_binding is required and must be at most 256 bytes")
	}
	if !safeAuthorityName(request.PredecessorWorkerID) {
		return fmt.Errorf("predecessor_worker_id is required")
	}
	if !validOpaqueLineageID(request.SessionLineageID) {
		return fmt.Errorf("session_lineage_id must be an opaque broker-generated lineage")
	}
	if request.PredecessorWorkerFenceEpoch < 1 {
		return fmt.Errorf("predecessor_worker_fence_epoch must be positive")
	}
	if strings.TrimSpace(request.IdempotencyKey) == "" || len(request.IdempotencyKey) > 256 {
		return fmt.Errorf("idempotency_key is required and must be at most 256 bytes")
	}
	return nil
}

func authoritySpec(worker AuthorityWorker, profile AuthorityProfile, cfg Config) AuthorityWorkerSpec {
	spec := AuthorityWorkerSpec{WorkerID: worker.WorkerID, Profile: worker.Profile, ProfileVersion: worker.ProfileVersion, PolicyDigest: worker.PolicyDigest, Image: profile.Image, Platform: profile.Platform, Command: append([]string(nil), profile.Command...), Resources: profile.Resources, Network: cfg.Networks[profile.NetworkPolicy], BrokerAgentID: profile.BrokerAgentID, BrokerSecretEnv: profile.BrokerSecretEnv, CoordinatorTokenEnv: profile.CoordinatorTokenEnv, CredentialBundle: profile.CredentialBundle, Repositories: append([]string(nil), profile.Repositories...), BranchPolicy: profile.BranchPolicy, Operations: append([]string(nil), profile.Operations...), ExtraMounts: append([]ExtraMount(nil), profile.ExtraMounts...), SessionIsolation: profile.SessionIsolation, Checkpoint: profile.Checkpoint, Storage: profile.Storage, SessionCapacity: profile.SessionCapacity, WorkerStorageLineageID: worker.WorkerStorageLineageID, WorkerFenceEpoch: worker.WorkerFenceEpoch, AgentdReadiness: configuredAgentdReadiness(profile)}
	if bundle, ok := cfg.Bundles[profile.CredentialBundle]; ok {
		spec.CredentialMount = credentialBundleMount(bundle)
	}
	return spec
}

func credentialBundleMount(bundle CredentialBundle) Mount {
	if bundle.SourceVolume != "" {
		return Mount{Source: bundle.SourceVolume, Target: bundle.MountPath, ReadOnly: bundle.ReadOnly, Volume: true}
	}
	return Mount{Source: bundle.SourcePath, Target: bundle.MountPath, ReadOnly: bundle.ReadOnly}
}

func decision(err error) string {
	if err != nil {
		return "deny"
	}
	return "allow"
}

func validAuthorityImageDigest(value string) bool {
	return regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(value)
}

func (s *AuthorityWorkerService) compensateCreatedWorker(ctx context.Context, oldWorkerID, workerID, containerID, health string, primary error) error {
	stopErr := s.runtime.Stop(context.WithoutCancel(ctx), containerID)
	var stateErr error
	if oldWorkerID == "" {
		stateErr = s.store.MarkFailed(context.WithoutCancel(ctx), workerID, health)
	} else {
		stateErr = s.store.FailReplacement(context.WithoutCancel(ctx), oldWorkerID, workerID, health)
	}
	return errors.Join(primary, stopErr, stateErr)
}

func (s *AuthorityWorkerService) log(operation, principal, profile string, worker AuthorityWorker, result string, err error) {
	if s.audit == nil {
		return
	}
	event := AuditEvent{
		Operation: operation, Principal: principal, Profile: profile, AuthorityWorkerID: worker.WorkerID,
		ProfileVersion: worker.ProfileVersion, PolicyDigest: worker.PolicyDigest, Generation: worker.Generation,
		AssignedSessions: worker.AssignedSessions, ImageDigest: worker.ImageDigest, Status: string(worker.State), Decision: result,
	}
	if err != nil {
		event.Error = err.Error()
	}
	s.audit.Log(event, NewRedactor(nil))
}
