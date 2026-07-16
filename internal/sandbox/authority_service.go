package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
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
	SessionBinding      string `json:"session_binding"`
	PredecessorWorkerID string `json:"predecessor_worker_id"`
	IdempotencyKey      string `json:"idempotency_key"`
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
	workspace, err := s.store.SessionWorkspace(ctx, binding)
	if err != nil {
		return nil, err
	}
	token := strings.TrimSpace(os.Getenv(profile.CoordinatorTokenEnv))
	if token == "" {
		return nil, fmt.Errorf("authority worker coordinator credential is unavailable")
	}
	payload, err := json.Marshal(map[string]any{"version": "agentd/v1", "coordinatorBinding": binding, "authorityBinding": lease.BindingDigest, "workspace": map[string]string{"workspaceRef": workspace.Path}})
	if err != nil {
		return nil, err
	}
	url := "http://sandbox-authority-" + lease.WorkerID + ":8080/v1/sessions"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("agentd session create: %w", err)
	}
	//nolint:errcheck // The response is decoded before return; a close error cannot alter admission state.
	defer resp.Body.Close()
	var result json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("agentd session create rejected")
	}
	return result, nil
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
	WorkerID            string
	Profile             string
	ProfileVersion      string
	PolicyDigest        string
	Image               string
	Platform            string
	Command             []string
	Resources           Resources
	Network             NetworkPolicy
	BrokerAgentID       string
	BrokerSecretEnv     string
	CoordinatorTokenEnv string
	CredentialBundle    string
	CredentialMount     Mount
	Repositories        []string
	BranchPolicy        BranchPolicy
	Operations          []string
	ExtraMounts         []ExtraMount
	SessionIsolation    SessionIsolation
	Checkpoint          CheckpointPolicy
	Storage             AuthorityStorage
	SessionCapacity     int
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

type AuthorityWorkerService struct {
	cfg         Config
	store       *AuthorityWorkerStore
	runtime     AuthorityWorkerRuntime
	audit       *AuditLogger
	now         func() time.Time
	newID       func() (string, error)
	checkpoints *CheckpointStore
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
	lease, err := s.store.Acquire(ctx, principal, request)
	if err != nil {
		return AuthoritySessionAdmission{}, err
	}
	workspace, err := s.store.AllocateSessionWorkspace(ctx, lease, profile.SessionIsolation)
	if err != nil {
		return AuthoritySessionAdmission{}, err
	}
	return AuthoritySessionAdmission{Lease: lease, Workspace: workspace}, nil
}

func NewAuthorityWorkerService(cfg Config, store *AuthorityWorkerStore, runtime AuthorityWorkerRuntime, audit *AuditLogger) *AuthorityWorkerService {
	return &AuthorityWorkerService{
		cfg: cfg, store: store, runtime: runtime, audit: audit,
		now:   func() time.Time { return time.Now().UTC() },
		newID: newRunID,
	}
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
	for _, worker := range workers {
		if _, err := s.authorize(principal, worker.Profile, "health"); err != nil {
			return err
		}
		if worker.ContainerID == "" {
			continue
		}
		healthy, evidence, inspectErr := s.runtime.Healthy(ctx, worker.ContainerID)
		if inspectErr != nil {
			healthy, evidence = false, "runtime_inspect_failed"
		}
		if healthy {
			if _, err := s.SetHealth(ctx, principal, worker.WorkerID, evidence, true); err != nil {
				return err
			}
			continue
		}
		if s.checkpoints != nil {
			if err := s.checkpoints.CheckpointWorker(ctx, worker); err != nil {
				return err
			}
		}
		if _, err := s.SetHealth(ctx, principal, worker.WorkerID, evidence, false); err != nil {
			return err
		}
		if _, err := s.Replace(ctx, principal, worker.WorkerID, "runtime_unhealthy"); err != nil {
			return err
		}
	}
	replacements, err := s.store.ReadyReplacementWorkersWithDrainedPredecessors(ctx)
	if err != nil {
		return err
	}
	for _, replacementWorkerID := range replacements {
		if err := s.retireDrainedPredecessor(ctx, replacementWorkerID); err != nil {
			return err
		}
	}
	return nil
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
	profileVersion, policyDigest, err := authorityProfileDigest(profileName, profile)
	if err != nil {
		return AuthorityWorker{}, err
	}
	workerID, err := s.newID()
	if err != nil {
		return AuthorityWorker{}, err
	}
	worker := AuthorityWorker{WorkerID: workerID, Profile: profileName, ProfileVersion: profileVersion, PolicyDigest: policyDigest, ImageReference: profile.Image, Generation: 1, State: AuthorityWorkerProvisioning, Capacity: profile.SessionCapacity}
	worker, err = s.store.CreateWorker(ctx, worker, profile.MaxWorkers)
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
	if _, err := s.authorize(principal, request.Profile, "acquire"); err != nil {
		s.log("authority_worker.acquire", principal, request.Profile, AuthorityWorker{}, "deny", err)
		return AuthorityLease{}, err
	}
	if err := validateAuthorityRequest(request); err != nil {
		s.log("authority_worker.acquire", principal, request.Profile, AuthorityWorker{}, "deny", err)
		return AuthorityLease{}, err
	}
	lease, err := s.store.Acquire(ctx, principal, request)
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
	reassignment, err := s.store.Reassign(ctx, principal, request.SessionBinding, request.PredecessorWorkerID, request.IdempotencyKey)
	if err == nil {
		// Runtime retirement is intentionally after the durable cutover. A crash
		// here leaves a draining zero-lease predecessor that Reconcile can retire.
		if retireErr := s.retireDrainedPredecessor(ctx, reassignment.ReplacementWorkerID); retireErr != nil {
			err = retireErr
		}
	}
	worker := AuthorityWorker{WorkerID: reassignment.ReplacementWorkerID, Profile: lease.Profile}
	s.log("authority_worker.reassign", principal, lease.Profile, worker, decision(err), err)
	return reassignment, err
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
	newID, err := s.newID()
	if err != nil {
		return AuthorityWorker{}, err
	}
	profileVersion, policyDigest, err := authorityProfileDigest(old.Profile, profile)
	if err != nil {
		return AuthorityWorker{}, err
	}
	replacement := AuthorityWorker{WorkerID: newID, Profile: old.Profile, ProfileVersion: profileVersion, PolicyDigest: policyDigest, ImageReference: profile.Image, Generation: old.Generation + 1, State: AuthorityWorkerProvisioning, Capacity: profile.SessionCapacity, DrainReason: reason}
	replacement, created, err := s.store.LinkReplacement(ctx, old.WorkerID, replacement, profile.MaxWorkers)
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
	if strings.TrimSpace(request.IdempotencyKey) == "" || len(request.IdempotencyKey) > 256 {
		return fmt.Errorf("idempotency_key is required and must be at most 256 bytes")
	}
	return nil
}

func authoritySpec(worker AuthorityWorker, profile AuthorityProfile, cfg Config) AuthorityWorkerSpec {
	spec := AuthorityWorkerSpec{WorkerID: worker.WorkerID, Profile: worker.Profile, ProfileVersion: worker.ProfileVersion, PolicyDigest: worker.PolicyDigest, Image: profile.Image, Platform: profile.Platform, Command: append([]string(nil), profile.Command...), Resources: profile.Resources, Network: cfg.Networks[profile.NetworkPolicy], BrokerAgentID: profile.BrokerAgentID, BrokerSecretEnv: profile.BrokerSecretEnv, CoordinatorTokenEnv: profile.CoordinatorTokenEnv, CredentialBundle: profile.CredentialBundle, Repositories: append([]string(nil), profile.Repositories...), BranchPolicy: profile.BranchPolicy, Operations: append([]string(nil), profile.Operations...), ExtraMounts: append([]ExtraMount(nil), profile.ExtraMounts...), SessionIsolation: profile.SessionIsolation, Checkpoint: profile.Checkpoint, Storage: profile.Storage, SessionCapacity: profile.SessionCapacity}
	if bundle, ok := cfg.Bundles[profile.CredentialBundle]; ok {
		spec.CredentialMount = Mount{Source: bundle.SourcePath, Target: bundle.MountPath, ReadOnly: bundle.ReadOnly}
	}
	return spec
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
