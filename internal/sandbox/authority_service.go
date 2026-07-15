package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

type AuthorityWorkerSpec struct {
	WorkerID         string
	Profile          string
	ProfileVersion   string
	PolicyDigest     string
	Image            string
	Resources        Resources
	Network          NetworkPolicy
	BrokerAgentID    string
	BrokerSecretEnv  string
	CredentialBundle string
	Repositories     []string
	BranchPolicy     BranchPolicy
	Operations       []string
	ExtraMounts      []ExtraMount
	SessionCapacity  int
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
}

type AuthorityWorkerService struct {
	cfg     Config
	store   *AuthorityWorkerStore
	runtime AuthorityWorkerRuntime
	audit   *AuditLogger
	now     func() time.Time
	newID   func() (string, error)
}

func NewAuthorityWorkerService(cfg Config, store *AuthorityWorkerStore, runtime AuthorityWorkerRuntime, audit *AuditLogger) *AuthorityWorkerService {
	return &AuthorityWorkerService{
		cfg: cfg, store: store, runtime: runtime, audit: audit,
		now:   func() time.Time { return time.Now().UTC() },
		newID: newRunID,
	}
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
	result, err := s.runtime.Create(ctx, authoritySpec(worker, profile, s.cfg.Networks[profile.NetworkPolicy]))
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
	s.log("authority_worker.health", principal, worker.Profile, worker, decision(err), err)
	return worker, err
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
	result, err := s.runtime.Create(ctx, authoritySpec(replacement, profile, s.cfg.Networks[profile.NetworkPolicy]))
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

func authoritySpec(worker AuthorityWorker, profile AuthorityProfile, network NetworkPolicy) AuthorityWorkerSpec {
	return AuthorityWorkerSpec{WorkerID: worker.WorkerID, Profile: worker.Profile, ProfileVersion: worker.ProfileVersion, PolicyDigest: worker.PolicyDigest, Image: profile.Image, Resources: profile.Resources, Network: network, BrokerAgentID: profile.BrokerAgentID, BrokerSecretEnv: profile.BrokerSecretEnv, CredentialBundle: profile.CredentialBundle, Repositories: append([]string(nil), profile.Repositories...), BranchPolicy: profile.BranchPolicy, Operations: append([]string(nil), profile.Operations...), ExtraMounts: append([]ExtraMount(nil), profile.ExtraMounts...), SessionCapacity: profile.SessionCapacity}
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
