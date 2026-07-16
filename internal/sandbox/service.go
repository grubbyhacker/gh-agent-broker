package sandbox

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	StatusPending  = "pending"
	StatusRunning  = "running"
	StatusStopped  = "stopped"
	StatusFailed   = "failed"
	StatusTimedOut = "timed_out"
	StatusCleaned  = "cleaned"
)

const (
	finalizeReasonWorkerExit                = "worker_exit"
	finalizeReasonStatusPollExited          = "status_poll_exited"
	finalizeReasonStatusPollDeadline        = "status_poll_deadline"
	finalizeReasonReconcileExited           = "reconcile_exited"
	finalizeReasonReconcileDeadline         = "reconcile_deadline"
	finalizeReasonReconcileMissing          = "reconcile_container_missing"
	finalizeReasonDeadline                  = "deadline"
	finalizeReasonDeadlineAlreadyExited     = "deadline_already_exited"
	finalizeReasonDeadlineStopAlreadyExited = "deadline_stop_already_exited"
	finalizeReasonDeadlineStopFailed        = "deadline_stop_failed"
	finalizeReasonManualStop                = "manual_stop"
	finalizeReasonLaunchCreateFailed        = "launch_create_failed"
	finalizeReasonLaunchStartFailed         = "launch_start_failed"

	terminalSourceExited         = "exited"
	terminalSourceTimedOut       = "timed_out"
	terminalSourceManualStop     = "manual_stop"
	terminalSourceStartupFailure = "startup_failure"
)

type Service struct {
	cfg                 Config
	runtime             RuntimeBackend
	audit               *AuditLogger
	mu                  sync.Mutex
	runs                map[string]*RunMetadata
	finalizing          map[string]chan struct{}
	profileReservations map[string]int
	launchIntents       *LaunchIntentStore
	intentLocksMu       sync.Mutex
	intentLocks         map[string]*intentLock
}

type intentLock struct {
	mu   sync.Mutex
	refs int
}

type launchValidationError struct{ err error }

func (e *launchValidationError) Error() string { return e.err.Error() }
func (e *launchValidationError) Unwrap() error { return e.err }

type pathPermissionFixer interface {
	MakeRemovable(ctx context.Context, image, path string) error
}

type runtimeFileWriter interface {
	WriteFile(ctx context.Context, image string, mounts []Mount, path string, contents []byte) error
}

type RunMetadata struct {
	RunID                string         `json:"run_id"`
	Profile              string         `json:"profile,omitempty"`
	Principal            string         `json:"principal,omitempty"`
	IdempotencyKeyDigest string         `json:"idempotency_key_digest,omitempty"`
	RequestFingerprint   string         `json:"request_fingerprint,omitempty"`
	LaunchConfigVersion  string         `json:"launch_config_version,omitempty"`
	Template             string         `json:"template"`
	Repo                 string         `json:"repo"`
	BaseBranch           string         `json:"base_branch"`
	Branch               string         `json:"branch"`
	Task                 string         `json:"task"`
	Focus                string         `json:"focus,omitempty"`
	WorkerAgentID        string         `json:"worker_agent_id"`
	BrokerAgentID        string         `json:"broker_agent_id"`
	CredentialBundle     string         `json:"credential_bundle,omitempty"`
	ContainerID          string         `json:"container_id,omitempty"`
	Image                string         `json:"image"`
	ImageDigest          string         `json:"image_digest,omitempty"`
	Status               string         `json:"status"`
	ExitCode             *int           `json:"exit_code,omitempty"`
	FinalizeReason       string         `json:"finalize_reason,omitempty"`
	TerminalSource       string         `json:"terminal_source,omitempty"`
	Error                string         `json:"error,omitempty"`
	Deliverables         []string       `json:"deliverables,omitempty"`
	Parameters           map[string]any `json:"parameters,omitempty"`
	StartedAt            time.Time      `json:"started_at"`
	Deadline             time.Time      `json:"deadline"`
	EndedAt              time.Time      `json:"ended_at,omitempty"`
}

type TaskContract struct {
	RunID           string         `json:"run_id"`
	Task            string         `json:"task"`
	Focus           string         `json:"focus,omitempty"`
	Repo            string         `json:"repo"`
	BaseBranch      string         `json:"base_branch"`
	Branch          string         `json:"branch"`
	WorkerAgentID   string         `json:"worker_agent_id"`
	BrokerRemoteURL string         `json:"broker_remote_url"`
	Deliverables    []string       `json:"deliverables,omitempty"`
	Parameters      map[string]any `json:"parameters,omitempty"`
}

type LaunchAgentInput struct {
	Template          string         `json:"template" yaml:"template" jsonschema:"sandbox template name"`
	Task              string         `json:"task" yaml:"task" jsonschema:"worker task description"`
	Repo              string         `json:"repo" yaml:"repo" jsonschema:"owner/repo repository"`
	BaseBranch        string         `json:"base_branch" yaml:"base_branch" jsonschema:"base branch"`
	Branch            string         `json:"branch,omitempty" yaml:"branch,omitempty" jsonschema:"optional branch; generated when omitted"`
	MaxRuntimeMinutes int            `json:"max_runtime_minutes,omitempty" yaml:"max_runtime_minutes,omitempty" jsonschema:"optional runtime cap within the template maximum"`
	MaxRuntimeSeconds int            `json:"max_runtime_seconds,omitempty" yaml:"max_runtime_seconds,omitempty" jsonschema:"optional shorter runtime cap within the template maximum"`
	Deliverables      []string       `json:"deliverables,omitempty" yaml:"deliverables,omitempty" jsonschema:"optional expected deliverable names"`
	Focus             string         `json:"focus,omitempty" yaml:"focus,omitempty" jsonschema:"optional constrained focus for the worker"`
	Parameters        map[string]any `json:"parameters,omitempty" yaml:"-" jsonschema:"broker-resolved opaque profile parameters"`
	Profile           string         `json:"-" yaml:"-"`
}

func (in *LaunchAgentInput) UnmarshalJSON(b []byte) error {
	type launchAgentInput LaunchAgentInput
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	allowed := map[string]bool{
		"template":            true,
		"task":                true,
		"repo":                true,
		"base_branch":         true,
		"branch":              true,
		"max_runtime_minutes": true,
		"max_runtime_seconds": true,
		"deliverables":        true,
		"focus":               true,
		"parameters":          true,
	}
	for key := range raw {
		if !allowed[key] {
			return fmt.Errorf("launch_agent does not accept caller-supplied %q", key)
		}
	}
	var decoded launchAgentInput
	if err := json.Unmarshal(b, &decoded); err != nil {
		return err
	}
	*in = LaunchAgentInput(decoded)
	return nil
}

type LaunchAgentOutput struct {
	RunID         string    `json:"run_id"`
	WorkerAgentID string    `json:"worker_agent_id"`
	Repo          string    `json:"repo"`
	Branch        string    `json:"branch"`
	Status        string    `json:"status"`
	Deadline      time.Time `json:"deadline"`
	Replay        bool      `json:"replay"`
}

type LaunchPreviewOutput struct {
	Profile          string              `json:"profile,omitempty"`
	Principal        string              `json:"principal,omitempty"`
	ConfigLoadedAt   time.Time           `json:"config_loaded_at"`
	ConfigVersion    string              `json:"config_version"`
	Request          LaunchAgentInput    `json:"request"`
	TaskContract     TaskContract        `json:"task_contract"`
	Template         TemplatePreview     `json:"template"`
	Budgets          LaunchPreviewBudget `json:"budgets"`
	AllowedActions   []string            `json:"allowed_actions,omitempty"`
	AllowedMutations []string            `json:"allowed_mutations"`
}

type TemplatePreview struct {
	Image            string    `json:"image"`
	Command          []string  `json:"command,omitempty"`
	User             string    `json:"user"`
	NetworkPolicy    string    `json:"network_policy"`
	CredentialBundle string    `json:"credential_bundle,omitempty"`
	BrokerAgentID    string    `json:"broker_agent_id"`
	Resources        Resources `json:"resources"`
}

type LaunchPreviewBudget struct {
	RuntimeSeconds int64     `json:"runtime_seconds"`
	Resources      Resources `json:"resources"`
}

type ValidateTemplateInput struct {
	Template string `json:"template"`
}

type TemplateOutput struct {
	Template string `json:"template"`
	Valid    bool   `json:"valid"`
}

type RunInput struct {
	RunID string `json:"run_id"`
}

type LogsInput struct {
	RunID    string `json:"run_id"`
	MaxBytes int    `json:"max_bytes,omitempty"`
}

type LogsOutput struct {
	RunID string `json:"run_id"`
	Logs  string `json:"logs"`
}

type StatusOutput struct {
	RunID       string              `json:"run_id"`
	Status      string              `json:"status"`
	Branch      string              `json:"branch,omitempty"`
	Repo        string              `json:"repo,omitempty"`
	ExitCode    *int                `json:"exit_code,omitempty"`
	Error       string              `json:"error,omitempty"`
	Deadline    time.Time           `json:"deadline,omitempty"`
	EndedAt     *time.Time          `json:"ended_at,omitempty"`
	Diagnostics *FailureDiagnostics `json:"diagnostics,omitempty"`
}

type FailureDiagnostics struct {
	Source              string   `json:"source"`
	Status              string   `json:"status,omitempty"`
	ExitCode            *int     `json:"exit_code,omitempty"`
	Message             string   `json:"message"`
	MissingDeliverables []string `json:"missing_deliverables,omitempty"`
}

type ListAgentsOutput struct {
	Runs []StatusOutput `json:"runs"`
}

func NewService(cfg Config, runtime RuntimeBackend, auditLog *AuditLogger) *Service {
	return NewServiceWithLaunchIntents(cfg, runtime, auditLog, nil)
}

func NewServiceWithLaunchIntents(cfg Config, runtime RuntimeBackend, auditLog *AuditLogger, store *LaunchIntentStore) *Service {
	cfg.ApplyDefaults()
	if cfg.ConfigLoadedAt.IsZero() || cfg.ConfigVersion == "" {
		cfg.StampLoaded(time.Now().UTC())
	}
	return &Service{
		cfg:                 cfg,
		runtime:             runtime,
		audit:               auditLog,
		runs:                map[string]*RunMetadata{},
		finalizing:          map[string]chan struct{}{},
		profileReservations: map[string]int{},
		launchIntents:       store,
		intentLocks:         map[string]*intentLock{},
	}
}

func (s *Service) Reconcile(ctx context.Context) error {
	entries, err := os.ReadDir(s.cfg.RunsDir)
	if err != nil {
		if os.IsNotExist(err) {
			if err := os.MkdirAll(s.cfg.RunsDir, 0o700); err != nil {
				return err
			}
			entries = nil
		} else {
			return err
		}
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		meta, err := readMetadata(filepath.Join(s.cfg.RunsDir, entry.Name(), "metadata.json"))
		if err != nil {
			continue
		}
		if s.launchIntents != nil {
			if err := s.launchIntents.RestoreMetadata(ctx, meta); err != nil {
				return fmt.Errorf("reconstruct launch intent index from run %q: %w", meta.RunID, err)
			}
		}
		if meta.ContainerID != "" && meta.Status == StatusRunning {
			status, err := s.runtime.Inspect(ctx, meta.ContainerID)
			if err != nil {
				finalized, _, finalizeErr := s.finalizeTerminalRun(ctx, meta.RunID, finalizeReasonReconcileMissing, terminalSourceStartupFailure, func(current RunMetadata) RunMetadata {
					current.Status = StatusFailed
					current.TerminalSource = terminalSourceStartupFailure
					current.Error = "container missing during startup reconciliation"
					current.EndedAt = time.Now().UTC()
					return current
				})
				if finalizeErr != nil {
					return finalizeErr
				}
				meta = finalized
			} else if !status.Running {
				finalized, _, err := s.finalizeTerminalRun(ctx, meta.RunID, finalizeReasonReconcileExited, terminalSourceExited, func(current RunMetadata) RunMetadata {
					return s.finalizeExitedRun(ctx, current, status)
				})
				if err != nil {
					return err
				}
				meta = finalized
			} else if time.Now().After(meta.Deadline) {
				finalized, _, err := s.finalizeTerminalRun(ctx, meta.RunID, finalizeReasonReconcileDeadline, terminalSourceTimedOut, func(current RunMetadata) RunMetadata {
					return s.markTimedOut(ctx, current)
				})
				if err != nil {
					return err
				}
				meta = finalized
			}
		}
		s.mu.Lock()
		cp := meta
		s.runs[meta.RunID] = &cp
		s.mu.Unlock()
		if meta.Status == StatusRunning {
			durable := false
			if s.launchIntents != nil {
				durable, err = s.launchIntents.IsNonterminalRun(ctx, meta.RunID)
				if err != nil {
					return fmt.Errorf("identify durable run %q: %w", meta.RunID, err)
				}
			}
			if !durable {
				go s.watchTimeout(context.WithoutCancel(ctx), meta.RunID, meta.Deadline)
				if meta.ContainerID != "" {
					go s.watchExit(context.WithoutCancel(ctx), meta.RunID, meta.ContainerID)
				}
			}
		}
	}
	if err := s.reconcileLaunchIntents(ctx); err != nil {
		return fmt.Errorf("reconcile durable launch intents: %w", err)
	}
	return nil
}

func (s *Service) DryRunLaunch(ctx context.Context, in LaunchAgentInput) (LaunchAgentOutput, error) {
	_ = ctx
	tmpl, runID, branch, runtimeLimit, err := s.validateLaunch(in)
	if err != nil {
		s.auditDeny("dry_run_launch", in, err)
		return LaunchAgentOutput{}, err
	}
	now := time.Now().UTC()
	deadline := now.Add(runtimeLimit)
	meta := RunMetadata{
		RunID:            runID,
		Profile:          in.Profile,
		Template:         in.Template,
		Repo:             in.Repo,
		BaseBranch:       in.BaseBranch,
		Branch:           branch,
		Task:             in.Task,
		Focus:            in.Focus,
		WorkerAgentID:    workerAgentID(tmpl, runID),
		BrokerAgentID:    tmpl.BrokerAgentID,
		CredentialBundle: tmpl.CredentialBundle,
		Image:            tmpl.Image,
		Status:           StatusPending,
		Deliverables:     deliverables(in.Deliverables, tmpl.Deliverables),
		Parameters:       cloneParameters(in.Parameters),
		StartedAt:        now,
		Deadline:         deadline,
	}
	if err := s.validateTaskContract(s.taskContract(meta)); err != nil {
		s.auditDeny("dry_run_launch", in, err)
		return LaunchAgentOutput{}, err
	}
	return LaunchAgentOutput{
		RunID:         runID,
		WorkerAgentID: workerAgentID(tmpl, runID),
		Repo:          in.Repo,
		Branch:        branch,
		Status:        StatusPending,
		Deadline:      deadline,
	}, nil
}

func (s *Service) PreviewLaunch(ctx context.Context, in LaunchAgentInput) (LaunchPreviewOutput, error) {
	_ = ctx
	tmpl, runID, branch, runtimeLimit, err := s.validateLaunch(in)
	if err != nil {
		return LaunchPreviewOutput{}, err
	}
	now := time.Now().UTC()
	meta := RunMetadata{
		RunID:            runID,
		Profile:          in.Profile,
		Template:         in.Template,
		Repo:             in.Repo,
		BaseBranch:       in.BaseBranch,
		Branch:           branch,
		Task:             in.Task,
		Focus:            in.Focus,
		WorkerAgentID:    workerAgentID(tmpl, runID),
		BrokerAgentID:    tmpl.BrokerAgentID,
		CredentialBundle: tmpl.CredentialBundle,
		Image:            tmpl.Image,
		Status:           StatusPending,
		Deliverables:     deliverables(in.Deliverables, tmpl.Deliverables),
		Parameters:       cloneParameters(in.Parameters),
		StartedAt:        now,
		Deadline:         now.Add(runtimeLimit),
	}
	contract := s.taskContract(meta)
	if err := s.validateTaskContract(contract); err != nil {
		return LaunchPreviewOutput{}, err
	}
	return LaunchPreviewOutput{
		ConfigLoadedAt: s.cfg.ConfigLoadedAt,
		ConfigVersion:  s.cfg.ConfigVersion,
		Request:        in,
		TaskContract:   contract,
		Template: TemplatePreview{
			Image:            tmpl.Image,
			Command:          append([]string(nil), tmpl.Command...),
			User:             tmpl.User,
			NetworkPolicy:    tmpl.NetworkPolicy,
			CredentialBundle: tmpl.CredentialBundle,
			BrokerAgentID:    tmpl.BrokerAgentID,
			Resources:        tmpl.Resources,
		},
		Budgets: LaunchPreviewBudget{
			RuntimeSeconds: int64(runtimeLimit / time.Second),
			Resources:      tmpl.Resources,
		},
		AllowedMutations: []string{},
	}, nil
}

func (s *Service) LaunchAgent(ctx context.Context, in LaunchAgentInput) (LaunchAgentOutput, error) {
	return s.launchAgent(ctx, "", in)
}

func (s *Service) launchAgent(ctx context.Context, principal string, in LaunchAgentInput) (LaunchAgentOutput, error) {
	tmpl, runID, branch, runtimeLimit, err := s.validateLaunch(in)
	if err != nil {
		s.auditDeny("launch_agent", in, err)
		return LaunchAgentOutput{}, &launchValidationError{err: err}
	}
	releaseProfileSlot, err := s.acquireProfileSlot(in.Profile)
	if err != nil {
		s.auditDeny("launch_agent", in, err)
		return LaunchAgentOutput{}, err
	}
	defer releaseProfileSlot()
	now := time.Now().UTC()
	deadline := now.Add(runtimeLimit)
	meta := RunMetadata{
		RunID:            runID,
		Profile:          in.Profile,
		Principal:        principal,
		Template:         in.Template,
		Repo:             in.Repo,
		BaseBranch:       in.BaseBranch,
		Branch:           branch,
		Task:             in.Task,
		Focus:            in.Focus,
		WorkerAgentID:    workerAgentID(tmpl, runID),
		BrokerAgentID:    tmpl.BrokerAgentID,
		CredentialBundle: tmpl.CredentialBundle,
		Image:            tmpl.Image,
		Status:           StatusPending,
		Deliverables:     deliverables(in.Deliverables, tmpl.Deliverables),
		Parameters:       cloneParameters(in.Parameters),
		StartedAt:        now,
		Deadline:         deadline,
	}
	if err := s.validateTaskContract(s.taskContract(meta)); err != nil {
		return LaunchAgentOutput{}, &launchValidationError{err: err}
	}
	runDir := s.runDir(runID)
	//nolint:gosec // G301: artifact readers need traverse-only access to /output while logs stay private.
	if err := os.MkdirAll(runDir, 0o711); err != nil {
		return LaunchAgentOutput{}, err
	}
	//nolint:gosec // G302: preserve execute-only traversal if an existing run dir was created more narrowly.
	//nolint:gosec // G302: artifact readers need traverse-only access while run files retain stricter modes.
	if err := os.Chmod(runDir, 0o711); err != nil {
		return LaunchAgentOutput{}, err
	}
	for _, dir := range []struct {
		name string
		mode os.FileMode
	}{
		{name: "input", mode: 0o755},
		{name: "work", mode: 0o777},
		{name: "output", mode: 0o777},
		{name: "lessons", mode: 0o777},
		{name: "logs", mode: 0o700},
	} {
		if err := os.MkdirAll(filepath.Join(runDir, dir.name), dir.mode); err != nil {
			return LaunchAgentOutput{}, err
		}
		if err := os.Chmod(filepath.Join(runDir, dir.name), dir.mode); err != nil {
			return LaunchAgentOutput{}, err
		}
	}
	if err := copyKnowledgeSnapshots(tmpl.KnowledgeSnapshots, filepath.Join(runDir, "input")); err != nil {
		return LaunchAgentOutput{}, err
	}
	if err := s.writeTaskInputs(meta); err != nil {
		return LaunchAgentOutput{}, err
	}
	spec, redactor, err := s.runtimeSpec(meta, tmpl)
	if err != nil {
		return LaunchAgentOutput{}, err
	}
	createStarted := time.Now()
	info, err := s.runtime.Create(ctx, spec)
	s.logSandboxCreation(meta, time.Since(createStarted), err)
	if err != nil {
		s.auditLifecycle(meta, "create_failed", nil, err)
		meta.Status = StatusFailed
		meta.FinalizeReason = finalizeReasonLaunchCreateFailed
		meta.TerminalSource = terminalSourceStartupFailure
		meta.Error = err.Error()
		meta.EndedAt = time.Now().UTC()
		s.writeCompletionStatus(ctx, meta)
		if writeErr := s.writeMetadata(meta); writeErr != nil {
			return LaunchAgentOutput{}, writeErr
		}
		s.audit.Log(s.auditEvent("launch_agent", meta, "deny", err), redactor)
		s.auditTerminalEvent(meta, finalizeReasonLaunchCreateFailed, terminalSourceStartupFailure, err)
		return LaunchAgentOutput{}, err
	}
	meta.ContainerID = info.ID
	meta.ImageDigest = info.ImageDigest
	s.auditLifecycle(meta, "created", nil, nil)
	if err := s.runtime.Start(ctx, info.ID); err != nil {
		s.auditLifecycle(meta, "start_failed", nil, err)
		meta.Status = StatusFailed
		meta.FinalizeReason = finalizeReasonLaunchStartFailed
		meta.TerminalSource = terminalSourceStartupFailure
		meta.Error = err.Error()
		meta.EndedAt = time.Now().UTC()
		s.writeCompletionStatus(ctx, meta)
		if writeErr := s.writeMetadata(meta); writeErr != nil {
			return LaunchAgentOutput{}, writeErr
		}
		s.audit.Log(s.auditEvent("launch_agent", meta, "deny", err), redactor)
		s.auditTerminalEvent(meta, finalizeReasonLaunchStartFailed, terminalSourceStartupFailure, err)
		return LaunchAgentOutput{}, err
	}
	s.auditLifecycle(meta, "started", nil, nil)
	meta.Status = StatusRunning
	if err := s.writeMetadata(meta); err != nil {
		return LaunchAgentOutput{}, err
	}
	s.mu.Lock()
	s.runs[runID] = &meta
	s.mu.Unlock()
	s.audit.Log(s.auditEvent("launch_agent", meta, "allow", nil), redactor)
	go s.watchTimeout(context.WithoutCancel(ctx), runID, deadline)
	go s.watchExit(context.WithoutCancel(ctx), runID, info.ID)
	return LaunchAgentOutput{RunID: runID, WorkerAgentID: meta.WorkerAgentID, Repo: meta.Repo, Branch: meta.Branch, Status: meta.Status, Deadline: meta.Deadline}, nil
}

func (s *Service) LaunchProfile(ctx context.Context, principal, profile, rawKey, fingerprint string, in LaunchAgentInput) (LaunchAgentOutput, error) {
	if rawKey == "" {
		return s.launchAgent(ctx, principal, in)
	}
	if s.launchIntents == nil {
		return LaunchAgentOutput{}, fmt.Errorf("durable launch intent store is unavailable")
	}
	digest := s.launchIntents.digestKey(rawKey)
	unlock := s.lockLaunchIntent(principal + "\x00" + profile + "\x00" + digest)
	defer unlock()

	intent, found, err := s.launchIntents.Lookup(ctx, principal, profile, digest)
	if err != nil {
		return LaunchAgentOutput{}, err
	}
	if found {
		if intent.RequestFingerprint != fingerprint {
			return LaunchAgentOutput{}, &intentConflictError{
				Code:    "idempotency_conflict",
				Message: "Idempotency-Key was already used for a different canonical request",
			}
		}
		out, err := s.resumeLaunchIntent(ctx, &intent, false)
		out.Replay = true
		return out, err
	}

	tmpl, runID, branch, runtimeLimit, err := s.validateLaunch(in)
	if err != nil {
		return LaunchAgentOutput{}, &launchValidationError{err: err}
	}
	now := time.Now().UTC()
	meta := RunMetadata{
		RunID: runID, Profile: profile, Principal: principal, IdempotencyKeyDigest: digest,
		RequestFingerprint: fingerprint, LaunchConfigVersion: s.cfg.ConfigVersion,
		Template: in.Template, Repo: in.Repo, BaseBranch: in.BaseBranch,
		Branch: branch, Task: in.Task, Focus: in.Focus, WorkerAgentID: workerAgentID(tmpl, runID),
		BrokerAgentID: tmpl.BrokerAgentID, CredentialBundle: tmpl.CredentialBundle, Image: tmpl.Image,
		Status: StatusPending, Deliverables: deliverables(in.Deliverables, tmpl.Deliverables),
		Parameters: cloneParameters(in.Parameters), StartedAt: now, Deadline: now.Add(runtimeLimit),
	}
	if err := s.validateTaskContract(s.taskContract(meta)); err != nil {
		return LaunchAgentOutput{}, &launchValidationError{err: err}
	}
	intent = launchIntent{
		Principal: principal, Profile: profile, KeyDigest: digest, RequestFingerprint: fingerprint,
		RunID: runID, State: intentStateCreated, Metadata: meta,
		Plan: launchIntentPlan{Version: 1, ConfigVersion: s.cfg.ConfigVersion, Request: in, RuntimeSeconds: int64(runtimeLimit / time.Second), Metadata: meta},
	}
	maxConcurrent := s.cfg.LaunchProfiles[profile].MaxConcurrentRuns
	persisted, created, err := s.launchIntents.Create(ctx, intent, maxConcurrent)
	if err != nil {
		return LaunchAgentOutput{}, err
	}
	if !created {
		if persisted.RequestFingerprint != fingerprint {
			return LaunchAgentOutput{}, &intentConflictError{Code: "idempotency_conflict", Message: "Idempotency-Key was already used for a different canonical request"}
		}
		intent = persisted
	}
	out, err := s.resumeLaunchIntent(ctx, &intent, false)
	out.Replay = !created
	return out, err
}

func (s *Service) reconcileLaunchIntents(ctx context.Context) error {
	if s.launchIntents == nil {
		return nil
	}
	intents, err := s.launchIntents.Nonterminal(ctx)
	if err != nil {
		return err
	}
	for i := range intents {
		if intents[i].Plan.ConfigVersion != s.cfg.ConfigVersion {
			return fmt.Errorf("incomplete launch intent %q was resolved with config version %q, current version is %q", intents[i].RunID, intents[i].Plan.ConfigVersion, s.cfg.ConfigVersion)
		}
		if _, err := s.resumeLaunchIntent(ctx, &intents[i], true); err != nil {
			return fmt.Errorf("recover launch intent %q: %w", intents[i].RunID, err)
		}
	}
	return nil
}

func (s *Service) resumeLaunchIntent(ctx context.Context, intent *launchIntent, recovering bool) (LaunchAgentOutput, error) {
	if intent.Plan.ConfigVersion != s.cfg.ConfigVersion {
		return LaunchAgentOutput{}, fmt.Errorf("launch intent config version mismatch")
	}
	meta := intent.Metadata
	if isTerminalStatus(meta.Status) || intent.State == intentStateTerminal {
		return launchOutput(meta), nil
	}
	tmpl, ok := s.cfg.Templates[meta.Template]
	if !ok {
		return LaunchAgentOutput{}, fmt.Errorf("launch intent references unknown template %q", meta.Template)
	}
	if intent.State == intentStateRunning {
		s.mu.Lock()
		cp := meta
		s.runs[meta.RunID] = &cp
		s.mu.Unlock()
		if meta.ContainerID != "" {
			status, err := s.runtime.Inspect(ctx, meta.ContainerID)
			if err != nil {
				return LaunchAgentOutput{}, err
			}
			if !status.Running {
				finalized, _, err := s.finalizeTerminalRun(ctx, meta.RunID, finalizeReasonReconcileExited, terminalSourceExited, func(current RunMetadata) RunMetadata {
					return s.finalizeExitedRun(ctx, current, status)
				})
				return launchOutput(finalized), err
			}
		}
		if recovering {
			go s.watchTimeout(context.WithoutCancel(ctx), meta.RunID, meta.Deadline)
			if meta.ContainerID != "" {
				go s.watchExit(context.WithoutCancel(ctx), meta.RunID, meta.ContainerID)
			}
		}
		return launchOutput(meta), nil
	}
	if err := s.prepareDurableRun(meta, tmpl); err != nil {
		return LaunchAgentOutput{}, err
	}
	spec, redactor, err := s.runtimeSpec(meta, tmpl)
	if err != nil {
		return LaunchAgentOutput{}, err
	}
	var info ContainerInfo
	if intent.State == intentStateContainerMade || intent.State == intentStateStartPending {
		status, inspectErr := s.runtime.Inspect(ctx, meta.ContainerID)
		if inspectErr != nil {
			return LaunchAgentOutput{}, fmt.Errorf("inspect persisted sandbox container %q: %w", meta.ContainerID, inspectErr)
		}
		lifecycle := ContainerExited
		if status.StartedAt.IsZero() {
			lifecycle = ContainerNeverStarted
		} else if status.Running {
			lifecycle = ContainerRunning
		}
		info = ContainerInfo{ID: meta.ContainerID, ImageDigest: meta.ImageDigest, Existing: true, Lifecycle: lifecycle, Status: status}
	} else {
		intent.State = intentStateCreatePending
		if err := s.launchIntents.Save(ctx, *intent); err != nil {
			return LaunchAgentOutput{}, err
		}
		createStarted := time.Now()
		info, err = s.runtime.Create(ctx, spec)
		s.logSandboxCreation(meta, time.Since(createStarted), err)
		if err != nil {
			s.auditLifecycle(meta, "create_failed", nil, err)
			return LaunchAgentOutput{}, err
		}
		meta.ContainerID = info.ID
		meta.ImageDigest = info.ImageDigest
		s.auditLifecycle(meta, "created", nil, nil)
		intent.Metadata = meta
		intent.State = intentStateContainerMade
		if err := s.launchIntents.Save(ctx, *intent); err != nil {
			return LaunchAgentOutput{}, err
		}
	}
	if info.Lifecycle == ContainerRunning {
		return s.commitRunningIntent(ctx, intent, meta, redactor)
	}
	if info.Lifecycle == ContainerExited {
		return s.commitExitedIntent(ctx, intent, meta, info.Status)
	}
	intent.State = intentStateStartPending
	intent.Metadata = meta
	if err := s.launchIntents.Save(ctx, *intent); err != nil {
		return LaunchAgentOutput{}, err
	}
	if err := s.runtime.Start(ctx, meta.ContainerID); err != nil {
		s.auditLifecycle(meta, "start_failed", nil, err)
		status, inspectErr := s.runtime.Inspect(ctx, meta.ContainerID)
		if inspectErr == nil && status.Running {
			return s.commitRunningIntent(ctx, intent, meta, redactor)
		}
		if inspectErr == nil && !status.StartedAt.IsZero() {
			return s.commitExitedIntent(ctx, intent, meta, status)
		}
		return LaunchAgentOutput{}, err
	}
	s.auditLifecycle(meta, "started", nil, nil)
	return s.commitRunningIntent(ctx, intent, meta, redactor)
}

func (s *Service) prepareDurableRun(meta RunMetadata, tmpl Template) error {
	runDir := s.runDir(meta.RunID)
	//nolint:gosec // G301: artifact readers need traverse-only access to /output while logs stay private.
	if err := os.MkdirAll(runDir, 0o711); err != nil {
		return err
	}
	//nolint:gosec // G302: artifact readers need traverse-only access while run files retain stricter modes.
	if err := os.Chmod(runDir, 0o711); err != nil {
		return err
	}
	for _, dir := range []struct {
		name string
		mode os.FileMode
	}{{"input", 0o755}, {"work", 0o777}, {"output", 0o777}, {"lessons", 0o777}, {"logs", 0o700}} {
		path := filepath.Join(runDir, dir.name)
		if err := os.MkdirAll(path, dir.mode); err != nil {
			return err
		}
		if err := os.Chmod(path, dir.mode); err != nil {
			return err
		}
	}
	if err := copyKnowledgeSnapshots(tmpl.KnowledgeSnapshots, filepath.Join(runDir, "input")); err != nil {
		return err
	}
	if err := s.writeTaskInputs(meta); err != nil {
		return err
	}
	return s.writeMetadataFile(meta)
}

func (s *Service) commitRunningIntent(ctx context.Context, intent *launchIntent, meta RunMetadata, redactor Redactor) (LaunchAgentOutput, error) {
	meta.Status = StatusRunning
	intent.State = intentStateRunning
	intent.Metadata = meta
	if err := s.launchIntents.Save(ctx, *intent); err != nil {
		return LaunchAgentOutput{}, err
	}
	if err := s.writeMetadata(meta); err != nil {
		return LaunchAgentOutput{}, err
	}
	s.auditLifecycle(meta, "running_committed", nil, nil)
	s.audit.Log(s.auditEvent("launch_agent", meta, "allow", nil), redactor)
	go s.watchTimeout(context.WithoutCancel(ctx), meta.RunID, meta.Deadline)
	go s.watchExit(context.WithoutCancel(ctx), meta.RunID, meta.ContainerID)
	return launchOutput(meta), nil
}

func (s *Service) commitExitedIntent(ctx context.Context, intent *launchIntent, meta RunMetadata, status ContainerStatus) (LaunchAgentOutput, error) {
	meta.Status = StatusRunning
	s.mu.Lock()
	cp := meta
	s.runs[meta.RunID] = &cp
	s.mu.Unlock()
	finalized, _, err := s.finalizeTerminalRun(ctx, meta.RunID, finalizeReasonReconcileExited, terminalSourceExited, func(current RunMetadata) RunMetadata {
		return s.finalizeExitedRun(ctx, current, status)
	})
	intent.Metadata = finalized
	intent.State = intentStateTerminal
	if saveErr := s.launchIntents.Save(ctx, *intent); saveErr != nil && err == nil {
		err = saveErr
	}
	return launchOutput(finalized), err
}

func launchOutput(meta RunMetadata) LaunchAgentOutput {
	return LaunchAgentOutput{RunID: meta.RunID, WorkerAgentID: meta.WorkerAgentID, Repo: meta.Repo, Branch: meta.Branch, Status: meta.Status, Deadline: meta.Deadline}
}

func (s *Service) lockLaunchIntent(scope string) func() {
	s.intentLocksMu.Lock()
	lock := s.intentLocks[scope]
	if lock == nil {
		lock = &intentLock{}
		s.intentLocks[scope] = lock
	}
	lock.refs++
	s.intentLocksMu.Unlock()
	lock.mu.Lock()
	return func() {
		lock.mu.Unlock()
		s.intentLocksMu.Lock()
		lock.refs--
		if lock.refs == 0 {
			delete(s.intentLocks, scope)
		}
		s.intentLocksMu.Unlock()
	}
}

func (s *Service) acquireProfileSlot(profile string) (func(), error) {
	if profile == "" {
		return func() {}, nil
	}
	launchProfile, ok := s.cfg.LaunchProfiles[profile]
	if !ok || launchProfile.MaxConcurrentRuns == 0 {
		return func() {}, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	active := 0
	for _, meta := range s.runs {
		if meta.Profile == profile && (meta.Status == StatusPending || meta.Status == StatusRunning) {
			active++
		}
	}
	if active+s.profileReservations[profile] >= launchProfile.MaxConcurrentRuns {
		return nil, &intentConflictError{Code: "profile_busy", Message: fmt.Sprintf("profile %q is busy; maximum concurrent runs is %d", profile, launchProfile.MaxConcurrentRuns)}
	}
	s.profileReservations[profile]++
	return func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.profileReservations[profile] <= 1 {
			delete(s.profileReservations, profile)
			return
		}
		s.profileReservations[profile]--
	}, nil
}

func (s *Service) ValidateTemplate(ctx context.Context, in ValidateTemplateInput) (TemplateOutput, error) {
	_ = ctx
	if strings.TrimSpace(in.Template) == "" {
		return TemplateOutput{}, fmt.Errorf("template is required")
	}
	if _, ok := s.cfg.Templates[in.Template]; !ok {
		return TemplateOutput{}, fmt.Errorf("unknown template %q", in.Template)
	}
	return TemplateOutput{Template: in.Template, Valid: true}, nil
}

func (s *Service) ListAgents(ctx context.Context) (ListAgentsOutput, error) {
	return s.listAgentsForPrincipal(ctx, "", nil, true)
}

func (s *Service) listAgentsForPrincipal(ctx context.Context, principal string, profiles []string, profileScope bool) (ListAgentsOutput, error) {
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()
	out := ListAgentsOutput{Runs: make([]StatusOutput, 0, len(s.runs))}
	for _, meta := range s.runs {
		if profiles != nil && !contains(profiles, meta.Profile) {
			continue
		}
		if !profileScope && meta.Principal != principal {
			continue
		}
		out.Runs = append(out.Runs, s.statusOutput(*meta))
	}
	return out, nil
}

func (s *Service) GetAgentStatus(ctx context.Context, in RunInput) (StatusOutput, error) {
	meta, err := s.lookupRun(in.RunID)
	if err != nil {
		return StatusOutput{}, err
	}
	if meta.ContainerID != "" && meta.Status == StatusRunning {
		status, err := s.runtime.Inspect(ctx, meta.ContainerID)
		if err == nil && status.Running && time.Now().UTC().After(meta.Deadline) {
			finalized, _, err := s.finalizeTerminalRun(ctx, meta.RunID, finalizeReasonStatusPollDeadline, terminalSourceTimedOut, func(current RunMetadata) RunMetadata {
				return s.markTimedOut(ctx, current)
			})
			if err != nil {
				return StatusOutput{}, err
			}
			meta = finalized
		} else if err == nil && !status.Running {
			finalized, _, err := s.finalizeTerminalRun(ctx, meta.RunID, finalizeReasonStatusPollExited, terminalSourceExited, func(current RunMetadata) RunMetadata {
				return s.finalizeExitedRun(ctx, current, status)
			})
			if err != nil {
				return StatusOutput{}, err
			}
			meta = finalized
		}
	}
	return s.statusOutput(meta), nil
}

func (s *Service) GetAgentLogs(ctx context.Context, in LogsInput) (LogsOutput, error) {
	meta, err := s.lookupRun(in.RunID)
	if err != nil {
		return LogsOutput{}, err
	}
	limit := in.MaxBytes
	if limit <= 0 || limit > s.cfg.LogByteLimit {
		limit = s.cfg.LogByteLimit
	}
	logs, err := s.runtime.Logs(ctx, meta.ContainerID, limit)
	if err != nil {
		return LogsOutput{}, err
	}
	return LogsOutput{RunID: meta.RunID, Logs: s.redactor(meta).Redact(logs)}, nil
}

func (s *Service) StopAgent(ctx context.Context, in RunInput) (StatusOutput, error) {
	meta, err := s.lookupRun(in.RunID)
	if err != nil {
		return StatusOutput{}, err
	}
	redactor := s.redactor(meta)
	if meta.ContainerID != "" && meta.Status == StatusRunning {
		if err := s.runtime.Stop(ctx, meta.ContainerID, s.cfg.StopGrace.Duration); err != nil {
			s.audit.Log(s.auditEvent("stop_agent", meta, "deny", err), redactor)
			return StatusOutput{}, err
		}
	}
	if meta.Status == StatusRunning {
		finalized, _, err := s.finalizeTerminalRun(ctx, meta.RunID, finalizeReasonManualStop, terminalSourceManualStop, func(current RunMetadata) RunMetadata {
			if current.ContainerID != "" {
				if status, inspectErr := s.runtime.Inspect(ctx, current.ContainerID); inspectErr == nil && status.ExitCode != nil {
					current.ExitCode = status.ExitCode
					current.EndedAt = status.EndedAt
				}
			}
			current.Status = StatusStopped
			current.FinalizeReason = finalizeReasonManualStop
			current.TerminalSource = terminalSourceManualStop
			if current.EndedAt.IsZero() {
				current.EndedAt = time.Now().UTC()
			}
			current.Error = ""
			return current
		})
		if err != nil {
			return StatusOutput{}, err
		}
		meta = finalized
	}
	s.audit.Log(s.auditEvent("stop_agent", meta, "allow", nil), redactor)
	return s.statusOutput(meta), nil
}

func (s *Service) CollectArtifacts(ctx context.Context, in RunInput) (CollectionOutput, error) {
	_ = ctx
	meta, err := s.lookupRun(in.RunID)
	if err != nil {
		return CollectionOutput{}, err
	}
	return collectFiles(filepath.Join(s.runDir(meta.RunID), "output"), meta.RunID, s.redactor(meta), defaultInlineLimit)
}

func (s *Service) CollectLessons(ctx context.Context, in RunInput) (CollectionOutput, error) {
	_ = ctx
	meta, err := s.lookupRun(in.RunID)
	if err != nil {
		return CollectionOutput{}, err
	}
	return collectFiles(filepath.Join(s.runDir(meta.RunID), "lessons"), meta.RunID, s.redactor(meta), defaultInlineLimit)
}

func (s *Service) CleanupRun(ctx context.Context, in RunInput) (StatusOutput, error) {
	_ = ctx
	meta, err := s.lookupRun(in.RunID)
	if err != nil {
		return StatusOutput{}, err
	}
	runDir := s.runDir(meta.RunID)
	if escapesBase(s.cfg.RunsDir, runDir) {
		return StatusOutput{}, fmt.Errorf("run directory escapes runs_dir")
	}
	if meta.ContainerID != "" {
		if err := s.runtime.Remove(ctx, meta.ContainerID); err != nil {
			return StatusOutput{}, err
		}
	}
	if err := os.RemoveAll(runDir); err != nil {
		if fixer, ok := s.runtime.(pathPermissionFixer); ok {
			if fixErr := fixer.MakeRemovable(ctx, meta.Image, runDir); fixErr == nil {
				err = os.RemoveAll(runDir)
			}
		}
		if err != nil {
			return StatusOutput{}, err
		}
	}
	meta.Status = StatusCleaned
	meta.EndedAt = time.Now().UTC()
	s.mu.Lock()
	delete(s.runs, meta.RunID)
	s.mu.Unlock()
	s.audit.Log(s.auditEvent("cleanup_run", meta, "allow", nil), s.redactor(meta))
	return s.statusOutput(meta), nil
}

func (s *Service) validateLaunch(in LaunchAgentInput) (Template, string, string, time.Duration, error) {
	tmpl, ok := s.cfg.Templates[in.Template]
	if !ok {
		return Template{}, "", "", 0, fmt.Errorf("policy denial: unknown template %q; choose a configured sandbox template", in.Template)
	}
	if !validRepo(in.Repo) {
		return Template{}, "", "", 0, fmt.Errorf("policy denial: repo must be owner/repo; supply an allowed repository such as owner/name")
	}
	if !containsFold(s.cfg.Repositories, in.Repo) {
		return Template{}, "", "", 0, fmt.Errorf("policy denial: repo %q is not allowed; choose one of the configured sandbox repositories", in.Repo)
	}
	if strings.TrimSpace(in.Task) == "" {
		return Template{}, "", "", 0, fmt.Errorf("task is required")
	}
	if len(in.Task) > s.cfg.MaxTaskBytes {
		return Template{}, "", "", 0, fmt.Errorf("policy denial: task exceeds max size %d bytes; shorten the task request", s.cfg.MaxTaskBytes)
	}
	if strings.TrimSpace(in.BaseBranch) == "" {
		return Template{}, "", "", 0, fmt.Errorf("base_branch is required")
	}
	if len(tmpl.BranchPolicy.BaseBranches) > 0 && !contains(tmpl.BranchPolicy.BaseBranches, in.BaseBranch) {
		return Template{}, "", "", 0, fmt.Errorf("policy denial: base_branch %q is not allowed; choose a base branch allowed by the template", in.BaseBranch)
	}
	runID, err := newRunID()
	if err != nil {
		return Template{}, "", "", 0, err
	}
	branch := strings.TrimSpace(in.Branch)
	if branch == "" {
		prefix := tmpl.BranchPolicy.GeneratePrefix
		if prefix == "" {
			prefix = "agent"
		}
		branch = strings.TrimRight(prefix, "/") + "/" + tmpl.BrokerAgentID + "/" + runID
	}
	if !safeBranch(branch) {
		return Template{}, "", "", 0, fmt.Errorf("policy denial: branch %q is unsafe; use a normal Git branch name without traversal, locks, spaces, or ref metacharacters", branch)
	}
	if len(tmpl.BranchPolicy.AllowedPatterns) > 0 && !matchesAny(tmpl.BranchPolicy.AllowedPatterns, branch) {
		return Template{}, "", "", 0, fmt.Errorf("policy denial: branch %q does not match template branch policy; use the configured generated branch or an allowed agent branch", branch)
	}
	runtimeLimit, err := runtimeLimit(in, tmpl)
	if err != nil {
		return Template{}, "", "", 0, err
	}
	return tmpl, runID, branch, runtimeLimit, nil
}

func runtimeLimit(in LaunchAgentInput, tmpl Template) (time.Duration, error) {
	maxRuntime := time.Duration(tmpl.MaxRuntimeMinutes) * time.Minute
	if in.MaxRuntimeMinutes != 0 && in.MaxRuntimeSeconds != 0 {
		return 0, fmt.Errorf("policy denial: set only one of max_runtime_minutes or max_runtime_seconds")
	}
	if in.MaxRuntimeSeconds != 0 {
		if in.MaxRuntimeSeconds < 1 {
			return 0, fmt.Errorf("policy denial: max_runtime_seconds must be positive")
		}
		limit := time.Duration(in.MaxRuntimeSeconds) * time.Second
		if limit > maxRuntime {
			return 0, fmt.Errorf("policy denial: max_runtime_seconds must not exceed template max_runtime_minutes %d; lower the requested runtime", tmpl.MaxRuntimeMinutes)
		}
		return limit, nil
	}
	runtimeMinutes := in.MaxRuntimeMinutes
	if runtimeMinutes == 0 {
		runtimeMinutes = tmpl.MaxRuntimeMinutes
	}
	if runtimeMinutes < 1 || runtimeMinutes > tmpl.MaxRuntimeMinutes {
		return 0, fmt.Errorf("policy denial: max_runtime_minutes must be between 1 and %d; lower the requested runtime", tmpl.MaxRuntimeMinutes)
	}
	return time.Duration(runtimeMinutes) * time.Minute, nil
}

func (s *Service) runtimeSpec(meta RunMetadata, tmpl Template) (RuntimeSpec, Redactor, error) {
	runDir := s.runDir(meta.RunID)
	env := map[string]string{
		"BROKER_URL":          s.cfg.BrokerURL,
		"BROKER_AGENT_ID":     tmpl.BrokerAgentID,
		"BROKER_AGENT_SECRET": tmpl.BrokerAgentSecret,
		"SANDBOX_RUN_ID":      meta.RunID,
		"SANDBOX_REPO":        meta.Repo,
		"SANDBOX_BRANCH":      meta.Branch,
		"SANDBOX_BASE_BRANCH": meta.BaseBranch,
		"HOME":                "/work/home",
		"HERMES_HOME":         "/work/hermes",
	}
	for k, v := range tmpl.Environment {
		if safeEnvKey(k) {
			env[k] = v
		}
	}
	labels := map[string]string{
		"gh-agent-broker.sandbox":  "true",
		"gh-agent-broker.run_id":   meta.RunID,
		"gh-agent-broker.template": meta.Template,
	}
	mounts := []Mount{
		{Source: filepath.Join(runDir, "input"), Target: "/input", ReadOnly: true},
		{Source: filepath.Join(runDir, "work"), Target: "/work", ReadOnly: false},
		{Source: filepath.Join(runDir, "output"), Target: "/output", ReadOnly: false},
		{Source: filepath.Join(runDir, "lessons"), Target: "/lessons", ReadOnly: false},
	}
	redactor := NewRedactor([]string{tmpl.BrokerAgentSecret})
	if tmpl.CredentialBundle != "" {
		bundle := s.cfg.Bundles[tmpl.CredentialBundle]
		if !contains(bundle.AllowedTemplates, meta.Template) {
			return RuntimeSpec{}, redactor, fmt.Errorf("credential bundle %q does not allow template %q", tmpl.CredentialBundle, meta.Template)
		}
		mounts = append(mounts, credentialBundleMount(bundle))
		bundleRedactor := RedactorForBundle(bundle)
		redactor.known = append(redactor.known, bundleRedactor.known...)
	}
	for _, mount := range tmpl.ExtraMounts {
		mounts = append(mounts, Mount{Source: mount.SourcePath, Target: mount.MountPath, ReadOnly: mount.ReadOnly})
	}
	spec := RuntimeSpec{
		RunID:      meta.RunID,
		Image:      tmpl.Image,
		Command:    tmpl.Command,
		User:       tmpl.User,
		Env:        env,
		Labels:     labels,
		Mounts:     mounts,
		Network:    s.cfg.Networks[tmpl.NetworkPolicy],
		Resources:  tmpl.Resources,
		WorkingDir: "/work",
		Timeout:    meta.Deadline.Sub(meta.StartedAt),
	}
	return spec, redactor, nil
}

func (s *Service) lookupRun(runID string) (RunMetadata, error) {
	if !safeRunID(runID) {
		return RunMetadata{}, fmt.Errorf("invalid run_id")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if meta, ok := s.runs[runID]; ok {
		return *meta, nil
	}
	meta, err := readMetadata(filepath.Join(s.runDir(runID), "metadata.json"))
	if err != nil {
		return RunMetadata{}, err
	}
	s.runs[runID] = &meta
	return meta, nil
}

func (s *Service) writeMetadata(meta RunMetadata) error {
	if err := s.writeMetadataFile(meta); err != nil {
		return err
	}
	if s.launchIntents != nil {
		if err := s.launchIntents.SaveMetadata(context.Background(), meta); err != nil {
			return err
		}
	}
	s.mu.Lock()
	cp := meta
	s.runs[meta.RunID] = &cp
	s.mu.Unlock()
	return nil
}

func (s *Service) writeMetadataFile(meta RunMetadata) error {
	path := filepath.Join(s.runDir(meta.RunID), "metadata.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(path, append(b, '\n'), 0o600)
}

func atomicWriteFile(path string, contents []byte, mode os.FileMode) (retErr error) {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".metadata-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() {
		if err := os.Remove(tmpPath); err != nil && !os.IsNotExist(err) {
			retErr = errors.Join(retErr, fmt.Errorf("remove temporary metadata: %w", err))
		}
	}()
	if err := tmp.Chmod(mode); err != nil {
		return errors.Join(err, tmp.Close())
	}
	if _, err := tmp.Write(contents); err != nil {
		return errors.Join(err, tmp.Close())
	}
	if err := tmp.Sync(); err != nil {
		return errors.Join(err, tmp.Close())
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	//nolint:gosec // G304: dir is the configured run metadata directory derived from path.
	dirFile, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer func() { retErr = errors.Join(retErr, dirFile.Close()) }()
	return dirFile.Sync()
}

func (s *Service) writeTaskInputs(meta RunMetadata) error {
	inputDir := filepath.Join(s.runDir(meta.RunID), "input")
	contract := s.taskContract(meta)
	if err := s.validateTaskContract(contract); err != nil {
		return err
	}
	if err := writeJSONFile(filepath.Join(inputDir, "task.json"), contract, 0o644); err != nil {
		return err
	}
	//nolint:gosec // G306: task inputs are mounted read-only and must be readable by the non-root worker.
	if err := os.WriteFile(filepath.Join(inputDir, "task.md"), []byte(strings.TrimSpace(meta.Task)+"\n"), 0o644); err != nil {
		return err
	}
	rules := sandboxRulesMarkdown(contract)
	//nolint:gosec // G306: sandbox rules are mounted read-only and must be readable by the non-root worker.
	return os.WriteFile(filepath.Join(inputDir, "sandbox-rules.md"), []byte(rules), 0o644)
}

func (s *Service) taskContract(meta RunMetadata) TaskContract {
	return TaskContract{
		RunID:           meta.RunID,
		Task:            meta.Task,
		Focus:           meta.Focus,
		Repo:            meta.Repo,
		BaseBranch:      meta.BaseBranch,
		Branch:          meta.Branch,
		WorkerAgentID:   meta.WorkerAgentID,
		BrokerRemoteURL: strings.TrimRight(s.cfg.BrokerURL, "/") + "/git/" + meta.Repo + ".git",
		Deliverables:    append([]string{}, meta.Deliverables...),
		Parameters:      cloneParameters(meta.Parameters),
	}
}

func (s *Service) validateTaskContract(contract TaskContract) error {
	b, err := json.Marshal(contract)
	if err != nil {
		return err
	}
	if len(b) > s.cfg.MaxTaskBytes {
		return fmt.Errorf("policy denial: resolved task contract exceeds max size %d bytes; shorten the task request or parameters", s.cfg.MaxTaskBytes)
	}
	return nil
}

func writeJSONFile(path string, value interface{}, mode os.FileMode) error {
	b, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	//nolint:gosec // G306: task contract is mounted read-only and must be readable by the non-root worker.
	return os.WriteFile(path, append(b, '\n'), mode)
}

func sandboxRulesMarkdown(contract TaskContract) string {
	var b strings.Builder
	b.WriteString("# Sandbox Rules\n\n")
	b.WriteString("These sandbox rules are supplied by the broker wrapper. Follow them before the user task.\n\n")
	b.WriteString("- Work under `/work` unless a task explicitly names `/output` or `/lessons`.\n")
	b.WriteString("- Use `BROKER_URL`, `BROKER_AGENT_ID`, and `BROKER_AGENT_SECRET` only through `gh-agent-broker-cli`, broker Git remotes, or the broker skill.\n")
	b.WriteString("- Do not print, store in artifacts, or otherwise expose broker secrets, provider credentials, authorization headers, GitHub App keys, JWTs, or installation tokens.\n")
	b.WriteString("- Do not push, create pull requests, create issues, or comment unless the user task explicitly asks for that operation. Broker policy remains authoritative.\n")
	b.WriteString("- Write required final artifacts before exiting.\n\n")
	b.WriteString("## Repository Context\n\n")
	fmt.Fprintf(&b, "- Repo: `%s`\n", contract.Repo)
	fmt.Fprintf(&b, "- Base branch: `%s`\n", contract.BaseBranch)
	fmt.Fprintf(&b, "- Sandbox branch: `%s`\n", contract.Branch)
	fmt.Fprintf(&b, "- Broker remote URL: `%s`\n", contract.BrokerRemoteURL)
	b.WriteString("- Repo setup is task-driven. If repository access is needed, initialize or clone using the broker remote and `gh-agent-broker-cli`.\n\n")
	if len(contract.Deliverables) > 0 {
		b.WriteString("## Required Deliverables\n\n")
		for _, deliverable := range contract.Deliverables {
			fmt.Fprintf(&b, "- `%s`\n", deliverable)
		}
		b.WriteString("\n")
	}
	return b.String()
}

func readMetadata(path string) (RunMetadata, error) {
	// #nosec G304 -- path is constrained to a sandbox run metadata file by caller.
	b, err := os.ReadFile(path)
	if err != nil {
		return RunMetadata{}, err
	}
	var meta RunMetadata
	if err := json.Unmarshal(b, &meta); err != nil {
		return RunMetadata{}, err
	}
	return meta, nil
}

func (s *Service) runDir(runID string) string {
	return filepath.Join(filepath.Clean(s.cfg.RunsDir), runID)
}

func (s *Service) redactor(meta RunMetadata) Redactor {
	tmpl := s.cfg.Templates[meta.Template]
	r := NewRedactor([]string{tmpl.BrokerAgentSecret})
	if tmpl.CredentialBundle != "" {
		br := RedactorForBundle(s.cfg.Bundles[tmpl.CredentialBundle])
		r.known = append(r.known, br.known...)
	}
	return r
}

func (s *Service) auditDeny(operation string, in LaunchAgentInput, err error) {
	s.audit.Log(AuditEvent{
		Operation:  operation,
		Template:   in.Template,
		Repo:       in.Repo,
		Branch:     in.Branch,
		Parameters: cloneParameters(in.Parameters),
		Decision:   "deny",
		Error:      err.Error(),
	}, NewRedactor(nil))
}

func (s *Service) auditEvent(operation string, meta RunMetadata, decision string, err error) AuditEvent {
	ev := AuditEvent{
		Operation:        operation,
		RunID:            meta.RunID,
		Template:         meta.Template,
		WorkerAgentID:    meta.WorkerAgentID,
		Repo:             meta.Repo,
		Branch:           meta.Branch,
		ImageDigest:      meta.ImageDigest,
		CredentialBundle: meta.CredentialBundle,
		ContainerID:      meta.ContainerID,
		Parameters:       cloneParameters(meta.Parameters),
		Status:           meta.Status,
		ExitCode:         meta.ExitCode,
		FinalizeReason:   meta.FinalizeReason,
		TerminalSource:   meta.TerminalSource,
		Decision:         decision,
	}
	if err != nil {
		ev.Error = err.Error()
	}
	return ev
}

// auditLifecycle records a bounded, redacted runtime observation. These events
// intentionally use stable stage names so operations can aggregate lifecycle
// failures without parsing human-facing terminal messages.
func (s *Service) auditLifecycle(meta RunMetadata, stage string, status *ContainerStatus, err error) {
	ev := s.auditEvent("container_lifecycle", meta, "allow", err)
	ev.LifecycleStage = stage
	if err != nil {
		ev.Decision = "deny"
	}
	if status != nil {
		running := status.Running
		ev.ContainerRunning = &running
		ev.ContainerError = status.Error
	}
	s.audit.Log(ev, s.redactor(meta))
}

func (s *Service) auditTerminalEvent(meta RunMetadata, reason, source string, err error) {
	ev := s.auditEvent("run_finalized", meta, "allow", err)
	ev.Terminal = true
	ev.FinalizeReason = reason
	ev.TerminalSource = source
	s.audit.Log(ev, s.redactor(meta))
}

func (s *Service) auditFinalizeFailure(runID, reason, source string, err error) {
	meta, lookupErr := s.lookupRun(runID)
	if lookupErr != nil {
		log.Printf(`{"event":"run_finalized","job_id":%q,"success":false,"finalize_reason":%q,"terminal_source":%q,"error":%q}`,
			runID, reason, source, err.Error())
		return
	}
	ev := s.auditEvent("run_finalized", meta, "deny", err)
	ev.Terminal = true
	ev.FinalizeReason = reason
	ev.TerminalSource = source
	s.audit.Log(ev, s.redactor(meta))
}

func terminalSourceForStatus(status, fallback string) string {
	switch status {
	case StatusTimedOut:
		return terminalSourceTimedOut
	case StatusStopped, StatusFailed:
		if fallback != "" {
			return fallback
		}
		return terminalSourceExited
	default:
		return fallback
	}
}

func (s *Service) watchTimeout(parent context.Context, runID string, deadline time.Time) {
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	<-timer.C
	ctx, cancel := context.WithTimeout(parent, s.cfg.StopGrace.Duration+5*time.Second)
	defer cancel()
	if _, _, err := s.finalizeTerminalRun(ctx, runID, finalizeReasonDeadline, terminalSourceTimedOut, func(meta RunMetadata) RunMetadata {
		return s.markTimedOut(ctx, meta)
	}); err != nil {
		s.auditFinalizeFailure(runID, finalizeReasonDeadline, terminalSourceTimedOut, err)
	}
}

func (s *Service) watchExit(parent context.Context, runID, containerID string) {
	status, err := s.runtime.Wait(parent, containerID)
	if err != nil {
		if status, inspectErr := s.runtime.Inspect(parent, containerID); inspectErr == nil && !status.Running {
			if meta, lookupErr := s.lookupRun(runID); lookupErr == nil {
				s.auditLifecycle(meta, "wait_recovered_by_inspect", &status, err)
			}
			if _, _, finalizeErr := s.finalizeTerminalRun(parent, runID, finalizeReasonWorkerExit, terminalSourceExited, func(meta RunMetadata) RunMetadata {
				return s.finalizeExitedRun(parent, meta, status)
			}); finalizeErr != nil {
				s.auditFinalizeFailure(runID, finalizeReasonWorkerExit, terminalSourceExited, finalizeErr)
			}
			return
		}
		meta, lookupErr := s.lookupRun(runID)
		if lookupErr == nil && meta.Status == StatusRunning {
			s.auditLifecycle(meta, "wait_failed", nil, err)
		}
		return
	}
	if meta, lookupErr := s.lookupRun(runID); lookupErr == nil {
		s.auditLifecycle(meta, "wait_completed", &status, nil)
	}
	if _, _, err := s.finalizeTerminalRun(parent, runID, finalizeReasonWorkerExit, terminalSourceExited, func(meta RunMetadata) RunMetadata {
		return s.finalizeExitedRun(parent, meta, status)
	}); err != nil {
		s.auditFinalizeFailure(runID, finalizeReasonWorkerExit, terminalSourceExited, err)
	}
}

func (s *Service) finalizeTerminalRun(ctx context.Context, runID, reason, source string, update func(RunMetadata) RunMetadata) (RunMetadata, bool, error) {
	meta, err := s.lookupRun(runID)
	if err != nil {
		return RunMetadata{}, false, err
	}
	if meta.Status != StatusRunning {
		return meta, false, nil
	}
	s.mu.Lock()
	current, ok := s.runs[runID]
	if ok {
		meta = *current
	}
	if meta.Status != StatusRunning {
		s.mu.Unlock()
		return meta, false, nil
	}
	if done, ok := s.finalizing[runID]; ok {
		s.mu.Unlock()
		select {
		case <-done:
			finalized, err := s.lookupRun(runID)
			return finalized, false, err
		case <-ctx.Done():
			return meta, false, ctx.Err()
		}
	}
	done := make(chan struct{})
	s.finalizing[runID] = done
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		delete(s.finalizing, runID)
		close(done)
		s.mu.Unlock()
	}()

	next := update(meta)
	if next.Status == StatusRunning {
		return next, false, nil
	}
	if next.FinalizeReason != "" {
		reason = next.FinalizeReason
	} else {
		next.FinalizeReason = reason
	}
	if next.TerminalSource != "" {
		source = next.TerminalSource
	}
	source = terminalSourceForStatus(next.Status, source)
	next.TerminalSource = source
	s.mu.Lock()
	current, ok = s.runs[runID]
	if ok && current.Status != StatusRunning {
		done := *current
		s.mu.Unlock()
		return done, false, nil
	}
	cp := next
	s.runs[runID] = &cp
	s.mu.Unlock()
	s.writeCompletionStatus(ctx, next)
	if err := s.writeMetadataFile(next); err != nil {
		ev := s.auditEvent("run_finalized", next, "deny", err)
		ev.Terminal = true
		ev.FinalizeReason = reason
		ev.TerminalSource = source
		s.audit.Log(ev, s.redactor(next))
		return next, true, err
	}
	if s.launchIntents != nil {
		if err := s.launchIntents.SaveMetadata(ctx, next); err != nil {
			return next, true, err
		}
	}
	s.auditTerminalEvent(next, reason, source, nil)
	return next, true, nil
}

func (s *Service) markTimedOut(ctx context.Context, meta RunMetadata) RunMetadata {
	if meta.ContainerID != "" {
		status, inspectErr := s.runtime.Inspect(ctx, meta.ContainerID)
		if inspectErr != nil {
			s.auditLifecycle(meta, "deadline_inspect_failed", nil, inspectErr)
			meta.Error = "run exceeded deadline; unable to inspect worker lifecycle: " + s.redactor(meta).Redact(inspectErr.Error())
		} else if !status.Running {
			s.auditLifecycle(meta, "deadline_already_exited", &status, nil)
			meta.FinalizeReason = finalizeReasonDeadlineAlreadyExited
			return s.finalizeExitedRun(ctx, meta, status)
		} else {
			s.auditLifecycle(meta, "deadline_running", &status, nil)
			meta.Error = s.timeoutFailureMessage(ctx, meta, status)
		}
		if err := s.runtime.Stop(ctx, meta.ContainerID, s.cfg.StopGrace.Duration); err != nil {
			s.auditLifecycle(meta, "deadline_stop_failed", nil, err)
			if code, ok := DockerStatusCode(err); ok && code == http.StatusNotModified {
				status, inspectErr := s.runtime.Inspect(ctx, meta.ContainerID)
				if inspectErr == nil && !status.Running {
					s.auditLifecycle(meta, "deadline_stop_already_exited", &status, nil)
					meta.FinalizeReason = finalizeReasonDeadlineStopAlreadyExited
					return s.finalizeExitedRun(ctx, meta, status)
				}
			}
			meta.FinalizeReason = finalizeReasonDeadlineStopFailed
			meta.Error = strings.TrimSpace(meta.Error + "; stop failed: " + s.redactor(meta).Redact(err.Error()))
		} else {
			s.auditLifecycle(meta, "deadline_stop_requested", nil, nil)
			status, err := s.runtime.Inspect(ctx, meta.ContainerID)
			if err == nil && status.ExitCode != nil {
				meta.ExitCode = status.ExitCode
			}
		}
	}
	if meta.FinalizeReason == "" {
		meta.FinalizeReason = finalizeReasonDeadline
	}
	if meta.Error == "" {
		meta.Error = "run exceeded deadline"
	}
	meta.Status = StatusTimedOut
	meta.TerminalSource = terminalSourceTimedOut
	meta.EndedAt = time.Now().UTC()
	if err := s.ensureFailureDiagnostics(meta, meta.Error); err != nil && !strings.Contains(meta.Error, err.Error()) {
		meta.Error = meta.Error + "; diagnostics write failed: " + err.Error()
	}
	return meta
}

func (s *Service) timeoutFailureMessage(ctx context.Context, meta RunMetadata, status ContainerStatus) string {
	message := "run exceeded deadline; worker remained running"
	if detail := strings.TrimSpace(status.Error); detail != "" {
		message += "; container error: " + s.redactor(meta).Redact(detail)
	}
	logs, err := s.runtime.Logs(ctx, meta.ContainerID, 2048)
	if err != nil {
		return message
	}
	logs = strings.TrimSpace(s.redactor(meta).Redact(logs))
	if logs != "" {
		message += "; worker log tail: " + abbreviate(logs, 500)
	}
	return message
}

func (s *Service) finalizeExitedRun(ctx context.Context, meta RunMetadata, status ContainerStatus) RunMetadata {
	meta.TerminalSource = terminalSourceExited
	meta.ExitCode = status.ExitCode
	meta.EndedAt = status.EndedAt
	if meta.EndedAt.IsZero() {
		meta.EndedAt = time.Now().UTC()
	}
	if status.ExitCode != nil && *status.ExitCode == 0 {
		meta.Status = StatusStopped
		meta.Error = ""
		return meta
	}
	meta.Status = StatusFailed
	meta.Error = s.workerFailureMessage(ctx, meta, status)
	if diagErr := s.ensureFailureDiagnostics(meta, meta.Error); diagErr != nil && meta.Error == "" {
		meta.Error = diagErr.Error()
	}
	return meta
}

func (s *Service) workerFailureMessage(ctx context.Context, meta RunMetadata, status ContainerStatus) string {
	message := strings.TrimSpace(status.Error)
	if message == "" {
		if status.ExitCode != nil {
			message = fmt.Sprintf("worker exited with code %d", *status.ExitCode)
		} else {
			message = "worker exited nonzero"
		}
	}
	if meta.ContainerID == "" {
		return message
	}
	logs, err := s.runtime.Logs(ctx, meta.ContainerID, 2048)
	if err != nil {
		return message
	}
	logs = strings.TrimSpace(s.redactor(meta).Redact(logs))
	if logs == "" {
		return message
	}
	return message + ": " + abbreviate(logs, 500)
}

type completionStatusFile struct {
	Timestamp time.Time `json:"timestamp"`
	Status    string    `json:"status"`
	ExitCode  int       `json:"exit_code"`
	Message   string    `json:"message"`
}

func (s *Service) writeCompletionStatus(ctx context.Context, meta RunMetadata) {
	status, ok := completionStatus(meta)
	if !ok {
		return
	}
	tmpl := s.cfg.Templates[meta.Template]
	statusPath := strings.TrimSpace(tmpl.CompletionStatusPath)
	if statusPath == "" {
		return
	}
	exitCode := 0
	if meta.ExitCode != nil {
		exitCode = *meta.ExitCode
	} else if status == StatusTimedOut {
		exitCode = -1
	}
	message := strings.TrimSpace(meta.Error)
	if message == "" {
		message = "worker completed successfully"
	}
	payload := completionStatusFile{
		Timestamp: time.Now().UTC(),
		Status:    status,
		ExitCode:  exitCode,
		Message:   abbreviate(s.redactor(meta).Redact(message), 500),
	}
	b, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		s.logCompletionStatusFailure(meta, err)
		return
	}
	spec, _, err := s.runtimeSpec(meta, tmpl)
	if err != nil {
		s.logCompletionStatusFailure(meta, err)
		return
	}
	b = append(b, '\n')
	hostPath, ok := resolveMountedPath(statusPath, spec.Mounts)
	if !ok {
		s.logCompletionStatusFailure(meta, fmt.Errorf("completion status path %q is not under a writable mount", statusPath))
		return
	}
	if writer, ok := s.runtime.(runtimeFileWriter); ok {
		if err := writer.WriteFile(ctx, tmpl.Image, spec.Mounts, statusPath, b); err != nil {
			s.logCompletionStatusFailure(meta, err)
		}
		return
	}
	//nolint:gosec // G306: completion status is non-secret health metadata read by the mounted service.
	if err := os.WriteFile(hostPath, b, 0o644); err != nil {
		s.logCompletionStatusFailure(meta, err)
	}
}

func completionStatus(meta RunMetadata) (string, bool) {
	switch meta.Status {
	case StatusStopped:
		return "success", true
	case StatusFailed:
		return StatusFailed, true
	case StatusTimedOut:
		return StatusTimedOut, true
	default:
		return "", false
	}
}

func resolveMountedPath(containerPath string, mounts []Mount) (string, bool) {
	cleanContainerPath := path.Clean(containerPath)
	for _, mount := range mounts {
		if mount.ReadOnly {
			continue
		}
		target := path.Clean(mount.Target)
		if cleanContainerPath != target && !strings.HasPrefix(cleanContainerPath, target+"/") {
			continue
		}
		rel, err := filepath.Rel(filepath.FromSlash(target), filepath.FromSlash(cleanContainerPath))
		if err != nil {
			continue
		}
		return filepath.Join(filepath.Clean(mount.Source), rel), true
	}
	return "", false
}

func abbreviate(value string, max int) string {
	value = strings.TrimSpace(value)
	if max <= 0 || len(value) <= max {
		return value
	}
	return strings.TrimSpace(value[:max]) + "..."
}

func (s *Service) logCompletionStatusFailure(meta RunMetadata, err error) {
	log.Printf(`{"event":"completion_status_write","job_id":%q,"profile":%q,"template":%q,"success":false,"error":%q}`,
		meta.RunID, meta.Profile, meta.Template, s.redactor(meta).Redact(err.Error()))
}

func (s *Service) logSandboxCreation(meta RunMetadata, duration time.Duration, err error) {
	success := err == nil
	errorMessage := ""
	if err != nil {
		errorMessage = "runtime_create_failed"
	}
	event := map[string]any{
		"event":       "sandbox_creation",
		"job_id":      meta.RunID,
		"profile":     meta.Profile,
		"template":    meta.Template,
		"success":     success,
		"duration_ms": duration.Milliseconds(),
	}
	if errorMessage != "" {
		event["error"] = errorMessage
	}
	b, marshalErr := json.Marshal(event)
	if marshalErr != nil {
		return
	}
	log.Print(string(b))
}

func (s *Service) ensureFailureDiagnostics(meta RunMetadata, message string) error {
	if meta.Status != StatusFailed && meta.Status != StatusTimedOut {
		return nil
	}
	path := filepath.Join(s.runDir(meta.RunID), "output", "wrapper-diagnostics.json")
	if _, err := os.Stat(path); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	diagnostics := FailureDiagnostics{
		Source:   "broker",
		Status:   meta.Status,
		ExitCode: meta.ExitCode,
		Message:  message,
	}
	if diagnostics.Message == "" {
		diagnostics.Message = "worker failed"
	}
	return writeJSONFile(path, diagnostics, 0o644)
}

func (s *Service) statusOutput(meta RunMetadata) StatusOutput {
	var ended *time.Time
	if !meta.EndedAt.IsZero() {
		ended = &meta.EndedAt
	}
	out := StatusOutput{
		RunID:       meta.RunID,
		Status:      meta.Status,
		Branch:      meta.Branch,
		Repo:        meta.Repo,
		ExitCode:    meta.ExitCode,
		Error:       meta.Error,
		Deadline:    meta.Deadline,
		EndedAt:     ended,
		Diagnostics: s.readFailureDiagnostics(meta),
	}
	return out
}

func (s *Service) readFailureDiagnostics(meta RunMetadata) *FailureDiagnostics {
	if meta.Status != StatusFailed && meta.Status != StatusTimedOut {
		return nil
	}
	path := filepath.Join(s.runDir(meta.RunID), "output", "wrapper-diagnostics.json")
	// #nosec G304 -- path is constrained to this run's output diagnostics file.
	b, err := os.ReadFile(path)
	if err != nil {
		message := meta.Error
		if message == "" {
			message = "worker failed"
		}
		return &FailureDiagnostics{Source: "broker", Status: meta.Status, ExitCode: meta.ExitCode, Message: message}
	}
	var diagnostics FailureDiagnostics
	if err := json.Unmarshal(b, &diagnostics); err != nil {
		return &FailureDiagnostics{Source: "broker", Status: meta.Status, ExitCode: meta.ExitCode, Message: "diagnostics file could not be decoded"}
	}
	if diagnostics.Source == "" {
		diagnostics.Source = "worker"
	}
	if diagnostics.Status == "" {
		diagnostics.Status = meta.Status
	}
	if diagnostics.ExitCode == nil {
		diagnostics.ExitCode = meta.ExitCode
	}
	redactor := s.redactor(meta)
	diagnostics.Message = redactor.Redact(diagnostics.Message)
	for i, item := range diagnostics.MissingDeliverables {
		diagnostics.MissingDeliverables[i] = redactor.Redact(item)
	}
	return &diagnostics
}

func deliverables(requested, defaults []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, item := range append(append([]string{}, defaults...), requested...) {
		item = strings.TrimSpace(item)
		if item == "" || seen[item] {
			continue
		}
		seen[item] = true
		out = append(out, item)
	}
	return out
}

func cloneParameters(in map[string]any) map[string]any {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		switch values := v.(type) {
		case []string:
			out[k] = append([]string(nil), values...)
		default:
			out[k] = values
		}
	}
	return out
}

func workerAgentID(tmpl Template, runID string) string {
	return tmpl.BrokerAgentID + ":" + runID
}

func newRunID() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return time.Now().UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(b[:]), nil
}

func safeRunID(id string) bool {
	if id == "" || strings.Contains(id, "/") || strings.Contains(id, "..") {
		return false
	}
	return regexp.MustCompile(`^[A-Za-z0-9_.:-]+$`).MatchString(id)
}

func safeBranch(branch string) bool {
	if branch == "" || strings.HasPrefix(branch, "/") || strings.HasSuffix(branch, "/") ||
		strings.Contains(branch, "..") || strings.Contains(branch, "\\") || strings.ContainsAny(branch, " ~^:?*[") ||
		strings.HasSuffix(branch, ".lock") || strings.Contains(branch, "//") || strings.Contains(branch, "@{") {
		return false
	}
	return true
}

func matchesAny(patterns []string, value string) bool {
	for _, pattern := range patterns {
		re, err := regexp.Compile(pattern)
		if err == nil && re.MatchString(value) {
			return true
		}
	}
	return false
}

func safeEnvKey(key string) bool {
	return regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`).MatchString(key) &&
		!strings.Contains(key, "SECRET") && !strings.Contains(key, "TOKEN") && key != "PATH"
}

func copyKnowledgeSnapshots(snapshots []string, inputDir string) error {
	for _, src := range snapshots {
		src = filepath.Clean(src)
		info, err := os.Lstat(src)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("knowledge snapshot %q is a symlink", src)
		}
		dst := filepath.Join(inputDir, filepath.Base(src))
		if info.IsDir() {
			if err := copyDir(src, dst); err != nil {
				return err
			}
		} else if err := copyFile(src, dst, info.Mode()); err != nil {
			return err
		}
	}
	return nil
}

func copyDir(src, dst string) error {
	return filepath.WalkDir(src, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			//nolint:gosec // G301: input snapshots are mounted read-only and must be readable by the non-root worker UID.
			return os.MkdirAll(target, 0o755)
		}
		return copyFile(path, target, info.Mode())
	})
}

func copyFile(src, dst string, mode os.FileMode) error {
	// #nosec G304 -- source is an operator-configured knowledge snapshot path.
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer closeBody(in)
	//nolint:gosec // G301: input snapshots are mounted read-only and must be readable by the non-root worker UID.
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	//nolint:gosec // G304: destination is generated under a sandbox run input directory from an operator-configured snapshot.
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, readableInputMode(mode))
	if err != nil {
		return err
	}
	defer closeBody(out)
	_, err = io.Copy(out, in)
	return err
}

func readableInputMode(mode os.FileMode) os.FileMode {
	perm := mode.Perm()
	if perm&0o444 == 0 {
		return 0o444
	}
	return perm | 0o444
}
