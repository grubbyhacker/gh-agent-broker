package sandbox

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strconv"
	"time"
)

const (
	codexRelayBaseURL            = "http://codex-subscription-relay:8093/backend-api/codex"
	codexInjectionDir            = "/dev/shm/codex-credential-injection"
	codexInjectionName           = "auth.json"
	codexAcceptanceMarker        = "/dev/shm/codex-credential-accepted"
	codexCredentialWaitTimeout   = 45 * time.Second
	codexPhasePreparationCreate  = "preparation_create_pending"
	codexPhasePreparationStart   = "preparation_start_pending"
	codexPhasePreparationRunning = "preparation_running"
	codexPhasePreparationRecon   = "preparation_reconcile_pending"
	codexPhasePreparationTerm    = "preparation_terminal"
	codexPhaseExecutionCreate    = "execution_create_pending"
	codexPhaseExecutionStart     = "execution_start_pending"
	codexPhaseBundleInject       = "bundle_inject_pending"
	codexPhaseBundleAccept       = "bundle_accept_pending"
	codexPhaseExecutionRunning   = "execution_running"
	codexPhaseExecutionRecon     = "execution_reconcile_pending"
	codexPhaseExecutionTerm      = "execution_terminal"
	codexPhaseRecoveryCreate     = "recovery_validation_create_pending"
	codexPhaseRecoveryStart      = "recovery_validation_start_pending"
	codexPhaseRecoveryRunning    = "recovery_validation_running"
	codexPhaseRecoveryTerm       = "recovery_validation_terminal"
	codexPhaseDeliveryCreate     = "delivery_create_pending"
	codexPhaseDeliveryStart      = "delivery_start_pending"
	codexPhaseDeliveryRunning    = "delivery_running"
	codexPhaseDeliveryRecon      = "delivery_reconcile_pending"
	codexPhaseDeliveryTerm       = "delivery_terminal"
)

type preparationResult struct {
	Version               string `json:"version"`
	Status                string `json:"status"`
	RunID                 string `json:"run_id"`
	Repository            string `json:"repository"`
	Branch                string `json:"branch"`
	WorkspaceHead         string `json:"workspace_head"`
	RefsSHA256            string `json:"refs_sha256"`
	ManifestSHA256        string `json:"manifest_sha256"`
	IssueNumber           int    `json:"issue_number"`
	SourceDeliveryID      string `json:"source_delivery_id"`
	RepairPRNumber        int    `json:"repair_pr_number,omitempty"`
	RepairHeadRef         string `json:"repair_head_ref,omitempty"`
	RepairExpectedHeadSHA string `json:"repair_expected_head_sha,omitempty"`
}

type executionResult struct {
	Version          string `json:"version"`
	Status           string `json:"status"`
	RunID            string `json:"run_id"`
	Repository       string `json:"repository"`
	Branch           string `json:"branch"`
	WorkspaceHead    string `json:"workspace_head"`
	RefsSHA256       string `json:"refs_sha256"`
	DiffSHA256       string `json:"diff_sha256"`
	ValidatedTreeSHA string `json:"validated_tree_sha"`
	FinalSHA256      string `json:"final_sha256"`
	VerifySHA256     string `json:"verify_sha256"`
	Verification     string `json:"verification"`
	FinalSizeBytes   int64  `json:"final_size_bytes"`
}

type executionFailure struct {
	Version          string `json:"version"`
	Status           string `json:"status"`
	RunID            string `json:"run_id"`
	Repository       string `json:"repository"`
	Branch           string `json:"branch"`
	Stage            string `json:"stage"`
	ExitCode         int    `json:"exit_code"`
	DiagnosticSource string `json:"diagnostic_source"`
	Diagnostic       string `json:"diagnostic"`
	EventsSizeBytes  int64  `json:"events_size_bytes"`
	EventsSHA256     string `json:"events_sha256"`
	StderrSizeBytes  int64  `json:"stderr_size_bytes"`
	StderrSHA256     string `json:"stderr_sha256"`
}

type githubExternalWaitReport struct {
	Version    string `json:"version"`
	Status     string `json:"status"`
	RunID      string `json:"run_id"`
	Repository string `json:"repository"`
	Branch     string `json:"branch"`
	Service    string `json:"service"`
	Phase      string `json:"phase"`
	Operation  string `json:"operation"`
	Reason     string `json:"reason"`
}

type recoveryValidationResult struct {
	Version          string `json:"version"`
	Status           string `json:"status"`
	RunID            string `json:"run_id"`
	Repository       string `json:"repository"`
	Branch           string `json:"branch"`
	ExpectedHeadSHA  string `json:"expected_head_sha,omitempty"`
	WinnerHeadSHA    string `json:"winner_head_sha"`
	CandidateHeadSHA string `json:"candidate_head_sha"`
	CandidateTreeSHA string `json:"candidate_tree_sha,omitempty"`
	ValidatedTreeSHA string `json:"validated_tree_sha"`
	VerifySHA256     string `json:"verify_sha256"`
	SealSHA256       string `json:"seal_sha256,omitempty"`
}

func (s *Service) resumeCodexIssueWorkflow(
	ctx context.Context,
	intent *launchIntent,
	profile LaunchProfile,
	recovering bool,
) (LaunchAgentOutput, error) {
	meta := intent.Metadata
	if isTerminalStatus(meta.Status) || intent.State == intentStateTerminal {
		return launchOutput(meta), nil
	}
	if meta.Status == StatusWaitingExternal || intent.State == intentStateWaitingExternal {
		return launchOutput(meta), nil
	}
	if s.codexIssuer == nil {
		return s.failCodexIntent(ctx, intent, meta, "credential_issuance", fmt.Errorf("codex credential holder is unavailable"))
	}
	workflow := profile.CodexIssueWorkflow
	if workflow == nil {
		return LaunchAgentOutput{}, fmt.Errorf("codex workflow configuration is missing")
	}
	if recovering {
		// Cleanup removes artifacts from pre-injection versions. Current
		// issuance state is token-free and safe to replay.
		if err := s.codexIssuer.Cleanup(meta.RunID); err != nil {
			return LaunchAgentOutput{}, fmt.Errorf("clean legacy Codex capability: %w", err)
		}
		if meta.Status == StatusRunning {
			go s.watchTimeout(context.WithoutCancel(ctx), meta.RunID, meta.Deadline)
		}
	}
	if err := s.prepareDurableRun(meta, s.cfg.Templates[workflow.ExecutionTemplate]); err != nil {
		return LaunchAgentOutput{}, err
	}
	if meta.Phase == "" {
		meta.Phase = codexPhasePreparationCreate
	}

	switch meta.Phase {
	case codexPhasePreparationCreate, codexPhasePreparationStart, codexPhasePreparationRunning,
		codexPhasePreparationRecon, codexPhasePreparationTerm:
		return s.resumePreparation(ctx, intent, meta, *workflow)
	case codexPhaseExecutionCreate, codexPhaseExecutionStart, codexPhaseBundleInject,
		codexPhaseBundleAccept, codexPhaseExecutionRunning:
		fallthrough
	case codexPhaseExecutionRecon, codexPhaseExecutionTerm:
		return s.resumeExecution(ctx, intent, meta, *workflow)
	case codexPhaseRecoveryCreate, codexPhaseRecoveryStart, codexPhaseRecoveryRunning, codexPhaseRecoveryTerm:
		return s.resumeRecoveryValidation(ctx, intent, meta, *workflow)
	case codexPhaseDeliveryCreate, codexPhaseDeliveryStart, codexPhaseDeliveryRunning,
		codexPhaseDeliveryRecon, codexPhaseDeliveryTerm:
		return s.resumeDelivery(ctx, intent, meta, *workflow)
	default:
		return s.failCodexIntent(ctx, intent, meta, "state_reconciliation", fmt.Errorf("unsupported Codex workflow phase %q", meta.Phase))
	}
}

// resumeRecoveryValidation runs exactly one credential-free verification after
// a positively identified stale lease. It deliberately cannot create a new
// model execution or access the broker.
func (s *Service) resumeRecoveryValidation(ctx context.Context, intent *launchIntent, meta RunMetadata, workflow CodexIssueWorkflow) (LaunchAgentOutput, error) {
	template := s.cfg.Templates[workflow.RecoveryTemplate]
	spec, _, err := s.runtimeSpec(meta, template)
	if err != nil {
		return LaunchAgentOutput{}, err
	}
	spec.RunID = meta.RunID + "-recover-" + strconv.Itoa(meta.RecoveryCount+1)
	spec.Labels["gh-agent-broker.parent_run_id"] = meta.RunID
	spec.Labels["gh-agent-broker.run_id"] = spec.RunID
	spec.Labels["gh-agent-broker.template"] = workflow.RecoveryTemplate
	spec.Labels["gh-agent-broker.phase"] = "recovery_validation"
	var info ContainerInfo
	if meta.RecoveryContainerID == "" {
		if meta.RecoveryCount >= 1 {
			return s.failCodexIntent(ctx, intent, meta, "recovery_bound", fmt.Errorf("stale lease recovery was already attempted"))
		}
		meta.Phase = codexPhaseRecoveryCreate
		if err := s.persistCodexIntent(ctx, intent, meta, intentStateCreatePending); err != nil {
			return LaunchAgentOutput{}, err
		}
		info, err = s.runtime.Create(ctx, spec)
		if err != nil {
			return s.failCodexIntent(ctx, intent, meta, "recovery_create", err)
		}
		meta.RecoveryContainerID, meta.ContainerID, meta.RecoveryCount = info.ID, info.ID, meta.RecoveryCount+1
		meta.Phase = codexPhaseRecoveryStart
		if err := s.persistCodexIntent(ctx, intent, meta, intentStateContainerMade); err != nil {
			return LaunchAgentOutput{}, err
		}
		if info.Lifecycle == "" {
			info.Lifecycle = ContainerNeverStarted
		}
	} else {
		status, inspectErr := s.runtime.Inspect(ctx, meta.RecoveryContainerID)
		if inspectErr != nil {
			return s.failCodexIntent(ctx, intent, meta, "recovery_reconcile", inspectErr)
		}
		info = ContainerInfo{ID: meta.RecoveryContainerID, Status: status, Lifecycle: lifecycleForStatus(status)}
	}
	if info.Lifecycle == ContainerExited {
		return s.completeRecoveryValidation(ctx, intent, meta, workflow, info.Status)
	}
	if info.Lifecycle == ContainerNeverStarted {
		meta.Phase = codexPhaseRecoveryStart
		if err := s.persistCodexIntent(ctx, intent, meta, intentStateStartPending); err != nil {
			return LaunchAgentOutput{}, err
		}
		if err := s.runtime.Start(ctx, meta.RecoveryContainerID); err != nil {
			return s.failCodexIntent(ctx, intent, meta, "recovery_start", err)
		}
	}
	meta.Status, meta.Phase = StatusRunning, codexPhaseRecoveryRunning
	if meta.RecoveryStartedAt.IsZero() {
		meta.RecoveryStartedAt = time.Now().UTC()
	}
	if err := s.persistCodexIntent(ctx, intent, meta, intentStateRunning); err != nil {
		return LaunchAgentOutput{}, err
	}
	s.watchCodexPhase(meta.RunID, meta.RecoveryContainerID)
	return launchOutput(meta), nil
}

func (s *Service) completeRecoveryValidation(ctx context.Context, intent *launchIntent, meta RunMetadata, workflow CodexIssueWorkflow, status ContainerStatus) (LaunchAgentOutput, error) {
	meta.RecoveryEndedAt, meta.Phase = terminalTime(status), codexPhaseRecoveryTerm
	if err := s.persistCodexIntent(ctx, intent, meta, intentStateRunning); err != nil {
		return LaunchAgentOutput{}, err
	}
	if status.ExitCode == nil || *status.ExitCode != 0 {
		return s.failCodexIntent(ctx, intent, meta, "recovery_validation", fmt.Errorf("credential-free recovery validation failed"))
	}
	if err := s.readRecoveryValidation(meta); err != nil {
		return s.failCodexIntent(ctx, intent, meta, "recovery_validation", err)
	}
	// The initial delivery container is terminal. Allocate and persist a new
	// runtime identity before the recovered delivery is created; Docker's
	// adoption key includes this run ID, so it cannot adopt the stale exit.
	meta.DeliveryContainerID, meta.ContainerID = "", ""
	meta.DeliveryAttempt++
	meta.Phase = codexPhaseDeliveryCreate
	return s.resumeDelivery(ctx, intent, meta, workflow)
}

func (s *Service) resumePreparation(
	ctx context.Context,
	intent *launchIntent,
	meta RunMetadata,
	workflow CodexIssueWorkflow,
) (LaunchAgentOutput, error) {
	template := s.cfg.Templates[workflow.PreparationTemplate]
	spec, _, err := s.runtimeSpec(meta, template)
	if err != nil {
		return LaunchAgentOutput{}, err
	}
	if meta.PreparationAttempt == 0 {
		meta.PreparationAttempt = 1
	}
	spec.RunID = meta.RunID + "-prep"
	if meta.PreparationAttempt > 1 {
		spec.RunID += "-" + strconv.Itoa(meta.PreparationAttempt)
	}
	spec.Labels["gh-agent-broker.parent_run_id"] = meta.RunID
	spec.Labels["gh-agent-broker.run_id"] = spec.RunID
	spec.Labels["gh-agent-broker.template"] = workflow.PreparationTemplate
	spec.Labels["gh-agent-broker.phase"] = "preparation"
	var info ContainerInfo
	if meta.PreparationContainerID == "" {
		meta.Phase = codexPhasePreparationCreate
		if err := s.persistCodexIntent(ctx, intent, meta, intentStateCreatePending); err != nil {
			return LaunchAgentOutput{}, err
		}
		info, err = s.runtime.Create(ctx, spec)
		if err != nil {
			return s.failCodexIntent(ctx, intent, meta, "preparation_create", err)
		}
		meta.PreparationContainerID = info.ID
		meta.PreparationContainerIDs = appendUniqueContainerID(meta.PreparationContainerIDs, info.ID)
		meta.ContainerID = info.ID
		meta.PreparationImageDigest = info.ImageDigest
		meta.PreparationPlatform = info.Platform
		meta.Phase = codexPhasePreparationStart
		if err := s.persistCodexIntent(ctx, intent, meta, intentStateContainerMade); err != nil {
			return LaunchAgentOutput{}, err
		}
		if info.Lifecycle == "" {
			info.Lifecycle = ContainerNeverStarted
		}
	} else {
		status, inspectErr := s.runtime.Inspect(ctx, meta.PreparationContainerID)
		if inspectErr != nil {
			return s.failCodexIntent(ctx, intent, meta, "preparation_reconcile", inspectErr)
		}
		info = ContainerInfo{ID: meta.PreparationContainerID, Status: status, Lifecycle: lifecycleForStatus(status)}
	}
	if info.Lifecycle == ContainerExited {
		return s.completePreparation(ctx, intent, meta, workflow, info.Status)
	}
	if info.Lifecycle == ContainerNeverStarted {
		meta.Phase = codexPhasePreparationStart
		if err := s.persistCodexIntent(ctx, intent, meta, intentStateStartPending); err != nil {
			return LaunchAgentOutput{}, err
		}
		if err := s.runtime.Start(ctx, meta.PreparationContainerID); err != nil {
			status, inspectErr := s.runtime.Inspect(ctx, meta.PreparationContainerID)
			if inspectErr == nil && !status.StartedAt.IsZero() {
				if status.Running {
					info.Status = status
				} else {
					return s.completePreparation(ctx, intent, meta, workflow, status)
				}
			} else {
				return s.failCodexIntent(ctx, intent, meta, "preparation_start", err)
			}
		}
	}
	meta.Status = StatusRunning
	meta.Phase = codexPhasePreparationRunning
	startDeadlineWatcher := meta.PreparationStartedAt.IsZero()
	if startDeadlineWatcher {
		meta.PreparationStartedAt = time.Now().UTC()
	}
	if err := s.persistCodexIntent(ctx, intent, meta, intentStateRunning); err != nil {
		return LaunchAgentOutput{}, err
	}
	if startDeadlineWatcher {
		go s.watchTimeout(context.WithoutCancel(ctx), meta.RunID, meta.Deadline)
	}
	s.watchCodexPhase(meta.RunID, meta.PreparationContainerID)
	return launchOutput(meta), nil
}

func (s *Service) completePreparation(
	ctx context.Context,
	intent *launchIntent,
	meta RunMetadata,
	workflow CodexIssueWorkflow,
	status ContainerStatus,
) (LaunchAgentOutput, error) {
	meta.PreparationEndedAt = terminalTime(status)
	meta.Phase = codexPhasePreparationTerm
	if err := s.persistCodexIntent(ctx, intent, meta, intentStateRunning); err != nil {
		return LaunchAgentOutput{}, err
	}
	if status.ExitCode == nil || *status.ExitCode != 0 {
		if status.ExitCode != nil && *status.ExitCode == 75 {
			if wait, err := s.readGitHubExternalWait(meta, "preparation"); err == nil {
				return s.waitForGitHub(ctx, intent, meta, wait)
			}
		}
		return s.failCodexIntent(ctx, intent, meta, "preparation", fmt.Errorf("credential-free preparation failed"))
	}
	result, err := s.readPreparationResult(meta)
	if err != nil {
		return s.failCodexIntent(ctx, intent, meta, "preparation_verification", err)
	}
	meta.Provenance.WorkspaceHead = result.WorkspaceHead
	meta.Provenance.ManifestSHA256 = result.ManifestSHA256
	if result.RepairPRNumber != 0 {
		meta.RepairPRNumber, meta.RepairHeadRef, meta.RepairAdmittedHeadSHA = result.RepairPRNumber, result.RepairHeadRef, result.RepairExpectedHeadSHA
		if err := s.writeRepairAuthority(meta); err != nil {
			return s.failCodexIntent(ctx, intent, meta, "preparation_verification", err)
		}
	}
	meta.Phase = codexPhaseExecutionCreate
	meta.ContainerID = ""
	if err := s.persistCodexIntent(ctx, intent, meta, intentStateRunning); err != nil {
		return LaunchAgentOutput{}, err
	}
	return s.resumeExecution(ctx, intent, meta, workflow)
}

func (s *Service) resumeExecution(
	ctx context.Context,
	intent *launchIntent,
	meta RunMetadata,
	workflow CodexIssueWorkflow,
) (LaunchAgentOutput, error) {
	durablePhase := meta.Phase
	template := s.cfg.Templates[workflow.ExecutionTemplate]
	spec, _, err := s.runtimeSpec(meta, template)
	if err != nil {
		return LaunchAgentOutput{}, err
	}
	spec.RunID = meta.RunID + "-exec"
	spec.Labels["gh-agent-broker.parent_run_id"] = meta.RunID
	spec.Labels["gh-agent-broker.run_id"] = spec.RunID
	spec.Labels["gh-agent-broker.template"] = workflow.ExecutionTemplate
	spec.Labels["gh-agent-broker.phase"] = "execution"
	spec.Env["AGENT_MODEL"] = meta.Provenance.Model
	spec.Env["AGENT_REASONING_EFFORT"] = meta.Provenance.Effort
	spec.Env["AGENT_MODEL_POLICY_VERSION"] = meta.Provenance.ModelPolicyVersion
	spec.Env["AGENT_CODEX_VERSION"] = meta.Provenance.CodexVersion
	spec.Env["AGENT_PROMPT_REVISION"] = meta.Provenance.PromptRevision
	spec.Env["AGENT_FINAL_OUTPUT_LIMIT"] = fmt.Sprintf("%d", s.cfg.TerminalResultByteLimit)
	spec.Env["CODEX_SUBSCRIPTION_RELAY_BASE_URL"] = codexRelayBaseURL
	var info ContainerInfo
	if meta.ExecutionContainerID == "" {
		info, err = s.runtime.Create(ctx, spec)
		if err != nil {
			return s.failCodexIntent(ctx, intent, meta, "execution_create", err)
		}
		meta.ExecutionContainerID = info.ID
		meta.ContainerID = info.ID
		meta.ImageDigest = info.ImageDigest
		meta.ExecutionPlatform = info.Platform
		meta.Phase = codexPhaseExecutionStart
		if err := s.persistCodexIntent(ctx, intent, meta, intentStateContainerMade); err != nil {
			return LaunchAgentOutput{}, err
		}
		if info.Lifecycle == "" {
			info.Lifecycle = ContainerNeverStarted
		}
	} else {
		status, inspectErr := s.runtime.Inspect(ctx, meta.ExecutionContainerID)
		if inspectErr != nil {
			return s.failCodexIntent(ctx, intent, meta, "execution_reconcile", inspectErr)
		}
		info = ContainerInfo{ID: meta.ExecutionContainerID, Status: status, Lifecycle: lifecycleForStatus(status)}
		if info.Lifecycle == ContainerRunning {
			switch durablePhase {
			case codexPhaseExecutionRunning:
				return s.adoptExecution(ctx, intent, meta)
			case codexPhaseBundleAccept:
				meta.Phase = codexPhaseBundleAccept
			case codexPhaseBundleInject:
				accepted, markerErr := s.runtime.PathExists(
					ctx,
					meta.ExecutionContainerID,
					codexAcceptanceMarker,
				)
				if markerErr != nil {
					return s.failCodexIntent(ctx, intent, meta, "credential_acceptance_reconcile", markerErr)
				}
				if accepted {
					meta.Phase = codexPhaseBundleAccept
				}
			case codexPhaseExecutionCreate, codexPhaseExecutionStart, codexPhaseExecutionRecon:
				// Start may have succeeded immediately before a crash.
				meta.Phase = codexPhaseBundleInject
			default:
				return s.failCodexIntent(
					ctx,
					intent,
					meta,
					"execution_reconcile",
					fmt.Errorf("running execution container has incompatible durable phase %q", durablePhase),
				)
			}
		}
	}
	if info.Lifecycle == ContainerExited {
		return s.completeExecution(ctx, intent, meta, info.Status)
	}
	if info.Lifecycle == ContainerNeverStarted {
		meta.Phase = codexPhaseExecutionStart
		if err := s.persistCodexIntent(ctx, intent, meta, intentStateStartPending); err != nil {
			return LaunchAgentOutput{}, err
		}
		if err := s.runtime.Start(ctx, meta.ExecutionContainerID); err != nil {
			status, inspectErr := s.runtime.Inspect(ctx, meta.ExecutionContainerID)
			if inspectErr == nil && !status.StartedAt.IsZero() {
				if status.Running {
					info.Status = status
				} else {
					return s.completeExecution(ctx, intent, meta, status)
				}
			} else {
				return s.failCodexIntent(ctx, intent, meta, "execution_start", err)
			}
		}
		meta.Phase = codexPhaseBundleInject
		if err := s.persistCodexIntent(ctx, intent, meta, intentStateRunning); err != nil {
			return LaunchAgentOutput{}, err
		}
	}
	if meta.Phase == codexPhaseExecutionStart {
		meta.Phase = codexPhaseBundleInject
		if err := s.persistCodexIntent(ctx, intent, meta, intentStateRunning); err != nil {
			return LaunchAgentOutput{}, err
		}
	}
	if meta.Phase == codexPhaseBundleInject {
		accepted, markerErr := s.runtime.PathExists(
			ctx,
			meta.ExecutionContainerID,
			codexAcceptanceMarker,
		)
		if markerErr != nil {
			return s.failCodexIntent(ctx, intent, meta, "credential_acceptance_reconcile", markerErr)
		}
		if !accepted {
			bundle, issueErr := s.codexIssuer.Issue(ctx, meta.RunID, meta.IdempotencyKeyDigest)
			if issueErr != nil {
				return s.failCodexIntent(ctx, intent, meta, "credential_issuance", issueErr)
			}
			if injectErr := s.runtime.InjectSecret(
				ctx,
				meta.ExecutionContainerID,
				codexInjectionDir,
				codexInjectionName,
				bundle,
			); injectErr != nil {
				return s.failCodexIntent(ctx, intent, meta, "credential_injection", injectErr)
			}
		}
		meta.Phase = codexPhaseBundleAccept
		if err := s.persistCodexIntent(ctx, intent, meta, intentStateRunning); err != nil {
			return LaunchAgentOutput{}, err
		}
	}
	if meta.Phase == codexPhaseBundleAccept {
		if err := s.runtime.WaitForPath(
			ctx,
			meta.ExecutionContainerID,
			codexAcceptanceMarker,
			codexCredentialWaitTimeout,
		); err != nil {
			return s.failCodexIntent(ctx, intent, meta, "credential_acceptance", err)
		}
		if err := s.codexIssuer.Consume(meta.RunID); err != nil {
			return s.failCodexIntent(ctx, intent, meta, "credential_consumption", err)
		}
	}
	return s.adoptExecution(ctx, intent, meta)
}

func (s *Service) adoptExecution(
	ctx context.Context,
	intent *launchIntent,
	meta RunMetadata,
) (LaunchAgentOutput, error) {
	meta.Status = StatusRunning
	meta.Phase = codexPhaseExecutionRunning
	if meta.ExecutionStartedAt.IsZero() {
		meta.ExecutionStartedAt = time.Now().UTC()
	}
	if err := s.persistCodexIntent(ctx, intent, meta, intentStateRunning); err != nil {
		return LaunchAgentOutput{}, err
	}
	s.watchCodexPhase(meta.RunID, meta.ExecutionContainerID)
	return launchOutput(meta), nil
}

func (s *Service) completeExecution(
	ctx context.Context,
	intent *launchIntent,
	meta RunMetadata,
	status ContainerStatus,
) (LaunchAgentOutput, error) {
	meta.ExecutionEndedAt = terminalTime(status)
	meta.Phase = codexPhaseExecutionTerm
	if err := s.persistCodexIntent(ctx, intent, meta, intentStateRunning); err != nil {
		return LaunchAgentOutput{}, err
	}
	if status.ExitCode == nil || *status.ExitCode != 0 {
		failure, err := s.readExecutionFailure(meta, status.ExitCode)
		if err != nil {
			return s.failCodexIntent(ctx, intent, meta, "execution", fmt.Errorf("codex execution failed: %w", err))
		}
		return s.failCodexIntent(ctx, intent, meta, "execution", fmt.Errorf("codex execution failed: %s", failure.Diagnostic))
	}
	if _, err := s.readExecutionResult(meta); err != nil {
		return s.failCodexIntent(ctx, intent, meta, "execution_verification", err)
	}
	meta.Phase = codexPhaseDeliveryCreate
	meta.ContainerID = ""
	if err := s.persistCodexIntent(ctx, intent, meta, intentStateRunning); err != nil {
		return LaunchAgentOutput{}, err
	}
	profile := s.cfg.LaunchProfiles[meta.Profile]
	return s.resumeDelivery(ctx, intent, meta, *profile.CodexIssueWorkflow)
}

func (s *Service) resumeDelivery(
	ctx context.Context,
	intent *launchIntent,
	meta RunMetadata,
	workflow CodexIssueWorkflow,
) (LaunchAgentOutput, error) {
	template := s.cfg.Templates[workflow.DeliveryTemplate]
	spec, _, err := s.runtimeSpec(meta, template)
	if err != nil {
		return LaunchAgentOutput{}, err
	}
	if meta.DeliveryAttempt == 0 {
		// Persist the attempt before Docker create so a restart reconciles the
		// same identity; recovery advances this durable counter before retrying.
		meta.DeliveryAttempt = 1
		if err := s.persistCodexIntent(ctx, intent, meta, intentStateCreatePending); err != nil {
			return LaunchAgentOutput{}, err
		}
	}
	spec.RunID = meta.RunID + "-deliver-" + strconv.Itoa(meta.DeliveryAttempt)
	spec.Labels["gh-agent-broker.parent_run_id"] = meta.RunID
	spec.Labels["gh-agent-broker.run_id"] = spec.RunID
	spec.Labels["gh-agent-broker.template"] = workflow.DeliveryTemplate
	spec.Labels["gh-agent-broker.phase"] = "delivery"
	var info ContainerInfo
	if meta.DeliveryContainerID == "" {
		meta.Phase = codexPhaseDeliveryCreate
		if err := s.persistCodexIntent(ctx, intent, meta, intentStateCreatePending); err != nil {
			return LaunchAgentOutput{}, err
		}
		info, err = s.runtime.Create(ctx, spec)
		if err != nil {
			return s.failCodexIntent(ctx, intent, meta, "delivery_create", err)
		}
		meta.DeliveryContainerID = info.ID
		meta.DeliveryContainerIDs = appendUniqueContainerID(meta.DeliveryContainerIDs, info.ID)
		meta.ContainerID = info.ID
		meta.DeliveryImageDigest = info.ImageDigest
		meta.DeliveryPlatform = info.Platform
		meta.Phase = codexPhaseDeliveryStart
		if err := s.persistCodexIntent(ctx, intent, meta, intentStateContainerMade); err != nil {
			return LaunchAgentOutput{}, err
		}
		if info.Lifecycle == "" {
			info.Lifecycle = ContainerNeverStarted
		}
	} else {
		status, inspectErr := s.runtime.Inspect(ctx, meta.DeliveryContainerID)
		if inspectErr != nil {
			return s.failCodexIntent(ctx, intent, meta, "delivery_reconcile", inspectErr)
		}
		info = ContainerInfo{ID: meta.DeliveryContainerID, Status: status, Lifecycle: lifecycleForStatus(status)}
	}
	if info.Lifecycle == ContainerExited {
		return s.completeDelivery(ctx, intent, meta, info.Status)
	}
	if info.Lifecycle == ContainerNeverStarted {
		meta.Phase = codexPhaseDeliveryStart
		if err := s.persistCodexIntent(ctx, intent, meta, intentStateStartPending); err != nil {
			return LaunchAgentOutput{}, err
		}
		if err := s.runtime.Start(ctx, meta.DeliveryContainerID); err != nil {
			status, inspectErr := s.runtime.Inspect(ctx, meta.DeliveryContainerID)
			if inspectErr == nil && !status.StartedAt.IsZero() {
				if status.Running {
					info.Status = status
				} else {
					return s.completeDelivery(ctx, intent, meta, status)
				}
			} else {
				return s.failCodexIntent(ctx, intent, meta, "delivery_start", err)
			}
		}
	}
	meta.Status = StatusRunning
	meta.Phase = codexPhaseDeliveryRunning
	if meta.DeliveryStartedAt.IsZero() {
		meta.DeliveryStartedAt = time.Now().UTC()
	}
	if err := s.persistCodexIntent(ctx, intent, meta, intentStateRunning); err != nil {
		return LaunchAgentOutput{}, err
	}
	s.watchCodexPhase(meta.RunID, meta.DeliveryContainerID)
	return launchOutput(meta), nil
}

func (s *Service) completeDelivery(
	ctx context.Context,
	intent *launchIntent,
	meta RunMetadata,
	status ContainerStatus,
) (LaunchAgentOutput, error) {
	meta.DeliveryEndedAt = terminalTime(status)
	meta.Phase = codexPhaseDeliveryTerm
	meta.Status = StatusRunning
	if err := s.persistCodexIntent(ctx, intent, meta, intentStateRunning); err != nil {
		return LaunchAgentOutput{}, err
	}
	if status.ExitCode != nil && *status.ExitCode != 0 {
		if *status.ExitCode == 75 {
			if wait, err := s.readGitHubExternalWait(meta, "delivery"); err == nil {
				return s.waitForGitHub(ctx, intent, meta, wait)
			}
		}
		if stale, err := s.readStaleLease(meta); err == nil && meta.RecoveryCount == 0 {
			meta.RecoveryExpectedHeadSHA = stale.ExpectedHeadSHA
			meta.RecoveryWinnerHeadSHA = stale.WinnerHeadSHA
			meta.RecoveryCandidateHeadSHA = stale.CandidateHeadSHA
			meta.RecoveryCandidateTreeSHA = stale.CandidateTreeSHA
			meta.RecoverySealSHA256 = stale.SealSHA256
			meta.Phase, meta.ContainerID = codexPhaseRecoveryCreate, ""
			profile := s.cfg.LaunchProfiles[meta.Profile]
			if err := s.persistCodexIntent(ctx, intent, meta, intentStateRunning); err != nil {
				return LaunchAgentOutput{}, err
			}
			return s.resumeRecoveryValidation(ctx, intent, meta, *profile.CodexIssueWorkflow)
		}
	}
	finalized, _, err := s.finalizeTerminalRun(ctx, meta.RunID, finalizeReasonWorkerExit, terminalSourceExited, func(current RunMetadata) RunMetadata {
		return s.finalizeExitedRun(ctx, current, status)
	})
	return launchOutput(finalized), err
}

func (s *Service) waitForGitHub(ctx context.Context, intent *launchIntent, meta RunMetadata, report githubExternalWaitReport) (LaunchAgentOutput, error) {
	now := time.Now().UTC()
	meta.Status = StatusWaitingExternal
	meta.Error = ""
	meta.ExitCode = nil
	meta.ExternalWait = &ExternalWait{
		Service: report.Service, Phase: report.Phase, Operation: report.Operation,
		Reason: report.Reason, Generation: meta.ResumeGeneration + 1, Since: now,
	}
	if err := s.persistCodexIntent(ctx, intent, meta, intentStateWaitingExternal); err != nil {
		return LaunchAgentOutput{}, err
	}
	s.audit.Log(s.auditEvent("run_waiting_external", meta, "allow", nil), s.redactor(meta))
	return launchOutput(meta), nil
}

func (s *Service) readGitHubExternalWait(meta RunMetadata, phase string) (githubExternalWaitReport, error) {
	path := filepath.Join(s.runDir(meta.RunID), "output", "external-wait.json")
	data, err := boundedRegularFile(path, 4096)
	if err != nil {
		return githubExternalWaitReport{}, err
	}
	var report githubExternalWaitReport
	if err := json.Unmarshal(data, &report); err != nil {
		return githubExternalWaitReport{}, err
	}
	validOperation := false
	switch phase {
	case "preparation":
		validOperation = contains([]string{"issue.read", "issue_comments.read", "pull.read", "ci.observe", "actions_job_log.read"}, report.Operation)
	case "delivery":
		validOperation = contains([]string{"pull.read", "pull.reconcile", "pull.create", "git.push"}, report.Operation)
	}
	if report.Version != "github-external-wait/v1" || report.Status != StatusWaitingExternal ||
		report.RunID != meta.RunID || report.Repository != meta.Repo || report.Branch != meta.Branch ||
		report.Service != "github" || report.Phase != phase || !validOperation ||
		!contains([]string{"unavailable", "rate_limited"}, report.Reason) {
		return githubExternalWaitReport{}, fmt.Errorf("invalid structured GitHub external-wait report")
	}
	return report, nil
}

func (s *Service) watchCodexPhase(runID, containerID string) {
	go func() {
		status, err := s.runtime.Wait(context.Background(), containerID)
		unlock := s.lockLaunchIntent("codex\x00" + runID)
		defer unlock()
		intent, found, lookupErr := s.launchIntents.LookupRun(context.Background(), runID)
		if lookupErr != nil || !found || isTerminalStatus(intent.Metadata.Status) {
			return
		}
		if err != nil {
			if _, failErr := s.failCodexIntent(context.Background(), &intent, intent.Metadata, "container_wait", err); failErr != nil {
				s.auditFinalizeFailure(runID, "codex_container_wait_failed", "codex_container_wait", failErr)
			}
			return
		}
		profile := s.cfg.LaunchProfiles[intent.Profile]
		if intent.Metadata.Phase == codexPhasePreparationRunning {
			if _, completeErr := s.completePreparation(context.Background(), &intent, intent.Metadata, *profile.CodexIssueWorkflow, status); completeErr != nil {
				s.auditFinalizeFailure(runID, "codex_preparation_failed", "codex_preparation", completeErr)
			}
			return
		}
		if intent.Metadata.Phase == codexPhaseExecutionRunning {
			if _, completeErr := s.completeExecution(context.Background(), &intent, intent.Metadata, status); completeErr != nil {
				s.auditFinalizeFailure(runID, "codex_execution_failed", "codex_execution", completeErr)
			}
			return
		}
		if intent.Metadata.Phase == codexPhaseRecoveryRunning {
			if _, completeErr := s.completeRecoveryValidation(context.Background(), &intent, intent.Metadata, *profile.CodexIssueWorkflow, status); completeErr != nil {
				s.auditFinalizeFailure(runID, "codex_recovery_validation_failed", "codex_recovery_validation", completeErr)
			}
			return
		}
		if intent.Metadata.Phase == codexPhaseDeliveryRunning {
			if _, completeErr := s.completeDelivery(context.Background(), &intent, intent.Metadata, status); completeErr != nil {
				s.auditFinalizeFailure(runID, "codex_delivery_failed", "codex_delivery", completeErr)
			}
		}
	}()
}

func (s *Service) failCodexIntent(
	ctx context.Context,
	intent *launchIntent,
	meta RunMetadata,
	stage string,
	cause error,
) (LaunchAgentOutput, error) {
	if stopErr := s.stopCurrentCodexPhase(ctx, meta); stopErr != nil {
		cause = errors.Join(cause, stopErr)
	}
	meta.Status = StatusFailed
	meta.FinalizeReason = "codex_" + stage + "_failed"
	meta.TerminalSource = "codex_" + stage
	meta.EndedAt = time.Now().UTC()
	if cleanupErr := s.codexIssuer.Cleanup(meta.RunID); cleanupErr != nil {
		cause = errors.Join(cause, fmt.Errorf("clean Codex issuance state: %w", cleanupErr))
	}
	meta.Error = abbreviate(s.redactor(meta).Redact(cause.Error()), 500)
	if err := s.persistTerminalResult(meta); err != nil {
		return LaunchAgentOutput{}, err
	}
	intent.Metadata = meta
	intent.State = intentStateTerminal
	if err := s.launchIntents.Save(ctx, *intent); err != nil {
		return LaunchAgentOutput{}, err
	}
	if err := s.writeMetadataFile(meta); err != nil {
		return LaunchAgentOutput{}, err
	}
	s.mu.Lock()
	cp := meta
	s.runs[meta.RunID] = &cp
	s.mu.Unlock()
	s.auditTerminalEvent(meta, meta.FinalizeReason, meta.TerminalSource, cause)
	return launchOutput(meta), nil
}

func (s *Service) stopCurrentCodexPhase(ctx context.Context, meta RunMetadata) error {
	containerID, phase := currentCodexPhaseContainer(meta)
	if containerID == "" {
		return nil
	}

	stopCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.cfg.StopGrace.Duration+5*time.Second)
	defer cancel()

	status, inspectErr := s.runtime.Inspect(stopCtx, containerID)
	if inspectErr == nil && !status.Running {
		return nil
	}

	stopErr := s.runtime.Stop(stopCtx, containerID, s.cfg.StopGrace.Duration)
	verified, verifyErr := s.runtime.Inspect(stopCtx, containerID)
	if stopErr != nil {
		if code, ok := DockerStatusCode(stopErr); ok && code == http.StatusNotModified &&
			verifyErr == nil && !verified.Running {
			return nil
		}
		err := fmt.Errorf("stop current Codex %s container %q: %w", phase, containerID, stopErr)
		if verifyErr != nil {
			return errors.Join(err, fmt.Errorf("verify current Codex %s container stopped: %w", phase, verifyErr))
		}
		if verified.Running {
			return errors.Join(err, fmt.Errorf("current Codex %s container remains running", phase))
		}
		return err
	}
	if verifyErr != nil {
		return fmt.Errorf("verify current Codex %s container %q stopped: %w", phase, containerID, verifyErr)
	}
	if verified.Running {
		return fmt.Errorf("verify current Codex %s container %q stopped: container remains running", phase, containerID)
	}
	return nil
}

func currentCodexPhaseContainer(meta RunMetadata) (string, string) {
	switch meta.Phase {
	case codexPhasePreparationStart, codexPhasePreparationRunning, codexPhasePreparationRecon,
		codexPhasePreparationTerm:
		return meta.PreparationContainerID, "preparation"
	case codexPhaseExecutionStart, codexPhaseBundleInject, codexPhaseBundleAccept,
		codexPhaseExecutionRunning, codexPhaseExecutionRecon, codexPhaseExecutionTerm:
		return meta.ExecutionContainerID, "execution"
	case codexPhaseRecoveryStart, codexPhaseRecoveryRunning, codexPhaseRecoveryTerm:
		return meta.RecoveryContainerID, "recovery validation"
	case codexPhaseDeliveryStart, codexPhaseDeliveryRunning, codexPhaseDeliveryRecon,
		codexPhaseDeliveryTerm:
		return meta.DeliveryContainerID, "delivery"
	default:
		return "", ""
	}
}

func (s *Service) persistCodexIntent(
	ctx context.Context,
	intent *launchIntent,
	meta RunMetadata,
	state string,
) error {
	intent.Metadata = meta
	intent.State = state
	if err := s.launchIntents.Save(ctx, *intent); err != nil {
		return err
	}
	if err := s.writeMetadataFile(meta); err != nil {
		return err
	}
	s.mu.Lock()
	cp := meta
	s.runs[meta.RunID] = &cp
	s.mu.Unlock()
	return nil
}

func (s *Service) readPreparationResult(meta RunMetadata) (preparationResult, error) {
	path := filepath.Join(s.runDir(meta.RunID), "work", "prepared", "preparation.json")
	data, err := boundedRegularFile(path, 4096)
	if err != nil {
		return preparationResult{}, fmt.Errorf("bounded preparation result is unavailable")
	}
	var result preparationResult
	if err := json.Unmarshal(data, &result); err != nil {
		return preparationResult{}, fmt.Errorf("preparation result is invalid")
	}
	if result.Version != "codex-preparation-result/v1" || result.Status != "prepared" ||
		result.RunID != meta.RunID || result.Repository != meta.Repo || result.Branch != meta.Branch ||
		result.IssueNumber != meta.Provenance.IssueNumber ||
		result.SourceDeliveryID != meta.Provenance.SourceDeliveryID ||
		!regexpSHA(result.WorkspaceHead, 40) || !regexpSHA(result.RefsSHA256, 64) ||
		!regexpSHA(result.ManifestSHA256, 64) {
		return preparationResult{}, fmt.Errorf("preparation result does not match broker launch identity")
	}
	if result.RepairPRNumber != 0 && (result.RepairPRNumber < 1 || result.RepairHeadRef == "" || !regexpSHA(result.RepairExpectedHeadSHA, 40)) {
		return preparationResult{}, fmt.Errorf("preparation repair authority is invalid")
	}
	return result, nil
}

func appendUniqueContainerID(ids []string, id string) []string {
	for _, existing := range ids {
		if existing == id {
			return ids
		}
	}
	return append(ids, id)
}

func (s *Service) writeRepairAuthority(meta RunMetadata) error {
	if meta.RepairPRNumber == 0 {
		return nil
	}
	b, err := json.Marshal(struct {
		PRNumber        int    `json:"pull_number"`
		HeadRef         string `json:"head_ref"`
		AdmittedHeadSHA string `json:"admitted_head_sha"`
	}{meta.RepairPRNumber, meta.RepairHeadRef, meta.RepairAdmittedHeadSHA})
	if err != nil {
		return err
	}
	return atomicWriteFile(filepath.Join(s.runDir(meta.RunID), "input", "repair-authority.json"), append(b, '\n'), 0o444)
}

func (s *Service) readExecutionResult(meta RunMetadata) (executionResult, error) {
	path := filepath.Join(s.runDir(meta.RunID), "work", "execution", "execution.json")
	data, err := boundedRegularFile(path, 4096)
	if err != nil {
		return executionResult{}, fmt.Errorf("bounded execution result is unavailable")
	}
	var result executionResult
	if err := json.Unmarshal(data, &result); err != nil {
		return executionResult{}, fmt.Errorf("execution result is invalid")
	}
	if result.Version != "codex-execution-result/v1" || result.Status != "executed" ||
		result.RunID != meta.RunID || result.Repository != meta.Repo || result.Branch != meta.Branch ||
		result.WorkspaceHead != meta.Provenance.WorkspaceHead || !regexpSHA(result.RefsSHA256, 64) ||
		!regexpSHA(result.DiffSHA256, 64) || !regexpSHA(result.ValidatedTreeSHA, 40) ||
		!regexpSHA(result.FinalSHA256, 64) || !regexpSHA(result.VerifySHA256, 64) ||
		result.Verification != "passed" || result.FinalSizeBytes < 1 ||
		result.FinalSizeBytes > int64(s.cfg.TerminalResultByteLimit) {
		return executionResult{}, fmt.Errorf("execution result does not match broker launch identity or bounds")
	}
	return result, nil
}

func (s *Service) readExecutionFailure(meta RunMetadata, exitCode *int) (executionFailure, error) {
	if exitCode == nil || *exitCode < 1 || *exitCode > 255 {
		return executionFailure{}, fmt.Errorf("container exit status is unavailable or invalid")
	}
	path := filepath.Join(s.runDir(meta.RunID), "work", "execution", "execution-failure.json")
	data, err := boundedRegularFile(path, 8192)
	if err != nil {
		return executionFailure{}, fmt.Errorf("bounded Codex failure diagnostic is unavailable")
	}
	var result executionFailure
	if err := json.Unmarshal(data, &result); err != nil {
		return executionFailure{}, fmt.Errorf("codex failure diagnostic is invalid")
	}
	validSource := result.DiagnosticSource == "event" || result.DiagnosticSource == "stderr" ||
		result.DiagnosticSource == "none" || result.DiagnosticSource == "oversize"
	if result.Version != "codex-execution-failure/v1" || result.Status != "failed" ||
		result.RunID != meta.RunID || result.Repository != meta.Repo || result.Branch != meta.Branch ||
		result.Stage != "codex" || result.ExitCode != *exitCode || !validSource ||
		result.Diagnostic == "" || len(result.Diagnostic) > 4096 ||
		result.EventsSizeBytes < 0 || result.EventsSizeBytes > 8*1024*1024 ||
		result.StderrSizeBytes < 0 || result.StderrSizeBytes > 8*1024*1024 ||
		!regexpSHA(result.EventsSHA256, 64) || !regexpSHA(result.StderrSHA256, 64) {
		return executionFailure{}, fmt.Errorf("codex failure diagnostic does not match broker launch identity or bounds")
	}
	return result, nil
}

func (s *Service) readStaleLease(meta RunMetadata) (recoveryValidationResult, error) {
	data, err := boundedRegularFile(filepath.Join(s.runDir(meta.RunID), "output", "stale-lease.json"), 2048)
	if err != nil {
		return recoveryValidationResult{}, err
	}
	var result recoveryValidationResult
	if err := json.Unmarshal(data, &result); err != nil || result.Version != "codex-stale-lease/v3" || result.Status != "stale_lease" ||
		result.RunID != meta.RunID || result.Repository != meta.Repo || result.Branch != meta.Branch ||
		!regexpSHA(result.ExpectedHeadSHA, 40) || !regexpSHA(result.WinnerHeadSHA, 40) || !regexpSHA(result.CandidateHeadSHA, 40) ||
		!regexpSHA(result.CandidateTreeSHA, 40) || !regexpSHA(result.SealSHA256, 64) ||
		result.SealSHA256 != recoverySeal(result.RunID, result.Repository, result.Branch, result.ExpectedHeadSHA, result.WinnerHeadSHA, result.CandidateHeadSHA, result.CandidateTreeSHA) {
		return recoveryValidationResult{}, fmt.Errorf("stale lease handoff is invalid")
	}
	return result, nil
}

func (s *Service) readRecoveryValidation(meta RunMetadata) error {
	data, err := boundedRegularFile(filepath.Join(s.runDir(meta.RunID), "work", "recovery", "recovery-validation.json"), 2048)
	if err != nil {
		return fmt.Errorf("bounded recovery validation result is unavailable")
	}
	var result recoveryValidationResult
	if err := json.Unmarshal(data, &result); err != nil || result.Version != "codex-recovery-validation/v1" || result.Status != "passed" ||
		result.RunID != meta.RunID || result.Repository != meta.Repo || result.Branch != meta.Branch ||
		result.WinnerHeadSHA != meta.RecoveryWinnerHeadSHA || result.CandidateHeadSHA != meta.RecoveryCandidateHeadSHA ||
		result.ValidatedTreeSHA != meta.RecoveryCandidateTreeSHA || result.SealSHA256 != meta.RecoverySealSHA256 ||
		!regexpSHA(result.WinnerHeadSHA, 40) || !regexpSHA(result.CandidateHeadSHA, 40) || !regexpSHA(result.ValidatedTreeSHA, 40) || !regexpSHA(result.VerifySHA256, 64) || !regexpSHA(result.SealSHA256, 64) {
		return fmt.Errorf("recovery validation result does not match broker launch identity")
	}
	return nil
}

func recoverySeal(runID, repository, branch, expected, winner, candidate, tree string) string {
	identity, err := json.Marshal(struct {
		Branch     string `json:"branch"`
		Candidate  string `json:"candidate_head_sha"`
		Tree       string `json:"candidate_tree_sha"`
		Expected   string `json:"expected_head_sha"`
		Repository string `json:"repository"`
		RunID      string `json:"run_id"`
		Winner     string `json:"winner_head_sha"`
	}{branch, candidate, tree, expected, repository, runID, winner})
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(identity)
	return hex.EncodeToString(sum[:])
}

func regexpSHA(value string, size int) bool {
	if len(value) != size {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' && r < 'a' || r > 'f' {
			return false
		}
	}
	return true
}

func lifecycleForStatus(status ContainerStatus) ContainerLifecycle {
	if status.Running {
		return ContainerRunning
	}
	if status.StartedAt.IsZero() {
		return ContainerNeverStarted
	}
	return ContainerExited
}

func terminalTime(status ContainerStatus) time.Time {
	if !status.EndedAt.IsZero() {
		return status.EndedAt
	}
	return time.Now().UTC()
}
