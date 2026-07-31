package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
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
	codexPhaseExecutionCreate    = "execution_create_pending"
	codexPhaseExecutionStart     = "execution_start_pending"
	codexPhaseBundleInject       = "bundle_inject_pending"
	codexPhaseBundleAccept       = "bundle_accept_pending"
	codexPhaseExecutionRunning   = "execution_running"
)

type preparationResult struct {
	Version          string `json:"version"`
	Status           string `json:"status"`
	RunID            string `json:"run_id"`
	Repository       string `json:"repository"`
	Branch           string `json:"branch"`
	WorkspaceHead    string `json:"workspace_head"`
	ManifestSHA256   string `json:"manifest_sha256"`
	IssueNumber      int    `json:"issue_number"`
	SourceDeliveryID string `json:"source_delivery_id"`
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
		go s.watchTimeout(context.WithoutCancel(ctx), meta.RunID, meta.Deadline)
	}
	if err := s.prepareDurableRun(meta, s.cfg.Templates[workflow.ExecutionTemplate]); err != nil {
		return LaunchAgentOutput{}, err
	}
	if meta.Phase == "" {
		meta.Phase = codexPhasePreparationCreate
	}

	switch meta.Phase {
	case codexPhasePreparationCreate, codexPhasePreparationStart, codexPhasePreparationRunning:
		return s.resumePreparation(ctx, intent, meta, *workflow)
	case codexPhaseExecutionCreate, codexPhaseExecutionStart, codexPhaseBundleInject,
		codexPhaseBundleAccept, codexPhaseExecutionRunning:
		return s.resumeExecution(ctx, intent, meta, *workflow)
	default:
		return s.failCodexIntent(ctx, intent, meta, "state_reconciliation", fmt.Errorf("unsupported Codex workflow phase %q", meta.Phase))
	}
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
	spec.RunID = meta.RunID + "-prep"
	spec.Labels["gh-agent-broker.parent_run_id"] = meta.RunID
	spec.Labels["gh-agent-broker.run_id"] = spec.RunID
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
	if status.ExitCode == nil || *status.ExitCode != 0 {
		return s.failCodexIntent(ctx, intent, meta, "preparation", fmt.Errorf("credential-free preparation failed"))
	}
	result, err := s.readPreparationResult(meta)
	if err != nil {
		return s.failCodexIntent(ctx, intent, meta, "preparation_verification", err)
	}
	meta.Provenance.WorkspaceHead = result.WorkspaceHead
	meta.Provenance.ManifestSHA256 = result.ManifestSHA256
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
	template := s.cfg.Templates[workflow.ExecutionTemplate]
	spec, _, err := s.runtimeSpec(meta, template)
	if err != nil {
		return LaunchAgentOutput{}, err
	}
	spec.RunID = meta.RunID + "-exec"
	spec.Labels["gh-agent-broker.parent_run_id"] = meta.RunID
	spec.Labels["gh-agent-broker.run_id"] = spec.RunID
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
		bundle, issueErr := s.codexIssuer.Issue(ctx, meta.RunID)
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
	meta.Status = StatusRunning
	if err := s.persistCodexIntent(ctx, intent, meta, intentStateRunning); err != nil {
		return LaunchAgentOutput{}, err
	}
	finalized, _, err := s.finalizeTerminalRun(ctx, meta.RunID, finalizeReasonWorkerExit, terminalSourceExited, func(current RunMetadata) RunMetadata {
		return s.finalizeExitedRun(ctx, current, status)
	})
	return launchOutput(finalized), err
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
	return launchOutput(meta), nil
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
		!regexpSHA(result.WorkspaceHead, 40) || !regexpSHA(result.ManifestSHA256, 64) {
		return preparationResult{}, fmt.Errorf("preparation result does not match broker launch identity")
	}
	return result, nil
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
