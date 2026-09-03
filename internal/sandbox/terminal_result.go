package sandbox

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	terminalResultVersion = "repository-task-terminal-result/v1"
	workerResultVersion   = "repository-task-worker-result/v1"
)

// TerminalResult is the only worker-produced output available to the terminal
// reporter. It intentionally excludes logs and arbitrary artifacts.
type TerminalResult struct {
	Version               string              `json:"version"`
	RunID                 string              `json:"run_id"`
	Profile               string              `json:"profile"`
	Repo                  string              `json:"repo"`
	Branch                string              `json:"branch,omitempty"`
	Status                string              `json:"status"`
	Outcome               string              `json:"outcome"`
	FinalizeReason        string              `json:"finalize_reason,omitempty"`
	TerminalSource        string              `json:"terminal_source,omitempty"`
	IdempotencyKeyDigest  string              `json:"idempotency_key_digest,omitempty"`
	RequestFingerprint    string              `json:"request_fingerprint,omitempty"`
	LaunchConfigVersion   string              `json:"launch_config_version,omitempty"`
	Result                map[string]any      `json:"result,omitempty"`
	FinalSummary          string              `json:"final_summary"`
	FailureStage          string              `json:"failure_stage,omitempty"`
	FailureReason         string              `json:"failure_reason,omitempty"`
	ModelExecutionStarted bool                `json:"model_execution_started"`
	FailureClass          string              `json:"failure_class,omitempty"`
	Provenance            *TerminalProvenance `json:"provenance,omitempty"`
}

type TerminalProvenance struct {
	ModelPolicy            string         `json:"model_policy"`
	ModelPolicyVersion     string         `json:"model_policy_version"`
	Model                  string         `json:"model"`
	Effort                 string         `json:"effort"`
	CodexVersion           string         `json:"codex_version"`
	PromptRevision         string         `json:"prompt_revision"`
	WorkerImageDigest      string         `json:"worker_image_digest"`
	WorkerPlatform         string         `json:"worker_platform"`
	PreparationImageDigest string         `json:"preparation_image_digest"`
	PreparationPlatform    string         `json:"preparation_platform"`
	WorkspaceHead          string         `json:"workspace_head"`
	ManifestSHA256         string         `json:"manifest_sha256"`
	IssueNumber            int            `json:"issue_number"`
	SourceDeliveryID       string         `json:"source_delivery_id"`
	PreparationStartedAt   string         `json:"preparation_started_at,omitempty"`
	PreparationEndedAt     string         `json:"preparation_ended_at,omitempty"`
	ExecutionStartedAt     string         `json:"execution_started_at,omitempty"`
	ExecutionEndedAt       string         `json:"execution_ended_at,omitempty"`
	DeliveryImageDigest    string         `json:"delivery_image_digest,omitempty"`
	DeliveryPlatform       string         `json:"delivery_platform,omitempty"`
	DeliveryStartedAt      string         `json:"delivery_started_at,omitempty"`
	DeliveryEndedAt        string         `json:"delivery_ended_at,omitempty"`
	VerificationTask       string         `json:"verification_task,omitempty"`
	VerificationResult     string         `json:"verification_result,omitempty"`
	Usage                  map[string]any `json:"usage,omitempty"`
}

func (s *Service) terminalResultPath(runID string) string {
	return filepath.Join(s.runDir(runID), "terminal-result.json")
}

func (s *Service) persistTerminalResult(meta RunMetadata) error {
	result := s.projectTerminalResult(meta)
	b, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(s.terminalResultPath(meta.RunID), append(b, '\n'), 0o600)
}

func (s *Service) GetTerminalResult(_ context.Context, in RunInput) (TerminalResult, error) {
	meta, err := s.lookupRun(in.RunID)
	if err != nil {
		return TerminalResult{}, err
	}
	if !isTerminalStatus(meta.Status) {
		return TerminalResult{}, fmt.Errorf("terminal result is not available")
	}
	b, err := os.ReadFile(s.terminalResultPath(meta.RunID)) // #nosec G304 -- run ID is validated by lookupRun.
	if err != nil {
		return TerminalResult{}, fmt.Errorf("terminal result unavailable")
	}
	var result TerminalResult
	if err := json.Unmarshal(b, &result); err != nil || result.Version != terminalResultVersion || result.RunID != meta.RunID {
		return TerminalResult{}, fmt.Errorf("terminal result unavailable")
	}
	return result, nil
}

func (s *Service) projectTerminalResult(meta RunMetadata) TerminalResult {
	result := TerminalResult{
		Version: terminalResultVersion, RunID: meta.RunID, Profile: meta.Profile,
		Repo: meta.Repo, Branch: meta.Branch, Status: meta.Status,
		FinalizeReason: meta.FinalizeReason, TerminalSource: meta.TerminalSource,
		IdempotencyKeyDigest: meta.IdempotencyKeyDigest, RequestFingerprint: meta.RequestFingerprint,
		LaunchConfigVersion:   meta.LaunchConfigVersion,
		ModelExecutionStarted: !meta.ExecutionStartedAt.IsZero(),
	}
	if meta.Provenance != nil {
		result.Provenance = s.terminalProvenance(meta)
	}
	if meta.Provenance != nil && meta.Error != "" && strings.HasPrefix(meta.TerminalSource, "codex_") {
		result.Outcome = StatusFailed
		result.FailureStage = strings.TrimPrefix(meta.TerminalSource, "codex_")
		reason := s.redactor(meta).Redact(meta.Error)
		if !meta.ExecutionStartedAt.IsZero() {
			if scanFailure := s.codexTokenScanFailure(meta); scanFailure != "" {
				reason = scanFailure
			} else if summary, outputFailure := s.readCodexFinalOutput(meta); outputFailure != "" {
				reason += "; " + outputFailure
			} else {
				result.FinalSummary = summary
			}
		}
		result.FailureReason = abbreviate(reason, 500)
		result.FailureClass = codexFailureClass(meta)
		return result
	}
	if meta.TerminalSource == terminalSourceStartupFailure && meta.Error != "" {
		result.Outcome = StatusFailed
		result.FailureStage = "sandbox_startup"
		result.FailureReason = abbreviate(s.redactor(meta).Redact(meta.Error), 500)
		result.FailureClass = "infrastructure"
		return result
	}
	workerResult, summary, stage, reason := s.readWorkerTerminalOutput(meta)
	if reason != "" {
		result.Outcome = fallbackOutcome(meta.Status)
		result.FailureStage, result.FailureReason = stage, reason
		result.FailureClass = "delivery"
		return result
	}
	result.Result, result.FinalSummary = workerResult, summary
	if result.Provenance != nil {
		if verification, ok := workerResult["verification"].(map[string]any); ok {
			if status, ok := verification["status"].(string); ok &&
				(status == "passed" || status == "failed" || status == "not_run") {
				result.Provenance.VerificationResult = status
			}
		}
	}
	if outcome, ok := workerResult["outcome"].(string); ok && outcome != "" {
		result.Outcome = outcome
	} else {
		result.Outcome = fallbackOutcome(meta.Status)
		result.FailureStage, result.FailureReason = "terminal_result", "result.json is missing outcome"
		result.FailureClass = "delivery"
		result.Result, result.FinalSummary = nil, ""
	}
	return result
}

// failure_class is intentionally small and stable; finalize_reason remains
// diagnostic detail rather than a machine-facing taxonomy.
func codexFailureClass(meta RunMetadata) string {
	stage := strings.TrimPrefix(meta.TerminalSource, "codex_")
	switch {
	case strings.HasPrefix(stage, "preparation"), strings.HasPrefix(stage, "credential"), strings.HasPrefix(stage, "execution_create"), strings.HasPrefix(stage, "execution_start"), strings.HasPrefix(stage, "bundle"):
		return "infrastructure"
	case strings.HasPrefix(stage, "execution"), strings.HasPrefix(stage, "timeout"):
		return "model_or_code"
	case strings.HasPrefix(stage, "recovery"), strings.HasPrefix(stage, "delivery"), strings.HasPrefix(stage, "stale"):
		return "delivery_or_lease"
	default:
		return "infrastructure"
	}
}

func (s *Service) readCodexFinalOutput(meta RunMetadata) (string, string) {
	data, err := boundedRegularFile(
		filepath.Join(s.runDir(meta.RunID), "output", "codex-final.txt"),
		s.cfg.TerminalResultByteLimit,
	)
	if err != nil {
		return "", terminalOutputError("codex-final.txt", err) + " after Codex execution began"
	}
	if len(data) == 0 {
		return "", "codex-final.txt is empty after Codex execution began"
	}
	if !utf8.Valid(data) {
		return "", "codex-final.txt is not valid UTF-8 after Codex execution began"
	}
	return string(data), ""
}

func (s *Service) codexTokenScanFailure(meta RunMetadata) string {
	runDir := s.runDir(meta.RunID)
	marker, err := boundedRegularFile(filepath.Join(runDir, "output", "codex-token-scan-failure"), 32)
	if err != nil {
		return ""
	}
	if string(marker) == "purge_failed\n" {
		return "credential contamination cleanup could not be verified; host-backed artifacts remain quarantined and delivery is blocked"
	}
	for _, relative := range []string{"work", "lessons"} {
		entries, readErr := os.ReadDir(filepath.Join(runDir, relative))
		if readErr != nil || len(entries) != 0 {
			return ""
		}
	}
	outputEntries, err := os.ReadDir(filepath.Join(runDir, "output"))
	if err != nil || len(outputEntries) != 1 || outputEntries[0].Name() != "codex-token-scan-failure" {
		return ""
	}
	switch string(marker) {
	case "contamination\n":
		return "exact task-credential contamination detected; disposable execution artifacts were purged"
	case "incomplete\n":
		return "task-credential scan was incomplete; disposable execution artifacts were purged"
	default:
		return ""
	}
}

func (s *Service) terminalProvenance(meta RunMetadata) *TerminalProvenance {
	provenance := &TerminalProvenance{
		ModelPolicy: meta.Provenance.ModelPolicy, ModelPolicyVersion: meta.Provenance.ModelPolicyVersion,
		Model: meta.Provenance.Model, Effort: meta.Provenance.Effort, CodexVersion: meta.Provenance.CodexVersion,
		PromptRevision: meta.Provenance.PromptRevision, WorkerImageDigest: meta.ImageDigest,
		WorkerPlatform: meta.ExecutionPlatform, PreparationImageDigest: meta.PreparationImageDigest,
		PreparationPlatform: meta.PreparationPlatform, WorkspaceHead: meta.Provenance.WorkspaceHead,
		ManifestSHA256: meta.Provenance.ManifestSHA256, IssueNumber: meta.Provenance.IssueNumber,
		SourceDeliveryID: meta.Provenance.SourceDeliveryID, VerificationTask: meta.VerificationTask,
		DeliveryImageDigest: meta.DeliveryImageDigest, DeliveryPlatform: meta.DeliveryPlatform,
	}
	for value, target := range map[time.Time]*string{
		meta.PreparationStartedAt: &provenance.PreparationStartedAt,
		meta.PreparationEndedAt:   &provenance.PreparationEndedAt,
		meta.ExecutionStartedAt:   &provenance.ExecutionStartedAt,
		meta.ExecutionEndedAt:     &provenance.ExecutionEndedAt,
		meta.DeliveryStartedAt:    &provenance.DeliveryStartedAt,
		meta.DeliveryEndedAt:      &provenance.DeliveryEndedAt,
	} {
		if !value.IsZero() {
			*target = value.UTC().Format(time.RFC3339Nano)
		}
	}
	path := filepath.Join(s.runDir(meta.RunID), "output", "codex-usage.json")
	if data, err := boundedRegularFile(path, 4096); err == nil {
		var usage map[string]any
		if json.Unmarshal(data, &usage) == nil && boundedUsage(usage) {
			provenance.Usage = usage
		}
	}
	return provenance
}

func boundedUsage(usage map[string]any) bool {
	if len(usage) > 4 {
		return false
	}
	for key, value := range usage {
		switch key {
		case "input_tokens", "cached_input_tokens", "output_tokens":
			number, ok := value.(float64)
			if !ok || number < 0 || number > 1_000_000_000 || number != math.Trunc(number) {
				return false
			}
		case "status":
			text, ok := value.(string)
			if !ok || len(text) > 32 {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func (s *Service) readWorkerTerminalOutput(meta RunMetadata) (map[string]any, string, string, string) {
	redactor := s.redactor(meta)
	resultBytes, err := boundedRegularFile(filepath.Join(s.runDir(meta.RunID), "output", "result.json"), s.cfg.TerminalResultByteLimit)
	if err != nil {
		return nil, "", "terminal_result", terminalOutputError("result.json", err)
	}
	var result map[string]any
	if err := json.Unmarshal(resultBytes, &result); err != nil || result == nil {
		return nil, "", "terminal_result", "result.json is not a JSON object"
	}
	redactJSON(result, redactor)
	if err := s.normalizeLegacyWorkerResult(meta, result, redactor); err != nil {
		return nil, "", "terminal_result", err.Error()
	}
	if meta.Provenance != nil {
		if err := validateCodexWorkerResult(meta, result); err != nil {
			return nil, "", "terminal_result", err.Error()
		}
	}
	redactedResult, err := json.Marshal(result)
	if err != nil || len(redactedResult) > s.cfg.TerminalResultByteLimit {
		return nil, "", "terminal_result", "result.json exceeds terminal_result_byte_limit after redaction"
	}
	summaryBytes, err := boundedRegularFile(filepath.Join(s.runDir(meta.RunID), "output", "final-summary.md"), s.cfg.TerminalResultByteLimit)
	if err != nil {
		return nil, "", "terminal_result", terminalOutputError("final-summary.md", err)
	}
	if !utf8.Valid(summaryBytes) {
		return nil, "", "terminal_result", "final-summary.md is not valid UTF-8"
	}
	summary := redactor.Redact(string(summaryBytes))
	if len(summary) > s.cfg.TerminalResultByteLimit {
		return nil, "", "terminal_result", "final-summary.md exceeds terminal_result_byte_limit after redaction"
	}
	return result, summary, "", ""
}

func validateCodexWorkerResult(meta RunMetadata, result map[string]any) error {
	for field, expected := range map[string]string{
		"version": workerResultVersion, "run_id": meta.RunID, "repository": meta.Repo,
		"base_branch": meta.BaseBranch,
	} {
		if actual, ok := result[field].(string); !ok || actual != expected {
			return fmt.Errorf("codex result.json %s does not match broker metadata", field)
		}
	}
	outcome, ok := result["outcome"].(string)
	if !ok || outcome != "no_change_required" && outcome != "ready_for_review" && outcome != StatusFailed {
		return fmt.Errorf("codex result.json outcome is unsupported")
	}
	verification, ok := result["verification"].(map[string]any)
	if !ok {
		return fmt.Errorf("codex result.json verification is missing")
	}
	status, ok := verification["status"].(string)
	if !ok || status != "passed" && status != "failed" && status != "not_run" {
		return fmt.Errorf("codex result.json verification status is unsupported")
	}
	if outcome != "ready_for_review" {
		return nil
	}
	pullRequest, ok := result["pull_request"].(map[string]any)
	if !ok {
		return fmt.Errorf("codex ready_for_review result is missing pull request identity")
	}
	number, numberOK := pullRequest["number"].(float64)
	htmlURL, htmlURLOK := pullRequest["html_url"].(string)
	apiURL, apiURLOK := pullRequest["url"].(string)
	if !numberOK || number < 1 || number != math.Trunc(number) ||
		!htmlURLOK || htmlURL == "" || !apiURLOK || apiURL == "" {
		return fmt.Errorf("codex ready_for_review pull request identity is invalid")
	}
	worker, workerOK := result["worker"].(string)
	if workerOK && worker == "codex" {
		for _, field := range []string{"branch", "expected_old_head_sha", "candidate_head_sha", "delivered_head_sha", "validated_tree_sha", "delivered_tree_sha"} {
			value, ok := result[field].(string)
			if !ok || (field == "branch" && value == "") || (field != "branch" && !isLowerHexSHA(value)) {
				return fmt.Errorf("codex ready_for_review result is missing valid %s", field)
			}
		}
		if result["delivered_tree_sha"] != result["validated_tree_sha"] {
			return fmt.Errorf("codex ready_for_review delivered tree does not match validated tree")
		}
	}
	return nil
}

func isLowerHexSHA(value string) bool {
	if len(value) != 40 {
		return false
	}
	for _, r := range value {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

func (s *Service) normalizeLegacyWorkerResult(meta RunMetadata, result map[string]any, redactor Redactor) error {
	if _, exists := result["version"]; exists {
		return nil
	}
	for field, expected := range map[string]string{
		"run_id":      meta.RunID,
		"repository":  meta.Repo,
		"base_branch": meta.BaseBranch,
		"branch":      meta.Branch,
	} {
		actual, ok := result[field].(string)
		if !ok || actual != expected {
			return fmt.Errorf("legacy result.json %s does not match broker metadata", field)
		}
	}
	outcome, ok := result["outcome"].(string)
	if !ok {
		return fmt.Errorf("legacy result.json is missing outcome")
	}
	verifyTask := ""
	if value, ok := result["verify_task"].(string); ok {
		verifyTask = value
	}
	verification := "not_run"
	switch outcome {
	case "no_change_required", "ready_for_review":
		if verifyTask != "" {
			verification = "passed"
		}
	case StatusFailed:
		if stage, ok := result["stage"].(string); ok && stage == "repository verification task" {
			verification = "failed"
		}
	default:
		return fmt.Errorf("legacy result.json outcome is unsupported")
	}
	if outcome == "ready_for_review" {
		pullRequest, err := s.readLegacyPullRequest(meta, redactor)
		if err != nil {
			return err
		}
		result["pull_request"] = pullRequest
	}
	result["version"] = workerResultVersion
	result["verification"] = map[string]any{"status": verification}
	return nil
}

func (s *Service) readLegacyPullRequest(meta RunMetadata, redactor Redactor) (map[string]any, error) {
	path := filepath.Join(s.runDir(meta.RunID), "output", "pull-request.json")
	contents, err := boundedRegularFile(path, s.cfg.TerminalResultByteLimit)
	if err != nil {
		return nil, fmt.Errorf("legacy ready_for_review result requires bounded pull-request.json")
	}
	var raw map[string]any
	if err := json.Unmarshal(contents, &raw); err != nil || raw == nil {
		return nil, fmt.Errorf("legacy pull-request.json is not a JSON object")
	}
	redactJSON(raw, redactor)
	number, numberOK := raw["number"].(float64)
	htmlURL, htmlURLOK := raw["html_url"].(string)
	apiURL, apiURLOK := raw["url"].(string)
	if !numberOK || number < 1 || number > math.MaxInt32 || number != math.Trunc(number) || !htmlURLOK || htmlURL == "" || !apiURLOK || apiURL == "" {
		return nil, fmt.Errorf("legacy pull-request.json is missing required identity")
	}
	return map[string]any{"number": number, "html_url": htmlURL, "url": apiURL}, nil
}

func boundedRegularFile(path string, limit int) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("not a regular file")
	}
	if info.Size() > int64(limit) {
		return nil, fmt.Errorf("exceeds terminal_result_byte_limit")
	}
	return os.ReadFile(path) // #nosec G304 -- fixed file below validated run directory.
}

func terminalOutputError(name string, err error) string {
	if os.IsNotExist(err) {
		return name + " is absent"
	}
	if strings.Contains(err.Error(), "exceeds terminal_result_byte_limit") {
		return name + " exceeds terminal_result_byte_limit"
	}
	return name + " is unavailable"
}

func fallbackOutcome(status string) string {
	switch status {
	case StatusTimedOut, StatusStopped, StatusCancelled:
		return status
	default:
		return StatusFailed
	}
}

func redactJSON(value any, redactor Redactor) {
	switch v := value.(type) {
	case map[string]any:
		for key, item := range v {
			if text, ok := item.(string); ok {
				v[key] = redactor.Redact(text)
			} else {
				redactJSON(item, redactor)
			}
		}
	case []any:
		for i := range v {
			if text, ok := v[i].(string); ok {
				v[i] = redactor.Redact(text)
			} else {
				redactJSON(v[i], redactor)
			}
		}
	}
}
