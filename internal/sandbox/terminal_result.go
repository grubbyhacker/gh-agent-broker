package sandbox

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

const (
	terminalResultVersion = "repository-task-terminal-result/v1"
	workerResultVersion   = "repository-task-worker-result/v1"
)

// TerminalResult is the only worker-produced output available to the terminal
// reporter. It intentionally excludes logs and arbitrary artifacts.
type TerminalResult struct {
	Version              string         `json:"version"`
	RunID                string         `json:"run_id"`
	Profile              string         `json:"profile"`
	Repo                 string         `json:"repo"`
	Branch               string         `json:"branch,omitempty"`
	Status               string         `json:"status"`
	Outcome              string         `json:"outcome"`
	FinalizeReason       string         `json:"finalize_reason,omitempty"`
	TerminalSource       string         `json:"terminal_source,omitempty"`
	IdempotencyKeyDigest string         `json:"idempotency_key_digest,omitempty"`
	RequestFingerprint   string         `json:"request_fingerprint,omitempty"`
	LaunchConfigVersion  string         `json:"launch_config_version,omitempty"`
	Result               map[string]any `json:"result,omitempty"`
	FinalSummary         string         `json:"final_summary"`
	FailureStage         string         `json:"failure_stage,omitempty"`
	FailureReason        string         `json:"failure_reason,omitempty"`
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
		LaunchConfigVersion: meta.LaunchConfigVersion,
	}
	workerResult, summary, stage, reason := s.readWorkerTerminalOutput(meta)
	if reason != "" {
		result.Outcome = fallbackOutcome(meta.Status)
		result.FailureStage, result.FailureReason = stage, reason
		return result
	}
	result.Result, result.FinalSummary = workerResult, summary
	if outcome, ok := workerResult["outcome"].(string); ok && outcome != "" {
		result.Outcome = outcome
	} else {
		result.Outcome = fallbackOutcome(meta.Status)
		result.FailureStage, result.FailureReason = "terminal_result", "result.json is missing outcome"
		result.Result, result.FinalSummary = nil, ""
	}
	return result
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
