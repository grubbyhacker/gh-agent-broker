package sandbox

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const defaultPruneMaxOutput = 200

const (
	reasonNotDirectory = "not_a_directory"
	reasonInvalidRunID = "invalid_run_id"
	reasonPathEscape   = "path_escape"
	reasonMetadataRead = "metadata_read_error"
	reasonNotTerminal  = "not_terminal"
	reasonActive       = "active"
	reasonKeepNewest   = "keep_newest"
	reasonTooNew       = "younger_than_max_age"
	reasonEligible     = "eligible"
	reasonDeleteAge    = "delete_age"
	reasonDeleteBudget = "delete_budget"
	reasonWithinBudget = "within_budget"
	reasonWouldDelete  = "would_delete"
	reasonDeleteFailed = "delete_failed"
	reasonDeleted      = "deleted"
	reasonRetained     = "retained"
)

type RetentionPolicy struct {
	MaxAge       time.Duration `json:"max_age"`
	KeepNewest   int           `json:"keep_newest"`
	TerminalOnly bool          `json:"terminal_only"`
	MaxBytes     int64         `json:"max_bytes"`
	DryRun       bool          `json:"dry_run"`
	MaxOutput    int           `json:"max_output"`
}

type PruneRun struct {
	RunID        string    `json:"run_id"`
	Status       string    `json:"status"`
	Template     string    `json:"template,omitempty"`
	Repo         string    `json:"repo,omitempty"`
	Branch       string    `json:"branch,omitempty"`
	LastActivity time.Time `json:"last_activity_at"`
	AgeSeconds   int64     `json:"age_seconds"`
	SizeBytes    int64     `json:"size_bytes"`
	Keep         bool      `json:"keep"`
	Delete       bool      `json:"delete"`
	Reason       string    `json:"reason"`
	Error        string    `json:"error,omitempty"`
}

type PruneReport struct {
	Timestamp    time.Time       `json:"timestamp"`
	RunsDir      string          `json:"runs_dir"`
	Policy       RetentionPolicy `json:"policy"`
	Scanned      int             `json:"scanned"`
	Considered   int             `json:"considered"`
	Deleted      int             `json:"deleted"`
	Failed       int             `json:"failed"`
	Skipped      int             `json:"skipped"`
	OutputLimit  int             `json:"output_limit"`
	BudgetBefore int64           `json:"budget_before_bytes,omitempty"`
	BudgetAfter  int64           `json:"budget_after_bytes,omitempty"`
	Truncated    bool            `json:"truncated"`
	Entries      []PruneRun      `json:"entries"`
	Errors       []string        `json:"errors,omitempty"`
}

type retentionCandidate struct {
	PruneRun
	meta      RunMetadata
	sizeKnown bool
}

func (p RetentionPolicy) normalize() RetentionPolicy {
	if p.MaxOutput <= 0 {
		p.MaxOutput = defaultPruneMaxOutput
	}
	if p.KeepNewest < 0 {
		p.KeepNewest = 0
	}
	if p.MaxAge == 0 {
		p.MaxAge = 24 * time.Hour
	}
	if p.MaxBytes < 0 {
		p.MaxBytes = 0
	}
	return p
}

func (p RetentionPolicy) maxAgeReached(at time.Time, now time.Time) bool {
	if p.MaxAge < 0 {
		return true
	}
	if p.MaxAge == 0 {
		return false
	}
	if at.IsZero() {
		return false
	}
	return now.Sub(at) >= p.MaxAge
}

func (s *Service) PruneRuns(ctx context.Context, policy RetentionPolicy) (PruneReport, error) {
	policy = policy.normalize()
	report := PruneReport{
		Timestamp:   time.Now().UTC(),
		RunsDir:     s.cfg.RunsDir,
		Policy:      policy,
		OutputLimit: policy.MaxOutput,
	}

	entries, err := os.ReadDir(s.cfg.RunsDir)
	if err != nil {
		if os.IsNotExist(err) {
			if mkErr := os.MkdirAll(s.cfg.RunsDir, 0o700); mkErr != nil {
				report.Errors = append(report.Errors, trimError(mkErr))
				return report, mkErr
			}
			return report, nil
		}
		report.Errors = append(report.Errors, trimError(err))
		return report, err
	}

	now := time.Now().UTC()
	candidates := make([]retentionCandidate, 0, len(entries))

	for _, entry := range entries {
		report.Scanned++
		switch {
		case entry.Type()&os.ModeSymlink != 0:
			report.Skipped++
			candidates = append(candidates, retentionCandidate{PruneRun: PruneRun{
				RunID:  entry.Name(),
				Reason: reasonNotDirectory,
			}})
			continue
		case !entry.IsDir():
			report.Skipped++
			candidates = append(candidates, retentionCandidate{PruneRun: PruneRun{
				RunID:  entry.Name(),
				Reason: reasonNotDirectory,
			}})
			continue
		}

		runID := entry.Name()
		if !safeRunID(runID) {
			report.Skipped++
			candidates = append(candidates, retentionCandidate{PruneRun: PruneRun{
				RunID:  runID,
				Reason: reasonInvalidRunID,
			}})
			continue
		}

		runDir := s.runDir(runID)
		if escapesBase(s.cfg.RunsDir, runDir) {
			report.Skipped++
			candidates = append(candidates, retentionCandidate{PruneRun: PruneRun{
				RunID:  runID,
				Reason: reasonPathEscape,
			}})
			continue
		}

		meta, readErr := readMetadata(filepath.Join(runDir, "metadata.json"))
		if readErr != nil {
			report.Skipped++
			candidates = append(candidates, retentionCandidate{PruneRun: PruneRun{
				RunID:  runID,
				Reason: reasonMetadataRead,
				Error:  trimError(readErr),
			}})
			continue
		}

		size, sizeErr := runDirSizeBytes(runDir)
		lastActivity := runLastActivity(meta, runDir)
		ageSeconds := int64(now.Sub(lastActivity).Seconds())
		if ageSeconds < 0 {
			ageSeconds = 0
		}

		candidate := retentionCandidate{
			meta: meta,
			PruneRun: PruneRun{
				RunID:        runID,
				Status:       meta.Status,
				Template:     meta.Template,
				Repo:         meta.Repo,
				Branch:       meta.Branch,
				LastActivity: lastActivity,
				AgeSeconds:   ageSeconds,
				SizeBytes:    size,
				Reason:       reasonEligible,
			},
		}
		if sizeErr != nil {
			candidate.Error = trimError(sizeErr)
			candidate.sizeKnown = false
		} else {
			candidate.sizeKnown = true
		}

		switch {
		case !isTerminalStatus(meta.Status) && policy.TerminalOnly:
			candidate.Reason = reasonNotTerminal
		case hasActiveStatus(meta.Status):
			candidate.Reason = reasonActive
		}
		candidates = append(candidates, candidate)
		report.Considered++
	}

	active := make([]*retentionCandidate, 0, len(candidates))
	for i := range candidates {
		if candidates[i].Reason == reasonEligible {
			active = append(active, &candidates[i])
		}
	}

	sort.SliceStable(active, func(i, j int) bool {
		if active[i].LastActivity.Equal(active[j].LastActivity) {
			return active[i].RunID < active[j].RunID
		}
		return active[i].LastActivity.After(active[j].LastActivity)
	})

	for i := 0; i < policy.KeepNewest && i < len(active); i++ {
		active[i].Keep = true
		active[i].Reason = reasonKeepNewest
	}

	selected := make([]*retentionCandidate, 0, len(active))
	for _, candidate := range active {
		if candidate.Keep {
			continue
		}
		if !policy.maxAgeReached(candidate.LastActivity, now) {
			candidate.Reason = reasonTooNew
			continue
		}
		candidate.Reason = reasonEligible
		selected = append(selected, candidate)
	}

	report.BudgetBefore = 0
	for _, candidate := range selected {
		if candidate.sizeKnown {
			report.BudgetBefore += candidate.SizeBytes
		}
	}

	report.BudgetAfter = report.BudgetBefore
	if policy.MaxBytes > 0 && report.BudgetBefore > policy.MaxBytes {
		sort.SliceStable(selected, func(i, j int) bool {
			if selected[i].LastActivity.Equal(selected[j].LastActivity) {
				return selected[i].RunID < selected[j].RunID
			}
			return selected[i].LastActivity.Before(selected[j].LastActivity)
		})

		for _, candidate := range selected {
			if report.BudgetAfter <= policy.MaxBytes {
				candidate.Reason = reasonWithinBudget
				continue
			}
			if !candidate.sizeKnown {
				candidate.Reason = reasonDeleteBudget
				candidate.Delete = true
				continue
			}
			candidate.Delete = true
			candidate.Reason = reasonDeleteBudget
			report.BudgetAfter -= candidate.SizeBytes
		}
	} else {
		for _, candidate := range selected {
			candidate.Delete = true
			candidate.Reason = reasonDeleteAge
		}
	}

	for _, candidate := range selected {
		if !candidate.Delete {
			continue
		}

		if policy.DryRun {
			candidate.Reason = reasonWouldDelete
			continue
		}

		if _, err := s.CleanupRun(ctx, RunInput{RunID: candidate.RunID}); err != nil {
			report.Failed++
			candidate.Error = trimError(err)
			candidate.Reason = reasonDeleteFailed
			s.audit.Log(s.auditEvent("prune_run", candidate.meta, "deny", err), s.redactor(candidate.meta))
			continue
		}

		report.Deleted++
		candidate.Reason = reasonDeleted
		s.audit.Log(s.auditEvent("prune_run", candidate.meta, "allow", nil), s.redactor(candidate.meta))
	}

	report.Entries = make([]PruneRun, 0, min(len(candidates), report.OutputLimit))
	for i, candidate := range candidates {
		if i >= report.OutputLimit {
			report.Truncated = true
			break
		}
		report.Entries = append(report.Entries, candidate.PruneRun)
	}

	for i := range candidates {
		if candidates[i].Reason == reasonEligible {
			candidates[i].Reason = reasonRetained
		}
	}

	if report.Failed > 0 {
		report.Errors = append(report.Errors, fmt.Sprintf("%d prune operations failed", report.Failed))
		return report, fmt.Errorf("%d prune operations failed", report.Failed)
	}
	return report, nil
}

func hasActiveStatus(status string) bool {
	switch status {
	case StatusPending, StatusRunning:
		return true
	default:
		return false
	}
}

func isTerminalStatus(status string) bool {
	switch status {
	case StatusStopped, StatusFailed, StatusTimedOut, StatusCleaned:
		return true
	default:
		return false
	}
}

func runLastActivity(meta RunMetadata, runDir string) time.Time {
	if !meta.EndedAt.IsZero() {
		return meta.EndedAt
	}
	if !meta.StartedAt.IsZero() {
		return meta.StartedAt
	}
	info, err := os.Stat(runDir)
	if err != nil {
		return time.Time{}
	}
	return info.ModTime().UTC()
}

func runDirSizeBytes(path string) (int64, error) {
	var size int64
	err := filepath.Walk(path, func(current string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil
		}
		if info.IsDir() {
			return nil
		}
		size += info.Size()
		return nil
	})
	return size, err
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func trimError(err error) string {
	if err == nil {
		return ""
	}
	return strings.TrimSpace(err.Error())
}
