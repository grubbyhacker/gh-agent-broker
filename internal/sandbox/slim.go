package sandbox

import (
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	slimArtifactsManifest = "slim-artifacts-manifest.json"
	slimRunLog            = "slim-run.log"
)

const (
	reasonWouldSlim   = "would_slim"
	reasonSlimmed     = "slimmed"
	reasonSlimmedNoop = "slim_noop"
	reasonSlimBudget  = "slim_budget"
	reasonNotSlimmed  = "not_slimmed"
)

type SlimRun struct {
	PruneRun
	SizeAfter       int64    `json:"size_after_bytes"`
	RemovedBytes    int64    `json:"removed_bytes"`
	RemovedEntries  int      `json:"removed_entries"`
	KeptEntries     int      `json:"kept_entries"`
	RemovedPaths    []string `json:"removed_paths,omitempty"`
	ArtifactPath    string   `json:"artifact_manifest_path,omitempty"`
	LogSnapshotPath string   `json:"log_snapshot_path,omitempty"`
}

type SlimReport struct {
	Timestamp    time.Time       `json:"timestamp"`
	RunsDir      string          `json:"runs_dir"`
	Policy       RetentionPolicy `json:"policy"`
	Scanned      int             `json:"scanned"`
	Considered   int             `json:"considered"`
	Slimmed      int             `json:"slimmed"`
	Failed       int             `json:"failed"`
	Skipped      int             `json:"skipped"`
	OutputLimit  int             `json:"output_limit"`
	BudgetBefore int64           `json:"budget_before_bytes,omitempty"`
	BudgetAfter  int64           `json:"budget_after_bytes,omitempty"`
	Truncated    bool            `json:"truncated"`
	Entries      []SlimRun       `json:"entries"`
	Errors       []string        `json:"errors,omitempty"`
}

type runArtifactManifest struct {
	RunID          string         `json:"run_id"`
	GeneratedAtUTC time.Time      `json:"generated_at_utc"`
	OutputFiles    []FileManifest `json:"output_files"`
	LessonFiles    []FileManifest `json:"lesson_files"`
}

type slimCandidate struct {
	retentionCandidate
	removedBytes    int64
	removedEntries  int
	keptEntries     int
	removedPaths    []string
	sizeAfter       int64
	artifactPath    string
	logSnapshotPath string
}

func (s *Service) SlimRuns(ctx context.Context, policy RetentionPolicy) (SlimReport, error) {
	policy = policy.normalize()
	report := SlimReport{
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
	candidates := make([]slimCandidate, 0, len(entries))

	for _, entry := range entries {
		report.Scanned++
		switch {
		case entry.Type()&os.ModeSymlink != 0:
			report.Skipped++
			candidates = append(candidates, slimCandidate{retentionCandidate: retentionCandidate{PruneRun: PruneRun{
				RunID:  entry.Name(),
				Reason: reasonNotDirectory,
			}}})
			continue
		case !entry.IsDir():
			report.Skipped++
			candidates = append(candidates, slimCandidate{retentionCandidate: retentionCandidate{PruneRun: PruneRun{
				RunID:  entry.Name(),
				Reason: reasonNotDirectory,
			}}})
			continue
		}

		runID := entry.Name()
		if !safeRunID(runID) {
			report.Skipped++
			candidates = append(candidates, slimCandidate{retentionCandidate: retentionCandidate{PruneRun: PruneRun{
				RunID:  runID,
				Reason: reasonInvalidRunID,
			}}})
			continue
		}

		runDir := s.runDir(runID)
		if escapesBase(s.cfg.RunsDir, runDir) {
			report.Skipped++
			candidates = append(candidates, slimCandidate{retentionCandidate: retentionCandidate{PruneRun: PruneRun{
				RunID:  runID,
				Reason: reasonPathEscape,
			}}})
			continue
		}

		meta, readErr := readMetadata(filepath.Join(runDir, "metadata.json"))
		if readErr != nil {
			report.Skipped++
			candidates = append(candidates, slimCandidate{retentionCandidate: retentionCandidate{PruneRun: PruneRun{
				RunID:  runID,
				Reason: reasonMetadataRead,
				Error:  trimError(readErr),
			}}})
			continue
		}

		size, sizeErr := runDirSizeBytes(runDir)
		lastActivity := runLastActivity(meta, runDir)
		ageSeconds := int64(now.Sub(lastActivity).Seconds())
		if ageSeconds < 0 {
			ageSeconds = 0
		}

		candidate := slimCandidate{
			retentionCandidate: retentionCandidate{
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
				sizeKnown: true,
			},
		}
		if sizeErr != nil {
			candidate.sizeKnown = false
			candidate.Error = trimError(sizeErr)
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

	active := make([]*slimCandidate, 0, len(candidates))
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

	selected := make([]*slimCandidate, 0, len(active))
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
			candidate.Delete = true
			candidate.Reason = reasonSlimBudget
			if candidate.sizeKnown {
				report.BudgetAfter -= candidate.SizeBytes
			}
		}
	} else {
		for _, candidate := range selected {
			candidate.Delete = true
			candidate.Reason = reasonEligible
		}
	}

	for _, candidate := range selected {
		if !candidate.Delete {
			continue
		}
		if policy.DryRun {
			candidate.Reason = reasonWouldSlim
			candidate.sizeAfter = candidate.SizeBytes
			candidate.removedBytes = 0
			candidate.removedEntries = 0
			candidate.keptEntries = 0
			report.Slimmed++
			continue
		}

		out, err := s.shrinkRunDirectory(ctx, candidate.meta)
		if err != nil {
			report.Failed++
			candidate.Error = trimError(err)
			candidate.Reason = reasonSlimmedNoop
			candidate.sizeAfter = out.SizeAfter
			candidate.removedBytes = out.RemovedBytes
			candidate.removedEntries = out.RemovedEntries
			candidate.keptEntries = out.KeptEntries
			candidate.removedPaths = append(candidate.removedPaths, out.RemovedPaths...)
			candidate.artifactPath = out.ArtifactPath
			candidate.logSnapshotPath = out.LogSnapshotPath
			s.audit.Log(s.auditEvent("slim_run", candidate.meta, "deny", err), s.redactor(candidate.meta))
			continue
		}
		candidate.Reason = reasonSlimmed
		candidate.sizeAfter = out.SizeAfter
		candidate.removedBytes = out.RemovedBytes
		candidate.removedEntries = out.RemovedEntries
		candidate.keptEntries = out.KeptEntries
		candidate.removedPaths = append(candidate.removedPaths, out.RemovedPaths...)
		candidate.artifactPath = out.ArtifactPath
		candidate.logSnapshotPath = out.LogSnapshotPath
		candidate.Error = out.Error
		report.Slimmed++
		s.audit.Log(s.auditEvent("slim_run", candidate.meta, "allow", nil), s.redactor(candidate.meta))
	}

	report.Entries = make([]SlimRun, 0, min(len(candidates), report.OutputLimit))
	for i, candidate := range candidates {
		if i >= report.OutputLimit {
			report.Truncated = true
			break
		}
		entry := SlimRun{
			PruneRun:       candidate.PruneRun,
			SizeAfter:      candidate.sizeAfter,
			RemovedBytes:   candidate.removedBytes,
			RemovedEntries: candidate.removedEntries,
			KeptEntries:    candidate.keptEntries,
		}
		if candidate.sizeAfter == 0 {
			entry.SizeAfter = candidate.SizeBytes - candidate.removedBytes
		}
		if entry.RemovedBytes < 0 {
			entry.RemovedBytes = 0
		}
		if entry.SizeAfter < 0 {
			entry.SizeAfter = candidate.SizeBytes
		}
		entry.RemovedPaths = append(entry.RemovedPaths, candidate.removedPaths...)
		entry.ArtifactPath = candidate.artifactPath
		entry.LogSnapshotPath = candidate.logSnapshotPath
		report.Entries = append(report.Entries, entry)
	}

	for i := range candidates {
		switch candidates[i].Reason {
		case reasonEligible:
			candidates[i].Reason = reasonNotSlimmed
		}
	}

	if policy.MaxBytes > 0 {
		report.BudgetAfter = 0
		for _, candidate := range selected {
			runDir := s.runDir(candidate.RunID)
			size, err := runDirSizeBytes(runDir)
			if err != nil {
				continue
			}
			report.BudgetAfter += size
		}
	}

	if report.Failed > 0 {
		report.Errors = append(report.Errors, fmt.Sprintf("%d slim operations failed", report.Failed))
		return report, fmt.Errorf("%d slim operations failed", report.Failed)
	}
	return report, nil
}

func (s *Service) shrinkRunDirectory(_ context.Context, meta RunMetadata) (SlimRun, error) {
	out := SlimRun{
		PruneRun: PruneRun{
			RunID:    meta.RunID,
			Status:   meta.Status,
			Template: meta.Template,
			Repo:     meta.Repo,
			Branch:   meta.Branch,
			Keep:     false,
			Delete:   true,
		},
	}

	if !isTerminalStatus(meta.Status) {
		out.Reason = reasonNotTerminal
		out.Error = "run is not terminal"
		return out, fmt.Errorf("run %q is not terminal", meta.RunID)
	}

	runDir := s.runDir(meta.RunID)
	if escapesBase(s.cfg.RunsDir, runDir) {
		out.Reason = reasonPathEscape
		return out, fmt.Errorf("run directory for %q escapes runs_dir", meta.RunID)
	}
	if _, err := os.Stat(runDir); err != nil {
		out.Reason = reasonMetadataRead
		out.Error = trimError(err)
		return out, fmt.Errorf("run directory for %q not found: %w", meta.RunID, err)
	}

	sizeBefore, err := runDirSizeBytes(runDir)
	if err != nil {
		out.Error = trimError(err)
		return out, err
	}
	out.SizeBytes = sizeBefore

	keep := collectKeepPaths(runDir, meta.Deliverables)
	metadataPath := filepath.Join(runDir, "metadata.json")
	inputPath := filepath.Join(runDir, "input")
	outputPath := filepath.Join(runDir, "output")
	lessonsPath := filepath.Join(runDir, "lessons")
	logsPath := filepath.Join(runDir, "logs")
	keep[metadataPath] = struct{}{}
	keep[inputPath] = struct{}{}
	keep[outputPath] = struct{}{}
	keep[lessonsPath] = struct{}{}
	keep[logsPath] = struct{}{}
	keep[filepath.Join(outputPath, "wrapper-diagnostics.json")] = struct{}{}
	keep[filepath.Join(outputPath, slimArtifactsManifest)] = struct{}{}
	keep[filepath.Join(logsPath, slimRunLog)] = struct{}{}

	trimmed, trimErr := trimForSlim(runDir, keep)
	if trimErr != nil {
		out.Reason = reasonSlimmedNoop
		out.Error = trimError(trimErr)
		return out, trimErr
	}

	out.RemovedBytes = trimmed.RemovedBytes
	out.RemovedEntries = trimmed.RemovedEntries
	out.KeptEntries = trimmed.KeptEntries
	out.RemovedPaths = trimmed.Removed
	manifestPath, manifestErr := writeSlimArtifactsManifest(meta.RunID, meta, outputPath, lessonsPath, s.redactor(meta))
	if manifestErr != nil {
		out.Reason = reasonSlimmedNoop
		out.Error = trimError(manifestErr)
		return out, manifestErr
	}
	out.ArtifactPath = manifestPath
	manifestRunPath := filepath.Join(runDir, manifestPath)
	keep[manifestRunPath] = struct{}{}

	logPath, logErr := s.captureSlimLogSnapshot(context.Background(), meta, runDir)
	if logErr != nil {
		existing := out.Error
		if existing != "" {
			out.Error = existing + "; " + trimError(logErr)
		} else {
			out.Error = trimError(logErr)
		}
	} else if logPath != "" {
		out.LogSnapshotPath = logPath
		keep[filepath.Join(logsPath, logPath)] = struct{}{}
	}

	sizeAfter, err := runDirSizeBytes(runDir)
	if err != nil {
		out.Reason = reasonSlimmedNoop
		out.Error = trimError(err)
		return out, err
	}
	out.SizeAfter = sizeAfter
	out.RemovedBytes = sizeBefore - sizeAfter
	if out.RemovedBytes < 0 {
		out.RemovedBytes = 0
	}
	out.Reason = reasonSlimmed
	return out, nil
}

type slimOutputEntries struct {
	Removed        []string
	RemovedBytes   int64
	RemovedEntries int
	KeptEntries    int
}

func trimForSlim(root string, keep map[string]struct{}) (slimOutputEntries, error) {
	out := slimOutputEntries{}
	entries, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			return out, nil
		}
		return out, err
	}

	for _, entry := range entries {
		path := filepath.Join(root, entry.Name())
		kept, err := isSlimKeptPath(path, keep)
		if err != nil {
			return out, err
		}
		if !kept {
			size, sizeErr := runDirSizeBytes(path)
			if sizeErr != nil {
				return out, sizeErr
			}
			if err := os.RemoveAll(path); err != nil {
				return out, err
			}
			rel, relErr := filepath.Rel(root, path)
			if relErr == nil {
				out.Removed = append(out.Removed, filepath.ToSlash(rel))
			} else {
				out.Removed = append(out.Removed, path)
			}
			out.RemovedBytes += size
			out.RemovedEntries++
			continue
		}

		if entry.Type()&os.ModeSymlink != 0 || !entry.IsDir() {
			out.KeptEntries++
			continue
		}

		out.KeptEntries++
		child, err := trimForSlim(path, keep)
		if err != nil {
			return out, err
		}
		for _, removed := range child.Removed {
			out.Removed = append(out.Removed, filepath.ToSlash(filepath.Join(entry.Name(), removed)))
		}
		out.RemovedBytes += child.RemovedBytes
		out.RemovedEntries += child.RemovedEntries
		out.KeptEntries += child.KeptEntries
	}
	return out, nil
}

func isSlimKeptPath(candidate string, keep map[string]struct{}) (bool, error) {
	candidate = filepath.Clean(candidate)
	for keepPath := range keep {
		rel, err := filepath.Rel(candidate, keepPath)
		if err != nil {
			return false, err
		}
		if rel == "." || rel == "" {
			return true, nil
		}
		if !strings.HasPrefix(rel, "..") {
			return true, nil
		}
	}
	return false, nil
}

func collectKeepPaths(runDir string, deliverables []string) map[string]struct{} {
	keep := map[string]struct{}{}
	outputDir := filepath.Join(runDir, "output")
	lessonDir := filepath.Join(runDir, "lessons")
	for _, raw := range deliverables {
		clean := path.Clean(strings.TrimSpace(raw))
		if clean == "." || clean == "/" {
			continue
		}
		if !strings.HasPrefix(clean, "/") {
			continue
		}
		switch {
		case clean == "/output":
			keep[outputDir] = struct{}{}
		case strings.HasPrefix(clean, "/output/"):
			rel := strings.TrimPrefix(clean, "/output/")
			candidate := filepath.Join(outputDir, filepath.FromSlash(rel))
			if escapesBase(outputDir, candidate) {
				continue
			}
			keep[candidate] = struct{}{}
		case clean == "/lessons":
			keep[lessonDir] = struct{}{}
		case strings.HasPrefix(clean, "/lessons/"):
			rel := strings.TrimPrefix(clean, "/lessons/")
			candidate := filepath.Join(lessonDir, filepath.FromSlash(rel))
			if escapesBase(lessonDir, candidate) {
				continue
			}
			keep[candidate] = struct{}{}
		}
	}
	return keep
}

func writeSlimArtifactsManifest(runID string, _ RunMetadata, outputDir, lessonDir string, redactor Redactor) (string, error) {
	outputCollection, err := collectFiles(outputDir, runID, redactor, 0)
	if err != nil && !os.IsNotExist(err) {
		return "", err
	}
	lessonCollection, err := collectFiles(lessonDir, runID, redactor, 0)
	if err != nil && !os.IsNotExist(err) {
		return "", err
	}
	payload := runArtifactManifest{
		RunID:          runID,
		GeneratedAtUTC: time.Now().UTC(),
		OutputFiles:    outputCollection.Files,
		LessonFiles:    lessonCollection.Files,
	}
	manifestPath := filepath.Join(outputDir, slimArtifactsManifest)
	if err := writeJSONFile(manifestPath, payload, 0o600); err != nil {
		return "", err
	}
	runDir := filepath.Dir(filepath.Dir(manifestPath))
	rel, err := filepath.Rel(runDir, manifestPath)
	if err != nil {
		return "", err
	}
	return filepath.ToSlash(rel), nil
}

func (s *Service) captureSlimLogSnapshot(ctx context.Context, meta RunMetadata, runDir string) (string, error) {
	if meta.ContainerID == "" {
		return "", nil
	}
	logs, err := s.runtime.Logs(ctx, meta.ContainerID, s.cfg.LogByteLimit)
	if err != nil {
		return "", err
	}
	redactor := s.redactor(meta)
	logs = strings.TrimRight(redactor.Redact(logs), "\n")
	logPath := filepath.Join(runDir, "logs", slimRunLog)
	if err := os.MkdirAll(filepath.Dir(logPath), 0o700); err != nil {
		return "", err
	}
	if err := os.WriteFile(logPath, []byte(logs+"\n"), 0o600); err != nil {
		return "", err
	}
	rel, err := filepath.Rel(runDir, logPath)
	if err != nil {
		return "", err
	}
	return filepath.ToSlash(rel), nil
}
