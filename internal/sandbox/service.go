package sandbox

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
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

type Service struct {
	cfg     Config
	runtime RuntimeBackend
	audit   *AuditLogger
	mu      sync.Mutex
	runs    map[string]*RunMetadata
}

type pathPermissionFixer interface {
	MakeRemovable(ctx context.Context, image, path string) error
}

type RunMetadata struct {
	RunID            string    `json:"run_id"`
	Template         string    `json:"template"`
	Repo             string    `json:"repo"`
	BaseBranch       string    `json:"base_branch"`
	Branch           string    `json:"branch"`
	Task             string    `json:"task"`
	Focus            string    `json:"focus,omitempty"`
	WorkerAgentID    string    `json:"worker_agent_id"`
	BrokerAgentID    string    `json:"broker_agent_id"`
	CredentialBundle string    `json:"credential_bundle,omitempty"`
	ContainerID      string    `json:"container_id,omitempty"`
	Image            string    `json:"image"`
	ImageDigest      string    `json:"image_digest,omitempty"`
	Status           string    `json:"status"`
	ExitCode         *int      `json:"exit_code,omitempty"`
	Error            string    `json:"error,omitempty"`
	Deliverables     []string  `json:"deliverables,omitempty"`
	StartedAt        time.Time `json:"started_at"`
	Deadline         time.Time `json:"deadline"`
	EndedAt          time.Time `json:"ended_at,omitempty"`
}

type LaunchAgentInput struct {
	Template          string   `json:"template" jsonschema:"sandbox template name"`
	Task              string   `json:"task" jsonschema:"worker task description"`
	Repo              string   `json:"repo" jsonschema:"owner/repo repository"`
	BaseBranch        string   `json:"base_branch" jsonschema:"base branch"`
	Branch            string   `json:"branch,omitempty" jsonschema:"optional branch; generated when omitted"`
	MaxRuntimeMinutes int      `json:"max_runtime_minutes,omitempty" jsonschema:"optional runtime cap within the template maximum"`
	Deliverables      []string `json:"deliverables,omitempty" jsonschema:"optional expected deliverable names"`
	Focus             string   `json:"focus,omitempty" jsonschema:"optional constrained focus for the worker"`
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
		"deliverables":        true,
		"focus":               true,
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
	RunID    string     `json:"run_id"`
	Status   string     `json:"status"`
	Branch   string     `json:"branch,omitempty"`
	Repo     string     `json:"repo,omitempty"`
	ExitCode *int       `json:"exit_code,omitempty"`
	Error    string     `json:"error,omitempty"`
	Deadline time.Time  `json:"deadline,omitempty"`
	EndedAt  *time.Time `json:"ended_at,omitempty"`
}

type ListAgentsOutput struct {
	Runs []StatusOutput `json:"runs"`
}

func NewService(cfg Config, runtime RuntimeBackend, auditLog *AuditLogger) *Service {
	return &Service{
		cfg:     cfg,
		runtime: runtime,
		audit:   auditLog,
		runs:    map[string]*RunMetadata{},
	}
}

func (s *Service) Reconcile(ctx context.Context) error {
	entries, err := os.ReadDir(s.cfg.RunsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return os.MkdirAll(s.cfg.RunsDir, 0o700)
		}
		return err
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		meta, err := readMetadata(filepath.Join(s.cfg.RunsDir, entry.Name(), "metadata.json"))
		if err != nil {
			continue
		}
		if meta.ContainerID != "" && meta.Status == StatusRunning {
			status, err := s.runtime.Inspect(ctx, meta.ContainerID)
			if err != nil {
				meta.Status = StatusFailed
				meta.Error = "container missing during startup reconciliation"
				meta.EndedAt = time.Now().UTC()
			} else if !status.Running {
				meta.ExitCode = status.ExitCode
				meta.EndedAt = status.EndedAt
				if status.ExitCode != nil && *status.ExitCode == 0 {
					meta.Status = StatusStopped
				} else {
					meta.Status = StatusFailed
				}
			} else if time.Now().After(meta.Deadline) {
				if err := s.runtime.Stop(ctx, meta.ContainerID, s.cfg.StopGrace.Duration); err != nil {
					meta.Error = err.Error()
				}
				meta.Status = StatusTimedOut
				meta.EndedAt = time.Now().UTC()
			}
			if err := s.writeMetadata(meta); err != nil {
				return err
			}
		}
		s.mu.Lock()
		cp := meta
		s.runs[meta.RunID] = &cp
		s.mu.Unlock()
	}
	return nil
}

func (s *Service) DryRunLaunch(ctx context.Context, in LaunchAgentInput) (LaunchAgentOutput, error) {
	_ = ctx
	tmpl, runID, branch, runtimeMinutes, err := s.validateLaunch(in)
	if err != nil {
		s.auditDeny("dry_run_launch", in, err)
		return LaunchAgentOutput{}, err
	}
	deadline := time.Now().UTC().Add(time.Duration(runtimeMinutes) * time.Minute)
	return LaunchAgentOutput{
		RunID:         runID,
		WorkerAgentID: workerAgentID(tmpl, runID),
		Repo:          in.Repo,
		Branch:        branch,
		Status:        StatusPending,
		Deadline:      deadline,
	}, nil
}

func (s *Service) LaunchAgent(ctx context.Context, in LaunchAgentInput) (LaunchAgentOutput, error) {
	tmpl, runID, branch, runtimeMinutes, err := s.validateLaunch(in)
	if err != nil {
		s.auditDeny("launch_agent", in, err)
		return LaunchAgentOutput{}, err
	}
	now := time.Now().UTC()
	deadline := now.Add(time.Duration(runtimeMinutes) * time.Minute)
	runDir := s.runDir(runID)
	if err := os.MkdirAll(runDir, 0o700); err != nil {
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
	meta := RunMetadata{
		RunID:            runID,
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
		StartedAt:        now,
		Deadline:         deadline,
	}
	spec, redactor, err := s.runtimeSpec(meta, tmpl)
	if err != nil {
		return LaunchAgentOutput{}, err
	}
	info, err := s.runtime.Create(ctx, spec)
	if err != nil {
		meta.Status = StatusFailed
		meta.Error = err.Error()
		meta.EndedAt = time.Now().UTC()
		if writeErr := s.writeMetadata(meta); writeErr != nil {
			return LaunchAgentOutput{}, writeErr
		}
		s.audit.Log(s.auditEvent("launch_agent", meta, "deny", err), redactor)
		return LaunchAgentOutput{}, err
	}
	meta.ContainerID = info.ID
	meta.ImageDigest = info.ImageDigest
	if err := s.runtime.Start(ctx, info.ID); err != nil {
		meta.Status = StatusFailed
		meta.Error = err.Error()
		meta.EndedAt = time.Now().UTC()
		if writeErr := s.writeMetadata(meta); writeErr != nil {
			return LaunchAgentOutput{}, writeErr
		}
		s.audit.Log(s.auditEvent("launch_agent", meta, "deny", err), redactor)
		return LaunchAgentOutput{}, err
	}
	meta.Status = StatusRunning
	if err := s.writeMetadata(meta); err != nil {
		return LaunchAgentOutput{}, err
	}
	s.mu.Lock()
	s.runs[runID] = &meta
	s.mu.Unlock()
	s.audit.Log(s.auditEvent("launch_agent", meta, "allow", nil), redactor)
	go s.watchTimeout(context.WithoutCancel(ctx), runID, deadline)
	return LaunchAgentOutput{RunID: runID, WorkerAgentID: meta.WorkerAgentID, Repo: meta.Repo, Branch: meta.Branch, Status: meta.Status, Deadline: meta.Deadline}, nil
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
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()
	out := ListAgentsOutput{Runs: make([]StatusOutput, 0, len(s.runs))}
	for _, meta := range s.runs {
		out.Runs = append(out.Runs, statusFromMetadata(*meta))
	}
	return out, nil
}

func (s *Service) GetAgentStatus(ctx context.Context, in RunInput) (StatusOutput, error) {
	_ = ctx
	meta, err := s.lookupRun(in.RunID)
	if err != nil {
		return StatusOutput{}, err
	}
	if meta.ContainerID != "" && meta.Status == StatusRunning {
		status, err := s.runtime.Inspect(ctx, meta.ContainerID)
		if err == nil && !status.Running {
			if status.ExitCode != nil && *status.ExitCode == 0 {
				meta.Status = StatusStopped
			} else {
				meta.Status = StatusFailed
			}
			meta.ExitCode = status.ExitCode
			meta.EndedAt = status.EndedAt
			if meta.EndedAt.IsZero() {
				meta.EndedAt = time.Now().UTC()
			}
			if err := s.writeMetadata(meta); err != nil {
				return StatusOutput{}, err
			}
		}
	}
	return statusFromMetadata(meta), nil
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
	meta.Status = StatusStopped
	meta.EndedAt = time.Now().UTC()
	if err := s.writeMetadata(meta); err != nil {
		return StatusOutput{}, err
	}
	s.audit.Log(s.auditEvent("stop_agent", meta, "allow", nil), redactor)
	return statusFromMetadata(meta), nil
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
	return statusFromMetadata(meta), nil
}

func (s *Service) validateLaunch(in LaunchAgentInput) (Template, string, string, int, error) {
	tmpl, ok := s.cfg.Templates[in.Template]
	if !ok {
		return Template{}, "", "", 0, fmt.Errorf("unknown template %q", in.Template)
	}
	if !validRepo(in.Repo) {
		return Template{}, "", "", 0, fmt.Errorf("repo must be owner/repo")
	}
	if !containsFold(s.cfg.Repositories, in.Repo) {
		return Template{}, "", "", 0, fmt.Errorf("repo %q is not allowed", in.Repo)
	}
	if strings.TrimSpace(in.Task) == "" {
		return Template{}, "", "", 0, fmt.Errorf("task is required")
	}
	if len(in.Task) > s.cfg.MaxTaskBytes {
		return Template{}, "", "", 0, fmt.Errorf("task exceeds max size %d bytes", s.cfg.MaxTaskBytes)
	}
	if strings.TrimSpace(in.BaseBranch) == "" {
		return Template{}, "", "", 0, fmt.Errorf("base_branch is required")
	}
	if len(tmpl.BranchPolicy.BaseBranches) > 0 && !contains(tmpl.BranchPolicy.BaseBranches, in.BaseBranch) {
		return Template{}, "", "", 0, fmt.Errorf("base_branch %q is not allowed", in.BaseBranch)
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
		return Template{}, "", "", 0, fmt.Errorf("branch %q is unsafe", branch)
	}
	if len(tmpl.BranchPolicy.AllowedPatterns) > 0 && !matchesAny(tmpl.BranchPolicy.AllowedPatterns, branch) {
		return Template{}, "", "", 0, fmt.Errorf("branch %q does not match template branch policy", branch)
	}
	runtimeMinutes := in.MaxRuntimeMinutes
	if runtimeMinutes == 0 {
		runtimeMinutes = tmpl.MaxRuntimeMinutes
	}
	if runtimeMinutes < 1 || runtimeMinutes > tmpl.MaxRuntimeMinutes {
		return Template{}, "", "", 0, fmt.Errorf("max_runtime_minutes must be between 1 and %d", tmpl.MaxRuntimeMinutes)
	}
	return tmpl, runID, branch, runtimeMinutes, nil
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
		mounts = append(mounts, Mount{Source: bundle.SourcePath, Target: bundle.MountPath, ReadOnly: true})
		bundleRedactor := RedactorForBundle(bundle)
		redactor.known = append(redactor.known, bundleRedactor.known...)
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
	path := filepath.Join(s.runDir(meta.RunID), "metadata.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, append(b, '\n'), 0o600); err != nil {
		return err
	}
	s.mu.Lock()
	cp := meta
	s.runs[meta.RunID] = &cp
	s.mu.Unlock()
	return nil
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
		Operation: operation,
		Template:  in.Template,
		Repo:      in.Repo,
		Branch:    in.Branch,
		Decision:  "deny",
		Error:     err.Error(),
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
		Status:           meta.Status,
		ExitCode:         meta.ExitCode,
		Decision:         decision,
	}
	if err != nil {
		ev.Error = err.Error()
	}
	return ev
}

func (s *Service) watchTimeout(parent context.Context, runID string, deadline time.Time) {
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	<-timer.C
	meta, err := s.lookupRun(runID)
	if err != nil || meta.Status != StatusRunning {
		return
	}
	ctx, cancel := context.WithTimeout(parent, s.cfg.StopGrace.Duration+5*time.Second)
	defer cancel()
	if err := s.runtime.Stop(ctx, meta.ContainerID, s.cfg.StopGrace.Duration); err != nil {
		meta.Error = err.Error()
	}
	meta.Status = StatusTimedOut
	meta.EndedAt = time.Now().UTC()
	if err := s.writeMetadata(meta); err != nil {
		meta.Error = err.Error()
	}
	s.audit.Log(s.auditEvent("timeout", meta, "allow", errors.New("run exceeded deadline")), s.redactor(meta))
}

func statusFromMetadata(meta RunMetadata) StatusOutput {
	var ended *time.Time
	if !meta.EndedAt.IsZero() {
		ended = &meta.EndedAt
	}
	return StatusOutput{
		RunID:    meta.RunID,
		Status:   meta.Status,
		Branch:   meta.Branch,
		Repo:     meta.Repo,
		ExitCode: meta.ExitCode,
		Error:    meta.Error,
		Deadline: meta.Deadline,
		EndedAt:  ended,
	}
}

func deliverables(requested, defaults []string) []string {
	if len(requested) > 0 {
		return append([]string{}, requested...)
	}
	return append([]string{}, defaults...)
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
