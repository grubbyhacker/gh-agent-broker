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

type TaskContract struct {
	RunID           string   `json:"run_id"`
	Task            string   `json:"task"`
	Focus           string   `json:"focus,omitempty"`
	Repo            string   `json:"repo"`
	BaseBranch      string   `json:"base_branch"`
	Branch          string   `json:"branch"`
	WorkerAgentID   string   `json:"worker_agent_id"`
	BrokerRemoteURL string   `json:"broker_remote_url"`
	Deliverables    []string `json:"deliverables,omitempty"`
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
					if status.Error != "" {
						meta.Error = status.Error
					} else {
						meta.Error = "worker exited nonzero"
					}
					if diagErr := s.ensureFailureDiagnostics(meta, meta.Error); diagErr != nil && meta.Error == "" {
						meta.Error = diagErr.Error()
					}
				}
			} else if time.Now().After(meta.Deadline) {
				meta = s.markTimedOut(ctx, meta)
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
	if err := s.writeTaskInputs(meta); err != nil {
		return LaunchAgentOutput{}, err
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
			meta = s.markTimedOut(ctx, meta)
			if err := s.writeMetadata(meta); err != nil {
				return StatusOutput{}, err
			}
		} else if err == nil && !status.Running {
			if status.ExitCode != nil && *status.ExitCode == 0 {
				meta.Status = StatusStopped
			} else {
				meta.Status = StatusFailed
				if status.Error != "" {
					meta.Error = status.Error
				} else {
					meta.Error = "worker exited nonzero"
				}
			}
			meta.ExitCode = status.ExitCode
			meta.EndedAt = status.EndedAt
			if meta.EndedAt.IsZero() {
				meta.EndedAt = time.Now().UTC()
			}
			if meta.Status == StatusFailed {
				if diagErr := s.ensureFailureDiagnostics(meta, meta.Error); diagErr != nil && meta.Error == "" {
					meta.Error = diagErr.Error()
				}
			}
			if err := s.writeMetadata(meta); err != nil {
				return StatusOutput{}, err
			}
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
	meta.Status = StatusStopped
	meta.EndedAt = time.Now().UTC()
	if err := s.writeMetadata(meta); err != nil {
		return StatusOutput{}, err
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

func (s *Service) validateLaunch(in LaunchAgentInput) (Template, string, string, int, error) {
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
	runtimeMinutes := in.MaxRuntimeMinutes
	if runtimeMinutes == 0 {
		runtimeMinutes = tmpl.MaxRuntimeMinutes
	}
	if runtimeMinutes < 1 || runtimeMinutes > tmpl.MaxRuntimeMinutes {
		return Template{}, "", "", 0, fmt.Errorf("policy denial: max_runtime_minutes must be between 1 and %d; lower the requested runtime", tmpl.MaxRuntimeMinutes)
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

func (s *Service) writeTaskInputs(meta RunMetadata) error {
	inputDir := filepath.Join(s.runDir(meta.RunID), "input")
	contract := TaskContract{
		RunID:           meta.RunID,
		Task:            meta.Task,
		Focus:           meta.Focus,
		Repo:            meta.Repo,
		BaseBranch:      meta.BaseBranch,
		Branch:          meta.Branch,
		WorkerAgentID:   meta.WorkerAgentID,
		BrokerRemoteURL: strings.TrimRight(s.cfg.BrokerURL, "/") + "/git/" + meta.Repo + ".git",
		Deliverables:    append([]string{}, meta.Deliverables...),
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
	meta = s.markTimedOut(ctx, meta)
	if err := s.writeMetadata(meta); err != nil {
		meta.Error = err.Error()
	}
	s.audit.Log(s.auditEvent("timeout", meta, "allow", errors.New("run exceeded deadline")), s.redactor(meta))
}

func (s *Service) markTimedOut(ctx context.Context, meta RunMetadata) RunMetadata {
	if meta.ContainerID != "" {
		if err := s.runtime.Stop(ctx, meta.ContainerID, s.cfg.StopGrace.Duration); err != nil {
			meta.Error = "run exceeded deadline; stop failed: " + err.Error()
		}
	}
	if meta.Error == "" {
		meta.Error = "run exceeded deadline"
	}
	meta.Status = StatusTimedOut
	meta.EndedAt = time.Now().UTC()
	if err := s.ensureFailureDiagnostics(meta, meta.Error); err != nil && !strings.Contains(meta.Error, err.Error()) {
		meta.Error = meta.Error + "; diagnostics write failed: " + err.Error()
	}
	return meta
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
