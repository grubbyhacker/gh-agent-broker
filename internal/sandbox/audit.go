package sandbox

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"gh-agent-broker/internal/securityscan"
)

type AuditLogger struct {
	mu   sync.Mutex
	file *os.File
}

type AuditEvent struct {
	Timestamp         time.Time      `json:"timestamp"`
	Operation         string         `json:"operation"`
	RunID             string         `json:"run_id,omitempty"`
	Principal         string         `json:"principal,omitempty"`
	Profile           string         `json:"profile,omitempty"`
	Template          string         `json:"template,omitempty"`
	ParentAgentID     string         `json:"parent_agent_id,omitempty"`
	WorkerAgentID     string         `json:"worker_agent_id,omitempty"`
	AuthorityWorkerID string         `json:"authority_worker_id,omitempty"`
	ProfileVersion    string         `json:"profile_version,omitempty"`
	PolicyDigest      string         `json:"policy_digest,omitempty"`
	Generation        int            `json:"generation,omitempty"`
	AssignedSessions  int            `json:"assigned_sessions,omitempty"`
	Repo              string         `json:"repo,omitempty"`
	Branch            string         `json:"branch,omitempty"`
	ImageDigest       string         `json:"image_digest,omitempty"`
	CredentialBundle  string         `json:"credential_bundle,omitempty"`
	ContainerID       string         `json:"container_id,omitempty"`
	LifecycleStage    string         `json:"lifecycle_stage,omitempty"`
	ContainerRunning  *bool          `json:"container_running,omitempty"`
	ContainerError    string         `json:"container_error,omitempty"`
	Parameters        map[string]any `json:"parameters,omitempty"`
	Status            string         `json:"status,omitempty"`
	ExitCode          *int           `json:"exit_code,omitempty"`
	Terminal          bool           `json:"terminal,omitempty"`
	FinalizeReason    string         `json:"finalize_reason,omitempty"`
	TerminalSource    string         `json:"terminal_source,omitempty"`
	Decision          string         `json:"decision"`
	Error             string         `json:"error,omitempty"`
}

func NewAuditLogger(path string) (*AuditLogger, error) {
	if path == "" {
		path = "sandbox-audit.jsonl"
	}
	dir := filepath.Dir(path)
	if dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
	}
	// #nosec G304 -- audit path is supplied by operator config.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	return &AuditLogger{file: f}, nil
}

func (l *AuditLogger) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	return l.file.Close()
}

func (l *AuditLogger) Log(ev AuditEvent, redactor Redactor) {
	if l == nil || l.file == nil {
		return
	}
	ev.Timestamp = time.Now().UTC()
	ev.Error = redactor.Redact(ev.Error)
	ev.ContainerError = redactor.Redact(ev.ContainerError)
	b, err := json.Marshal(ev)
	if err != nil {
		return
	}
	if finding := securityscan.Fields(map[string]string{"audit_event": string(b)}); finding != nil {
		ev = AuditEvent{
			Timestamp: ev.Timestamp,
			Operation: "security.egress_blocked",
			RunID:     ev.RunID,
			Principal: ev.Principal,
			Profile:   ev.Profile,
			Template:  ev.Template,
			Repo:      ev.Repo,
			Decision:  "deny",
			Status:    finding.Code,
			Error:     "credential-shaped material suppressed from audit log",
		}
		b, err = json.Marshal(ev)
		if err != nil {
			return
		}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, err := l.file.Write(append(b, '\n')); err != nil {
		return
	}
}
