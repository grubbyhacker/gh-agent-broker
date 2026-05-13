package sandbox

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type AuditLogger struct {
	mu   sync.Mutex
	file *os.File
}

type AuditEvent struct {
	Timestamp        time.Time `json:"timestamp"`
	Operation        string    `json:"operation"`
	RunID            string    `json:"run_id,omitempty"`
	Template         string    `json:"template,omitempty"`
	ParentAgentID    string    `json:"parent_agent_id,omitempty"`
	WorkerAgentID    string    `json:"worker_agent_id,omitempty"`
	Repo             string    `json:"repo,omitempty"`
	Branch           string    `json:"branch,omitempty"`
	ImageDigest      string    `json:"image_digest,omitempty"`
	CredentialBundle string    `json:"credential_bundle,omitempty"`
	Status           string    `json:"status,omitempty"`
	ExitCode         *int      `json:"exit_code,omitempty"`
	Decision         string    `json:"decision"`
	Error            string    `json:"error,omitempty"`
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
	b, err := json.Marshal(ev)
	if err != nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, err := l.file.Write(append(b, '\n')); err != nil {
		return
	}
}
