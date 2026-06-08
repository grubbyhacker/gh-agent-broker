package proxy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type auditLogger struct {
	mu   sync.Mutex
	file *os.File
}

type auditEvent struct {
	Timestamp time.Time `json:"timestamp"`
	RunID     string    `json:"run_id,omitempty"`
	Model     string    `json:"model,omitempty"`
	Decision  string    `json:"decision"`
	Tokens    int       `json:"tokens,omitempty"`
	Error     string    `json:"error,omitempty"`
}

func newAuditLogger(path string) (*auditLogger, error) {
	if path == "" {
		return &auditLogger{}, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	// #nosec G304 -- audit path is operator controlled.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	return &auditLogger{file: f}, nil
}

func (l *auditLogger) Log(ev auditEvent) {
	if l == nil || l.file == nil {
		return
	}
	ev.Timestamp = time.Now().UTC()
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

func (l *auditLogger) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	return l.file.Close()
}
