// Package audit writes broker decision and result events to JSONL.
package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Logger struct {
	mu   sync.Mutex
	file *os.File
}

type Event struct {
	Timestamp            time.Time              `json:"timestamp"`
	OperationID          string                 `json:"operation_id"`
	AgentID              string                 `json:"agent_id,omitempty"`
	Operation            string                 `json:"operation"`
	Repo                 string                 `json:"repo,omitempty"`
	Branch               string                 `json:"branch,omitempty"`
	RunID                string                 `json:"run_id,omitempty"`
	RequestedPermissions []string               `json:"requested_permissions,omitempty"`
	Decision             string                 `json:"decision"`
	GitHubURL            string                 `json:"github_url,omitempty"`
	Result               string                 `json:"result,omitempty"`
	Error                string                 `json:"error,omitempty"`
	Extra                map[string]interface{} `json:"extra,omitempty"`
}

func New(path string) (*Logger, error) {
	if path == "" {
		path = "audit.jsonl"
	}
	dir := filepath.Dir(path)
	if dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
	}

	// #nosec G304 -- audit path is an operator-controlled broker config value.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	return &Logger{file: f}, nil
}

func (l *Logger) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	return l.file.Close()
}

func (l *Logger) Log(ev Event) {
	if l == nil || l.file == nil {
		return
	}
	ev.Timestamp = time.Now().UTC()
	ev.Error = Redact(ev.Error)
	ev.Result = Redact(ev.Result)
	if ev.Extra != nil {
		ev.Extra = redactMap(ev.Extra)
	}
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

func redactMap(in map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(in))
	for k, v := range in {
		lk := strings.ToLower(k)
		if strings.Contains(lk, "token") || strings.Contains(lk, "secret") || strings.Contains(lk, "authorization") || strings.Contains(lk, "private_key") {
			out[k] = "[REDACTED]"
			continue
		}
		if s, ok := v.(string); ok {
			out[k] = Redact(s)
			continue
		}
		out[k] = v
	}
	return out
}

func Redact(s string) string {
	if s == "" {
		return s
	}
	replacements := []string{"token ", "Bearer ", "authorization:", "Authorization:"}
	out := s
	for _, marker := range replacements {
		idx := strings.Index(out, marker)
		if idx >= 0 {
			end := strings.IndexAny(out[idx+len(marker):], " \n\r\t")
			if end < 0 {
				out = out[:idx+len(marker)] + "[REDACTED]"
			} else {
				start := idx + len(marker)
				out = out[:start] + "[REDACTED]" + out[start+end:]
			}
		}
	}
	return out
}
