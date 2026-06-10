// Package idempotency stores successful mutation responses for safe retry.
package idempotency

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"

	"gh-agent-broker/internal/config"
)

var mu sync.Mutex

type Record struct {
	CreatedAt time.Time       `json:"created_at"`
	Operation string          `json:"operation"`
	Status    int             `json:"status"`
	Body      json.RawMessage `json:"body"`
}

type state struct {
	Keys map[string]Record `json:"keys"`
}

func Load(cfg config.IdempotencyConfig, key string) (Record, bool, error) {
	if cfg.StatePath == "" || key == "" {
		return Record{}, false, nil
	}
	mu.Lock()
	defer mu.Unlock()
	st, err := readState(cfg.StatePath)
	if err != nil {
		return Record{}, false, err
	}
	rec, ok := st.Keys[key]
	return rec, ok, nil
}

func Store(cfg config.IdempotencyConfig, key string, rec Record) error {
	if cfg.StatePath == "" || key == "" {
		return nil
	}
	if rec.CreatedAt.IsZero() {
		rec.CreatedAt = time.Now().UTC()
	}
	mu.Lock()
	defer mu.Unlock()
	st, err := readState(cfg.StatePath)
	if err != nil {
		return err
	}
	st.Keys[key] = rec
	return writeState(cfg.StatePath, st)
}

func readState(path string) (state, error) {
	st := state{Keys: map[string]Record{}}
	// #nosec G304 -- idempotency state path is supplied by operator-controlled broker config.
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return st, nil
		}
		return st, err
	}
	if len(b) == 0 {
		return st, nil
	}
	if err := json.Unmarshal(b, &st); err != nil {
		return st, err
	}
	if st.Keys == nil {
		st.Keys = map[string]Record{}
	}
	return st, nil
}

func writeState(path string, st state) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
