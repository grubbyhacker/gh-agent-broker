// Package limits enforces durable per-run broker mutation budgets.
package limits

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"gh-agent-broker/internal/config"
)

var mu sync.Mutex

type Decision struct {
	Allowed bool
	Reason  string
	RunID   string
	Class   string
}

type state struct {
	Runs map[string]runState `json:"runs"`
}

type runState struct {
	Total   int            `json:"total"`
	Classes map[string]int `json:"classes"`
}

func CheckAndReserve(cfg config.MutationLimitsConfig, operation string, metadata map[string]string) (Decision, error) {
	if cfg.StatePath == "" || cfg.MaxNewObjectsPerRun == 0 && len(cfg.ClassLimits) == 0 {
		return Decision{Allowed: true}, nil
	}
	runField := cfg.RunMetadataField
	if runField == "" {
		runField = "Run-Id"
	}
	runID := metadata[runField]
	if runID == "" {
		return Decision{Allowed: false, Reason: fmt.Sprintf("mutation budget requires metadata field %q", runField)}, nil
	}
	class := operationClass(cfg, operation, metadata)
	mu.Lock()
	defer mu.Unlock()
	st, err := readState(cfg.StatePath)
	if err != nil {
		return Decision{}, err
	}
	rs := st.Runs[runID]
	if rs.Classes == nil {
		rs.Classes = map[string]int{}
	}
	if cfg.MaxNewObjectsPerRun > 0 && rs.Total >= cfg.MaxNewObjectsPerRun {
		return Decision{Allowed: false, Reason: "per-run new GitHub object budget exhausted", RunID: runID, Class: class}, nil
	}
	if limit := cfg.ClassLimits[class]; limit > 0 && rs.Classes[class] >= limit {
		return Decision{Allowed: false, Reason: fmt.Sprintf("per-run %s GitHub object budget exhausted", class), RunID: runID, Class: class}, nil
	}
	rs.Total++
	rs.Classes[class]++
	st.Runs[runID] = rs
	if err := writeState(cfg.StatePath, st); err != nil {
		return Decision{}, err
	}
	return Decision{Allowed: true, RunID: runID, Class: class}, nil
}

func operationClass(cfg config.MutationLimitsConfig, operation string, metadata map[string]string) string {
	if cfg.ActionMetadataField != "" {
		if class := metadata[cfg.ActionMetadataField]; class != "" {
			return class
		}
	}
	if class := cfg.OperationClasses[operation]; class != "" {
		return class
	}
	return operation
}

func readState(path string) (state, error) {
	var st state
	st.Runs = map[string]runState{}
	// #nosec G304 -- mutation budget state path is supplied by operator-controlled broker config.
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
	if st.Runs == nil {
		st.Runs = map[string]runState{}
	}
	return st, nil
}

func writeState(path string, st state) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
