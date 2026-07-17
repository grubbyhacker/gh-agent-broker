// Package pushtripwire defines the bounded scanner wire contract and durable
// response controls for asynchronous post-push inspection.
package pushtripwire

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const Version = "broker/push-tripwire/v1"

var (
	idPattern      = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
	repoPattern    = regexp.MustCompile(`^[a-z0-9_.-]+/[a-z0-9_.-]+$`)
	refPattern     = regexp.MustCompile(`^refs/heads/[A-Za-z0-9._/-]{1,220}$`)
	shaPattern     = regexp.MustCompile(`^[0-9a-f]{40}$`)
	profilePattern = regexp.MustCompile(`^[A-Za-z0-9._/-]{1,128}$`)
)

type MaterialRequest struct {
	Version    string `json:"version"`
	DeliveryID string `json:"delivery_id"`
	Repository string `json:"repository"`
	Ref        string `json:"ref"`
	Before     string `json:"before"`
	After      string `json:"after"`
}

type Commit struct {
	SHA     string `json:"sha"`
	Message string `json:"message"`
}

type File struct {
	CommitSHA     string `json:"commit_sha"`
	Path          string `json:"path"`
	Side          string `json:"side"`
	Status        string `json:"status"`
	BlobSHA       string `json:"blob_sha,omitempty"`
	Size          int64  `json:"size"`
	ContentBase64 string `json:"content_base64,omitempty"`
}

type MaterialResponse struct {
	Version    string         `json:"version"`
	DeliveryID string         `json:"delivery_id"`
	Repository string         `json:"repository"`
	Ref        string         `json:"ref"`
	Before     string         `json:"before"`
	After      string         `json:"after"`
	Complete   bool           `json:"complete"`
	ReasonCode string         `json:"reason_code,omitempty"`
	Bounds     MaterialBounds `json:"bounds"`
	Commits    []Commit       `json:"commits"`
	Files      []File         `json:"files"`
}

type MaterialBounds struct {
	CommitCount int   `json:"commit_count"`
	PathCount   int   `json:"path_count"`
	TotalBytes  int64 `json:"total_bytes"`
}

func (r MaterialRequest) Validate() error {
	if r.Version != Version || !idPattern.MatchString(r.DeliveryID) || !repoPattern.MatchString(r.Repository) || !refPattern.MatchString(r.Ref) || !shaPattern.MatchString(r.Before) || !shaPattern.MatchString(r.After) || r.After == strings.Repeat("0", 40) {
		return errors.New("invalid push tripwire material identity")
	}
	return nil
}

func Authenticate(header, secret string) bool {
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) || secret == "" {
		return false
	}
	provided := strings.TrimPrefix(header, prefix)
	return len(provided) == len(secret) && subtle.ConstantTimeCompare([]byte(provided), []byte(secret)) == 1
}

type Binding struct {
	WorkerID               string `json:"worker_id"`
	LogicalSessionID       string `json:"logical_session_id"`
	SessionLineageID       string `json:"session_lineage_id"`
	WorkerStorageLineageID string `json:"worker_storage_lineage_id"`
	WorkerFenceEpoch       int64  `json:"worker_fence_epoch"`
}

type ResponseRequest struct {
	Version           string   `json:"version"`
	FindingID         string   `json:"finding_id"`
	DeliveryID        string   `json:"delivery_id"`
	Repository        string   `json:"repository"`
	Ref               string   `json:"ref"`
	Before            string   `json:"before"`
	After             string   `json:"after"`
	Severity          string   `json:"severity"`
	ReasonCode        string   `json:"reason_code"`
	FingerprintID     string   `json:"fingerprint_id"`
	Profile           string   `json:"profile"`
	ProfileGeneration int64    `json:"profile_generation"`
	Binding           *Binding `json:"binding,omitempty"`
	Actions           []string `json:"actions"`
}

func (r ResponseRequest) Validate() error {
	if r.Version != Version || !idPattern.MatchString(r.FindingID) || !idPattern.MatchString(r.DeliveryID) || !repoPattern.MatchString(r.Repository) || !refPattern.MatchString(r.Ref) || !shaPattern.MatchString(r.Before) || !shaPattern.MatchString(r.After) || (r.Severity != "high" && r.Severity != "low") || !idPattern.MatchString(r.ReasonCode) || (r.FingerprintID != "" && !idPattern.MatchString(r.FingerprintID)) || !profilePattern.MatchString(r.Profile) || r.ProfileGeneration < 1 || len(r.Actions) < 1 || len(r.Actions) > 2 {
		return errors.New("invalid push tripwire response identity")
	}
	seen := map[string]bool{}
	for _, action := range r.Actions {
		if seen[action] || (action != "halt_issuance" && action != "fence_worker_session") {
			return errors.New("invalid or duplicate push tripwire response action")
		}
		seen[action] = true
	}
	if seen["fence_worker_session"] {
		b := r.Binding
		if b == nil || !idPattern.MatchString(b.WorkerID) || !idPattern.MatchString(b.LogicalSessionID) || !idPattern.MatchString(b.SessionLineageID) || !idPattern.MatchString(b.WorkerStorageLineageID) || b.WorkerFenceEpoch < 1 {
			return errors.New("fence_worker_session requires a complete worker binding")
		}
	}
	return nil
}

type FenceAdapter interface {
	Fence(context.Context, Binding, string) error
}

type ActionState struct {
	Action      string `json:"action"`
	State       string `json:"state"`
	CompletedAt string `json:"completed_at"`
}

type ResponseResult struct {
	Version          string        `json:"version"`
	FindingID        string        `json:"finding_id"`
	IdempotentReplay bool          `json:"idempotent_replay"`
	Actions          []ActionState `json:"actions"`
}

type Store struct{ db *sql.DB }

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	for _, stmt := range []string{
		`PRAGMA journal_mode=WAL`,
		`CREATE TABLE IF NOT EXISTS issuance_halts (profile TEXT NOT NULL, generation INTEGER NOT NULL, finding_id TEXT NOT NULL, PRIMARY KEY(profile,generation))`,
		`CREATE TABLE IF NOT EXISTS issuance_enforcement_catalog (profile TEXT NOT NULL, generation INTEGER NOT NULL, registered_at TEXT NOT NULL, PRIMARY KEY(profile,generation))`,
		`CREATE TABLE IF NOT EXISTS responses (idempotency_key TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, request BLOB NOT NULL, response BLOB NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS fence_requests (finding_id TEXT PRIMARY KEY, binding BLOB NOT NULL, state TEXT NOT NULL)`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			return nil, errors.Join(fmt.Errorf("initialize push tripwire state: %w", err), db.Close())
		}
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

// ReplaceEnforcementCatalog is called by the sandbox authority process at
// startup. It proves which exact profile generations consult this shared state
// before issuing new worker or session authority.
func (s *Store) ReplaceEnforcementCatalog(ctx context.Context, profiles map[string]int64) error {
	if len(profiles) == 0 {
		return errors.New("issuance enforcement catalog must not be empty")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM issuance_enforcement_catalog`); err != nil {
		return errors.Join(err, tx.Rollback())
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for profile, generation := range profiles {
		if !profilePattern.MatchString(profile) || generation < 1 {
			return errors.Join(errors.New("invalid issuance enforcement profile generation"), tx.Rollback())
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO issuance_enforcement_catalog(profile,generation,registered_at) VALUES(?,?,?)`, profile, generation, now); err != nil {
			return errors.Join(err, tx.Rollback())
		}
	}
	return tx.Commit()
}

func fingerprint(req ResponseRequest) (string, error) {
	copyReq := req
	copyReq.Actions = append([]string(nil), req.Actions...)
	sort.Strings(copyReq.Actions)
	b, err := json.Marshal(copyReq)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func (s *Store) Apply(ctx context.Context, key string, req ResponseRequest, adapter FenceAdapter) (ResponseResult, error) {
	if !idPattern.MatchString(key) {
		return ResponseResult{}, errors.New("valid Idempotency-Key is required")
	}
	fp, err := fingerprint(req)
	if err != nil {
		return ResponseResult{}, err
	}
	var oldFP string
	var oldBody []byte
	err = s.db.QueryRowContext(ctx, `SELECT fingerprint,response FROM responses WHERE idempotency_key=?`, key).Scan(&oldFP, &oldBody)
	if err == nil {
		if oldFP != fp {
			return ResponseResult{}, errors.New("idempotency key reused for a different response")
		}
		var out ResponseResult
		if err := json.Unmarshal(oldBody, &out); err != nil {
			return ResponseResult{}, err
		}
		if req.Binding != nil && adapter != nil {
			for i := range out.Actions {
				if out.Actions[i].Action == "fence_worker_session" && out.Actions[i].State == "fence_requested" {
					if err := adapter.Fence(ctx, *req.Binding, req.FindingID); err == nil {
						out.Actions[i].State = "fenced"
						out.Actions[i].CompletedAt = time.Now().UTC().Format(time.RFC3339Nano)
						body, err := json.Marshal(out)
						if err != nil {
							return ResponseResult{}, err
						}
						if _, err := s.db.ExecContext(ctx, `UPDATE fence_requests SET state='fenced' WHERE finding_id=?`, req.FindingID); err != nil {
							return ResponseResult{}, err
						}
						if _, err := s.db.ExecContext(ctx, `UPDATE responses SET response=? WHERE idempotency_key=?`, body, key); err != nil {
							return ResponseResult{}, err
						}
					}
				}
			}
		}
		out.IdempotentReplay = true
		return out, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return ResponseResult{}, err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ResponseResult{}, err
	}
	out := ResponseResult{Version: Version, FindingID: req.FindingID}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for _, action := range req.Actions {
		switch action {
		case "halt_issuance":
			var registered int
			if err = tx.QueryRowContext(ctx, `SELECT 1 FROM issuance_enforcement_catalog WHERE profile=? AND generation=?`, req.Profile, req.ProfileGeneration).Scan(&registered); err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					err = errors.New("authority issuance enforcement is not registered for profile generation")
				}
				return ResponseResult{}, errors.Join(err, tx.Rollback())
			}
			if _, err = tx.ExecContext(ctx, `INSERT OR IGNORE INTO issuance_halts(profile,generation,finding_id) VALUES(?,?,?)`, req.Profile, req.ProfileGeneration, req.FindingID); err != nil {
				return ResponseResult{}, errors.Join(err, tx.Rollback())
			}
			out.Actions = append(out.Actions, ActionState{Action: action, State: "halted", CompletedAt: now})
		case "fence_worker_session":
			binding, marshalErr := json.Marshal(req.Binding)
			if marshalErr != nil {
				return ResponseResult{}, errors.Join(marshalErr, tx.Rollback())
			}
			if _, err = tx.ExecContext(ctx, `INSERT OR IGNORE INTO fence_requests(finding_id,binding,state) VALUES(?,?,'requested')`, req.FindingID, binding); err != nil {
				return ResponseResult{}, errors.Join(err, tx.Rollback())
			}
			out.Actions = append(out.Actions, ActionState{Action: action, State: "fence_requested", CompletedAt: now})
		}
	}
	body, err := json.Marshal(out)
	if err != nil {
		return ResponseResult{}, errors.Join(err, tx.Rollback())
	}
	requestBody, err := json.Marshal(req)
	if err != nil {
		return ResponseResult{}, errors.Join(err, tx.Rollback())
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO responses(idempotency_key,fingerprint,request,response) VALUES(?,?,?,?)`, key, fp, requestBody, body); err != nil {
		return ResponseResult{}, errors.Join(err, tx.Rollback())
	}
	if err = tx.Commit(); err != nil {
		return ResponseResult{}, err
	}

	if req.Binding != nil && adapter != nil {
		if err := adapter.Fence(ctx, *req.Binding, req.FindingID); err == nil {
			if _, err := s.db.ExecContext(ctx, `UPDATE fence_requests SET state='fenced' WHERE finding_id=?`, req.FindingID); err != nil {
				return ResponseResult{}, err
			}
			for i := range out.Actions {
				if out.Actions[i].Action == "fence_worker_session" {
					out.Actions[i].State = "fenced"
					out.Actions[i].CompletedAt = time.Now().UTC().Format(time.RFC3339Nano)
				}
			}
			body, err = json.Marshal(out)
			if err != nil {
				return ResponseResult{}, err
			}
			if _, err := s.db.ExecContext(ctx, `UPDATE responses SET response=? WHERE idempotency_key=?`, body, key); err != nil {
				return ResponseResult{}, err
			}
		}
	}
	return out, nil
}

// CheckIssuance fails closed: any state read error is returned to the caller,
// which must not issue credentials or work for the requested generation.
func (s *Store) CheckIssuance(ctx context.Context, profile string, generation int64) error {
	var registered int
	if err := s.db.QueryRowContext(ctx, `SELECT 1 FROM issuance_enforcement_catalog WHERE profile=? AND generation=?`, profile, generation).Scan(&registered); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return errors.New("authority issuance enforcement registration is unavailable")
		}
		return fmt.Errorf("read push tripwire enforcement catalog: %w", err)
	}
	var finding string
	err := s.db.QueryRowContext(ctx, `SELECT finding_id FROM issuance_halts WHERE profile=? AND generation=?`, profile, generation).Scan(&finding)
	if err == nil {
		return fmt.Errorf("issuance halted by push tripwire finding %s", finding)
	}
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	return fmt.Errorf("read push tripwire issuance state: %w", err)
}
