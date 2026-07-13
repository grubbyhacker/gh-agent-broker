package sandbox

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

const (
	launchIntentSchemaVersion = 1
	launchFingerprintVersion  = "sandbox-rest-launch:v1"

	intentStateCreated       = "intent_created"
	intentStateCreatePending = "create_pending"
	intentStateContainerMade = "container_created"
	intentStateStartPending  = "start_pending"
	intentStateRunning       = "running"
	intentStateTerminal      = "terminal"
)

type LaunchIntentStore struct {
	db   *sql.DB
	salt []byte
}

type launchIntentPlan struct {
	Version        int              `json:"version"`
	ConfigVersion  string           `json:"config_version"`
	Request        LaunchAgentInput `json:"request"`
	RuntimeSeconds int64            `json:"runtime_seconds"`
	Metadata       RunMetadata      `json:"metadata"`
}

type launchIntent struct {
	Principal          string
	Profile            string
	KeyDigest          string
	RequestFingerprint string
	RunID              string
	State              string
	Plan               launchIntentPlan
	Metadata           RunMetadata
}

type intentConflictError struct {
	Code    string
	Message string
}

func (e *intentConflictError) Error() string { return e.Message }

func OpenLaunchIntentStore(ctx context.Context, path string) (*LaunchIntentStore, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("launch intent store path must be absolute")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create launch intent store directory: %w", err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open launch intent store: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	store := &LaunchIntentStore{db: db}
	if err := store.initialize(ctx); err != nil {
		return nil, errors.Join(err, db.Close())
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return nil, errors.Join(fmt.Errorf("secure launch intent store: %w", err), db.Close())
	}
	return store, nil
}

func (s *LaunchIntentStore) initialize(ctx context.Context) error {
	var journal string
	if err := s.db.QueryRowContext(ctx, "PRAGMA journal_mode=WAL").Scan(&journal); err != nil || journal != "wal" {
		return fmt.Errorf("enable launch intent WAL mode: mode=%q: %w", journal, err)
	}
	if _, err := s.db.ExecContext(ctx, "PRAGMA synchronous=FULL"); err != nil {
		return fmt.Errorf("enable launch intent synchronous FULL: %w", err)
	}
	var synchronous int
	if err := s.db.QueryRowContext(ctx, "PRAGMA synchronous").Scan(&synchronous); err != nil || synchronous != 2 {
		return fmt.Errorf("verify launch intent synchronous FULL: value=%d: %w", synchronous, err)
	}
	if _, err := s.db.ExecContext(ctx, "PRAGMA busy_timeout=5000"); err != nil {
		return fmt.Errorf("configure launch intent busy timeout: %w", err)
	}
	var integrity string
	if err := s.db.QueryRowContext(ctx, "PRAGMA quick_check").Scan(&integrity); err != nil || integrity != "ok" {
		return fmt.Errorf("launch intent store integrity check failed: %q: %w", integrity, err)
	}
	var version int
	if err := s.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return fmt.Errorf("read launch intent schema version: %w", err)
	}
	if version != 0 && version != launchIntentSchemaVersion {
		return fmt.Errorf("unsupported launch intent schema version %d", version)
	}
	if version == 0 {
		if err := s.migrateV1(ctx); err != nil {
			return err
		}
	}
	var salt []byte
	err := s.db.QueryRowContext(ctx, "SELECT value FROM launch_settings WHERE name = 'idempotency_hmac_salt'").Scan(&salt)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		salt = make([]byte, 32)
		if _, err := rand.Read(salt); err != nil {
			return fmt.Errorf("generate launch intent salt: %w", err)
		}
		if _, err := s.db.ExecContext(ctx, "INSERT INTO launch_settings(name, value) VALUES('idempotency_hmac_salt', ?)", salt); err != nil {
			return fmt.Errorf("persist launch intent salt: %w", err)
		}
	case err != nil:
		return fmt.Errorf("read launch intent salt: %w", err)
	case len(salt) != 32:
		return fmt.Errorf("launch intent salt is malformed")
	}
	s.salt = append([]byte(nil), salt...)
	return nil
}

func (s *LaunchIntentStore) migrateV1(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin launch intent migration: %w", err)
	}
	defer rollbackLaunchIntentTx(tx)
	statements := []string{
		`CREATE TABLE launch_settings (name TEXT PRIMARY KEY, value BLOB NOT NULL) STRICT`,
		`CREATE TABLE launch_intents (
			principal TEXT NOT NULL,
			profile TEXT NOT NULL,
			key_digest TEXT NOT NULL,
			request_fingerprint TEXT NOT NULL,
			run_id TEXT NOT NULL UNIQUE,
			state TEXT NOT NULL,
			plan_json BLOB NOT NULL,
			metadata_json BLOB NOT NULL,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			PRIMARY KEY (principal, profile, key_digest)
		) STRICT`,
		`CREATE INDEX launch_intents_profile_state ON launch_intents(profile, state)`,
		`PRAGMA user_version=1`,
	}
	for _, statement := range statements {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("migrate launch intent store: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit launch intent migration: %w", err)
	}
	return nil
}

func (s *LaunchIntentStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *LaunchIntentStore) digestKey(raw string) string {
	mac := hmac.New(sha256.New, s.salt)
	_, _ = mac.Write([]byte(raw))
	return hex.EncodeToString(mac.Sum(nil))
}

func requestFingerprint(canonical []byte) string {
	sum := sha256.Sum256(append([]byte(launchFingerprintVersion+"\n"), canonical...))
	return hex.EncodeToString(sum[:])
}

func (s *LaunchIntentStore) Lookup(ctx context.Context, principal, profile, digest string) (launchIntent, bool, error) {
	row := s.db.QueryRowContext(ctx, `SELECT request_fingerprint, run_id, state, plan_json, metadata_json
		FROM launch_intents WHERE principal=? AND profile=? AND key_digest=?`, principal, profile, digest)
	return scanLaunchIntent(row, principal, profile, digest)
}

func (s *LaunchIntentStore) Create(ctx context.Context, intent launchIntent, maxConcurrent int) (launchIntent, bool, error) {
	planJSON, err := json.Marshal(intent.Plan)
	if err != nil {
		return launchIntent{}, false, err
	}
	metadataJSON, err := json.Marshal(intent.Metadata)
	if err != nil {
		return launchIntent{}, false, err
	}
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return launchIntent{}, false, err
	}
	defer closeLaunchIntentConn(conn)
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return launchIntent{}, false, fmt.Errorf("begin immediate launch intent transaction: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			rollbackLaunchIntentConn(context.WithoutCancel(ctx), conn)
		}
	}()
	row := conn.QueryRowContext(ctx, `SELECT request_fingerprint, run_id, state, plan_json, metadata_json
		FROM launch_intents WHERE principal=? AND profile=? AND key_digest=?`, intent.Principal, intent.Profile, intent.KeyDigest)
	existing, found, err := scanLaunchIntent(row, intent.Principal, intent.Profile, intent.KeyDigest)
	if err != nil {
		return launchIntent{}, false, err
	}
	if found {
		return existing, false, nil
	}
	if maxConcurrent > 0 {
		var active int
		if err := conn.QueryRowContext(ctx, `SELECT count(*) FROM launch_intents WHERE profile=? AND state<>?`, intent.Profile, intentStateTerminal).Scan(&active); err != nil {
			return launchIntent{}, false, err
		}
		if active >= maxConcurrent {
			return launchIntent{}, false, &intentConflictError{Code: "profile_busy", Message: fmt.Sprintf("profile %q is busy; maximum concurrent runs is %d", intent.Profile, maxConcurrent)}
		}
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err = conn.ExecContext(ctx, `INSERT INTO launch_intents
		(principal, profile, key_digest, request_fingerprint, run_id, state, plan_json, metadata_json, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, intent.Principal, intent.Profile, intent.KeyDigest,
		intent.RequestFingerprint, intent.RunID, intent.State, planJSON, metadataJSON, now, now)
	if err != nil {
		return launchIntent{}, false, fmt.Errorf("persist launch intent: %w", err)
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return launchIntent{}, false, fmt.Errorf("commit launch intent: %w", err)
	}
	committed = true
	return intent, true, nil
}

func (s *LaunchIntentStore) RestoreMetadata(ctx context.Context, meta RunMetadata) error {
	if meta.Principal == "" || meta.Profile == "" || meta.IdempotencyKeyDigest == "" || meta.RequestFingerprint == "" || meta.LaunchConfigVersion == "" {
		return nil
	}
	state := intentStateCreated
	switch {
	case isTerminalStatus(meta.Status):
		state = intentStateTerminal
	case meta.Status == StatusRunning:
		state = intentStateRunning
	case meta.ContainerID != "":
		state = intentStateStartPending
	}
	runtimeSeconds := int64(meta.Deadline.Sub(meta.StartedAt) / time.Second)
	request := LaunchAgentInput{
		Template: meta.Template, Task: meta.Task, Repo: meta.Repo, BaseBranch: meta.BaseBranch,
		Branch: meta.Branch, MaxRuntimeSeconds: int(runtimeSeconds), Deliverables: append([]string(nil), meta.Deliverables...),
		Focus: meta.Focus, Parameters: cloneParameters(meta.Parameters), Profile: meta.Profile,
	}
	intent := launchIntent{
		Principal: meta.Principal, Profile: meta.Profile, KeyDigest: meta.IdempotencyKeyDigest,
		RequestFingerprint: meta.RequestFingerprint, RunID: meta.RunID, State: state, Metadata: meta,
		Plan: launchIntentPlan{Version: 1, ConfigVersion: meta.LaunchConfigVersion, Request: request, RuntimeSeconds: runtimeSeconds, Metadata: meta},
	}
	existing, created, err := s.Create(ctx, intent, 0)
	if err != nil {
		return fmt.Errorf("restore launch intent for run %q: %w", meta.RunID, err)
	}
	if !created && (existing.RunID != meta.RunID || existing.RequestFingerprint != meta.RequestFingerprint) {
		return fmt.Errorf("run metadata for %q conflicts with durable launch intent for run %q", meta.RunID, existing.RunID)
	}
	return nil
}

func (s *LaunchIntentStore) Save(ctx context.Context, intent launchIntent) error {
	planJSON, err := json.Marshal(intent.Plan)
	if err != nil {
		return err
	}
	metadataJSON, err := json.Marshal(intent.Metadata)
	if err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx, `UPDATE launch_intents SET state=?, plan_json=?, metadata_json=?, updated_at=? WHERE run_id=?`,
		intent.State, planJSON, metadataJSON, time.Now().UTC().Format(time.RFC3339Nano), intent.RunID)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		return fmt.Errorf("launch intent update affected %d rows: %w", rows, err)
	}
	return nil
}

func (s *LaunchIntentStore) SaveMetadata(ctx context.Context, meta RunMetadata) error {
	metadataJSON, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	state := intentStateRunning
	if isTerminalStatus(meta.Status) {
		state = intentStateTerminal
	}
	_, err = s.db.ExecContext(ctx, `UPDATE launch_intents SET state=?, metadata_json=?, updated_at=? WHERE run_id=?`,
		state, metadataJSON, time.Now().UTC().Format(time.RFC3339Nano), meta.RunID)
	return err
}

func (s *LaunchIntentStore) Nonterminal(ctx context.Context) ([]launchIntent, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT principal, profile, key_digest, request_fingerprint, run_id, state, plan_json, metadata_json
		FROM launch_intents WHERE state<>? ORDER BY created_at`, intentStateTerminal)
	if err != nil {
		return nil, err
	}
	defer closeLaunchIntentRows(rows)
	var intents []launchIntent
	for rows.Next() {
		var intent launchIntent
		var planJSON, metadataJSON []byte
		if err := rows.Scan(&intent.Principal, &intent.Profile, &intent.KeyDigest, &intent.RequestFingerprint, &intent.RunID, &intent.State, &planJSON, &metadataJSON); err != nil {
			return nil, err
		}
		if err := decodeLaunchIntent(&intent, planJSON, metadataJSON); err != nil {
			return nil, err
		}
		intents = append(intents, intent)
	}
	return intents, rows.Err()
}

func rollbackLaunchIntentTx(tx *sql.Tx) {
	if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
		// The operation's primary error remains authoritative; SQLite will also roll back on close.
		return
	}
}

func rollbackLaunchIntentConn(ctx context.Context, conn *sql.Conn) {
	if _, err := conn.ExecContext(ctx, "ROLLBACK"); err != nil {
		// SQLite also rolls back the transaction when the connection closes.
		return
	}
}

func closeLaunchIntentConn(conn *sql.Conn) {
	if err := conn.Close(); err != nil {
		// The operation's primary result remains authoritative.
		return
	}
}

func closeLaunchIntentRows(rows *sql.Rows) {
	if err := rows.Close(); err != nil {
		// rows.Err reports iteration failures to the caller; there is no useful recovery here.
		return
	}
}

func (s *LaunchIntentStore) IsNonterminalRun(ctx context.Context, runID string) (bool, error) {
	var exists bool
	err := s.db.QueryRowContext(ctx, `SELECT EXISTS(
		SELECT 1 FROM launch_intents WHERE run_id=? AND state<>?
	)`, runID, intentStateTerminal).Scan(&exists)
	return exists, err
}

type rowScanner interface{ Scan(...any) error }

func scanLaunchIntent(row rowScanner, principal, profile, digest string) (launchIntent, bool, error) {
	intent := launchIntent{Principal: principal, Profile: profile, KeyDigest: digest}
	var planJSON, metadataJSON []byte
	err := row.Scan(&intent.RequestFingerprint, &intent.RunID, &intent.State, &planJSON, &metadataJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return launchIntent{}, false, nil
	}
	if err != nil {
		return launchIntent{}, false, err
	}
	if err := decodeLaunchIntent(&intent, planJSON, metadataJSON); err != nil {
		return launchIntent{}, false, err
	}
	return intent, true, nil
}

func decodeLaunchIntent(intent *launchIntent, planJSON, metadataJSON []byte) error {
	if err := json.Unmarshal(planJSON, &intent.Plan); err != nil {
		return fmt.Errorf("decode launch intent plan for run %q: %w", intent.RunID, err)
	}
	if err := json.Unmarshal(metadataJSON, &intent.Metadata); err != nil {
		return fmt.Errorf("decode launch intent metadata for run %q: %w", intent.RunID, err)
	}
	if intent.Plan.Version != 1 || intent.RunID == "" || intent.Metadata.RunID != intent.RunID || intent.Plan.Metadata.RunID != intent.RunID {
		return fmt.Errorf("launch intent for run %q is malformed", intent.RunID)
	}
	return nil
}
