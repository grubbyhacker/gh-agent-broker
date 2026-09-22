package capability

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
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
	storeSchemaVersion = 1

	// handleBytes is the entropy of an issued capability handle: a
	// broker-verified opaque 256-bit token (agent-infra-docs PR #19).
	handleBytes = 32

	// Capability lifecycle states.
	stateActive  = "active"
	stateRevoked = "revoked"
)

// Store errors callers are expected to distinguish. None of these ever carries a
// plaintext handle: a handle appears only in the return of Issue.
var (
	ErrStoreClosed       = errors.New("capability store is closed")
	ErrHandleNotFound    = errors.New("capability handle not found")
	ErrRevoked           = errors.New("capability has been revoked")
	ErrHandleMalformed   = errors.New("capability handle is malformed")
	ErrReservationDenied = errors.New("capability reservation denied")
)

// Store is the broker-owned durable capability registry. It is the SOLE mint
// authority: only Issue creates a capability, and it stores the SHA-256 hash of
// the handle, never the handle itself. Verify and Reserve authenticate a
// presented handle by hashing it and matching the stored hash in constant time.
//
// Same storage discipline as internal/release: modernc.org/sqlite, WAL journal,
// synchronous=FULL, verified quick_check, PRAGMA user_version schema versioning,
// STRICT tables, a single connection, an absolute path, and 0600 file mode.
type Store struct {
	db   *sql.DB
	now  func() time.Time
	eval PolicyEvaluator
}

var (
	_ Issuer   = (*Store)(nil)
	_ Verifier = (*Store)(nil)
	_ Reserver = (*Store)(nil)
)

// Reservation is the running per-run accounting the store maintains atomically.
type Reservation struct {
	Calls  int64
	Tokens int64
}

// OpenStore opens or creates the capability store at an absolute path.
func OpenStore(ctx context.Context, path string) (*Store, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("capability store path must be absolute")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create capability store directory: %w", err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open capability store: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	store := &Store{db: db, now: time.Now}
	if err := store.initialize(ctx); err != nil {
		return nil, errors.Join(err, db.Close())
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return nil, errors.Join(fmt.Errorf("secure capability store: %w", err), db.Close())
	}
	return store, nil
}

func (s *Store) initialize(ctx context.Context) error {
	var journal string
	if err := s.db.QueryRowContext(ctx, "PRAGMA journal_mode=WAL").Scan(&journal); err != nil || journal != "wal" {
		return fmt.Errorf("enable capability WAL mode: mode=%q: %w", journal, err)
	}
	if _, err := s.db.ExecContext(ctx, "PRAGMA synchronous=FULL"); err != nil {
		return fmt.Errorf("enable capability synchronous FULL: %w", err)
	}
	var synchronous int
	if err := s.db.QueryRowContext(ctx, "PRAGMA synchronous").Scan(&synchronous); err != nil || synchronous != 2 {
		return fmt.Errorf("verify capability synchronous FULL: value=%d: %w", synchronous, err)
	}
	if _, err := s.db.ExecContext(ctx, "PRAGMA busy_timeout=5000"); err != nil {
		return fmt.Errorf("configure capability busy timeout: %w", err)
	}
	var integrity string
	if err := s.db.QueryRowContext(ctx, "PRAGMA quick_check").Scan(&integrity); err != nil || integrity != "ok" {
		return fmt.Errorf("capability store integrity check failed: %q: %w", integrity, err)
	}
	var version int
	if err := s.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return fmt.Errorf("read capability schema version: %w", err)
	}
	if version != 0 && version != storeSchemaVersion {
		return fmt.Errorf("unsupported capability schema version %d", version)
	}
	if version == 0 {
		if err := s.migrateV1(ctx); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) migrateV1(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin capability migration: %w", err)
	}
	defer rollbackStore(tx)
	statements := []string{
		`CREATE TABLE capabilities (
			handle_sha256 TEXT PRIMARY KEY,
			agent_type TEXT NOT NULL,
			mode TEXT NOT NULL,
			run_id TEXT NOT NULL,
			work_item_id TEXT NOT NULL,
			allowed_models TEXT NOT NULL,
			call_budget INTEGER NOT NULL,
			token_budget INTEGER NOT NULL,
			expiry TEXT NOT NULL,
			state TEXT NOT NULL,
			reserved_calls INTEGER NOT NULL DEFAULT 0,
			reserved_tokens INTEGER NOT NULL DEFAULT 0,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		) STRICT`,
		`CREATE INDEX capabilities_run ON capabilities(run_id)`,
		`PRAGMA user_version=1`,
	}
	for _, statement := range statements {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("migrate capability store: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit capability migration: %w", err)
	}
	return nil
}

// Close closes the store.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// Issue mints a capability for the given claims and returns the plaintext handle
// EXACTLY ONCE. Only the handle's SHA-256 is persisted, so the plaintext cannot
// be recovered from the store, logs, or audit. The store is the sole mint
// authority.
func (s *Store) Issue(ctx context.Context, claims Claims) (handle string, err error) {
	if err := s.eval.Validate(claims, s.now()); err != nil {
		return "", err
	}
	raw := make([]byte, handleBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate capability handle: %w", err)
	}
	handle = hex.EncodeToString(raw)
	digest := hashHandle(handle)
	modelsJSON, err := json.Marshal(claims.AllowedModels())
	if err != nil {
		return "", fmt.Errorf("encode capability allowed models: %w", err)
	}
	now := s.now().UTC()
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO capabilities
		 (handle_sha256, agent_type, mode, run_id, work_item_id, allowed_models,
		  call_budget, token_budget, expiry, state, reserved_calls, reserved_tokens, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, ?, ?)`,
		digest, claims.agentType, string(claims.mode), claims.runID, claims.workItemID,
		string(modelsJSON), claims.callBudget, claims.tokenBudget,
		formatStoreTime(claims.expiry), stateActive, formatStoreTime(now), formatStoreTime(now)); err != nil {
		return "", fmt.Errorf("persist capability: %w", err)
	}
	return handle, nil
}

// Verify authenticates a presented handle and returns its trusted server-side
// claims plus current reservation. It fails closed on a malformed handle, an
// unknown handle, a revoked capability, or expired/incoherent claims. The lookup
// matches the stored hash in constant time.
func (s *Store) Verify(ctx context.Context, handle string) (Claims, Reservation, error) {
	row, err := s.lookup(ctx, handle)
	if err != nil {
		return Claims{}, Reservation{}, err
	}
	if err := s.eval.Validate(row.claims, s.now()); err != nil {
		return Claims{}, Reservation{}, err
	}
	return row.claims, row.reservation, nil
}

// Reserve atomically authorizes and records a call/token reservation for the run
// the handle belongs to. The whole read-authorize-write is one transaction, so
// concurrent reservations cannot exceed the budget. It reuses PolicyEvaluator for
// identity, model, expiry, and budget-headroom checks against the CURRENT
// reserved totals. Returns the new running reservation.
func (s *Store) Reserve(ctx context.Context, handle string, req Request) (Reservation, error) {
	digest, err := digestOf(handle)
	if err != nil {
		return Reservation{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Reservation{}, fmt.Errorf("begin capability reserve: %w", err)
	}
	defer rollbackStore(tx)

	row, err := scanCapabilityTx(ctx, tx, digest)
	if err != nil {
		return Reservation{}, err
	}

	// Fill in the current reserved totals so PolicyEvaluator checks headroom
	// against durable state, not caller-asserted amounts.
	req.ReservedCalls = row.reservation.Calls
	req.ReservedTokens = row.reservation.Tokens
	if err := s.eval.Authorize(row.claims, req, s.now()); err != nil {
		return Reservation{}, err
	}

	newCalls := row.reservation.Calls + req.Calls
	newTokens := row.reservation.Tokens + req.Tokens
	if _, err := tx.ExecContext(ctx,
		`UPDATE capabilities SET reserved_calls = ?, reserved_tokens = ?, updated_at = ?
		 WHERE handle_sha256 = ? AND state = ?`,
		newCalls, newTokens, formatStoreTime(s.now().UTC()), digest, stateActive); err != nil {
		return Reservation{}, fmt.Errorf("record capability reservation: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return Reservation{}, fmt.Errorf("commit capability reservation: %w", err)
	}
	return Reservation{Calls: newCalls, Tokens: newTokens}, nil
}

// Revoke marks a capability revoked so a later Verify/Reserve fails closed. It is
// idempotent: revoking an already-revoked capability is a no-op success.
func (s *Store) Revoke(ctx context.Context, handle string) error {
	digest, err := digestOf(handle)
	if err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE capabilities SET state = ?, updated_at = ? WHERE handle_sha256 = ?`,
		stateRevoked, formatStoreTime(s.now().UTC()), digest)
	if err != nil {
		return fmt.Errorf("revoke capability: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("read revoke result: %w", err)
	}
	if affected == 0 {
		return ErrHandleNotFound
	}
	return nil
}

type capabilityRow struct {
	claims      Claims
	reservation Reservation
	state       string
}

func (s *Store) lookup(ctx context.Context, handle string) (capabilityRow, error) {
	digest, err := digestOf(handle)
	if err != nil {
		return capabilityRow{}, err
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return capabilityRow{}, fmt.Errorf("begin capability lookup: %w", err)
	}
	defer rollbackStore(tx)
	return scanCapabilityTx(ctx, tx, digest)
}

func scanCapabilityTx(ctx context.Context, tx *sql.Tx, digest string) (capabilityRow, error) {
	var (
		agentType, mode, runID, workItemID, models, expiryStr, state string
		callBudget, tokenBudget, reservedCalls, reservedTokens       int64
		storedDigest                                                 string
	)
	err := tx.QueryRowContext(ctx,
		`SELECT handle_sha256, agent_type, mode, run_id, work_item_id, allowed_models,
		        call_budget, token_budget, expiry, state, reserved_calls, reserved_tokens
		 FROM capabilities WHERE handle_sha256 = ?`, digest).
		Scan(&storedDigest, &agentType, &mode, &runID, &workItemID, &models,
			&callBudget, &tokenBudget, &expiryStr, &state, &reservedCalls, &reservedTokens)
	if errors.Is(err, sql.ErrNoRows) {
		return capabilityRow{}, ErrHandleNotFound
	}
	if err != nil {
		return capabilityRow{}, fmt.Errorf("scan capability: %w", err)
	}
	// Constant-time confirm the stored digest matches the lookup digest. The
	// PRIMARY KEY lookup already selected by digest; this guards against any
	// non-constant-time comparison leaking through a future change.
	if subtle.ConstantTimeCompare([]byte(storedDigest), []byte(digest)) != 1 {
		return capabilityRow{}, ErrHandleNotFound
	}
	if state == stateRevoked {
		return capabilityRow{}, ErrRevoked
	}
	expiry, err := parseStoreTime(expiryStr)
	if err != nil {
		return capabilityRow{}, err
	}
	allowedModels, err := decodeAllowedModels(models)
	if err != nil {
		return capabilityRow{}, err
	}
	claims, err := NewClaims(ClaimsInput{
		AgentType:     agentType,
		Mode:          Mode(mode),
		RunID:         runID,
		WorkItemID:    workItemID,
		AllowedModels: allowedModels,
		CallBudget:    callBudget,
		TokenBudget:   tokenBudget,
		Expiry:        expiry,
	})
	if err != nil {
		return capabilityRow{}, fmt.Errorf("reconstruct capability claims: %w", err)
	}
	return capabilityRow{
		claims:      claims,
		reservation: Reservation{Calls: reservedCalls, Tokens: reservedTokens},
		state:       state,
	}, nil
}

func hashHandle(handle string) string {
	sum := sha256.Sum256([]byte(handle))
	return hex.EncodeToString(sum[:])
}

// digestOf validates a presented handle's shape and returns its SHA-256 digest.
// A handle is 64 lowercase hex chars (32 bytes). Rejecting a malformed handle
// before hashing keeps a bad input from ever reaching a lookup.
func digestOf(handle string) (string, error) {
	if len(handle) != handleBytes*2 {
		return "", ErrHandleMalformed
	}
	if _, err := hex.DecodeString(handle); err != nil {
		return "", ErrHandleMalformed
	}
	return hashHandle(handle), nil
}

func formatStoreTime(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func decodeAllowedModels(value string) ([]string, error) {
	var models []string
	if err := json.Unmarshal([]byte(value), &models); err != nil {
		return nil, fmt.Errorf("decode stored allowed_models: %w", err)
	}
	return models, nil
}

func parseStoreTime(value string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse stored timestamp %q: %w", value, err)
	}
	return t.UTC(), nil
}

func rollbackStore(tx *sql.Tx) {
	if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
		_ = err
	}
}

// Validate performs an offline integrity check over the durable state: schema
// version, coherent claims per row, and reservations within budget. It never
// mutates state and never touches a handle (only stored hashes exist).
func (s *Store) Validate(ctx context.Context) (err error) {
	var version int
	if err := s.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}
	if version != storeSchemaVersion {
		return fmt.Errorf("unexpected schema version %d, want %d", version, storeSchemaVersion)
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT handle_sha256, agent_type, mode, run_id, work_item_id, allowed_models,
		        call_budget, token_budget, expiry, state, reserved_calls, reserved_tokens
		 FROM capabilities`)
	if err != nil {
		return fmt.Errorf("scan capabilities: %w", err)
	}
	defer func() {
		if cerr := rows.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()
	for rows.Next() {
		var (
			digest, agentType, mode, runID, workItemID, models, expiryStr, state string
			callBudget, tokenBudget, reservedCalls, reservedTokens               int64
		)
		if err := rows.Scan(&digest, &agentType, &mode, &runID, &workItemID, &models,
			&callBudget, &tokenBudget, &expiryStr, &state, &reservedCalls, &reservedTokens); err != nil {
			return fmt.Errorf("scan validation row: %w", err)
		}
		if len(digest) != sha256.Size*2 {
			return fmt.Errorf("capability for run %s has a malformed stored hash", runID)
		}
		if state != stateActive && state != stateRevoked {
			return fmt.Errorf("capability for run %s has unknown state %q", runID, state)
		}
		expiry, err := parseStoreTime(expiryStr)
		if err != nil {
			return err
		}
		allowedModels, err := decodeAllowedModels(models)
		if err != nil {
			return fmt.Errorf("capability for run %s has invalid allowed_models: %w", runID, err)
		}
		if _, err := NewClaims(ClaimsInput{
			AgentType: agentType, Mode: Mode(mode), RunID: runID, WorkItemID: workItemID,
			AllowedModels: allowedModels, CallBudget: callBudget, TokenBudget: tokenBudget, Expiry: expiry,
		}); err != nil {
			return fmt.Errorf("capability for run %s has incoherent claims: %w", runID, err)
		}
		if reservedCalls < 0 || reservedTokens < 0 || reservedCalls > callBudget || reservedTokens > tokenBudget {
			return fmt.Errorf("capability for run %s has reservation outside budget", runID)
		}
	}
	return rows.Err()
}
