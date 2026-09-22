// Package correlation owns the broker's durable run-to-PR correlation and its
// transactional outbox for Signal Plane.
//
// The correlation is a broker-authoritative side effect: it is recorded only
// when the broker's OWN authenticated pull.create succeeds, binding the returned
// repository and PR number to the authenticated run capability/identity that
// made the call. Agent output, branch names, and PR body markers are never
// treated as authority — an unknown or unbound call records nothing.
//
// Two rows are written in ONE transaction so the correlation cannot exist
// without its outbox event and the event cannot exist without the correlation:
//
//   - pr_correlations: the durable association (identity, repo, PR number).
//   - outbox_events: a versioned event for Signal Plane to claim/ack.
//
// The outbox is required rather than a best-effort notification because the
// correlation must survive a crash between the GitHub response and the event
// being observed. Signal Plane consumption itself lives elsewhere; this package
// only produces and exposes the durable events with a claim/ack/retry reader.
package correlation

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

const (
	schemaVersion = 1

	// OutboxEventVersion is the versioned envelope kind Signal Plane consumes.
	// The version is part of the persisted payload so a consumer can refuse an
	// envelope shape it does not understand.
	OutboxEventVersion = "run-pr-correlation/v1"

	// maxPayloadBytes bounds a serialized outbox payload. The payload is
	// broker-derived and small (identity + repo + PR number + timestamps); the
	// bound is a hard backstop against an unexpectedly large record ever being
	// persisted or handed to a consumer.
	maxPayloadBytes = 8 * 1024

	// Outbox event lifecycle.
	statusPending = "pending"
	statusClaimed = "claimed"
	statusAcked   = "acked"
)

// Errors callers are expected to distinguish.
var (
	ErrNotFound      = errors.New("correlation not found")
	ErrClaimMismatch = errors.New("outbox claim token does not match")
	ErrPayloadBounds = errors.New("outbox payload exceeds bounded size")
)

// Identity is the authenticated broker-owned identity a correlation binds to.
// It is derived entirely from the broker's authentication and operation, never
// from agent-supplied request content. RunID is an optional recorded attribute
// read from the broker's configured run metadata field; it is descriptive, not
// authority, and an empty RunID is valid (the binding still holds via AgentID
// and OperationID).
type Identity struct {
	// AgentID is the authenticated broker agent identity (deny-by-default).
	AgentID string
	// OperationID is the broker-assigned operation id for the pull.create call.
	OperationID string
	// RunID is an optional descriptive run correlation attribute; never authority.
	RunID string
}

// Correlation is one durable run-to-PR association.
type Correlation struct {
	ID          int64
	AgentID     string
	OperationID string
	RunID       string
	Repo        string
	PRNumber    int64
	CreatedAt   time.Time
}

// OutboxEvent is one versioned, bounded event awaiting Signal Plane consumption.
type OutboxEvent struct {
	ID         int64
	Version    string
	Status     string
	Payload    []byte
	ClaimToken string
	ClaimedAt  *time.Time
	Attempts   int64
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// eventPayload is the bounded, broker-derived envelope body. It is intentionally
// flat and small.
type eventPayload struct {
	Version     string `json:"version"`
	AgentID     string `json:"agent_id"`
	OperationID string `json:"operation_id"`
	RunID       string `json:"run_id,omitempty"`
	Repo        string `json:"repo"`
	PRNumber    int64  `json:"pr_number"`
	RecordedAt  string `json:"recorded_at"`
}

// Store is the broker-owned correlation registry and outbox.
type Store struct {
	db  *sql.DB
	now func() time.Time
}

// Open opens or creates the store at an absolute path with the broker's standard
// storage discipline: single connection, WAL, synchronous=FULL, integrity check,
// user_version schema versioning, STRICT tables, and 0600 file mode.
func Open(ctx context.Context, path string) (*Store, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("correlation store path must be absolute")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create correlation store directory: %w", err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open correlation store: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	store := &Store{db: db, now: time.Now}
	if err := store.initialize(ctx); err != nil {
		return nil, errors.Join(err, db.Close())
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return nil, errors.Join(fmt.Errorf("secure correlation store: %w", err), db.Close())
	}
	return store, nil
}

func (s *Store) initialize(ctx context.Context) error {
	var journal string
	if err := s.db.QueryRowContext(ctx, "PRAGMA journal_mode=WAL").Scan(&journal); err != nil || journal != "wal" {
		return fmt.Errorf("enable correlation WAL mode: mode=%q: %w", journal, err)
	}
	if _, err := s.db.ExecContext(ctx, "PRAGMA synchronous=FULL"); err != nil {
		return fmt.Errorf("enable correlation synchronous FULL: %w", err)
	}
	var synchronous int
	if err := s.db.QueryRowContext(ctx, "PRAGMA synchronous").Scan(&synchronous); err != nil || synchronous != 2 {
		return fmt.Errorf("verify correlation synchronous FULL: value=%d: %w", synchronous, err)
	}
	if _, err := s.db.ExecContext(ctx, "PRAGMA busy_timeout=5000"); err != nil {
		return fmt.Errorf("configure correlation busy timeout: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, "PRAGMA foreign_keys=ON"); err != nil {
		return fmt.Errorf("enable correlation foreign keys: %w", err)
	}
	var integrity string
	if err := s.db.QueryRowContext(ctx, "PRAGMA quick_check").Scan(&integrity); err != nil || integrity != "ok" {
		return fmt.Errorf("correlation store integrity check failed: %q: %w", integrity, err)
	}
	var version int
	if err := s.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return fmt.Errorf("read correlation schema version: %w", err)
	}
	if version != 0 && version != schemaVersion {
		return fmt.Errorf("unsupported correlation schema version %d", version)
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
		return fmt.Errorf("begin correlation migration: %w", err)
	}
	defer rollback(tx)
	statements := []string{
		`CREATE TABLE pr_correlations (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			agent_id TEXT NOT NULL,
			operation_id TEXT NOT NULL,
			run_id TEXT NOT NULL,
			repo TEXT NOT NULL,
			pr_number INTEGER NOT NULL,
			created_at TEXT NOT NULL,
			UNIQUE (repo, pr_number),
			UNIQUE (operation_id)
		) STRICT`,
		`CREATE INDEX pr_correlations_agent ON pr_correlations(agent_id)`,
		`CREATE TABLE outbox_events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			correlation_id INTEGER NOT NULL REFERENCES pr_correlations(id),
			version TEXT NOT NULL,
			status TEXT NOT NULL,
			payload BLOB NOT NULL,
			claim_token TEXT NOT NULL DEFAULT '',
			claimed_at TEXT,
			attempts INTEGER NOT NULL DEFAULT 0,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			UNIQUE (correlation_id)
		) STRICT`,
		`CREATE INDEX outbox_events_status ON outbox_events(status, id)`,
		`PRAGMA user_version=1`,
	}
	for _, statement := range statements {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("migrate correlation store: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit correlation migration: %w", err)
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

// Record binds an authenticated broker pull.create success to its returned
// repository and PR number, writing the correlation and its versioned outbox
// event in a SINGLE transaction.
//
// It fails closed on unknown or unbound calls: an empty AgentID or OperationID,
// an empty repo, or a non-positive PR number records NOTHING and returns an
// error. It is idempotent on the broker OperationID: replaying the same
// operation returns the existing correlation without writing a second event, so
// a retry after a crash between GitHub and commit converges on one event.
func (s *Store) Record(ctx context.Context, id Identity, repo string, prNumber int64) (Correlation, error) {
	if id.AgentID == "" || id.OperationID == "" {
		return Correlation{}, fmt.Errorf("correlation requires an authenticated broker identity")
	}
	if repo == "" || prNumber <= 0 {
		return Correlation{}, fmt.Errorf("correlation requires a repo and a positive PR number")
	}
	now := s.now().UTC()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Correlation{}, fmt.Errorf("begin correlation record: %w", err)
	}
	defer rollback(tx)

	// Idempotency: an existing correlation for this broker operation id means
	// the pull.create side effect was already recorded. Return it unchanged.
	existing, err := correlationByOperation(ctx, tx, id.OperationID)
	switch {
	case err == nil:
		return existing, nil
	case !errors.Is(err, ErrNotFound):
		return Correlation{}, err
	}

	res, err := tx.ExecContext(ctx,
		`INSERT INTO pr_correlations (agent_id, operation_id, run_id, repo, pr_number, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		id.AgentID, id.OperationID, id.RunID, repo, prNumber, formatTime(now))
	if err != nil {
		return Correlation{}, fmt.Errorf("insert correlation: %w", err)
	}
	correlationID, err := res.LastInsertId()
	if err != nil {
		return Correlation{}, fmt.Errorf("read correlation id: %w", err)
	}

	payload, err := buildPayload(id, repo, prNumber, now)
	if err != nil {
		return Correlation{}, err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO outbox_events (correlation_id, version, status, payload, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		correlationID, OutboxEventVersion, statusPending, payload, formatTime(now), formatTime(now)); err != nil {
		return Correlation{}, fmt.Errorf("insert outbox event: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return Correlation{}, fmt.Errorf("commit correlation record: %w", err)
	}
	return Correlation{
		ID:          correlationID,
		AgentID:     id.AgentID,
		OperationID: id.OperationID,
		RunID:       id.RunID,
		Repo:        repo,
		PRNumber:    prNumber,
		CreatedAt:   now,
	}, nil
}

// GetByPR resolves a correlation by repository and PR number, the exact key a
// later review webhook maps back to.
func (s *Store) GetByPR(ctx context.Context, repo string, prNumber int64) (Correlation, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, agent_id, operation_id, run_id, repo, pr_number, created_at
		 FROM pr_correlations WHERE repo = ? AND pr_number = ?`, repo, prNumber)
	return scanCorrelation(row)
}

// ClaimPending atomically claims up to limit pending (or claim-expired) outbox
// events for a consumer, stamping a claim token and moving them to claimed. A
// claim older than claimTTL is reclaimable, so a consumer that crashes after
// claiming but before acking does not strand the event. Returns the claimed
// events; the caller acks each with Ack or lets the claim expire to retry.
func (s *Store) ClaimPending(ctx context.Context, claimToken string, limit int, claimTTL time.Duration) ([]OutboxEvent, error) {
	if claimToken == "" {
		return nil, fmt.Errorf("claim requires a non-empty claim token")
	}
	if limit <= 0 {
		limit = 1
	}
	now := s.now().UTC()
	expiry := now.Add(-claimTTL)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin outbox claim: %w", err)
	}
	defer rollback(tx)

	rows, err := tx.QueryContext(ctx,
		`SELECT id FROM outbox_events
		 WHERE status = ? OR (status = ? AND (claimed_at IS NULL OR claimed_at <= ?))
		 ORDER BY id LIMIT ?`,
		statusPending, statusClaimed, formatTime(expiry), limit)
	if err != nil {
		return nil, fmt.Errorf("select claimable outbox events: %w", err)
	}
	var candidateIDs []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, errors.Join(fmt.Errorf("scan claimable id: %w", err), rows.Close())
		}
		candidateIDs = append(candidateIDs, id)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Join(err, rows.Close())
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}

	claimed := make([]OutboxEvent, 0, len(candidateIDs))
	for _, id := range candidateIDs {
		if _, err := tx.ExecContext(ctx,
			`UPDATE outbox_events
			 SET status = ?, claim_token = ?, claimed_at = ?, attempts = attempts + 1, updated_at = ?
			 WHERE id = ?`,
			statusClaimed, claimToken, formatTime(now), formatTime(now), id); err != nil {
			return nil, fmt.Errorf("claim outbox event %d: %w", id, err)
		}
		event, err := outboxByID(ctx, tx, id)
		if err != nil {
			return nil, err
		}
		claimed = append(claimed, event)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit outbox claim: %w", err)
	}
	return claimed, nil
}

// Ack marks a claimed outbox event delivered. It refuses if the claim token
// does not match the current holder, so a stale consumer whose claim already
// expired and was reclaimed cannot ack another consumer's delivery.
func (s *Store) Ack(ctx context.Context, eventID int64, claimToken string) error {
	now := s.now().UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin outbox ack: %w", err)
	}
	defer rollback(tx)

	event, err := outboxByID(ctx, tx, eventID)
	if err != nil {
		return err
	}
	if event.Status != statusClaimed || event.ClaimToken != claimToken {
		return ErrClaimMismatch
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE outbox_events SET status = ?, updated_at = ? WHERE id = ?`,
		statusAcked, formatTime(now), eventID); err != nil {
		return fmt.Errorf("ack outbox event: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit outbox ack: %w", err)
	}
	return nil
}

// PendingCount returns the number of outbox events not yet acked. Used by tests
// and the offline validator to reason about drain state.
func (s *Store) PendingCount(ctx context.Context) (int64, error) {
	var count int64
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM outbox_events WHERE status != ?`, statusAcked).Scan(&count); err != nil {
		return 0, fmt.Errorf("count pending outbox events: %w", err)
	}
	return count, nil
}

// Validate performs an offline integrity check over the durable state: schema
// version, referential integrity between events and correlations, one event per
// correlation, known event versions, bounded payload sizes, and payloads that
// decode and agree with their correlation row. It never mutates state.
func (s *Store) Validate(ctx context.Context) (err error) {
	var version int
	if err := s.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}
	if version != schemaVersion {
		return fmt.Errorf("unexpected schema version %d, want %d", version, schemaVersion)
	}
	var orphanEvents int64
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM outbox_events e
		 LEFT JOIN pr_correlations c ON c.id = e.correlation_id
		 WHERE c.id IS NULL`).Scan(&orphanEvents); err != nil {
		return fmt.Errorf("check orphan events: %w", err)
	}
	if orphanEvents != 0 {
		return fmt.Errorf("%d outbox events reference a missing correlation", orphanEvents)
	}
	var correlationsWithoutEvent int64
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM pr_correlations c
		 LEFT JOIN outbox_events e ON e.correlation_id = c.id
		 WHERE e.id IS NULL`).Scan(&correlationsWithoutEvent); err != nil {
		return fmt.Errorf("check correlations without event: %w", err)
	}
	if correlationsWithoutEvent != 0 {
		return fmt.Errorf("%d correlations have no outbox event", correlationsWithoutEvent)
	}

	rows, err := s.db.QueryContext(ctx,
		`SELECT c.repo, c.pr_number, c.operation_id, e.version, e.payload
		 FROM outbox_events e JOIN pr_correlations c ON c.id = e.correlation_id`)
	if err != nil {
		return fmt.Errorf("scan events for validation: %w", err)
	}
	defer func() {
		if cerr := rows.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()
	for rows.Next() {
		var repo, operationID, version string
		var prNumber int64
		var payload []byte
		if err := rows.Scan(&repo, &prNumber, &operationID, &version, &payload); err != nil {
			return fmt.Errorf("scan validation row: %w", err)
		}
		if version != OutboxEventVersion {
			return fmt.Errorf("unknown outbox event version %q for %s#%d", version, repo, prNumber)
		}
		if len(payload) > maxPayloadBytes {
			return fmt.Errorf("%w: %s#%d payload is %d bytes", ErrPayloadBounds, repo, prNumber, len(payload))
		}
		var decoded eventPayload
		if err := json.Unmarshal(payload, &decoded); err != nil {
			return fmt.Errorf("decode payload for %s#%d: %w", repo, prNumber, err)
		}
		if decoded.Repo != repo || decoded.PRNumber != prNumber || decoded.OperationID != operationID {
			return fmt.Errorf("payload disagrees with correlation for %s#%d", repo, prNumber)
		}
		if decoded.Version != OutboxEventVersion {
			return fmt.Errorf("payload version %q disagrees with envelope for %s#%d", decoded.Version, repo, prNumber)
		}
	}
	return rows.Err()
}

func buildPayload(id Identity, repo string, prNumber int64, now time.Time) ([]byte, error) {
	payload, err := json.Marshal(eventPayload{
		Version:     OutboxEventVersion,
		AgentID:     id.AgentID,
		OperationID: id.OperationID,
		RunID:       id.RunID,
		Repo:        repo,
		PRNumber:    prNumber,
		RecordedAt:  formatTime(now),
	})
	if err != nil {
		return nil, fmt.Errorf("marshal outbox payload: %w", err)
	}
	if len(payload) > maxPayloadBytes {
		return nil, fmt.Errorf("%w: %d bytes", ErrPayloadBounds, len(payload))
	}
	return payload, nil
}

func correlationByOperation(ctx context.Context, tx *sql.Tx, operationID string) (Correlation, error) {
	row := tx.QueryRowContext(ctx,
		`SELECT id, agent_id, operation_id, run_id, repo, pr_number, created_at
		 FROM pr_correlations WHERE operation_id = ?`, operationID)
	return scanCorrelation(row)
}

func outboxByID(ctx context.Context, tx *sql.Tx, id int64) (OutboxEvent, error) {
	row := tx.QueryRowContext(ctx,
		`SELECT id, version, status, payload, claim_token, claimed_at, attempts, created_at, updated_at
		 FROM outbox_events WHERE id = ?`, id)
	var event OutboxEvent
	var claimedAt sql.NullString
	var createdAt, updatedAt string
	if err := row.Scan(&event.ID, &event.Version, &event.Status, &event.Payload,
		&event.ClaimToken, &claimedAt, &event.Attempts, &createdAt, &updatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return OutboxEvent{}, ErrNotFound
		}
		return OutboxEvent{}, fmt.Errorf("scan outbox event: %w", err)
	}
	if claimedAt.Valid {
		t, err := parseTime(claimedAt.String)
		if err != nil {
			return OutboxEvent{}, err
		}
		event.ClaimedAt = &t
	}
	var err error
	if event.CreatedAt, err = parseTime(createdAt); err != nil {
		return OutboxEvent{}, err
	}
	if event.UpdatedAt, err = parseTime(updatedAt); err != nil {
		return OutboxEvent{}, err
	}
	return event, nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanCorrelation(row rowScanner) (Correlation, error) {
	var c Correlation
	var createdAt string
	if err := row.Scan(&c.ID, &c.AgentID, &c.OperationID, &c.RunID, &c.Repo, &c.PRNumber, &createdAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Correlation{}, ErrNotFound
		}
		return Correlation{}, fmt.Errorf("scan correlation: %w", err)
	}
	var err error
	if c.CreatedAt, err = parseTime(createdAt); err != nil {
		return Correlation{}, err
	}
	return c, nil
}

func formatTime(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func parseTime(value string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse stored timestamp %q: %w", value, err)
	}
	return t.UTC(), nil
}

func rollback(tx *sql.Tx) {
	if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
		// A rollback after a successful commit is a no-op error; anything else is
		// surfaced through the operation's own error path. Nothing to do here.
		_ = err
	}
}
