// Package release owns the broker's AgentRelease registry.
//
// An AgentRelease is an immutable artifact: a digest-pinned image plus its
// provenance. The registry is the broker's own durable state, not configuration
// rendered into the broker at deploy time, so publishing a new agent
// implementation does not require a broker deploy.
//
// The authority split this package enforces:
//
//   - a publisher may PUBLISH a candidate; it cannot promote and cannot launch;
//   - a promoter may PROMOTE a verified, acquired generation; it cannot launch;
//   - the broker RESOLVES the active generation and is the sole runtime authority;
//   - callers name an agent type, never an image, release, or generation.
//
// Two properties are load-bearing:
//
// Monotonic generations. Generations are broker-assigned and strictly
// increasing. Promotion refuses a generation at or below the currently active
// one, because neither digests nor commits have a reliable total order.
// Returning to an earlier generation is Rollback: a separate, audited operation.
//
// Fail closed on availability. The sandbox launches an image that is already
// present; it does not pull. So an active generation whose image is not locally
// available must not launch. Reconcile marks such generations unavailable and
// Resolve then refuses, rather than allowing a launch that would fail or,
// worse, silently run something else.
package release

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const releaseSchemaVersion = 1

// Release states.
const (
	StateCandidate  = "candidate"
	StateVerified   = "verified"
	StateActive     = "active"
	StateSuperseded = "superseded"
	StateRolledBack = "rolled_back"
)

// Audited operations.
const (
	OperationPublish  = "publish"
	OperationVerify   = "verify"
	OperationAcquire  = "acquire"
	OperationPromote  = "promote"
	OperationRollback = "rollback"
	OperationEvict    = "evict"
)

// digestPinnedReference requires an image reference pinned by digest. A tag is
// never sufficient: a tag can move underneath a run.
var digestPinnedReference = regexp.MustCompile(`^[a-z0-9]+(?:[._\-/][a-z0-9]+)*(?::[A-Za-z0-9._\-]+)?@sha256:[0-9a-f]{64}$`)

var digestOnly = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

var agentTypePattern = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

// Errors callers are expected to distinguish.
var (
	ErrNotFound        = errors.New("release not found")
	ErrNoActiveRelease = errors.New("no active release for agent type")
	ErrUnavailable     = errors.New("active release image is not locally available")
	ErrNotPromotable   = errors.New("release is not promotable")
	ErrNotMonotonic    = errors.New("release generation is not newer than the active generation")
)

// Provenance is what a release must carry to be verifiable. Field names mirror
// the AgentType release_requirements declared in deployment-owned policy.
type Provenance struct {
	SourceRevision           string `json:"source_revision"`
	DependencyManifestSHA256 string `json:"dependency_manifest_sha256,omitempty"`
	Platform                 string `json:"platform"`
	PublishedBy              string `json:"published_by,omitempty"`
	PublishedAt              string `json:"published_at,omitempty"`
}

// Release is one immutable artifact at one generation.
type Release struct {
	Generation     int64
	AgentType      string
	ImageReference string
	ImageDigest    string
	Provenance     Provenance
	State          string
	Available      bool
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// Requirements are the verification rules a release must satisfy, taken from
// the agent type's declared release_requirements.
type Requirements struct {
	ProvenanceFields []string
	Platforms        []string
}

// Store is the broker-owned release registry.
type Store struct {
	db *sql.DB
}

// Open opens or creates the registry at an absolute path.
func Open(ctx context.Context, path string) (*Store, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("release store path must be absolute")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create release store directory: %w", err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open release store: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	store := &Store{db: db}
	if err := store.initialize(ctx); err != nil {
		return nil, errors.Join(err, db.Close())
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return nil, errors.Join(fmt.Errorf("secure release store: %w", err), db.Close())
	}
	return store, nil
}

// Close releases the underlying database.
func (s *Store) Close() error { return s.db.Close() }

func (s *Store) initialize(ctx context.Context) error {
	var journal string
	if err := s.db.QueryRowContext(ctx, "PRAGMA journal_mode=WAL").Scan(&journal); err != nil || journal != "wal" {
		return fmt.Errorf("enable release store WAL mode: mode=%q: %w", journal, err)
	}
	if _, err := s.db.ExecContext(ctx, "PRAGMA synchronous=FULL"); err != nil {
		return fmt.Errorf("enable release store synchronous FULL: %w", err)
	}
	var synchronous int
	if err := s.db.QueryRowContext(ctx, "PRAGMA synchronous").Scan(&synchronous); err != nil || synchronous != 2 {
		return fmt.Errorf("verify release store synchronous FULL: value=%d: %w", synchronous, err)
	}
	if _, err := s.db.ExecContext(ctx, "PRAGMA foreign_keys=ON"); err != nil {
		return fmt.Errorf("enable release store foreign keys: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, "PRAGMA busy_timeout=5000"); err != nil {
		return fmt.Errorf("configure release store busy timeout: %w", err)
	}
	var integrity string
	if err := s.db.QueryRowContext(ctx, "PRAGMA quick_check").Scan(&integrity); err != nil || integrity != "ok" {
		return fmt.Errorf("release store integrity check failed: %q: %w", integrity, err)
	}
	var version int
	if err := s.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return fmt.Errorf("read release schema version: %w", err)
	}
	if version != 0 && version != releaseSchemaVersion {
		return fmt.Errorf("unsupported release schema version %d", version)
	}
	if version == 0 {
		return s.migrateV1(ctx)
	}
	return nil
}

func closeReleaseRows(rows *sql.Rows) {
	if err := rows.Close(); err != nil {
		// rows.Err reports iteration failures to the caller; there is no useful
		// recovery here.
		return
	}
}

func rollback(tx *sql.Tx) {
	if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
		fmt.Fprintf(os.Stderr, "release store rollback failed: %v\n", err)
	}
}

func (s *Store) migrateV1(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin release migration: %w", err)
	}
	defer rollback(tx)
	statements := []string{
		`CREATE TABLE agent_releases (
			generation INTEGER PRIMARY KEY AUTOINCREMENT,
			agent_type TEXT NOT NULL,
			image_reference TEXT NOT NULL,
			image_digest TEXT NOT NULL,
			provenance_json BLOB NOT NULL,
			state TEXT NOT NULL,
			available INTEGER NOT NULL,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		) STRICT`,
		`CREATE UNIQUE INDEX agent_releases_type_digest ON agent_releases(agent_type, image_digest)`,
		`CREATE INDEX agent_releases_type_state ON agent_releases(agent_type, state)`,
		`CREATE TABLE release_audit (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			generation INTEGER NOT NULL REFERENCES agent_releases(generation),
			agent_type TEXT NOT NULL,
			operation TEXT NOT NULL,
			actor TEXT NOT NULL,
			detail TEXT NOT NULL,
			recorded_at TEXT NOT NULL
		) STRICT`,
		`CREATE INDEX release_audit_generation ON release_audit(generation)`,
		`PRAGMA user_version=1`,
	}
	for _, statement := range statements {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("migrate release store: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit release migration: %w", err)
	}
	return nil
}

func now() string { return time.Now().UTC().Format(time.RFC3339Nano) }

func parseTime(value string) time.Time {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}
	}
	return parsed
}

func digestOf(reference string) (string, error) {
	index := strings.LastIndex(reference, "@")
	if index < 0 {
		return "", fmt.Errorf("image reference must be digest-pinned")
	}
	digest := reference[index+1:]
	if !digestOnly.MatchString(digest) {
		return "", fmt.Errorf("image digest must be a sha256 digest")
	}
	return digest, nil
}

func (s *Store) audit(ctx context.Context, tx *sql.Tx, generation int64, agentType, operation, actor, detail string) error {
	_, err := tx.ExecContext(ctx,
		`INSERT INTO release_audit (generation, agent_type, operation, actor, detail, recorded_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		generation, agentType, operation, actor, detail, now())
	if err != nil {
		return fmt.Errorf("record release audit: %w", err)
	}
	return nil
}

// PublishCandidate records a proposed release. It does not make it runnable.
func (s *Store) PublishCandidate(ctx context.Context, agentType, imageReference string, provenance Provenance, actor string) (Release, error) {
	if !agentTypePattern.MatchString(agentType) {
		return Release{}, fmt.Errorf("agent type must be kebab-case")
	}
	if !digestPinnedReference.MatchString(imageReference) {
		return Release{}, fmt.Errorf("image reference must be digest-pinned, got %q", imageReference)
	}
	digest, err := digestOf(imageReference)
	if err != nil {
		return Release{}, err
	}
	if actor == "" {
		return Release{}, fmt.Errorf("publish requires an actor")
	}
	encoded, err := json.Marshal(provenance)
	if err != nil {
		return Release{}, fmt.Errorf("encode provenance: %w", err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Release{}, fmt.Errorf("begin publish: %w", err)
	}
	defer rollback(tx)

	timestamp := now()
	result, err := tx.ExecContext(ctx,
		`INSERT INTO agent_releases
		 (agent_type, image_reference, image_digest, provenance_json, state, available, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, 0, ?, ?)`,
		agentType, imageReference, digest, encoded, StateCandidate, timestamp, timestamp)
	if err != nil {
		return Release{}, fmt.Errorf("insert release candidate: %w", err)
	}
	generation, err := result.LastInsertId()
	if err != nil {
		return Release{}, fmt.Errorf("read assigned generation: %w", err)
	}
	if err := s.audit(ctx, tx, generation, agentType, OperationPublish, actor, imageReference); err != nil {
		return Release{}, err
	}
	if err := tx.Commit(); err != nil {
		return Release{}, fmt.Errorf("commit publish: %w", err)
	}

	return Release{
		Generation:     generation,
		AgentType:      agentType,
		ImageReference: imageReference,
		ImageDigest:    digest,
		Provenance:     provenance,
		State:          StateCandidate,
		CreatedAt:      parseTime(timestamp),
		UpdatedAt:      parseTime(timestamp),
	}, nil
}

// verify checks a candidate against deployment-owned requirements. It is kept
// internal so callers cannot separately authorize verification.
func (s *Store) verify(ctx context.Context, generation int64, requirements Requirements, actor string) error {
	if actor == "" {
		return fmt.Errorf("verify requires an actor")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin verify: %w", err)
	}
	defer rollback(tx)

	item, err := loadTx(ctx, tx, generation)
	if err != nil {
		return err
	}
	if item.State != StateCandidate && item.State != StateVerified {
		return fmt.Errorf("%w: generation %d is %s", ErrNotPromotable, generation, item.State)
	}
	if err := checkRequirements(item, requirements); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE agent_releases SET state = ?, updated_at = ? WHERE generation = ?`,
		StateVerified, now(), generation); err != nil {
		return fmt.Errorf("mark release verified: %w", err)
	}
	if err := s.audit(ctx, tx, generation, item.AgentType, OperationVerify, actor, item.ImageDigest); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit verify: %w", err)
	}
	return nil
}

func checkRequirements(item Release, requirements Requirements) error {
	present := map[string]string{
		"source_revision":            item.Provenance.SourceRevision,
		"dependency_manifest_sha256": item.Provenance.DependencyManifestSHA256,
		"platform":                   item.Provenance.Platform,
		"image_digest":               item.ImageDigest,
	}
	for _, field := range requirements.ProvenanceFields {
		value, known := present[field]
		if !known {
			return fmt.Errorf("unknown required provenance field %q", field)
		}
		if value == "" {
			return fmt.Errorf("release is missing required provenance field %q", field)
		}
	}
	if len(requirements.Platforms) > 0 {
		matched := false
		for _, platform := range requirements.Platforms {
			if platform == item.Provenance.Platform {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("release platform %q is not among the required platforms %v",
				item.Provenance.Platform, requirements.Platforms)
		}
	}
	return nil
}

// markAvailable records an observed local image state. It is internal so no
// caller can assert availability.
func (s *Store) markAvailable(ctx context.Context, generation int64, available bool, actor string) error {
	if actor == "" {
		return fmt.Errorf("availability change requires an actor")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin availability update: %w", err)
	}
	defer rollback(tx)

	item, err := loadTx(ctx, tx, generation)
	if err != nil {
		return err
	}
	flag := 0
	operation := OperationEvict
	if available {
		flag = 1
		operation = OperationAcquire
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE agent_releases SET available = ?, updated_at = ? WHERE generation = ?`,
		flag, now(), generation); err != nil {
		return fmt.Errorf("update release availability: %w", err)
	}
	if err := s.audit(ctx, tx, generation, item.AgentType, operation, actor, item.ImageDigest); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit availability update: %w", err)
	}
	return nil
}

// VerifyAndMarkAvailable is the broker's single internal acquisition boundary.
// Verification is committed before acquire runs; a failed acquisition leaves a
// verified but unavailable candidate, which remains non-promotable.
func (s *Store) VerifyAndMarkAvailable(ctx context.Context, generation int64, requirements Requirements, verifier, acquirer string, acquire func(context.Context, Release) error) error {
	if err := s.verify(ctx, generation, requirements, verifier); err != nil {
		return err
	}
	item, err := s.load(ctx, generation)
	if err != nil {
		return err
	}
	if err := acquire(ctx, item); err != nil {
		return err
	}
	return s.markAvailable(ctx, generation, true, acquirer)
}

// Promote activates a verified, locally available generation. It refuses any
// generation at or below the currently active one; going backwards is Rollback.
func (s *Store) Promote(ctx context.Context, generation int64, actor string) error {
	if actor == "" {
		return fmt.Errorf("promote requires an actor")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin promote: %w", err)
	}
	defer rollback(tx)

	item, err := loadTx(ctx, tx, generation)
	if err != nil {
		return err
	}
	if item.State != StateVerified {
		return fmt.Errorf("%w: generation %d is %s, expected %s",
			ErrNotPromotable, generation, item.State, StateVerified)
	}
	if !item.Available {
		return fmt.Errorf("%w: generation %d must be acquired before promotion", ErrUnavailable, generation)
	}

	active, err := activeTx(ctx, tx, item.AgentType)
	switch {
	case errors.Is(err, ErrNoActiveRelease):
	case err != nil:
		return err
	default:
		if generation <= active.Generation {
			return fmt.Errorf("%w: generation %d is not newer than active generation %d; use rollback",
				ErrNotMonotonic, generation, active.Generation)
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE agent_releases SET state = ?, updated_at = ? WHERE generation = ?`,
			StateSuperseded, now(), active.Generation); err != nil {
			return fmt.Errorf("supersede previous release: %w", err)
		}
	}

	if _, err := tx.ExecContext(ctx,
		`UPDATE agent_releases SET state = ?, updated_at = ? WHERE generation = ?`,
		StateActive, now(), generation); err != nil {
		return fmt.Errorf("activate release: %w", err)
	}
	if err := s.audit(ctx, tx, generation, item.AgentType, OperationPromote, actor, item.ImageDigest); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit promote: %w", err)
	}
	return nil
}

// Rollback returns an agent type to an earlier generation. It is deliberately a
// distinct, audited operation rather than a side effect of promotion.
func (s *Store) Rollback(ctx context.Context, agentType string, generation int64, actor string) error {
	if actor == "" {
		return fmt.Errorf("rollback requires an actor")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin rollback: %w", err)
	}
	defer rollback(tx)

	item, err := loadTx(ctx, tx, generation)
	if err != nil {
		return err
	}
	if item.AgentType != agentType {
		return fmt.Errorf("generation %d belongs to agent type %q, not %q",
			generation, item.AgentType, agentType)
	}
	if !item.Available {
		return fmt.Errorf("%w: generation %d is not locally available", ErrUnavailable, generation)
	}
	if item.State != StateSuperseded && item.State != StateRolledBack && item.State != StateVerified {
		return fmt.Errorf("%w: generation %d is %s", ErrNotPromotable, generation, item.State)
	}

	active, err := activeTx(ctx, tx, agentType)
	switch {
	case errors.Is(err, ErrNoActiveRelease):
	case err != nil:
		return err
	default:
		if _, err := tx.ExecContext(ctx,
			`UPDATE agent_releases SET state = ?, updated_at = ? WHERE generation = ?`,
			StateRolledBack, now(), active.Generation); err != nil {
			return fmt.Errorf("retire rolled-back release: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE agent_releases SET state = ?, updated_at = ? WHERE generation = ?`,
		StateActive, now(), generation); err != nil {
		return fmt.Errorf("activate rollback target: %w", err)
	}
	if err := s.audit(ctx, tx, generation, agentType, OperationRollback, actor, item.ImageDigest); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit rollback: %w", err)
	}
	return nil
}

// Resolve returns the release a launch of this agent type must use. It fails
// closed when the active image is not locally available, because the sandbox
// launches an already-present image and does not pull.
func (s *Store) Resolve(ctx context.Context, agentType string) (Release, error) {
	item, err := s.Active(ctx, agentType)
	if err != nil {
		return Release{}, err
	}
	if !item.Available {
		return Release{}, fmt.Errorf("%w: agent type %q generation %d digest %s",
			ErrUnavailable, agentType, item.Generation, item.ImageDigest)
	}
	return item, nil
}

// Active returns the active release regardless of availability.
func (s *Store) Active(ctx context.Context, agentType string) (Release, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT generation, agent_type, image_reference, image_digest, provenance_json, state, available, created_at, updated_at
		 FROM agent_releases WHERE agent_type = ? AND state = ?`,
		agentType, StateActive)
	item, err := scan(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Release{}, fmt.Errorf("%w: %s", ErrNoActiveRelease, agentType)
	}
	if err != nil {
		return Release{}, err
	}
	return item, nil
}

// Get returns one release by generation.
func (s *Store) Get(ctx context.Context, generation int64) (Release, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT generation, agent_type, image_reference, image_digest, provenance_json, state, available, created_at, updated_at
		 FROM agent_releases WHERE generation = ?`, generation)
	item, err := scan(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Release{}, fmt.Errorf("%w: generation %d", ErrNotFound, generation)
	}
	return item, err
}

// ActiveReleases returns every active release, for startup reconciliation.
func (s *Store) ActiveReleases(ctx context.Context) ([]Release, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT generation, agent_type, image_reference, image_digest, provenance_json, state, available, created_at, updated_at
		 FROM agent_releases WHERE state = ? ORDER BY agent_type`, StateActive)
	if err != nil {
		return nil, fmt.Errorf("list active releases: %w", err)
	}
	defer closeReleaseRows(rows)

	var items []Release
	for rows.Next() {
		item, err := scanRows(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate active releases: %w", err)
	}
	return items, nil
}

// AvailabilityCheck reports whether an image digest is present locally.
type AvailabilityCheck func(ctx context.Context, imageReference, imageDigest string) (bool, error)

// ReconcileResult describes one active release that is not runnable.
type ReconcileResult struct {
	AgentType      string
	Generation     int64
	ImageReference string
	ImageDigest    string
}

// Reconcile re-checks every active release against local image availability.
// Run it at startup and after a restore: the registry is backed up, Docker image
// state is not, so an active generation can reference an absent image. Missing
// images are marked unavailable so Resolve fails closed, and returned so the
// caller can reacquire them by digest.
func (s *Store) Reconcile(ctx context.Context, check AvailabilityCheck, actor string) ([]ReconcileResult, error) {
	if check == nil {
		return nil, fmt.Errorf("reconcile requires an availability check")
	}
	if actor == "" {
		return nil, fmt.Errorf("reconcile requires an actor")
	}
	items, err := s.ActiveReleases(ctx)
	if err != nil {
		return nil, err
	}
	var missing []ReconcileResult
	for _, item := range items {
		available, err := check(ctx, item.ImageReference, item.ImageDigest)
		if err != nil {
			return nil, fmt.Errorf("check availability of %s: %w", item.ImageDigest, err)
		}
		if available == item.Available {
			continue
		}
		if err := s.markAvailable(ctx, item.Generation, available, actor); err != nil {
			return nil, err
		}
		if !available {
			missing = append(missing, ReconcileResult{
				AgentType:      item.AgentType,
				Generation:     item.Generation,
				ImageReference: item.ImageReference,
				ImageDigest:    item.ImageDigest,
			})
		}
	}
	// Report any active release still unavailable, including ones already marked.
	for _, item := range items {
		if item.Available {
			continue
		}
		alreadyReported := false
		for _, entry := range missing {
			if entry.Generation == item.Generation {
				alreadyReported = true
				break
			}
		}
		if alreadyReported {
			continue
		}
		available, err := check(ctx, item.ImageReference, item.ImageDigest)
		if err != nil {
			return nil, fmt.Errorf("check availability of %s: %w", item.ImageDigest, err)
		}
		if !available {
			missing = append(missing, ReconcileResult{
				AgentType:      item.AgentType,
				Generation:     item.Generation,
				ImageReference: item.ImageReference,
				ImageDigest:    item.ImageDigest,
			})
		}
	}
	return missing, nil
}

// AuditEntry is one recorded registry operation.
type AuditEntry struct {
	Generation int64
	AgentType  string
	Operation  string
	Actor      string
	Detail     string
	RecordedAt time.Time
}

// AuditTrail returns the recorded operations for one generation, oldest first.
func (s *Store) AuditTrail(ctx context.Context, generation int64) ([]AuditEntry, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT generation, agent_type, operation, actor, detail, recorded_at
		 FROM release_audit WHERE generation = ? ORDER BY id`, generation)
	if err != nil {
		return nil, fmt.Errorf("read release audit: %w", err)
	}
	defer closeReleaseRows(rows)

	var entries []AuditEntry
	for rows.Next() {
		var entry AuditEntry
		var recordedAt string
		if err := rows.Scan(&entry.Generation, &entry.AgentType, &entry.Operation,
			&entry.Actor, &entry.Detail, &recordedAt); err != nil {
			return nil, fmt.Errorf("scan release audit: %w", err)
		}
		entry.RecordedAt = parseTime(recordedAt)
		entries = append(entries, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate release audit: %w", err)
	}
	return entries, nil
}

type scanner interface {
	Scan(dest ...any) error
}

func scan(row scanner) (Release, error) {
	var (
		item       Release
		provenance []byte
		available  int
		createdAt  string
		updatedAt  string
	)
	if err := row.Scan(&item.Generation, &item.AgentType, &item.ImageReference, &item.ImageDigest,
		&provenance, &item.State, &available, &createdAt, &updatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Release{}, err
		}
		return Release{}, fmt.Errorf("scan release: %w", err)
	}
	if err := json.Unmarshal(provenance, &item.Provenance); err != nil {
		return Release{}, fmt.Errorf("decode release provenance: %w", err)
	}
	item.Available = available == 1
	item.CreatedAt = parseTime(createdAt)
	item.UpdatedAt = parseTime(updatedAt)
	return item, nil
}

func scanRows(rows *sql.Rows) (Release, error) { return scan(rows) }

func loadTx(ctx context.Context, tx *sql.Tx, generation int64) (Release, error) {
	row := tx.QueryRowContext(ctx,
		`SELECT generation, agent_type, image_reference, image_digest, provenance_json, state, available, created_at, updated_at
		 FROM agent_releases WHERE generation = ?`, generation)
	item, err := scan(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Release{}, fmt.Errorf("%w: generation %d", ErrNotFound, generation)
	}
	return item, err
}

func (s *Store) load(ctx context.Context, generation int64) (Release, error) {
	row := s.db.QueryRowContext(ctx, `SELECT generation, agent_type, image_reference, image_digest, provenance_json, state, available, created_at, updated_at FROM agent_releases WHERE generation = ?`, generation)
	item, err := scan(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Release{}, fmt.Errorf("%w: generation %d", ErrNotFound, generation)
	}
	return item, err
}

func activeTx(ctx context.Context, tx *sql.Tx, agentType string) (Release, error) {
	row := tx.QueryRowContext(ctx,
		`SELECT generation, agent_type, image_reference, image_digest, provenance_json, state, available, created_at, updated_at
		 FROM agent_releases WHERE agent_type = ? AND state = ?`, agentType, StateActive)
	item, err := scan(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Release{}, fmt.Errorf("%w: %s", ErrNoActiveRelease, agentType)
	}
	return item, err
}
