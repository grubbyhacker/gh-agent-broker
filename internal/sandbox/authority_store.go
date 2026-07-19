package sandbox

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"gh-agent-broker/internal/pushtripwire"

	_ "modernc.org/sqlite"
)

const authorityStoreSchemaVersion = 12

const (
	authorityAdoptionPending          = "pending"
	authorityAdoptionConfirmed        = "confirmed"
	authorityAdoptionConflict         = "conflict"
	authorityAdoptionLegacyUnresolved = "legacy_unresolved"
)

type AuthorityWorkerState string

const (
	AuthorityWorkerProvisioning AuthorityWorkerState = "provisioning"
	AuthorityWorkerStarting     AuthorityWorkerState = "starting"
	AuthorityWorkerReady        AuthorityWorkerState = "ready"
	AuthorityWorkerDraining     AuthorityWorkerState = "draining"
	AuthorityWorkerUnhealthy    AuthorityWorkerState = "unhealthy"
	AuthorityWorkerStopped      AuthorityWorkerState = "stopped"
	AuthorityWorkerFailed       AuthorityWorkerState = "failed"
)

type AuthorityWorker struct {
	WorkerID               string               `json:"worker_id"`
	Profile                string               `json:"profile"`
	ProfileVersion         string               `json:"profile_version"`
	PolicyDigest           string               `json:"policy_digest"`
	ImageReference         string               `json:"image_reference"`
	ImageDigest            string               `json:"image_digest"`
	Generation             int                  `json:"generation"`
	ContainerID            string               `json:"container_id,omitempty"`
	State                  AuthorityWorkerState `json:"state"`
	Capacity               int                  `json:"capacity"`
	AssignedSessions       int                  `json:"assigned_sessions"`
	Health                 string               `json:"health,omitempty"`
	DrainReason            string               `json:"drain_reason,omitempty"`
	ReplacementWorker      string               `json:"replacement_worker_id,omitempty"`
	HeartbeatAt            time.Time            `json:"heartbeat_at,omitempty"`
	CreatedAt              time.Time            `json:"created_at"`
	UpdatedAt              time.Time            `json:"updated_at"`
	WorkerStorageLineageID string               `json:"worker_storage_lineage_id"`
	WorkerFenceEpoch       int64                `json:"worker_fence_epoch"`
}

type AuthorityLease struct {
	Principal              string    `json:"principal"`
	Profile                string    `json:"profile"`
	WorkerID               string    `json:"worker_id"`
	SessionLineageID       string    `json:"session_lineage_id"`
	WorkerStorageLineageID string    `json:"worker_storage_lineage_id"`
	WorkerFenceEpoch       int64     `json:"worker_fence_epoch"`
	ProfileVersion         string    `json:"profile_version"`
	PolicyDigest           string    `json:"policy_digest"`
	BindingDigest          string    `json:"session_binding_digest"`
	IdempotencyDigest      string    `json:"idempotency_key_digest"`
	CreatedAt              time.Time `json:"created_at"`
	ReleasedAt             time.Time `json:"released_at,omitempty"`
	Replay                 bool      `json:"replay"`
}

// AuthoritySessionReassignment is the durable result of moving one logical
// session between a linked predecessor and replacement.  The replacement is
// always selected by the broker, never by a caller.
type AuthoritySessionReassignment struct {
	Lease               AuthorityLease `json:"lease"`
	PredecessorWorkerID string         `json:"predecessor_worker_id"`
	ReplacementWorkerID string         `json:"replacement_worker_id"`
	Replay              bool           `json:"replay"`
}

// authorityAgentdAdoption is the durable, replayable half of a reassignment.
// Every value needed to reproduce and verify the agentd command is captured in
// the same transaction as the lease/workspace CAS.
type authorityAgentdAdoption struct {
	BindingDigest        string
	CoordinatorBinding   string
	AuthorityBinding     string
	ProfileVersion       string
	PolicyDigest         string
	SessionLineageID     string
	AgentdSessionID      string
	Predecessor          agentdWorkerBinding
	Successor            agentdWorkerBinding
	RebindIdempotencyKey string
	Workspace            agentdSessionWorkspace
	State                string
	ErrorCode            string
}

// ReassignmentErrorCode is deliberately narrow so coordinators can decide
// whether to retry, refresh their binding, or surface a deterministic denial.
type ReassignmentErrorCode string

const (
	ReassignmentNotReady               ReassignmentErrorCode = "reassignment_not_ready"
	ReassignmentStalePredecessor       ReassignmentErrorCode = "reassignment_stale_predecessor"
	ReassignmentConflictingReplacement ReassignmentErrorCode = "reassignment_conflicting_replacement"
	ReassignmentCapacity               ReassignmentErrorCode = "reassignment_capacity"
	ReassignmentReplay                 ReassignmentErrorCode = "reassignment_replay"
	ReassignmentRebindRetryable        ReassignmentErrorCode = "reassignment_rebind_retryable"
	ReassignmentRebindConflict         ReassignmentErrorCode = "reassignment_rebind_conflict"
)

type ReassignmentError struct {
	Code ReassignmentErrorCode
	Err  error
}

func (e *ReassignmentError) Error() string { return e.Err.Error() }
func (e *ReassignmentError) Unwrap() error { return e.Err }

func reassignmentError(code ReassignmentErrorCode, format string, args ...any) error {
	return &ReassignmentError{Code: code, Err: fmt.Errorf(format, args...)}
}

type AuthorityWorkerStore struct {
	db                         *sql.DB
	salt                       []byte
	sessionMu                  sync.Mutex
	afterIssuanceCheckForTest  func()
	afterIssuanceCommitForTest func()
}

func (s *AuthorityWorkerStore) checkIssuanceInTransaction(ctx context.Context, conn *sql.Conn, profile string, generation int64) error {
	if err := pushtripwire.CheckIssuanceState(ctx, conn, profile, generation); err != nil {
		return fmt.Errorf("authority issuance denied: %w", err)
	}
	if s.afterIssuanceCheckForTest != nil {
		s.afterIssuanceCheckForTest()
	}
	return nil
}

func OpenAuthorityWorkerStore(ctx context.Context, path string) (*AuthorityWorkerStore, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("authority worker store path must be absolute")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create authority worker store directory: %w", err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open authority worker store: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	store := &AuthorityWorkerStore{db: db}
	if err := store.initialize(ctx); err != nil {
		return nil, errors.Join(err, db.Close())
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return nil, errors.Join(fmt.Errorf("secure authority worker store: %w", err), db.Close())
	}
	return store, nil
}

func (s *AuthorityWorkerStore) initialize(ctx context.Context) error {
	for _, statement := range []string{
		"PRAGMA foreign_keys=ON",
		"PRAGMA journal_mode=WAL",
		"PRAGMA synchronous=FULL",
		"PRAGMA busy_timeout=5000",
	} {
		if _, err := s.db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("initialize authority worker store: %w", err)
		}
	}
	var integrity string
	if err := s.db.QueryRowContext(ctx, "PRAGMA quick_check").Scan(&integrity); err != nil || integrity != "ok" {
		return fmt.Errorf("authority worker store integrity check failed: %q: %w", integrity, err)
	}
	var version int
	if err := s.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	if version > authorityStoreSchemaVersion {
		return fmt.Errorf("unsupported authority worker schema version %d", version)
	}
	if version == 0 {
		if err := s.migrateV1(ctx); err != nil {
			return err
		}
		version = 1
	}
	if version == 1 {
		if err := s.migrateV2(ctx); err != nil {
			return err
		}
		version = 2
	}
	if version == 2 {
		if err := s.migrateV3(ctx); err != nil {
			return err
		}
		version = 3
	}
	if version == 3 {
		if err := s.migrateV4(ctx); err != nil {
			return err
		}
		version = 4
	}
	if version == 4 {
		if err := s.migrateV5(ctx); err != nil {
			return err
		}
		version = 5
	}
	if version == 5 {
		if err := s.migrateV6(ctx); err != nil {
			return err
		}
		version = 6
	}
	if version == 6 {
		if err := s.migrateV7(ctx); err != nil {
			return err
		}
		version = 7
	}
	if version == 7 {
		if err := s.migrateV8(ctx); err != nil {
			return err
		}
		version = 8
	}
	if version == 8 {
		if err := s.migrateV9(ctx); err != nil {
			return err
		}
		version = 9
	}
	if version == 9 {
		if err := s.migrateV10(ctx); err != nil {
			return err
		}
		version = 10
	}
	if version == 10 {
		if err := s.migrateV11(ctx); err != nil {
			return err
		}
	}
	if version == 11 {
		if err := s.migrateV12(ctx); err != nil {
			return err
		}
	}
	var salt []byte
	err := s.db.QueryRowContext(ctx, "SELECT value FROM authority_settings WHERE name='request_hmac_salt'").Scan(&salt)
	if errors.Is(err, sql.ErrNoRows) {
		salt = make([]byte, 32)
		if _, err := rand.Read(salt); err != nil {
			return err
		}
		if _, err := s.db.ExecContext(ctx, "INSERT INTO authority_settings(name,value) VALUES('request_hmac_salt',?)", salt); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	if len(salt) != 32 {
		return fmt.Errorf("authority worker request salt is malformed")
	}
	s.salt = append([]byte(nil), salt...)
	return nil
}

// V11 records the immutable registered-task input with the lease.  Legacy
// leases deliberately have no row and therefore cannot enter this lifecycle.
func (s *AuthorityWorkerStore) migrateV11(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `CREATE UNIQUE INDEX authority_session_leases_principal_binding ON authority_session_leases(principal,binding_digest);
	CREATE TABLE authority_registered_admissions (
		principal TEXT NOT NULL, binding_digest TEXT NOT NULL,
		protocol_version TEXT NOT NULL, work_item_id TEXT NOT NULL, route_snapshot_id TEXT NOT NULL,
		canonical_task_json TEXT NOT NULL, admission_task_digest TEXT NOT NULL,
		PRIMARY KEY(principal,binding_digest),
		FOREIGN KEY(principal,binding_digest) REFERENCES authority_session_leases(principal,binding_digest)
	) STRICT; PRAGMA user_version=11`)
	return err
}

// V12 repairs databases created by the original V11 migration, whose
// single-column relationship did not model the lease's principal binding.
func (s *AuthorityWorkerStore) migrateV12(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `PRAGMA foreign_keys=OFF;
	CREATE UNIQUE INDEX IF NOT EXISTS authority_session_leases_principal_binding ON authority_session_leases(principal,binding_digest);
	CREATE TABLE authority_registered_admissions_v12 (
		principal TEXT NOT NULL, binding_digest TEXT NOT NULL,
		protocol_version TEXT NOT NULL, work_item_id TEXT NOT NULL, route_snapshot_id TEXT NOT NULL,
		canonical_task_json TEXT NOT NULL, admission_task_digest TEXT NOT NULL,
		PRIMARY KEY(principal,binding_digest),
		FOREIGN KEY(principal,binding_digest) REFERENCES authority_session_leases(principal,binding_digest)
	) STRICT;
	INSERT INTO authority_registered_admissions_v12(principal,binding_digest,protocol_version,work_item_id,route_snapshot_id,canonical_task_json,admission_task_digest)
	SELECT l.principal,a.binding_digest,a.protocol_version,a.work_item_id,a.route_snapshot_id,a.canonical_task_json,a.admission_task_digest
	FROM authority_registered_admissions a JOIN authority_session_leases l ON l.binding_digest=a.binding_digest;
	DROP TABLE authority_registered_admissions;
	ALTER TABLE authority_registered_admissions_v12 RENAME TO authority_registered_admissions;
	PRAGMA foreign_keys=ON;
	PRAGMA user_version=12;
	PRAGMA foreign_key_check`)
	return err
}

func (s *AuthorityWorkerStore) migrateV1(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer rollbackAuthorityTx(tx)
	statements := []string{
		`CREATE TABLE authority_settings (name TEXT PRIMARY KEY, value BLOB NOT NULL) STRICT`,
		`CREATE TABLE authority_workers (
			worker_id TEXT PRIMARY KEY, profile TEXT NOT NULL, profile_version TEXT NOT NULL,
			policy_digest TEXT NOT NULL, image_reference TEXT NOT NULL, image_digest TEXT NOT NULL DEFAULT '', generation INTEGER NOT NULL,
			container_id TEXT NOT NULL DEFAULT '', state TEXT NOT NULL, capacity INTEGER NOT NULL,
			assigned_sessions INTEGER NOT NULL DEFAULT 0, health TEXT NOT NULL DEFAULT '',
			drain_reason TEXT NOT NULL DEFAULT '', replacement_worker_id TEXT NOT NULL DEFAULT '',
			heartbeat_at TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
			CHECK(capacity > 0), CHECK(assigned_sessions >= 0), CHECK(assigned_sessions <= capacity)
		) STRICT`,
		`CREATE INDEX authority_workers_available ON authority_workers(profile,state,assigned_sessions,generation)`,
		`CREATE TABLE authority_session_leases (
			principal TEXT NOT NULL, profile TEXT NOT NULL, idempotency_digest TEXT NOT NULL,
			request_fingerprint TEXT NOT NULL, binding_digest TEXT NOT NULL UNIQUE,
			worker_id TEXT NOT NULL REFERENCES authority_workers(worker_id),
			created_at TEXT NOT NULL, released_at TEXT NOT NULL DEFAULT '',
			PRIMARY KEY(principal,profile,idempotency_digest)
		) STRICT`,
		`PRAGMA user_version=1`,
	}
	for _, statement := range statements {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("migrate authority worker store: %w", err)
		}
	}
	return tx.Commit()
}

func (s *AuthorityWorkerStore) migrateV2(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `CREATE TABLE authority_session_workspaces (
		binding_digest TEXT PRIMARY KEY REFERENCES authority_session_leases(binding_digest),
		worker_id TEXT NOT NULL REFERENCES authority_workers(worker_id),
		uid INTEGER NOT NULL, gid INTEGER NOT NULL, workspace_path TEXT NOT NULL,
		created_at TEXT NOT NULL, UNIQUE(worker_id,uid), UNIQUE(worker_id,gid), UNIQUE(workspace_path)
	) STRICT; PRAGMA user_version=2`)
	return err
}

func (s *AuthorityWorkerStore) migrateV3(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `CREATE TABLE authority_session_reassignments (
		principal TEXT NOT NULL, idempotency_digest TEXT NOT NULL,
		request_fingerprint TEXT NOT NULL, binding_digest TEXT NOT NULL,
		predecessor_worker_id TEXT NOT NULL REFERENCES authority_workers(worker_id),
		replacement_worker_id TEXT NOT NULL REFERENCES authority_workers(worker_id),
		created_at TEXT NOT NULL,
		PRIMARY KEY(principal,idempotency_digest), UNIQUE(principal,binding_digest)
	) STRICT;
	CREATE INDEX authority_session_reassignments_replacement ON authority_session_reassignments(replacement_worker_id);
	PRAGMA user_version=3`)
	return err
}

// V4 makes the logical session identity independent of a worker generation.
// Existing sessions receive a one-time opaque lineage during migration.
func (s *AuthorityWorkerStore) migrateV4(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `ALTER TABLE authority_session_leases ADD COLUMN lineage_id TEXT NOT NULL DEFAULT '';
	ALTER TABLE authority_session_leases ADD COLUMN fence_epoch INTEGER NOT NULL DEFAULT 1;
	ALTER TABLE authority_session_workspaces ADD COLUMN lineage_id TEXT NOT NULL DEFAULT '';
	UPDATE authority_session_leases SET lineage_id=lower(hex(randomblob(16))) WHERE lineage_id='';
	UPDATE authority_session_workspaces SET lineage_id=(SELECT lineage_id FROM authority_session_leases l WHERE l.binding_digest=authority_session_workspaces.binding_digest) WHERE lineage_id='';
	CREATE UNIQUE INDEX authority_session_leases_lineage ON authority_session_leases(lineage_id);
	CREATE UNIQUE INDEX authority_session_workspaces_lineage ON authority_session_workspaces(lineage_id);
	PRAGMA user_version=4`)
	return err
}

// V5 separates worker-generation storage fencing from logical session
// identity. Existing linked replacement chains receive one durable storage
// lineage and monotonically increasing worker epochs.
func (s *AuthorityWorkerStore) migrateV5(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `ALTER TABLE authority_workers ADD COLUMN worker_storage_lineage_id TEXT NOT NULL DEFAULT '';
	ALTER TABLE authority_workers ADD COLUMN worker_fence_epoch INTEGER NOT NULL DEFAULT 1;
	WITH RECURSIVE worker_chains(worker_id,worker_storage_lineage_id,worker_fence_epoch) AS (
		SELECT root.worker_id,lower(hex(randomblob(16))),1 FROM authority_workers root
		WHERE NOT EXISTS (SELECT 1 FROM authority_workers predecessor WHERE predecessor.replacement_worker_id=root.worker_id)
		UNION ALL
		SELECT replacement.worker_id,worker_chains.worker_storage_lineage_id,worker_chains.worker_fence_epoch+1
		FROM worker_chains JOIN authority_workers predecessor ON predecessor.worker_id=worker_chains.worker_id
		JOIN authority_workers replacement ON replacement.worker_id=predecessor.replacement_worker_id
	)
	UPDATE authority_workers SET
		worker_storage_lineage_id=(SELECT worker_storage_lineage_id FROM worker_chains WHERE worker_chains.worker_id=authority_workers.worker_id),
		worker_fence_epoch=(SELECT worker_fence_epoch FROM worker_chains WHERE worker_chains.worker_id=authority_workers.worker_id);
	ALTER TABLE authority_session_leases RENAME COLUMN lineage_id TO session_lineage_id;
	ALTER TABLE authority_session_workspaces RENAME COLUMN lineage_id TO session_lineage_id;
	DROP INDEX authority_session_leases_lineage;
	DROP INDEX authority_session_workspaces_lineage;
	CREATE UNIQUE INDEX authority_session_leases_session_lineage ON authority_session_leases(session_lineage_id);
	CREATE UNIQUE INDEX authority_session_workspaces_session_lineage ON authority_session_workspaces(session_lineage_id);
	ALTER TABLE authority_session_leases DROP COLUMN fence_epoch;
	PRAGMA user_version=5`)
	return err
}

// V6 records agentd's generated session identifier beside the broker-owned
// session lineage. Reassignment can therefore address only the durable agentd
// session associated during creation, never a caller-selected identity.
func (s *AuthorityWorkerStore) migrateV6(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `ALTER TABLE authority_session_workspaces ADD COLUMN agentd_session_id TEXT NOT NULL DEFAULT '';
	PRAGMA user_version=6`)
	return err
}

// V7 makes agentd adoption a durable, replayable transition. Existing
// reassignment rows cannot recover the unhashed coordinator binding and are
// deliberately left unresolved so they can never make a predecessor eligible
// for automatic retirement.
func (s *AuthorityWorkerStore) migrateV7(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `ALTER TABLE authority_session_reassignments ADD COLUMN coordinator_binding TEXT NOT NULL DEFAULT '';
	ALTER TABLE authority_session_reassignments ADD COLUMN authority_binding TEXT NOT NULL DEFAULT '';
	ALTER TABLE authority_session_reassignments ADD COLUMN session_lineage_id TEXT NOT NULL DEFAULT '';
	ALTER TABLE authority_session_reassignments ADD COLUMN agentd_session_id TEXT NOT NULL DEFAULT '';
	ALTER TABLE authority_session_reassignments ADD COLUMN predecessor_storage_lineage_id TEXT NOT NULL DEFAULT '';
	ALTER TABLE authority_session_reassignments ADD COLUMN predecessor_fence_epoch INTEGER NOT NULL DEFAULT 0;
	ALTER TABLE authority_session_reassignments ADD COLUMN replacement_storage_lineage_id TEXT NOT NULL DEFAULT '';
	ALTER TABLE authority_session_reassignments ADD COLUMN replacement_fence_epoch INTEGER NOT NULL DEFAULT 0;
	ALTER TABLE authority_session_reassignments ADD COLUMN rebind_idempotency_key TEXT NOT NULL DEFAULT '';
	ALTER TABLE authority_session_reassignments ADD COLUMN workspace_ref TEXT NOT NULL DEFAULT '';
	ALTER TABLE authority_session_reassignments ADD COLUMN workspace_uid INTEGER NOT NULL DEFAULT 0;
	ALTER TABLE authority_session_reassignments ADD COLUMN workspace_gid INTEGER NOT NULL DEFAULT 0;
	ALTER TABLE authority_session_reassignments ADD COLUMN adoption_state TEXT NOT NULL DEFAULT 'legacy_unresolved';
	ALTER TABLE authority_session_reassignments ADD COLUMN adoption_error_code TEXT NOT NULL DEFAULT '';
	ALTER TABLE authority_session_reassignments ADD COLUMN adoption_confirmed_at TEXT NOT NULL DEFAULT '';
	UPDATE authority_session_reassignments SET authority_binding=coalesce((SELECT profile FROM authority_session_leases lease WHERE lease.binding_digest=authority_session_reassignments.binding_digest),'');
	CREATE INDEX authority_session_reassignments_adoption ON authority_session_reassignments(adoption_state,created_at,binding_digest);
	PRAGMA user_version=7`)
	return err
}

// V8 records one transition per predecessor generation. The earlier unique
// binding constraint prevented a durable logical session from surviving a
// second worker replacement.
func (s *AuthorityWorkerStore) migrateV8(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DROP INDEX IF EXISTS authority_session_reassignments_replacement;
	CREATE TABLE authority_session_reassignments_v8 (
		principal TEXT NOT NULL, idempotency_digest TEXT NOT NULL,
		request_fingerprint TEXT NOT NULL, binding_digest TEXT NOT NULL,
		predecessor_worker_id TEXT NOT NULL REFERENCES authority_workers(worker_id),
		replacement_worker_id TEXT NOT NULL REFERENCES authority_workers(worker_id),
		created_at TEXT NOT NULL, coordinator_binding TEXT NOT NULL DEFAULT '',
		authority_binding TEXT NOT NULL DEFAULT '', session_lineage_id TEXT NOT NULL DEFAULT '',
		agentd_session_id TEXT NOT NULL DEFAULT '', predecessor_storage_lineage_id TEXT NOT NULL DEFAULT '',
		predecessor_fence_epoch INTEGER NOT NULL DEFAULT 0, replacement_storage_lineage_id TEXT NOT NULL DEFAULT '',
		replacement_fence_epoch INTEGER NOT NULL DEFAULT 0, rebind_idempotency_key TEXT NOT NULL DEFAULT '',
		workspace_ref TEXT NOT NULL DEFAULT '', workspace_uid INTEGER NOT NULL DEFAULT 0,
		workspace_gid INTEGER NOT NULL DEFAULT 0, adoption_state TEXT NOT NULL DEFAULT 'legacy_unresolved',
		adoption_error_code TEXT NOT NULL DEFAULT '', adoption_confirmed_at TEXT NOT NULL DEFAULT '',
		PRIMARY KEY(principal,idempotency_digest),
		UNIQUE(principal,binding_digest,predecessor_fence_epoch)
	) STRICT;
	INSERT INTO authority_session_reassignments_v8(
		principal,idempotency_digest,request_fingerprint,binding_digest,predecessor_worker_id,replacement_worker_id,created_at,
		coordinator_binding,authority_binding,session_lineage_id,agentd_session_id,predecessor_storage_lineage_id,
		predecessor_fence_epoch,replacement_storage_lineage_id,replacement_fence_epoch,rebind_idempotency_key,
		workspace_ref,workspace_uid,workspace_gid,adoption_state,adoption_error_code,adoption_confirmed_at)
	SELECT principal,idempotency_digest,request_fingerprint,binding_digest,predecessor_worker_id,replacement_worker_id,created_at,
		coordinator_binding,authority_binding,session_lineage_id,agentd_session_id,predecessor_storage_lineage_id,
		predecessor_fence_epoch,replacement_storage_lineage_id,replacement_fence_epoch,rebind_idempotency_key,
		workspace_ref,workspace_uid,workspace_gid,adoption_state,adoption_error_code,adoption_confirmed_at
	FROM authority_session_reassignments;
	DROP TABLE authority_session_reassignments;
	ALTER TABLE authority_session_reassignments_v8 RENAME TO authority_session_reassignments;
	CREATE INDEX authority_session_reassignments_replacement ON authority_session_reassignments(replacement_worker_id);
	CREATE INDEX authority_session_reassignments_adoption ON authority_session_reassignments(adoption_state,created_at,binding_digest);
	PRAGMA user_version=8`)
	return err
}

// V9 snapshots the immutable profile identity needed by a coordinator to
// reconcile a lost reassignment response against the complete transition.
func (s *AuthorityWorkerStore) migrateV9(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `ALTER TABLE authority_session_reassignments ADD COLUMN profile_version TEXT NOT NULL DEFAULT '';
	ALTER TABLE authority_session_reassignments ADD COLUMN policy_digest TEXT NOT NULL DEFAULT '';
	UPDATE authority_session_reassignments SET
		profile_version=coalesce((SELECT profile_version FROM authority_workers worker WHERE worker.worker_id=authority_session_reassignments.replacement_worker_id),''),
		policy_digest=coalesce((SELECT policy_digest FROM authority_workers worker WHERE worker.worker_id=authority_session_reassignments.replacement_worker_id),'');
	PRAGMA user_version=9`)
	return err
}

// V10 adds the broker-owned, append-only smart-HTTP transport journal. The
// table is deliberately in the authority database so one durable boundary
// binds the active lease and the observed operation.
func (s *AuthorityWorkerStore) migrateV10(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `CREATE TABLE repository_transport_events (
		cursor INTEGER PRIMARY KEY AUTOINCREMENT,
		operation_id TEXT NOT NULL,
		phase_ordinal INTEGER NOT NULL,
		phase TEXT NOT NULL,
		principal TEXT NOT NULL,
		worker_id TEXT NOT NULL,
		session_lineage_id TEXT NOT NULL,
		worker_storage_lineage_id TEXT NOT NULL,
		worker_fence_epoch INTEGER NOT NULL,
		profile_version TEXT NOT NULL,
		policy_digest TEXT NOT NULL,
		method TEXT NOT NULL,
		service TEXT NOT NULL,
		repository TEXT NOT NULL,
		request_path TEXT NOT NULL,
		requested_refs_json TEXT NOT NULL,
		ref_updates_json TEXT NOT NULL,
		credential_header_present INTEGER NOT NULL,
		decision TEXT NOT NULL,
		outcome_code TEXT NOT NULL,
		http_status INTEGER NOT NULL,
		backend_status INTEGER NOT NULL,
		before_refs_digest TEXT NOT NULL,
		after_refs_digest TEXT NOT NULL,
		previous_event_digest TEXT NOT NULL,
		event_digest TEXT NOT NULL UNIQUE,
		UNIQUE(operation_id, phase_ordinal),
		CHECK(phase_ordinal >= 1),
		CHECK(phase IN ('received','forwarded','denied','completed','failed')),
		CHECK(credential_header_present IN (0,1))
	) STRICT;
	CREATE INDEX repository_transport_events_operation ON repository_transport_events(operation_id,phase_ordinal);
	PRAGMA user_version=10`)
	return err
}

func (s *AuthorityWorkerStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *AuthorityWorkerStore) requestDigest(raw string) string {
	mac := hmac.New(sha256.New, s.salt)
	_, _ = mac.Write([]byte(raw))
	return hex.EncodeToString(mac.Sum(nil))
}

func (s *AuthorityWorkerStore) rebindIdempotencyKey(sessionID string, predecessor, successor agentdWorkerBinding) string {
	return s.requestDigest(fmt.Sprintf("agentd-rebind:v1\x00%s\x00%s\x00%s\x00%d\x00%s\x00%s\x00%d", sessionID, predecessor.WorkerID, predecessor.StorageLineageID, predecessor.FenceEpoch, successor.WorkerID, successor.StorageLineageID, successor.FenceEpoch))
}

func newOpaqueLineageID(kind string) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate %s lineage: %w", kind, err)
	}
	return hex.EncodeToString(b), nil
}

func validOpaqueLineageID(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 16
}

func (s *AuthorityWorkerStore) CreateWorker(ctx context.Context, worker AuthorityWorker, maxWorkers int, issuanceGeneration int64) (AuthorityWorker, error) {
	if worker.WorkerStorageLineageID == "" {
		lineageID, err := newOpaqueLineageID("worker storage")
		if err != nil {
			return AuthorityWorker{}, err
		}
		worker.WorkerStorageLineageID, worker.WorkerFenceEpoch = lineageID, 1
	}
	if !validOpaqueLineageID(worker.WorkerStorageLineageID) || worker.WorkerFenceEpoch != 1 || worker.Generation != 1 {
		return AuthorityWorker{}, fmt.Errorf("initial authority worker requires an opaque storage lineage, generation 1, and worker fence epoch 1")
	}
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return AuthorityWorker{}, err
	}
	defer closeAuthorityConn(conn)
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return AuthorityWorker{}, err
	}
	committed := false
	defer func() {
		if !committed {
			rollbackAuthorityConn(context.WithoutCancel(ctx), conn)
		}
	}()
	if err := s.checkIssuanceInTransaction(ctx, conn, worker.Profile, issuanceGeneration); err != nil {
		return AuthorityWorker{}, err
	}
	var count int
	if err := conn.QueryRowContext(ctx, `SELECT count(*) FROM authority_workers WHERE profile=? AND state NOT IN (?,?)`, worker.Profile, AuthorityWorkerStopped, AuthorityWorkerFailed).Scan(&count); err != nil {
		return AuthorityWorker{}, err
	}
	if count >= maxWorkers {
		return AuthorityWorker{}, fmt.Errorf("authority profile %q is at its worker limit %d", worker.Profile, maxWorkers)
	}
	now := time.Now().UTC()
	worker.CreatedAt, worker.UpdatedAt = now, now
	_, err = conn.ExecContext(ctx, `INSERT INTO authority_workers
		(worker_id,profile,profile_version,policy_digest,image_reference,image_digest,generation,container_id,state,capacity,assigned_sessions,health,drain_reason,replacement_worker_id,heartbeat_at,created_at,updated_at,worker_storage_lineage_id,worker_fence_epoch)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, worker.WorkerID, worker.Profile, worker.ProfileVersion,
		worker.PolicyDigest, worker.ImageReference, worker.ImageDigest, worker.Generation, worker.ContainerID, worker.State, worker.Capacity,
		worker.AssignedSessions, worker.Health, worker.DrainReason, worker.ReplacementWorker, formatAuthorityTime(worker.HeartbeatAt), formatAuthorityTime(now), formatAuthorityTime(now), worker.WorkerStorageLineageID, worker.WorkerFenceEpoch)
	if err != nil {
		return AuthorityWorker{}, err
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return AuthorityWorker{}, err
	}
	committed = true
	if s.afterIssuanceCommitForTest != nil {
		s.afterIssuanceCommitForTest()
	}
	return worker, nil
}

func (s *AuthorityWorkerStore) GetWorker(ctx context.Context, workerID string) (AuthorityWorker, error) {
	return scanAuthorityWorker(s.db.QueryRowContext(ctx, `SELECT worker_id,profile,profile_version,policy_digest,image_reference,image_digest,generation,container_id,state,capacity,assigned_sessions,health,drain_reason,replacement_worker_id,heartbeat_at,created_at,updated_at,worker_storage_lineage_id,worker_fence_epoch FROM authority_workers WHERE worker_id=?`, workerID))
}

func (s *AuthorityWorkerStore) ListLiveWorkers(ctx context.Context) ([]AuthorityWorker, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT worker_id,profile,profile_version,policy_digest,image_reference,image_digest,generation,container_id,state,capacity,assigned_sessions,health,drain_reason,replacement_worker_id,heartbeat_at,created_at,updated_at,worker_storage_lineage_id,worker_fence_epoch FROM authority_workers WHERE state IN (?,?,?) ORDER BY profile,generation,worker_id`, AuthorityWorkerStarting, AuthorityWorkerReady, AuthorityWorkerUnhealthy)
	if err != nil {
		return nil, err
	}
	defer func() {
		//nolint:errcheck // Result rows are exhausted before close.
		_ = rows.Close()
	}()
	var workers []AuthorityWorker
	for rows.Next() {
		worker, err := scanAuthorityWorker(rows)
		if err != nil {
			return nil, err
		}
		workers = append(workers, worker)
	}
	return workers, rows.Err()
}

func (s *AuthorityWorkerStore) UpdateWorkerRuntime(ctx context.Context, workerID, containerID, imageDigest string) (AuthorityWorker, error) {
	result, err := s.db.ExecContext(ctx, `UPDATE authority_workers SET container_id=?,image_digest=?,state=?,updated_at=? WHERE worker_id=? AND state=?`, containerID, imageDigest, AuthorityWorkerStarting, formatAuthorityTime(time.Now().UTC()), workerID, AuthorityWorkerProvisioning)
	if err != nil {
		return AuthorityWorker{}, err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return AuthorityWorker{}, err
	}
	if rows != 1 {
		worker, getErr := s.GetWorker(ctx, workerID)
		if getErr != nil {
			return AuthorityWorker{}, getErr
		}
		if worker.ContainerID != containerID || worker.ImageDigest != imageDigest {
			return AuthorityWorker{}, fmt.Errorf("worker %q runtime identity conflicts with its durable record", workerID)
		}
		switch worker.State {
		case AuthorityWorkerStarting, AuthorityWorkerReady, AuthorityWorkerUnhealthy, AuthorityWorkerDraining:
			return worker, nil
		default:
			return AuthorityWorker{}, fmt.Errorf("worker %q cannot reconcile runtime identity from state %q", workerID, worker.State)
		}
	}
	return s.GetWorker(ctx, workerID)
}

func (s *AuthorityWorkerStore) SetWorkerHealth(ctx context.Context, workerID, health string, ready bool) (AuthorityWorker, error) {
	now := time.Now().UTC()
	if !ready {
		result, err := s.db.ExecContext(ctx, `UPDATE authority_workers SET state=?,health=?,heartbeat_at=?,updated_at=? WHERE worker_id=? AND state IN (?,?,?)`, AuthorityWorkerUnhealthy, health, formatAuthorityTime(now), formatAuthorityTime(now), workerID, AuthorityWorkerStarting, AuthorityWorkerReady, AuthorityWorkerUnhealthy)
		if err != nil {
			return AuthorityWorker{}, err
		}
		rows, err := result.RowsAffected()
		if err != nil {
			return AuthorityWorker{}, err
		}
		if rows != 1 {
			return AuthorityWorker{}, fmt.Errorf("worker %q cannot accept a health transition", workerID)
		}
		return s.GetWorker(ctx, workerID)
	}
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return AuthorityWorker{}, err
	}
	defer closeAuthorityConn(conn)
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return AuthorityWorker{}, err
	}
	committed := false
	defer func() {
		if !committed {
			rollbackAuthorityConn(context.WithoutCancel(ctx), conn)
		}
	}()
	var generation int
	if err := conn.QueryRowContext(ctx, `SELECT generation FROM authority_workers WHERE worker_id=?`, workerID).Scan(&generation); err != nil {
		return AuthorityWorker{}, err
	}
	var predecessorLinks int
	if err := conn.QueryRowContext(ctx, `SELECT count(*) FROM authority_workers WHERE replacement_worker_id=?`, workerID).Scan(&predecessorLinks); err != nil {
		return AuthorityWorker{}, err
	}
	if generation > 1 && predecessorLinks != 1 {
		return AuthorityWorker{}, fmt.Errorf("replacement worker %q has %d predecessor links; refusing readiness cutover", workerID, predecessorLinks)
	}
	result, err := conn.ExecContext(ctx, `UPDATE authority_workers SET state=?,health=?,heartbeat_at=?,updated_at=? WHERE worker_id=? AND state IN (?,?,?)`, AuthorityWorkerReady, health, formatAuthorityTime(now), formatAuthorityTime(now), workerID, AuthorityWorkerStarting, AuthorityWorkerReady, AuthorityWorkerUnhealthy)
	if err != nil {
		return AuthorityWorker{}, err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return AuthorityWorker{}, err
	}
	if rows != 1 {
		return AuthorityWorker{}, fmt.Errorf("worker %q cannot accept a health transition", workerID)
	}
	if _, err := conn.ExecContext(ctx, `UPDATE authority_workers SET state=?,updated_at=? WHERE replacement_worker_id=? AND state IN (?,?,?)`, AuthorityWorkerDraining, formatAuthorityTime(now), workerID, AuthorityWorkerStarting, AuthorityWorkerReady, AuthorityWorkerUnhealthy); err != nil {
		return AuthorityWorker{}, err
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return AuthorityWorker{}, err
	}
	committed = true
	return scanAuthorityWorker(conn.QueryRowContext(ctx, `SELECT worker_id,profile,profile_version,policy_digest,image_reference,image_digest,generation,container_id,state,capacity,assigned_sessions,health,drain_reason,replacement_worker_id,heartbeat_at,created_at,updated_at,worker_storage_lineage_id,worker_fence_epoch FROM authority_workers WHERE worker_id=?`, workerID))
}

func (s *AuthorityWorkerStore) Acquire(ctx context.Context, principal string, request AuthorityWorkerRequest, issuanceGeneration int64) (AuthorityLease, error) {
	idem := s.requestDigest(request.IdempotencyKey)
	binding := s.requestDigest(request.SessionBinding)
	fingerprint := s.requestDigest("request:" + request.Profile + "\x00" + request.SessionBinding)
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return AuthorityLease{}, err
	}
	defer closeAuthorityConn(conn)
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return AuthorityLease{}, err
	}
	committed := false
	defer func() {
		if !committed {
			rollbackAuthorityConn(context.WithoutCancel(ctx), conn)
		}
	}()
	var lease AuthorityLease
	var storedFingerprint, created, released string
	err = conn.QueryRowContext(ctx, `SELECT l.profile,l.worker_id,l.session_lineage_id,l.binding_digest,l.idempotency_digest,l.request_fingerprint,l.created_at,l.released_at,w.worker_storage_lineage_id,w.worker_fence_epoch,w.profile_version,w.policy_digest FROM authority_session_leases l JOIN authority_workers w ON w.worker_id=l.worker_id WHERE l.principal=? AND l.profile=? AND l.idempotency_digest=?`, principal, request.Profile, idem).
		Scan(&lease.Profile, &lease.WorkerID, &lease.SessionLineageID, &lease.BindingDigest, &lease.IdempotencyDigest, &storedFingerprint, &created, &released, &lease.WorkerStorageLineageID, &lease.WorkerFenceEpoch, &lease.ProfileVersion, &lease.PolicyDigest)
	if err == nil {
		if storedFingerprint != fingerprint {
			return AuthorityLease{}, fmt.Errorf("idempotency conflict")
		}
		lease.Principal, lease.Replay = principal, true
		lease.CreatedAt, err = parseAuthorityTime(created)
		if err != nil {
			return AuthorityLease{}, err
		}
		lease.ReleasedAt, err = parseAuthorityTime(released)
		if err != nil {
			return AuthorityLease{}, err
		}
		if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
			return AuthorityLease{}, err
		}
		committed = true
		return lease, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return AuthorityLease{}, err
	}
	if err := s.checkIssuanceInTransaction(ctx, conn, request.Profile, issuanceGeneration); err != nil {
		return AuthorityLease{}, err
	}
	var workerID string
	err = conn.QueryRowContext(ctx, `SELECT worker_id FROM authority_workers WHERE profile=? AND state=? AND assigned_sessions<capacity ORDER BY generation,created_at,worker_id LIMIT 1`, request.Profile, AuthorityWorkerReady).Scan(&workerID)
	if errors.Is(err, sql.ErrNoRows) {
		return AuthorityLease{}, fmt.Errorf("authority profile %q has no ready worker capacity", request.Profile)
	}
	if err != nil {
		return AuthorityLease{}, err
	}
	result, err := conn.ExecContext(ctx, `UPDATE authority_workers SET assigned_sessions=assigned_sessions+1,updated_at=? WHERE worker_id=? AND state=? AND assigned_sessions<capacity`, formatAuthorityTime(time.Now().UTC()), workerID, AuthorityWorkerReady)
	if err != nil {
		return AuthorityLease{}, err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return AuthorityLease{}, err
	}
	if rows != 1 {
		return AuthorityLease{}, fmt.Errorf("authority worker capacity changed")
	}
	now := time.Now().UTC()
	lineageID, err := newOpaqueLineageID("session")
	if err != nil {
		return AuthorityLease{}, err
	}
	_, err = conn.ExecContext(ctx, `INSERT INTO authority_session_leases(principal,profile,idempotency_digest,request_fingerprint,binding_digest,worker_id,session_lineage_id,created_at) VALUES(?,?,?,?,?,?,?,?)`, principal, request.Profile, idem, fingerprint, binding, workerID, lineageID, formatAuthorityTime(now))
	if err != nil {
		return AuthorityLease{}, err
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return AuthorityLease{}, err
	}
	committed = true
	var workerStorageLineageID, profileVersion, policyDigest string
	var workerFenceEpoch int64
	if err := conn.QueryRowContext(ctx, `SELECT worker_storage_lineage_id,worker_fence_epoch,profile_version,policy_digest FROM authority_workers WHERE worker_id=?`, workerID).Scan(&workerStorageLineageID, &workerFenceEpoch, &profileVersion, &policyDigest); err != nil {
		return AuthorityLease{}, err
	}
	return AuthorityLease{Principal: principal, Profile: request.Profile, WorkerID: workerID, SessionLineageID: lineageID, WorkerStorageLineageID: workerStorageLineageID, WorkerFenceEpoch: workerFenceEpoch, ProfileVersion: profileVersion, PolicyDigest: policyDigest, BindingDigest: binding, IdempotencyDigest: idem, CreatedAt: now}, nil
}

func (s *AuthorityWorkerStore) Release(ctx context.Context, principal, sessionBinding string) (AuthorityLease, error) {
	binding := s.requestDigest(sessionBinding)
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return AuthorityLease{}, err
	}
	defer closeAuthorityConn(conn)
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return AuthorityLease{}, err
	}
	committed := false
	defer func() {
		if !committed {
			rollbackAuthorityConn(context.WithoutCancel(ctx), conn)
		}
	}()
	var lease AuthorityLease
	var created, released string
	err = conn.QueryRowContext(ctx, `SELECT l.profile,l.worker_id,l.session_lineage_id,l.idempotency_digest,l.created_at,l.released_at,w.worker_storage_lineage_id,w.worker_fence_epoch,w.profile_version,w.policy_digest FROM authority_session_leases l JOIN authority_workers w ON w.worker_id=l.worker_id WHERE l.principal=? AND l.binding_digest=?`, principal, binding).
		Scan(&lease.Profile, &lease.WorkerID, &lease.SessionLineageID, &lease.IdempotencyDigest, &created, &released, &lease.WorkerStorageLineageID, &lease.WorkerFenceEpoch, &lease.ProfileVersion, &lease.PolicyDigest)
	if err != nil {
		return AuthorityLease{}, err
	}
	lease.Principal, lease.BindingDigest = principal, binding
	lease.CreatedAt, err = parseAuthorityTime(created)
	if err != nil {
		return AuthorityLease{}, err
	}
	if released != "" {
		lease.ReleasedAt, err = parseAuthorityTime(released)
		if err != nil {
			return AuthorityLease{}, err
		}
		lease.Replay = true
	} else {
		now := time.Now().UTC()
		if _, err := conn.ExecContext(ctx, `UPDATE authority_session_leases SET released_at=? WHERE principal=? AND binding_digest=? AND released_at=''`, formatAuthorityTime(now), principal, binding); err != nil {
			return AuthorityLease{}, err
		}
		result, err := conn.ExecContext(ctx, `UPDATE authority_workers SET assigned_sessions=assigned_sessions-1,updated_at=? WHERE worker_id=? AND assigned_sessions>0`, formatAuthorityTime(now), lease.WorkerID)
		if err != nil {
			return AuthorityLease{}, err
		}
		rows, err := result.RowsAffected()
		if err != nil {
			return AuthorityLease{}, err
		}
		if rows != 1 {
			return AuthorityLease{}, fmt.Errorf("authority lease capacity invariant failed")
		}
		lease.ReleasedAt = now
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return AuthorityLease{}, err
	}
	committed = true
	return lease, nil
}

func (s *AuthorityWorkerStore) GetLease(ctx context.Context, principal, sessionBinding string) (AuthorityLease, error) {
	binding := s.requestDigest(sessionBinding)
	var lease AuthorityLease
	var created, released string
	err := s.db.QueryRowContext(ctx, `SELECT l.profile,l.worker_id,l.session_lineage_id,l.idempotency_digest,l.created_at,l.released_at,w.worker_storage_lineage_id,w.worker_fence_epoch,w.profile_version,w.policy_digest FROM authority_session_leases l JOIN authority_workers w ON w.worker_id=l.worker_id WHERE l.principal=? AND l.binding_digest=?`, principal, binding).
		Scan(&lease.Profile, &lease.WorkerID, &lease.SessionLineageID, &lease.IdempotencyDigest, &created, &released, &lease.WorkerStorageLineageID, &lease.WorkerFenceEpoch, &lease.ProfileVersion, &lease.PolicyDigest)
	if err != nil {
		return AuthorityLease{}, err
	}
	lease.Principal, lease.BindingDigest = principal, binding
	lease.CreatedAt, err = parseAuthorityTime(created)
	if err != nil {
		return AuthorityLease{}, err
	}
	lease.ReleasedAt, err = parseAuthorityTime(released)
	if err != nil {
		return AuthorityLease{}, err
	}
	return lease, nil
}

func (s *AuthorityWorkerStore) ValidateSessionFence(ctx context.Context, workerID, sessionLineageID string, workerFenceEpoch int64) (bool, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM authority_session_leases l
		JOIN authority_session_workspaces sw ON sw.session_lineage_id=l.session_lineage_id
		JOIN authority_workers aw ON aw.worker_id=l.worker_id
		WHERE l.worker_id=? AND l.session_lineage_id=? AND aw.worker_fence_epoch=? AND l.released_at='' AND sw.worker_id=?`, workerID, sessionLineageID, workerFenceEpoch, workerID).Scan(&count)
	return count == 1, err
}

// Reassign moves an active lease only to the replacement durably linked to the
// supplied predecessor.  Lease ownership, workspace ownership, and capacity
// accounting commit together, so a process crash leaves either side intact.
func (s *AuthorityWorkerStore) Reassign(ctx context.Context, principal, sessionBinding, sessionLineageID, predecessorWorkerID string, predecessorWorkerFenceEpoch int64, idempotencyKey string, workspace SessionWorkspace, issuanceGeneration int64) (AuthoritySessionReassignment, error) {
	binding := s.requestDigest(sessionBinding)
	idem := s.requestDigest(idempotencyKey)
	fingerprint := s.requestDigest(fmt.Sprintf("reassign:%s\x00%s\x00%s\x00%d", sessionBinding, sessionLineageID, predecessorWorkerID, predecessorWorkerFenceEpoch))
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return AuthoritySessionReassignment{}, err
	}
	defer closeAuthorityConn(conn)
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return AuthoritySessionReassignment{}, err
	}
	committed := false
	defer func() {
		if !committed {
			rollbackAuthorityConn(context.WithoutCancel(ctx), conn)
		}
	}()

	var reassignment AuthoritySessionReassignment
	var storedFingerprint string
	err = conn.QueryRowContext(ctx, `SELECT predecessor_worker_id,replacement_worker_id,request_fingerprint
		FROM authority_session_reassignments WHERE principal=? AND idempotency_digest=?`, principal, idem).
		Scan(&reassignment.PredecessorWorkerID, &reassignment.ReplacementWorkerID, &storedFingerprint)
	if err == nil {
		if storedFingerprint != fingerprint {
			return AuthoritySessionReassignment{}, reassignmentError(ReassignmentReplay, "reassignment idempotency key conflicts with a prior request")
		}
		lease, err := getLeaseByDigest(ctx, conn, principal, binding)
		if err != nil {
			return AuthoritySessionReassignment{}, err
		}
		if lease.WorkerID != reassignment.ReplacementWorkerID || !lease.ReleasedAt.IsZero() {
			return AuthoritySessionReassignment{}, reassignmentError(ReassignmentConflictingReplacement, "reassignment record no longer matches the active session lease")
		}
		reassignment.Lease, reassignment.Replay = lease, true
		if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
			return AuthoritySessionReassignment{}, err
		}
		committed = true
		return reassignment, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return AuthoritySessionReassignment{}, err
	}
	// A retry may use a fresh coordinator request key after the broker response
	// was lost. The durable binding transition, not that transport-level key,
	// is the unique effect. Resume only the exact recorded transition.
	err = conn.QueryRowContext(ctx, `SELECT predecessor_worker_id,replacement_worker_id,request_fingerprint
		FROM authority_session_reassignments WHERE principal=? AND binding_digest=? AND predecessor_fence_epoch=?`, principal, binding, predecessorWorkerFenceEpoch).
		Scan(&reassignment.PredecessorWorkerID, &reassignment.ReplacementWorkerID, &storedFingerprint)
	if err == nil {
		if storedFingerprint != fingerprint {
			return AuthoritySessionReassignment{}, reassignmentError(ReassignmentConflictingReplacement, "session has a different durable reassignment transition")
		}
		lease, err := getLeaseByDigest(ctx, conn, principal, binding)
		if err != nil {
			return AuthoritySessionReassignment{}, err
		}
		if lease.WorkerID != reassignment.ReplacementWorkerID || !lease.ReleasedAt.IsZero() {
			return AuthoritySessionReassignment{}, reassignmentError(ReassignmentConflictingReplacement, "reassignment record no longer matches the active session lease")
		}
		reassignment.Lease, reassignment.Replay = lease, true
		if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
			return AuthoritySessionReassignment{}, err
		}
		committed = true
		return reassignment, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return AuthoritySessionReassignment{}, err
	}

	lease, err := getLeaseByDigest(ctx, conn, principal, binding)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return AuthoritySessionReassignment{}, reassignmentError(ReassignmentStalePredecessor, "session binding is not an active lease for this principal")
		}
		return AuthoritySessionReassignment{}, err
	}
	if !lease.ReleasedAt.IsZero() || lease.WorkerID != predecessorWorkerID || lease.SessionLineageID != sessionLineageID || lease.WorkerFenceEpoch != predecessorWorkerFenceEpoch {
		return AuthoritySessionReassignment{}, reassignmentError(ReassignmentStalePredecessor, "session binding is not assigned to the supplied predecessor")
	}
	var replacementID string
	var predecessorProfile string
	if err := conn.QueryRowContext(ctx, `SELECT profile,replacement_worker_id FROM authority_workers WHERE worker_id=?`, predecessorWorkerID).Scan(&predecessorProfile, &replacementID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return AuthoritySessionReassignment{}, reassignmentError(ReassignmentStalePredecessor, "supplied predecessor does not exist")
		}
		return AuthoritySessionReassignment{}, err
	}
	if replacementID == "" {
		return AuthoritySessionReassignment{}, reassignmentError(ReassignmentNotReady, "predecessor has no broker-recorded replacement")
	}
	if err := s.checkIssuanceInTransaction(ctx, conn, predecessorProfile, issuanceGeneration); err != nil {
		return AuthoritySessionReassignment{}, err
	}
	var replacementProfile, replacementProfileVersion, replacementPolicyDigest, replacementImage, replacementStorageLineageID string
	var replacementState AuthorityWorkerState
	var replacementCapacity, replacementAssigned int
	var replacementWorkerFenceEpoch int64
	if err := conn.QueryRowContext(ctx, `SELECT profile,profile_version,policy_digest,image_reference,state,capacity,assigned_sessions,worker_storage_lineage_id,worker_fence_epoch FROM authority_workers WHERE worker_id=?`, replacementID).Scan(&replacementProfile, &replacementProfileVersion, &replacementPolicyDigest, &replacementImage, &replacementState, &replacementCapacity, &replacementAssigned, &replacementStorageLineageID, &replacementWorkerFenceEpoch); err != nil {
		return AuthoritySessionReassignment{}, reassignmentError(ReassignmentConflictingReplacement, "broker-recorded replacement is unavailable")
	}
	var predecessorProfileVersion, predecessorPolicyDigest, predecessorImage string
	var predecessorCapacity int
	if err := conn.QueryRowContext(ctx, `SELECT profile_version,policy_digest,image_reference,capacity FROM authority_workers WHERE worker_id=?`, predecessorWorkerID).Scan(&predecessorProfileVersion, &predecessorPolicyDigest, &predecessorImage, &predecessorCapacity); err != nil {
		return AuthoritySessionReassignment{}, reassignmentError(ReassignmentConflictingReplacement, "predecessor immutable identity is unavailable")
	}
	if replacementProfile != predecessorProfile || replacementProfileVersion != predecessorProfileVersion || replacementPolicyDigest != predecessorPolicyDigest || replacementImage != predecessorImage || replacementCapacity != predecessorCapacity {
		return AuthoritySessionReassignment{}, reassignmentError(ReassignmentConflictingReplacement, "broker-recorded replacement has a different authority profile")
	}
	if replacementStorageLineageID != lease.WorkerStorageLineageID || replacementWorkerFenceEpoch != predecessorWorkerFenceEpoch+1 {
		return AuthoritySessionReassignment{}, reassignmentError(ReassignmentConflictingReplacement, "replacement storage lineage or worker fence epoch is not the exact successor")
	}
	if replacementState != AuthorityWorkerReady {
		return AuthoritySessionReassignment{}, reassignmentError(ReassignmentNotReady, "broker-recorded replacement is not ready")
	}
	if replacementAssigned >= replacementCapacity {
		return AuthoritySessionReassignment{}, reassignmentError(ReassignmentCapacity, "broker-recorded replacement has no session capacity")
	}
	var durableAgentdSessionID, durableSessionLineageID, durableWorkspacePath string
	var durableUID, durableGID int
	if err := conn.QueryRowContext(ctx, `SELECT agentd_session_id,session_lineage_id,workspace_path,uid,gid FROM authority_session_workspaces WHERE binding_digest=? AND worker_id=?`, binding, predecessorWorkerID).Scan(&durableAgentdSessionID, &durableSessionLineageID, &durableWorkspacePath, &durableUID, &durableGID); err != nil {
		return AuthoritySessionReassignment{}, reassignmentError(ReassignmentConflictingReplacement, "session workspace is missing or belongs to another worker")
	}
	if workspace.AgentdSessionID != durableAgentdSessionID || workspace.SessionLineageID != durableSessionLineageID || workspace.Path != durableWorkspacePath || workspace.UID != durableUID || workspace.GID != durableGID {
		return AuthoritySessionReassignment{}, reassignmentError(ReassignmentConflictingReplacement, "session workspace identity changed before reassignment")
	}
	now := time.Now().UTC()
	result, err := conn.ExecContext(ctx, `UPDATE authority_workers SET assigned_sessions=assigned_sessions-1,updated_at=? WHERE worker_id=? AND assigned_sessions>0`, formatAuthorityTime(now), predecessorWorkerID)
	if err != nil {
		return AuthoritySessionReassignment{}, err
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		return AuthoritySessionReassignment{}, reassignmentError(ReassignmentStalePredecessor, "predecessor capacity no longer contains the session")
	}
	result, err = conn.ExecContext(ctx, `UPDATE authority_workers SET assigned_sessions=assigned_sessions+1,updated_at=? WHERE worker_id=? AND state=? AND assigned_sessions<capacity`, formatAuthorityTime(now), replacementID, AuthorityWorkerReady)
	if err != nil {
		return AuthoritySessionReassignment{}, err
	}
	rows, err = result.RowsAffected()
	if err != nil || rows != 1 {
		return AuthoritySessionReassignment{}, reassignmentError(ReassignmentCapacity, "broker-recorded replacement capacity changed")
	}
	result, err = conn.ExecContext(ctx, `UPDATE authority_session_leases SET worker_id=? WHERE principal=? AND binding_digest=? AND session_lineage_id=? AND worker_id=? AND released_at=''`, replacementID, principal, binding, sessionLineageID, predecessorWorkerID)
	if err != nil {
		return AuthoritySessionReassignment{}, err
	}
	rows, err = result.RowsAffected()
	if err != nil || rows != 1 {
		return AuthoritySessionReassignment{}, reassignmentError(ReassignmentStalePredecessor, "session lease changed during reassignment")
	}
	result, err = conn.ExecContext(ctx, `UPDATE authority_session_workspaces SET worker_id=? WHERE session_lineage_id=? AND binding_digest=? AND worker_id=?`, replacementID, lease.SessionLineageID, binding, predecessorWorkerID)
	if err != nil {
		return AuthoritySessionReassignment{}, err
	}
	rows, err = result.RowsAffected()
	if err != nil || rows != 1 {
		return AuthoritySessionReassignment{}, reassignmentError(ReassignmentConflictingReplacement, "session workspace is missing or belongs to another worker")
	}
	predecessorBinding := agentdWorkerBinding{WorkerID: predecessorWorkerID, StorageLineageID: lease.WorkerStorageLineageID, FenceEpoch: predecessorWorkerFenceEpoch}
	successorBinding := agentdWorkerBinding{WorkerID: replacementID, StorageLineageID: replacementStorageLineageID, FenceEpoch: replacementWorkerFenceEpoch}
	rebindIdempotencyKey := s.rebindIdempotencyKey(workspace.AgentdSessionID, predecessorBinding, successorBinding)
	if _, err := conn.ExecContext(ctx, `INSERT INTO authority_session_reassignments(
		principal,idempotency_digest,request_fingerprint,binding_digest,predecessor_worker_id,replacement_worker_id,created_at,
		coordinator_binding,authority_binding,profile_version,policy_digest,session_lineage_id,agentd_session_id,
		predecessor_storage_lineage_id,predecessor_fence_epoch,replacement_storage_lineage_id,replacement_fence_epoch,
		rebind_idempotency_key,workspace_ref,workspace_uid,workspace_gid,adoption_state)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		principal, idem, fingerprint, binding, predecessorWorkerID, replacementID, formatAuthorityTime(now),
		sessionBinding, lease.Profile, replacementProfileVersion, replacementPolicyDigest, sessionLineageID, workspace.AgentdSessionID,
		predecessorBinding.StorageLineageID, predecessorBinding.FenceEpoch, successorBinding.StorageLineageID, successorBinding.FenceEpoch,
		rebindIdempotencyKey, workspace.Path, workspace.UID, workspace.GID, authorityAdoptionPending); err != nil {
		return AuthoritySessionReassignment{}, err
	}
	lease.WorkerID = replacementID
	lease.WorkerStorageLineageID = replacementStorageLineageID
	lease.WorkerFenceEpoch = replacementWorkerFenceEpoch
	reassignment = AuthoritySessionReassignment{Lease: lease, PredecessorWorkerID: predecessorWorkerID, ReplacementWorkerID: replacementID}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return AuthoritySessionReassignment{}, err
	}
	committed = true
	return reassignment, nil
}

func getLeaseByDigest(ctx context.Context, queryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, principal, binding string,
) (AuthorityLease, error) {
	var lease AuthorityLease
	var created, released string
	err := queryer.QueryRowContext(ctx, `SELECT l.profile,l.worker_id,l.session_lineage_id,l.idempotency_digest,l.created_at,l.released_at,w.worker_storage_lineage_id,w.worker_fence_epoch,w.profile_version,w.policy_digest FROM authority_session_leases l JOIN authority_workers w ON w.worker_id=l.worker_id WHERE l.principal=? AND l.binding_digest=?`, principal, binding).
		Scan(&lease.Profile, &lease.WorkerID, &lease.SessionLineageID, &lease.IdempotencyDigest, &created, &released, &lease.WorkerStorageLineageID, &lease.WorkerFenceEpoch, &lease.ProfileVersion, &lease.PolicyDigest)
	if err != nil {
		return AuthorityLease{}, err
	}
	lease.Principal, lease.BindingDigest = principal, binding
	if lease.CreatedAt, err = parseAuthorityTime(created); err != nil {
		return AuthorityLease{}, err
	}
	lease.ReleasedAt, err = parseAuthorityTime(released)
	return lease, err
}

const authorityAdoptionSelect = `SELECT binding_digest,coordinator_binding,authority_binding,profile_version,policy_digest,session_lineage_id,agentd_session_id,
	predecessor_worker_id,predecessor_storage_lineage_id,predecessor_fence_epoch,
	replacement_worker_id,replacement_storage_lineage_id,replacement_fence_epoch,
	rebind_idempotency_key,workspace_ref,workspace_uid,workspace_gid,adoption_state,adoption_error_code
	FROM authority_session_reassignments`

func scanAuthorityAgentdAdoption(scanner interface{ Scan(...any) error }) (authorityAgentdAdoption, error) {
	var adoption authorityAgentdAdoption
	err := scanner.Scan(
		&adoption.BindingDigest, &adoption.CoordinatorBinding, &adoption.AuthorityBinding, &adoption.ProfileVersion, &adoption.PolicyDigest, &adoption.SessionLineageID, &adoption.AgentdSessionID,
		&adoption.Predecessor.WorkerID, &adoption.Predecessor.StorageLineageID, &adoption.Predecessor.FenceEpoch,
		&adoption.Successor.WorkerID, &adoption.Successor.StorageLineageID, &adoption.Successor.FenceEpoch,
		&adoption.RebindIdempotencyKey, &adoption.Workspace.WorkspaceRef, &adoption.Workspace.UID, &adoption.Workspace.GID,
		&adoption.State, &adoption.ErrorCode,
	)
	return adoption, err
}

func (s *AuthorityWorkerStore) AgentdAdoption(ctx context.Context, bindingDigest string) (authorityAgentdAdoption, error) {
	return scanAuthorityAgentdAdoption(s.db.QueryRowContext(ctx, authorityAdoptionSelect+` WHERE binding_digest=? ORDER BY predecessor_fence_epoch DESC LIMIT 1`, bindingDigest))
}

// RequireConfirmedCoordinatorRouting blocks all session traffic while the
// latest durable reassignment generation is incomplete or does not describe
// the active lease exactly. A binding with no reassignment history is ready.
func (s *AuthorityWorkerStore) RequireConfirmedCoordinatorRouting(ctx context.Context, binding string, lease AuthorityLease) error {
	adoption, err := s.AgentdAdoption(ctx, lease.BindingDigest)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if adoption.State != authorityAdoptionConfirmed {
		return fmt.Errorf("coordinator session reassignment is not confirmed")
	}
	if adoption.CoordinatorBinding != binding || adoption.AuthorityBinding != lease.Profile ||
		adoption.ProfileVersion != lease.ProfileVersion || adoption.PolicyDigest != lease.PolicyDigest ||
		adoption.SessionLineageID != lease.SessionLineageID || adoption.Successor.WorkerID != lease.WorkerID ||
		adoption.Successor.StorageLineageID != lease.WorkerStorageLineageID || adoption.Successor.FenceEpoch != lease.WorkerFenceEpoch {
		return fmt.Errorf("coordinator session reassignment does not match the active lease")
	}
	return nil
}

func (s *AuthorityWorkerStore) AgentdAdoptionAtEpoch(ctx context.Context, bindingDigest string, predecessorEpoch int64) (authorityAgentdAdoption, error) {
	return scanAuthorityAgentdAdoption(s.db.QueryRowContext(ctx, authorityAdoptionSelect+` WHERE binding_digest=? AND predecessor_fence_epoch=?`, bindingDigest, predecessorEpoch))
}

func (s *AuthorityWorkerStore) AgentdAdoptionForPrincipalAtEpoch(ctx context.Context, principal, bindingDigest string, predecessorEpoch int64) (authorityAgentdAdoption, error) {
	return scanAuthorityAgentdAdoption(s.db.QueryRowContext(ctx, authorityAdoptionSelect+` WHERE principal=? AND binding_digest=? AND predecessor_fence_epoch=?`, principal, bindingDigest, predecessorEpoch))
}

func (s *AuthorityWorkerStore) UnconfirmedAgentdAdoptions(ctx context.Context) ([]authorityAgentdAdoption, error) {
	rows, err := s.db.QueryContext(ctx, authorityAdoptionSelect+` WHERE adoption_state<>? ORDER BY created_at,binding_digest`, authorityAdoptionConfirmed)
	if err != nil {
		return nil, err
	}
	defer func() {
		//nolint:errcheck // Read-only rows are exhausted before close; no recovery action exists on close.
		_ = rows.Close()
	}()
	var adoptions []authorityAgentdAdoption
	for rows.Next() {
		adoption, err := scanAuthorityAgentdAdoption(rows)
		if err != nil {
			return nil, err
		}
		adoptions = append(adoptions, adoption)
	}
	return adoptions, rows.Err()
}

func (s *AuthorityWorkerStore) ConfirmAgentdAdoption(ctx context.Context, adoption authorityAgentdAdoption) error {
	result, err := s.db.ExecContext(ctx, `UPDATE authority_session_reassignments SET adoption_state=?,adoption_error_code='',adoption_confirmed_at=?
		WHERE binding_digest=? AND coordinator_binding=? AND authority_binding=? AND profile_version=? AND policy_digest=? AND session_lineage_id=? AND agentd_session_id=?
		AND predecessor_worker_id=? AND predecessor_storage_lineage_id=? AND predecessor_fence_epoch=?
		AND replacement_worker_id=? AND replacement_storage_lineage_id=? AND replacement_fence_epoch=?
		AND rebind_idempotency_key=? AND workspace_ref=? AND workspace_uid=? AND workspace_gid=? AND adoption_state=?`,
		authorityAdoptionConfirmed, formatAuthorityTime(time.Now().UTC()),
		adoption.BindingDigest, adoption.CoordinatorBinding, adoption.AuthorityBinding, adoption.ProfileVersion, adoption.PolicyDigest, adoption.SessionLineageID, adoption.AgentdSessionID,
		adoption.Predecessor.WorkerID, adoption.Predecessor.StorageLineageID, adoption.Predecessor.FenceEpoch,
		adoption.Successor.WorkerID, adoption.Successor.StorageLineageID, adoption.Successor.FenceEpoch,
		adoption.RebindIdempotencyKey, adoption.Workspace.WorkspaceRef, adoption.Workspace.UID, adoption.Workspace.GID, authorityAdoptionPending)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 1 {
		return nil
	}
	current, err := s.AgentdAdoptionAtEpoch(ctx, adoption.BindingDigest, adoption.Predecessor.FenceEpoch)
	if err == nil && current.State == authorityAdoptionConfirmed && current == adoptionWithState(adoption, authorityAdoptionConfirmed, "") {
		return nil
	}
	return fmt.Errorf("agentd adoption transition changed before confirmation")
}

func adoptionWithState(adoption authorityAgentdAdoption, state, errorCode string) authorityAgentdAdoption {
	adoption.State, adoption.ErrorCode = state, errorCode
	return adoption
}

func (s *AuthorityWorkerStore) RecordAgentdAdoptionConflict(ctx context.Context, adoption authorityAgentdAdoption, code string) error {
	if code != "rebind_conflict" && code != "session_fenced" && code != "agentd_rebind_rejected" {
		return fmt.Errorf("invalid agentd adoption conflict code")
	}
	current, err := s.AgentdAdoptionAtEpoch(ctx, adoption.BindingDigest, adoption.Predecessor.FenceEpoch)
	if err != nil {
		return err
	}
	if current.State == authorityAdoptionConflict && current.ErrorCode == code {
		return nil
	}
	if current != adoptionWithState(adoption, authorityAdoptionPending, "") {
		return fmt.Errorf("agentd adoption transition changed before conflict was recorded")
	}
	result, err := s.db.ExecContext(ctx, `UPDATE authority_session_reassignments SET adoption_state=?,adoption_error_code=?
		WHERE binding_digest=? AND adoption_state=?`, authorityAdoptionConflict, code, adoption.BindingDigest, authorityAdoptionPending)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 1 {
		return nil
	}
	current, err = s.AgentdAdoptionAtEpoch(ctx, adoption.BindingDigest, adoption.Predecessor.FenceEpoch)
	if err == nil && current.State == authorityAdoptionConflict && current.ErrorCode == code {
		return nil
	}
	return fmt.Errorf("agentd adoption transition changed before conflict was recorded")
}

func (s *AuthorityWorkerStore) ListActiveLeases(ctx context.Context, workerID string) ([]AuthorityLease, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT l.principal,l.profile,l.worker_id,l.binding_digest,l.idempotency_digest,l.created_at,l.session_lineage_id,w.worker_storage_lineage_id,w.worker_fence_epoch FROM authority_session_leases l JOIN authority_workers w ON w.worker_id=l.worker_id WHERE l.worker_id=? AND l.released_at='' ORDER BY l.created_at,l.binding_digest`, workerID)
	if err != nil {
		return nil, err
	}
	defer func() {
		//nolint:errcheck // Read-only rows are already exhausted; no recovery action exists on close.
		_ = rows.Close()
	}()
	var out []AuthorityLease
	for rows.Next() {
		var lease AuthorityLease
		var created string
		if err := rows.Scan(&lease.Principal, &lease.Profile, &lease.WorkerID, &lease.BindingDigest, &lease.IdempotencyDigest, &created, &lease.SessionLineageID, &lease.WorkerStorageLineageID, &lease.WorkerFenceEpoch); err != nil {
			return nil, err
		}
		var err error
		lease.CreatedAt, err = parseAuthorityTime(created)
		if err != nil {
			return nil, err
		}
		out = append(out, lease)
	}
	return out, rows.Err()
}

func (s *AuthorityWorkerStore) Drain(ctx context.Context, workerID, reason string) (AuthorityWorker, error) {
	result, err := s.db.ExecContext(ctx, `UPDATE authority_workers SET state=?,drain_reason=?,updated_at=? WHERE worker_id=? AND state IN (?,?,?)`, AuthorityWorkerDraining, reason, formatAuthorityTime(time.Now().UTC()), workerID, AuthorityWorkerStarting, AuthorityWorkerReady, AuthorityWorkerUnhealthy)
	if err != nil {
		return AuthorityWorker{}, err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return AuthorityWorker{}, err
	}
	if rows == 0 {
		worker, getErr := s.GetWorker(ctx, workerID)
		if getErr != nil {
			return AuthorityWorker{}, getErr
		}
		if worker.State != AuthorityWorkerDraining {
			return AuthorityWorker{}, fmt.Errorf("worker %q cannot drain from state %q", workerID, worker.State)
		}
		return worker, nil
	}
	return s.GetWorker(ctx, workerID)
}

// DrainedPredecessor returns a zero-lease worker only when every durable
// reassignment from it has confirmed exact agentd adoption.
func (s *AuthorityWorkerStore) DrainedPredecessor(ctx context.Context, replacementWorkerID string) (AuthorityWorker, bool, error) {
	worker, err := scanAuthorityWorker(s.db.QueryRowContext(ctx, `SELECT worker_id,profile,profile_version,policy_digest,image_reference,image_digest,generation,container_id,state,capacity,assigned_sessions,health,drain_reason,replacement_worker_id,heartbeat_at,created_at,updated_at,worker_storage_lineage_id,worker_fence_epoch FROM authority_workers predecessor
		WHERE replacement_worker_id=? AND state=? AND assigned_sessions=0
		AND NOT EXISTS (SELECT 1 FROM authority_session_reassignments transition WHERE transition.predecessor_worker_id=predecessor.worker_id AND transition.adoption_state<>?)`, replacementWorkerID, AuthorityWorkerDraining, authorityAdoptionConfirmed))
	if errors.Is(err, sql.ErrNoRows) {
		return AuthorityWorker{}, false, nil
	}
	if err != nil {
		return AuthorityWorker{}, false, err
	}
	return worker, true, nil
}

// ReadyReplacementWorkersWithDrainedPredecessors supplies reconciliation with
// committed cutovers whose runtime retirement was interrupted after commit.
func (s *AuthorityWorkerStore) ReadyReplacementWorkersWithDrainedPredecessors(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT replacement_worker_id FROM authority_workers predecessor
		WHERE predecessor.state=? AND predecessor.assigned_sessions=0 AND predecessor.replacement_worker_id<>''
		AND EXISTS (SELECT 1 FROM authority_workers replacement WHERE replacement.worker_id=predecessor.replacement_worker_id AND replacement.state=?)
		AND NOT EXISTS (SELECT 1 FROM authority_session_reassignments transition WHERE transition.predecessor_worker_id=predecessor.worker_id AND transition.adoption_state<>?)`, AuthorityWorkerDraining, AuthorityWorkerReady, authorityAdoptionConfirmed)
	if err != nil {
		return nil, err
	}
	defer func() {
		//nolint:errcheck // Read-only rows are exhausted before close; no recovery action exists on close.
		_ = rows.Close()
	}()
	var workerIDs []string
	for rows.Next() {
		var workerID string
		if err := rows.Scan(&workerID); err != nil {
			return nil, err
		}
		workerIDs = append(workerIDs, workerID)
	}
	return workerIDs, rows.Err()
}

// MarkDrainedStopped records retirement only after the runtime has stopped the
// zero-lease predecessor.  The conditional update keeps a concurrent lease or
// state transition from being silently discarded.
func (s *AuthorityWorkerStore) MarkDrainedStopped(ctx context.Context, workerID string) error {
	result, err := s.db.ExecContext(ctx, `UPDATE authority_workers SET state=?,updated_at=? WHERE worker_id=? AND state=? AND assigned_sessions=0
		AND NOT EXISTS (SELECT 1 FROM authority_session_reassignments transition WHERE transition.predecessor_worker_id=authority_workers.worker_id AND transition.adoption_state<>?)`, AuthorityWorkerStopped, formatAuthorityTime(time.Now().UTC()), workerID, AuthorityWorkerDraining, authorityAdoptionConfirmed)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return fmt.Errorf("drained worker %q was not retired", workerID)
	}
	return nil
}

func (s *AuthorityWorkerStore) LinkReplacement(ctx context.Context, oldWorkerID string, replacement AuthorityWorker, maxWorkers int, issuanceGeneration int64) (AuthorityWorker, bool, error) {
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return AuthorityWorker{}, false, err
	}
	defer closeAuthorityConn(conn)
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return AuthorityWorker{}, false, err
	}
	committed := false
	defer func() {
		if !committed {
			rollbackAuthorityConn(context.WithoutCancel(ctx), conn)
		}
	}()
	var existing, predecessorStorageLineageID string
	var predecessorWorkerFenceEpoch int64
	if err := conn.QueryRowContext(ctx, `SELECT replacement_worker_id,worker_storage_lineage_id,worker_fence_epoch FROM authority_workers WHERE worker_id=?`, oldWorkerID).Scan(&existing, &predecessorStorageLineageID, &predecessorWorkerFenceEpoch); err != nil {
		return AuthorityWorker{}, false, err
	}
	if existing != "" {
		worker, err := scanAuthorityWorker(conn.QueryRowContext(ctx, `SELECT worker_id,profile,profile_version,policy_digest,image_reference,image_digest,generation,container_id,state,capacity,assigned_sessions,health,drain_reason,replacement_worker_id,heartbeat_at,created_at,updated_at,worker_storage_lineage_id,worker_fence_epoch FROM authority_workers WHERE worker_id=?`, existing))
		if err != nil {
			return AuthorityWorker{}, false, err
		}
		if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
			return AuthorityWorker{}, false, err
		}
		committed = true
		return worker, false, nil
	}
	if err := s.checkIssuanceInTransaction(ctx, conn, replacement.Profile, issuanceGeneration); err != nil {
		return AuthorityWorker{}, false, err
	}
	var active int
	if err := conn.QueryRowContext(ctx, `SELECT count(*) FROM authority_workers WHERE profile=? AND state NOT IN (?,?)`, replacement.Profile, AuthorityWorkerStopped, AuthorityWorkerFailed).Scan(&active); err != nil {
		return AuthorityWorker{}, false, err
	}
	if active >= maxWorkers+1 {
		return AuthorityWorker{}, false, fmt.Errorf("authority profile %q exceeds replacement allowance", replacement.Profile)
	}
	now := time.Now().UTC()
	replacement.CreatedAt, replacement.UpdatedAt = now, now
	replacement.WorkerStorageLineageID = predecessorStorageLineageID
	replacement.WorkerFenceEpoch = predecessorWorkerFenceEpoch + 1
	if !validOpaqueLineageID(replacement.WorkerStorageLineageID) || replacement.WorkerFenceEpoch < 2 {
		return AuthorityWorker{}, false, fmt.Errorf("predecessor worker storage lineage is invalid")
	}
	_, err = conn.ExecContext(ctx, `INSERT INTO authority_workers(worker_id,profile,profile_version,policy_digest,image_reference,image_digest,generation,state,capacity,created_at,updated_at,worker_storage_lineage_id,worker_fence_epoch) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`, replacement.WorkerID, replacement.Profile, replacement.ProfileVersion, replacement.PolicyDigest, replacement.ImageReference, replacement.ImageDigest, replacement.Generation, replacement.State, replacement.Capacity, formatAuthorityTime(now), formatAuthorityTime(now), replacement.WorkerStorageLineageID, replacement.WorkerFenceEpoch)
	if err != nil {
		return AuthorityWorker{}, false, err
	}
	_, err = conn.ExecContext(ctx, `UPDATE authority_workers SET drain_reason=?,replacement_worker_id=?,updated_at=? WHERE worker_id=?`, replacement.DrainReason, replacement.WorkerID, formatAuthorityTime(now), oldWorkerID)
	if err != nil {
		return AuthorityWorker{}, false, err
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return AuthorityWorker{}, false, err
	}
	committed = true
	return replacement, true, nil
}

func (s *AuthorityWorkerStore) FailReplacement(ctx context.Context, oldWorkerID, replacementWorkerID, health string) error {
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer closeAuthorityConn(conn)
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			rollbackAuthorityConn(context.WithoutCancel(ctx), conn)
		}
	}()
	now := formatAuthorityTime(time.Now().UTC())
	if _, err := conn.ExecContext(ctx, `UPDATE authority_workers SET state=?,health=?,updated_at=? WHERE worker_id=?`, AuthorityWorkerFailed, health, now, replacementWorkerID); err != nil {
		return err
	}
	result, err := conn.ExecContext(ctx, `UPDATE authority_workers SET replacement_worker_id='',drain_reason=CASE WHEN state=? THEN drain_reason ELSE '' END,updated_at=? WHERE worker_id=? AND replacement_worker_id=?`, AuthorityWorkerDraining, now, oldWorkerID, replacementWorkerID)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return fmt.Errorf("worker %q replacement link changed", oldWorkerID)
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return err
	}
	committed = true
	return nil
}

func (s *AuthorityWorkerStore) MarkFailed(ctx context.Context, workerID, health string) error {
	result, err := s.db.ExecContext(ctx, `UPDATE authority_workers SET state=?,health=?,updated_at=? WHERE worker_id=?`, AuthorityWorkerFailed, health, formatAuthorityTime(time.Now().UTC()), workerID)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return fmt.Errorf("worker %q was not marked failed", workerID)
	}
	return nil
}

type authorityRowScanner interface{ Scan(...any) error }

func scanAuthorityWorker(row authorityRowScanner) (AuthorityWorker, error) {
	var worker AuthorityWorker
	var heartbeat, created, updated string
	err := row.Scan(&worker.WorkerID, &worker.Profile, &worker.ProfileVersion, &worker.PolicyDigest, &worker.ImageReference, &worker.ImageDigest, &worker.Generation, &worker.ContainerID, &worker.State, &worker.Capacity, &worker.AssignedSessions, &worker.Health, &worker.DrainReason, &worker.ReplacementWorker, &heartbeat, &created, &updated, &worker.WorkerStorageLineageID, &worker.WorkerFenceEpoch)
	if err != nil {
		return AuthorityWorker{}, err
	}
	worker.HeartbeatAt, err = parseAuthorityTime(heartbeat)
	if err != nil {
		return AuthorityWorker{}, err
	}
	worker.CreatedAt, err = parseAuthorityTime(created)
	if err != nil {
		return AuthorityWorker{}, err
	}
	worker.UpdatedAt, err = parseAuthorityTime(updated)
	if err != nil {
		return AuthorityWorker{}, err
	}
	return worker, nil
}

func formatAuthorityTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}

func parseAuthorityTime(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, nil
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse authority worker timestamp: %w", err)
	}
	return parsed, nil
}

func rollbackAuthorityTx(tx *sql.Tx) {
	if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
		return
	}
}

func rollbackAuthorityConn(ctx context.Context, conn *sql.Conn) {
	if _, err := conn.ExecContext(ctx, "ROLLBACK"); err != nil {
		return
	}
}

func closeAuthorityConn(conn *sql.Conn) {
	if err := conn.Close(); err != nil {
		return
	}
}
