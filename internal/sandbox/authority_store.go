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

	_ "modernc.org/sqlite"
)

const authorityStoreSchemaVersion = 2

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
	WorkerID          string               `json:"worker_id"`
	Profile           string               `json:"profile"`
	ProfileVersion    string               `json:"profile_version"`
	PolicyDigest      string               `json:"policy_digest"`
	ImageReference    string               `json:"image_reference"`
	ImageDigest       string               `json:"image_digest"`
	Generation        int                  `json:"generation"`
	ContainerID       string               `json:"container_id,omitempty"`
	State             AuthorityWorkerState `json:"state"`
	Capacity          int                  `json:"capacity"`
	AssignedSessions  int                  `json:"assigned_sessions"`
	Health            string               `json:"health,omitempty"`
	DrainReason       string               `json:"drain_reason,omitempty"`
	ReplacementWorker string               `json:"replacement_worker_id,omitempty"`
	HeartbeatAt       time.Time            `json:"heartbeat_at,omitempty"`
	CreatedAt         time.Time            `json:"created_at"`
	UpdatedAt         time.Time            `json:"updated_at"`
}

type AuthorityLease struct {
	Principal         string    `json:"principal"`
	Profile           string    `json:"profile"`
	WorkerID          string    `json:"worker_id"`
	BindingDigest     string    `json:"session_binding_digest"`
	IdempotencyDigest string    `json:"idempotency_key_digest"`
	CreatedAt         time.Time `json:"created_at"`
	ReleasedAt        time.Time `json:"released_at,omitempty"`
	Replay            bool      `json:"replay"`
}

type AuthorityWorkerStore struct {
	db        *sql.DB
	salt      []byte
	sessionMu sync.Mutex
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

func (s *AuthorityWorkerStore) CreateWorker(ctx context.Context, worker AuthorityWorker, maxWorkers int) (AuthorityWorker, error) {
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
		(worker_id,profile,profile_version,policy_digest,image_reference,image_digest,generation,container_id,state,capacity,assigned_sessions,health,drain_reason,replacement_worker_id,heartbeat_at,created_at,updated_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, worker.WorkerID, worker.Profile, worker.ProfileVersion,
		worker.PolicyDigest, worker.ImageReference, worker.ImageDigest, worker.Generation, worker.ContainerID, worker.State, worker.Capacity,
		worker.AssignedSessions, worker.Health, worker.DrainReason, worker.ReplacementWorker, formatAuthorityTime(worker.HeartbeatAt), formatAuthorityTime(now), formatAuthorityTime(now))
	if err != nil {
		return AuthorityWorker{}, err
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return AuthorityWorker{}, err
	}
	committed = true
	return worker, nil
}

func (s *AuthorityWorkerStore) GetWorker(ctx context.Context, workerID string) (AuthorityWorker, error) {
	return scanAuthorityWorker(s.db.QueryRowContext(ctx, `SELECT worker_id,profile,profile_version,policy_digest,image_reference,image_digest,generation,container_id,state,capacity,assigned_sessions,health,drain_reason,replacement_worker_id,heartbeat_at,created_at,updated_at FROM authority_workers WHERE worker_id=?`, workerID))
}

func (s *AuthorityWorkerStore) ListLiveWorkers(ctx context.Context) ([]AuthorityWorker, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT worker_id,profile,profile_version,policy_digest,image_reference,image_digest,generation,container_id,state,capacity,assigned_sessions,health,drain_reason,replacement_worker_id,heartbeat_at,created_at,updated_at FROM authority_workers WHERE state IN (?,?,?) ORDER BY profile,generation,worker_id`, AuthorityWorkerStarting, AuthorityWorkerReady, AuthorityWorkerUnhealthy)
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
	return scanAuthorityWorker(conn.QueryRowContext(ctx, `SELECT worker_id,profile,profile_version,policy_digest,image_reference,image_digest,generation,container_id,state,capacity,assigned_sessions,health,drain_reason,replacement_worker_id,heartbeat_at,created_at,updated_at FROM authority_workers WHERE worker_id=?`, workerID))
}

func (s *AuthorityWorkerStore) Acquire(ctx context.Context, principal string, request AuthorityWorkerRequest) (AuthorityLease, error) {
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
	err = conn.QueryRowContext(ctx, `SELECT profile,worker_id,binding_digest,idempotency_digest,request_fingerprint,created_at,released_at FROM authority_session_leases WHERE principal=? AND profile=? AND idempotency_digest=?`, principal, request.Profile, idem).
		Scan(&lease.Profile, &lease.WorkerID, &lease.BindingDigest, &lease.IdempotencyDigest, &storedFingerprint, &created, &released)
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
	_, err = conn.ExecContext(ctx, `INSERT INTO authority_session_leases(principal,profile,idempotency_digest,request_fingerprint,binding_digest,worker_id,created_at) VALUES(?,?,?,?,?,?,?)`, principal, request.Profile, idem, fingerprint, binding, workerID, formatAuthorityTime(now))
	if err != nil {
		return AuthorityLease{}, err
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return AuthorityLease{}, err
	}
	committed = true
	return AuthorityLease{Principal: principal, Profile: request.Profile, WorkerID: workerID, BindingDigest: binding, IdempotencyDigest: idem, CreatedAt: now}, nil
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
	err = conn.QueryRowContext(ctx, `SELECT profile,worker_id,idempotency_digest,created_at,released_at FROM authority_session_leases WHERE principal=? AND binding_digest=?`, principal, binding).
		Scan(&lease.Profile, &lease.WorkerID, &lease.IdempotencyDigest, &created, &released)
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
	err := s.db.QueryRowContext(ctx, `SELECT profile,worker_id,idempotency_digest,created_at,released_at FROM authority_session_leases WHERE principal=? AND binding_digest=?`, principal, binding).
		Scan(&lease.Profile, &lease.WorkerID, &lease.IdempotencyDigest, &created, &released)
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

func (s *AuthorityWorkerStore) ListActiveLeases(ctx context.Context, workerID string) ([]AuthorityLease, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT principal,profile,worker_id,binding_digest,idempotency_digest,created_at FROM authority_session_leases WHERE worker_id=? AND released_at='' ORDER BY created_at,binding_digest`, workerID)
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
		if err := rows.Scan(&lease.Principal, &lease.Profile, &lease.WorkerID, &lease.BindingDigest, &lease.IdempotencyDigest, &created); err != nil {
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

func (s *AuthorityWorkerStore) LinkReplacement(ctx context.Context, oldWorkerID string, replacement AuthorityWorker, maxWorkers int) (AuthorityWorker, bool, error) {
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
	var existing string
	if err := conn.QueryRowContext(ctx, `SELECT replacement_worker_id FROM authority_workers WHERE worker_id=?`, oldWorkerID).Scan(&existing); err != nil {
		return AuthorityWorker{}, false, err
	}
	if existing != "" {
		worker, err := scanAuthorityWorker(conn.QueryRowContext(ctx, `SELECT worker_id,profile,profile_version,policy_digest,image_reference,image_digest,generation,container_id,state,capacity,assigned_sessions,health,drain_reason,replacement_worker_id,heartbeat_at,created_at,updated_at FROM authority_workers WHERE worker_id=?`, existing))
		if err != nil {
			return AuthorityWorker{}, false, err
		}
		if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
			return AuthorityWorker{}, false, err
		}
		committed = true
		return worker, false, nil
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
	_, err = conn.ExecContext(ctx, `INSERT INTO authority_workers(worker_id,profile,profile_version,policy_digest,image_reference,image_digest,generation,state,capacity,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, replacement.WorkerID, replacement.Profile, replacement.ProfileVersion, replacement.PolicyDigest, replacement.ImageReference, replacement.ImageDigest, replacement.Generation, replacement.State, replacement.Capacity, formatAuthorityTime(now), formatAuthorityTime(now))
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
	err := row.Scan(&worker.WorkerID, &worker.Profile, &worker.ProfileVersion, &worker.PolicyDigest, &worker.ImageReference, &worker.ImageDigest, &worker.Generation, &worker.ContainerID, &worker.State, &worker.Capacity, &worker.AssignedSessions, &worker.Health, &worker.DrainReason, &worker.ReplacementWorker, &heartbeat, &created, &updated)
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
