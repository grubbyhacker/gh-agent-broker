package sandbox

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
)

// TransportObserver is the broker-only writer for repository_transport_events.
// It intentionally exposes no query or mutation API for callers.
type TransportObserver struct{ store *AuthorityWorkerStore }

type TransportAuthority struct {
	Principal, WorkerID, SessionLineageID, WorkerStorageLineageID string
	WorkerFenceEpoch                                              int64
	ProfileVersion, PolicyDigest                                  string
}

type TransportOperation struct {
	OperationID, Method, Service, Repository, RequestPath string
	RequestedRefs, RefUpdates                             any
	CredentialHeaderPresent                               bool
	Authority                                             TransportAuthority
	phaseOrdinal                                          int
}

// OpenTransportObserver opens the existing authority boundary and applies its
// migration. The path is operator configuration, never request input.
func OpenTransportObserver(ctx context.Context, path string) (*TransportObserver, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("transport authority store path must be absolute")
	}
	store, err := OpenAuthorityWorkerStore(ctx, path)
	if err != nil {
		return nil, err
	}
	return &TransportObserver{store: store}, nil
}

func (o *TransportObserver) Close() error { return o.store.Close() }

// ResolveAuthority derives the sole active lease for the reviewed profile. A
// caller can name neither the profile nor any authority coordinate.
func (o *TransportObserver) ResolveAuthority(ctx context.Context, profile string) (TransportAuthority, error) {
	rows, err := o.store.db.QueryContext(ctx, `SELECT l.principal,l.worker_id,l.session_lineage_id,w.worker_storage_lineage_id,w.worker_fence_epoch,w.profile_version,w.policy_digest
		FROM authority_session_leases l JOIN authority_workers w ON w.worker_id=l.worker_id
		WHERE l.profile=? AND l.released_at=''`, profile)
	if err != nil {
		return TransportAuthority{}, fmt.Errorf("query active transport authority: %w", err)
	}
	defer closeTransportRows(rows)
	var out TransportAuthority
	count := 0
	for rows.Next() {
		count++
		if err := rows.Scan(&out.Principal, &out.WorkerID, &out.SessionLineageID, &out.WorkerStorageLineageID, &out.WorkerFenceEpoch, &out.ProfileVersion, &out.PolicyDigest); err != nil {
			return TransportAuthority{}, fmt.Errorf("scan active transport authority: %w", err)
		}
	}
	if err := rows.Err(); err != nil {
		return TransportAuthority{}, fmt.Errorf("read active transport authority: %w", err)
	}
	if count != 1 {
		return TransportAuthority{}, fmt.Errorf("transport authority profile %q has %d active leases", profile, count)
	}
	return out, nil
}

func (o *TransportObserver) Received(ctx context.Context, op *TransportOperation) error {
	return o.append(ctx, op, "received", "", "", 0, 0)
}

func (o *TransportObserver) Forwarded(ctx context.Context, op *TransportOperation) error {
	return o.append(ctx, op, "forwarded", "allowed", "", 0, 0)
}

func (o *TransportObserver) Terminal(ctx context.Context, op *TransportOperation, phase, decision, outcome string, status, backend int) error {
	if phase != "denied" && phase != "completed" && phase != "failed" {
		return fmt.Errorf("invalid transport terminal phase %q", phase)
	}
	return o.append(ctx, op, phase, decision, outcome, status, backend)
}

func (o *TransportObserver) append(ctx context.Context, op *TransportOperation, phase, decision, outcome string, status, backend int) error {
	if op.OperationID == "" || op.Authority.Principal == "" {
		return fmt.Errorf("transport operation is missing broker-owned identity")
	}
	expectedOrdinal := map[string]int{"received": 1, "forwarded": 2, "denied": 2, "completed": 3, "failed": 3}[phase]
	if expectedOrdinal == 0 || op.phaseOrdinal+1 != expectedOrdinal {
		return fmt.Errorf("invalid transport phase transition to %q", phase)
	}
	op.phaseOrdinal++
	requested, err := json.Marshal(op.RequestedRefs)
	if err != nil {
		return fmt.Errorf("encode requested refs: %w", err)
	}
	updates, err := json.Marshal(op.RefUpdates)
	if err != nil {
		return fmt.Errorf("encode ref updates: %w", err)
	}
	credential := 0
	if op.CredentialHeaderPresent {
		credential = 1
	}
	tx, err := o.store.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transport append: %w", err)
	}
	defer rollbackTransportTx(tx)
	var previous string
	if err := tx.QueryRowContext(ctx, `SELECT event_digest FROM repository_transport_events ORDER BY cursor DESC LIMIT 1`).Scan(&previous); err != nil {
		if err != sql.ErrNoRows {
			return fmt.Errorf("read previous transport digest: %w", err)
		}
		previous = ""
	}
	// The digest covers every persisted value except itself; this makes a
	// missing, reordered, or rewritten phase detectable by the fixed reader.
	payload, err := json.Marshal(struct {
		OperationID, Phase, Principal, WorkerID, SessionLineageID, WorkerStorageLineageID, ProfileVersion, PolicyDigest, Method, Service, Repository, RequestPath, RequestedRefs, RefUpdates, Decision, Outcome, Previous string
		PhaseOrdinal, WorkerFenceEpoch, CredentialHeaderPresent, HTTPStatus, BackendStatus                                                                                                                                int64
	}{op.OperationID, phase, op.Authority.Principal, op.Authority.WorkerID, op.Authority.SessionLineageID, op.Authority.WorkerStorageLineageID, op.Authority.ProfileVersion, op.Authority.PolicyDigest, op.Method, op.Service, op.Repository, op.RequestPath, string(requested), string(updates), decision, outcome, previous, int64(op.phaseOrdinal), op.Authority.WorkerFenceEpoch, int64(credential), int64(status), int64(backend)})
	if err != nil {
		return fmt.Errorf("encode transport digest: %w", err)
	}
	sum := sha256.Sum256(payload)
	digest := hex.EncodeToString(sum[:])
	_, err = tx.ExecContext(ctx, `INSERT INTO repository_transport_events(
		operation_id,phase_ordinal,phase,principal,worker_id,session_lineage_id,worker_storage_lineage_id,worker_fence_epoch,profile_version,policy_digest,method,service,repository,request_path,requested_refs_json,ref_updates_json,credential_header_present,decision,outcome_code,http_status,backend_status,before_refs_digest,after_refs_digest,previous_event_digest,event_digest)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		op.OperationID, op.phaseOrdinal, phase, op.Authority.Principal, op.Authority.WorkerID, op.Authority.SessionLineageID, op.Authority.WorkerStorageLineageID, op.Authority.WorkerFenceEpoch, op.Authority.ProfileVersion, op.Authority.PolicyDigest, op.Method, op.Service, op.Repository, op.RequestPath, string(requested), string(updates), credential, decision, outcome, status, backend, "", "", previous, digest)
	if err != nil {
		return fmt.Errorf("append transport %s: %w", phase, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit transport %s: %w", phase, err)
	}
	return nil
}

func closeTransportRows(rows *sql.Rows) {
	if err := rows.Close(); err != nil {
		return
	}
}

func rollbackTransportTx(tx *sql.Tx) {
	if err := tx.Rollback(); err != nil {
		return
	}
}

// transportEventCount supports focused invariant tests; it is not a broker API.
func (o *TransportObserver) transportEventCount(ctx context.Context) (int, error) {
	var count int
	err := o.store.db.QueryRowContext(ctx, `SELECT count(*) FROM repository_transport_events`).Scan(&count)
	return count, err
}
