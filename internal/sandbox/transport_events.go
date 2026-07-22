package sandbox

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
)

// TransportObserver is the broker-only writer for repository_transport_events.
// It intentionally exposes no query or mutation API for callers.
type TransportObserver struct{ store *AuthorityWorkerStore }

type TransportAuthority struct {
	Principal, Profile, WorkerID, SessionLineageID, SessionBindingDigest, WorkerStorageLineageID string
	WorkerFenceEpoch                                                                             int64
	ProfileVersion, PolicyDigest                                                                 string
}

type TransportOperation struct {
	OperationID, Method, Service, Repository, RequestPath string
	RequestedRefs, RefUpdates                             any
	CredentialHeaderPresent                               bool
	Authority                                             TransportAuthority
	phaseOrdinal                                          int
}

// GreenPRTransportAdmission is derived exclusively from the active durable
// lease, its immutable registered task, and a completed broker Git operation.
type GreenPRTransportAdmission struct {
	Task        RegisteredTask
	TaskDigest  string
	OperationID string
	PushedSHA   string
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
// ResolveAuthority resolves only the active lease authenticated by the fixed
// broker-issued transport context. The context is an HMAC under store-private
// material; it is neither an agent credential nor derivable by another worker.
func (o *TransportObserver) ResolveAuthority(ctx context.Context, transportContext string) (TransportAuthority, error) {
	rows, err := o.store.db.QueryContext(ctx, `SELECT l.principal,l.profile,l.worker_id,l.session_lineage_id,l.binding_digest,w.worker_storage_lineage_id,w.worker_fence_epoch,w.profile_version,w.policy_digest
		FROM authority_session_leases l JOIN authority_workers w ON w.worker_id=l.worker_id
		WHERE l.released_at=''`)
	if err != nil {
		return TransportAuthority{}, fmt.Errorf("query active transport authority: %w", err)
	}
	defer closeTransportRows(rows)
	var out TransportAuthority
	matches := 0
	for rows.Next() {
		var candidate TransportAuthority
		if err := rows.Scan(&candidate.Principal, &candidate.Profile, &candidate.WorkerID, &candidate.SessionLineageID, &candidate.SessionBindingDigest, &candidate.WorkerStorageLineageID, &candidate.WorkerFenceEpoch, &candidate.ProfileVersion, &candidate.PolicyDigest); err != nil {
			return TransportAuthority{}, fmt.Errorf("scan active transport authority: %w", err)
		}
		if secureTokenEqual(transportContext, o.transportContext(candidate)) {
			out = candidate
			matches++
		}
	}
	if err := rows.Err(); err != nil {
		return TransportAuthority{}, fmt.Errorf("read active transport authority: %w", err)
	}
	if matches != 1 {
		return TransportAuthority{}, fmt.Errorf("transport authority context is unavailable")
	}
	return out, nil
}

// TransportContext returns the fixed capability delivered to the exact active
// agentd session by the broker-owned session supervisor. It is intentionally
// opaque and cannot name a profile, task, push, or completion fact.
func (o *TransportObserver) TransportContext(authority TransportAuthority) string {
	return o.transportContext(authority)
}

// LeaseTransportContext is called only by the broker's session handoff path to
// deliver the fixed context to the selected agentd session.
func (o *TransportObserver) LeaseTransportContext(ctx context.Context, principal, bindingDigest string) (string, error) {
	var authority TransportAuthority
	err := o.store.db.QueryRowContext(ctx, `SELECT l.principal,l.profile,l.worker_id,l.session_lineage_id,l.binding_digest,w.worker_storage_lineage_id,w.worker_fence_epoch,w.profile_version,w.policy_digest FROM authority_session_leases l JOIN authority_workers w ON w.worker_id=l.worker_id WHERE l.principal=? AND l.binding_digest=? AND l.released_at=''`, principal, bindingDigest).Scan(&authority.Principal, &authority.Profile, &authority.WorkerID, &authority.SessionLineageID, &authority.SessionBindingDigest, &authority.WorkerStorageLineageID, &authority.WorkerFenceEpoch, &authority.ProfileVersion, &authority.PolicyDigest)
	if err != nil {
		return "", fmt.Errorf("read active transport authority: %w", err)
	}
	return o.transportContext(authority), nil
}

func (o *TransportObserver) transportContext(authority TransportAuthority) string {
	return deriveTransportContext(o.store.salt, authority)
}

func deriveTransportContext(secret []byte, authority TransportAuthority) string {
	payload := authority.Principal + "\x00" + authority.Profile + "\x00" + authority.WorkerID + "\x00" + authority.WorkerStorageLineageID + "\x00" + fmt.Sprint(authority.WorkerFenceEpoch) + "\x00" + authority.SessionLineageID + "\x00" + authority.SessionBindingDigest
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte("gh-agent-broker/transport-context/v1\x00" + payload))
	return "atc1." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// GreenPRAdmission returns the one current registered task and exact pushed
// head for a profile. It accepts no caller identity, SHA, or PR data.
func (o *TransportObserver) GreenPRAdmission(ctx context.Context, transportContext string) (GreenPRTransportAdmission, error) {
	authority, err := o.ResolveAuthority(ctx, transportContext)
	if err != nil {
		return GreenPRTransportAdmission{}, err
	}
	var canonical, digest string
	err = o.store.db.QueryRowContext(ctx, `SELECT a.canonical_task_json,a.admission_task_digest FROM authority_registered_admissions a JOIN authority_session_leases l ON l.principal=a.principal AND l.binding_digest=a.binding_digest WHERE l.principal=? AND l.binding_digest=? AND l.worker_id=? AND l.session_lineage_id=? AND l.released_at=''`, authority.Principal, authority.SessionBindingDigest, authority.WorkerID, authority.SessionLineageID).Scan(&canonical, &digest)
	if err != nil {
		return GreenPRTransportAdmission{}, fmt.Errorf("read registered transport admission: %w", err)
	}
	var wire struct {
		Source RegisteredTaskSource `json:"registered_task_source"`
		Task   RegisteredTask       `json:"registered_task"`
	}
	if err := json.Unmarshal([]byte(canonical), &wire); err != nil {
		return GreenPRTransportAdmission{}, fmt.Errorf("registered transport admission is corrupt")
	}
	validated, err := validateRegisteredAdmission(RegisteredAdmissionRequest{Version: coordinatorRegisteredProtocolVersion, Profile: authority.Profile, IdempotencyKey: "green-pr-observe", SessionBinding: "session:" + wire.Source.WorkItemID, Source: wire.Source, Task: wire.Task, AdmissionTaskDigest: digest})
	if err != nil || validated.CanonicalJSON != canonical {
		return GreenPRTransportAdmission{}, fmt.Errorf("registered transport admission is invalid")
	}
	rows, err := o.store.db.QueryContext(ctx, `SELECT operation_id,ref_updates_json FROM repository_transport_events WHERE principal=? AND worker_id=? AND worker_storage_lineage_id=? AND worker_fence_epoch=? AND repository=? AND service='git-receive-pack' AND phase='completed' ORDER BY cursor DESC`, authority.Principal, authority.WorkerID, authority.WorkerStorageLineageID, authority.WorkerFenceEpoch, wire.Task.Parameters.Repository)
	if err != nil {
		return GreenPRTransportAdmission{}, fmt.Errorf("read broker push operation: %w", err)
	}
	defer closeTransportRows(rows)
	for rows.Next() {
		var operationID, encoded string
		if err := rows.Scan(&operationID, &encoded); err != nil {
			return GreenPRTransportAdmission{}, err
		}
		var updates []struct {
			After string `json:"After"`
			Ref   string `json:"Ref"`
		}
		if json.Unmarshal([]byte(encoded), &updates) != nil {
			continue
		}
		for _, update := range updates {
			if update.Ref == "refs/heads/"+wire.Task.Parameters.BranchRef && sha40.MatchString(update.After) {
				return GreenPRTransportAdmission{Task: validated.Task, TaskDigest: digest, OperationID: operationID, PushedSHA: update.After}, nil
			}
		}
	}
	if err := rows.Err(); err != nil {
		return GreenPRTransportAdmission{}, err
	}
	return GreenPRTransportAdmission{}, fmt.Errorf("registered task has no completed broker push")
}

func (o *TransportObserver) Received(ctx context.Context, op *TransportOperation) error {
	return o.append(ctx, op, "received", "", "", 0, 0)
}

// ReceivedEffectCredential is the linearization barrier between effect
// credential custody and Git transport. It revalidates the complete custody
// snapshot and appends Received under the same SQLite writer transaction that
// orders release and reassignment. The transaction commits before any upstream
// request is made.
func (o *TransportObserver) ReceivedEffectCredential(ctx context.Context, agentID, secret, repository string, expected GitCredentialAuthority, op *TransportOperation) error {
	conn, err := o.store.db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("open effect transport barrier: %w", err)
	}
	defer closeAuthorityConn(conn)
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return fmt.Errorf("begin effect transport barrier: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			rollbackAuthorityConn(context.WithoutCancel(ctx), conn)
		}
	}()
	current, valid, err := o.store.authenticateGitCredential(ctx, conn, agentID, secret, repository)
	if err != nil {
		return fmt.Errorf("revalidate effect transport authority: %w", err)
	}
	if !valid || current != expected {
		return fmt.Errorf("effect transport authority is unavailable")
	}
	op.Authority = current.TransportAuthority
	if err := insertTransportEvent(ctx, conn, op, 1, "received", "", "", 0, 0); err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return fmt.Errorf("commit effect transport barrier: %w", err)
	}
	committed = true
	op.phaseOrdinal = 1
	return nil
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
	phaseOrdinal := op.phaseOrdinal + 1
	tx, err := o.store.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transport append: %w", err)
	}
	defer rollbackTransportTx(tx)
	if err := insertTransportEvent(ctx, tx, op, phaseOrdinal, phase, decision, outcome, status, backend); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit transport %s: %w", phase, err)
	}
	op.phaseOrdinal = phaseOrdinal
	return nil
}

type transportEventQueryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func insertTransportEvent(ctx context.Context, queryer transportEventQueryer, op *TransportOperation, phaseOrdinal int, phase, decision, outcome string, status, backend int) error {
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
	var previous string
	if err := queryer.QueryRowContext(ctx, `SELECT event_digest FROM repository_transport_events ORDER BY cursor DESC LIMIT 1`).Scan(&previous); err != nil {
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
	}{op.OperationID, phase, op.Authority.Principal, op.Authority.WorkerID, op.Authority.SessionLineageID, op.Authority.WorkerStorageLineageID, op.Authority.ProfileVersion, op.Authority.PolicyDigest, op.Method, op.Service, op.Repository, op.RequestPath, string(requested), string(updates), decision, outcome, previous, int64(phaseOrdinal), op.Authority.WorkerFenceEpoch, int64(credential), int64(status), int64(backend)})
	if err != nil {
		return fmt.Errorf("encode transport digest: %w", err)
	}
	sum := sha256.Sum256(payload)
	digest := hex.EncodeToString(sum[:])
	_, err = queryer.ExecContext(ctx, `INSERT INTO repository_transport_events(
		operation_id,phase_ordinal,phase,principal,worker_id,session_lineage_id,worker_storage_lineage_id,worker_fence_epoch,profile_version,policy_digest,method,service,repository,request_path,requested_refs_json,ref_updates_json,credential_header_present,decision,outcome_code,http_status,backend_status,before_refs_digest,after_refs_digest,previous_event_digest,event_digest)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		op.OperationID, phaseOrdinal, phase, op.Authority.Principal, op.Authority.WorkerID, op.Authority.SessionLineageID, op.Authority.WorkerStorageLineageID, op.Authority.WorkerFenceEpoch, op.Authority.ProfileVersion, op.Authority.PolicyDigest, op.Method, op.Service, op.Repository, op.RequestPath, string(requested), string(updates), credential, decision, outcome, status, backend, "", "", previous, digest)
	if err != nil {
		return fmt.Errorf("append transport %s: %w", phase, err)
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
