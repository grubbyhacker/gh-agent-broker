package sandbox

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
)

const (
	coordinatorRegisteredProtocolVersion = "broker/coordinator/v2"
	githubGreenPRContractDigest          = "sha256:40963efb60fd00563bd6a33f1325b45008a917ebf17c110f9d3c86f7dd77d1fb"
)

type RegisteredTaskSource struct {
	WorkItemID      string `json:"work_item_id"`
	RouteSnapshotID string `json:"route_snapshot_id"`
}
type RegisteredTaskParameters struct {
	Repository string `json:"repository"`
	BaseBranch string `json:"baseBranch"`
	BranchRef  string `json:"branchRef"`
}
type RegisteredTask struct {
	TaskKind           string                   `json:"taskKind"`
	TaskVersion        string                   `json:"taskVersion"`
	CompletionContract string                   `json:"completionContract"`
	VerifierID         string                   `json:"verifierId"`
	ContractDigest     string                   `json:"contractDigest"`
	TaskEvidenceDigest string                   `json:"taskEvidenceDigest"`
	Parameters         RegisteredTaskParameters `json:"parameters"`
}
type RegisteredAdmissionRequest struct {
	Version             string               `json:"version"`
	Profile             string               `json:"profile"`
	IdempotencyKey      string               `json:"idempotency_key"`
	SessionBinding      string               `json:"session_binding"`
	Source              RegisteredTaskSource `json:"registered_task_source"`
	Task                RegisteredTask       `json:"registered_task"`
	AdmissionTaskDigest string               `json:"admission_task_digest"`
}

func (r *RegisteredAdmissionRequest) UnmarshalJSON(data []byte) error {
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	type request RegisteredAdmissionRequest
	var decoded request
	if err := decoder.Decode(&decoded); err != nil {
		return fmt.Errorf("invalid registered admission request: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("invalid registered admission request: trailing JSON value")
	}
	*r = RegisteredAdmissionRequest(decoded)
	return nil
}

type registeredAdmission struct {
	Source                RegisteredTaskSource
	Task                  RegisteredTask
	CanonicalJSON, Digest string
}

type registeredTurnState struct {
	IdempotencyDigest string
	SessionID         string
	TurnID            string
	ModelEffectID     string
	SubmitCursor      int64
	EventsAfter       int64
}

var (
	registeredOpaqueID  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	sha256Digest        = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	sha40               = regexp.MustCompile(`^[0-9a-f]{40}$`)
	githubGreenPRBranch = regexp.MustCompile(`^agent/fleiglabs-repo-agent/[a-z0-9][a-z0-9-]{0,62}$`)
)

func validateRegisteredAdmission(r RegisteredAdmissionRequest) (registeredAdmission, error) {
	if r.Version != coordinatorRegisteredProtocolVersion {
		return registeredAdmission{}, fmt.Errorf("registered admission version is invalid")
	}
	if err := validateAuthorityRequest(AuthorityWorkerRequest{Profile: r.Profile, IdempotencyKey: r.IdempotencyKey, SessionBinding: r.SessionBinding}); err != nil {
		return registeredAdmission{}, err
	}
	if !registeredOpaqueID.MatchString(r.Source.WorkItemID) || !registeredOpaqueID.MatchString(r.Source.RouteSnapshotID) || r.SessionBinding != "session:"+r.Source.WorkItemID {
		return registeredAdmission{}, fmt.Errorf("registered task source and session binding are invalid")
	}
	t := r.Task
	if t.TaskKind != "github_green_pr_v1" || t.TaskVersion != "1.0.0" || t.CompletionContract != "github_green_pr_v1" || t.VerifierID != "github_green_pr_v1" || t.ContractDigest != githubGreenPRContractDigest || !sha256Digest.MatchString(t.TaskEvidenceDigest) || t.Parameters.Repository != "grubbyhacker/repository-worker-lifecycle-test" || t.Parameters.BaseBranch != "main" || !githubGreenPRBranch.MatchString(t.Parameters.BranchRef) {
		return registeredAdmission{}, fmt.Errorf("registered task is invalid")
	}
	// All accepted strings are ASCII-safe identifiers, so this literal is also
	// RFC 8785/JCS canonical JSON (lexicographic keys, no insignificant space).
	c := `{"registered_task":{"completionContract":"` + t.CompletionContract + `","contractDigest":"` + t.ContractDigest + `","parameters":{"baseBranch":"` + t.Parameters.BaseBranch + `","branchRef":"` + t.Parameters.BranchRef + `","repository":"` + t.Parameters.Repository + `"},"taskEvidenceDigest":"` + t.TaskEvidenceDigest + `","taskKind":"` + t.TaskKind + `","taskVersion":"` + t.TaskVersion + `","verifierId":"` + t.VerifierID + `"},"registered_task_source":{"route_snapshot_id":"` + r.Source.RouteSnapshotID + `","work_item_id":"` + r.Source.WorkItemID + `"}}`
	s := sha256.Sum256([]byte(c))
	digest := "sha256:" + hex.EncodeToString(s[:])
	if r.AdmissionTaskDigest != digest {
		return registeredAdmission{}, fmt.Errorf("admission_task_digest mismatch")
	}
	return registeredAdmission{Source: r.Source, Task: t, CanonicalJSON: c, Digest: digest}, nil
}

func (s *AuthorityWorkerStore) RegisteredTurn(ctx context.Context, principal, binding string) (registeredTurnState, error) {
	state := registeredTurnState{}
	err := s.db.QueryRowContext(ctx, `SELECT idempotency_digest,session_id,turn_id,model_effect_id,submit_cursor,events_after
		FROM authority_registered_turns WHERE principal=? AND binding_digest=?`, principal, s.requestDigest(binding)).Scan(
		&state.IdempotencyDigest, &state.SessionID, &state.TurnID, &state.ModelEffectID, &state.SubmitCursor, &state.EventsAfter)
	return state, err
}

func (s *AuthorityWorkerStore) RecordRegisteredTurn(ctx context.Context, principal, binding, idempotencyKey string, state registeredTurnState) error {
	bindingDigest := s.requestDigest(binding)
	idempotencyDigest := s.requestDigest(idempotencyKey)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer rollbackAuthorityTx(tx)
	if _, err = tx.ExecContext(ctx, `INSERT INTO authority_registered_turns(principal,binding_digest,idempotency_digest,session_id,turn_id,model_effect_id,submit_cursor)
		VALUES(?,?,?,?,?,?,?)`, principal, bindingDigest, idempotencyDigest, state.SessionID, state.TurnID, state.ModelEffectID, state.SubmitCursor); err != nil {
		return fmt.Errorf("record registered turn: %w", err)
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO authority_effect_custody(principal,binding_digest,model_effect_id,session_id,worker_id,worker_storage_lineage_id,worker_fence_epoch,authority_profile,authority_profile_version,policy_digest,registered_task_digest)
		SELECT l.principal,l.binding_digest,?,rt.session_id,l.worker_id,w.worker_storage_lineage_id,w.worker_fence_epoch,l.profile,w.profile_version,w.policy_digest,a.admission_task_digest
		FROM authority_session_leases l
		JOIN authority_registered_turns rt ON rt.principal=l.principal AND rt.binding_digest=l.binding_digest
		JOIN authority_registered_admissions a ON a.principal=l.principal AND a.binding_digest=l.binding_digest
		JOIN authority_workers w ON w.worker_id=l.worker_id
		WHERE l.principal=? AND l.binding_digest=? AND l.released_at=''`, state.ModelEffectID, principal, bindingDigest); err != nil {
		return fmt.Errorf("record registered effect custody: %w", err)
	}
	return tx.Commit()
}

// RecordRegisteredEvents advances the source-closed event cursor and latches
// terminal effect events in one transaction. A distinct effect can enter the
// projection only through its own active, authorized event. Callers supply
// only an already-validated agentd projection, never a terminal state of their
// own.
func (s *AuthorityWorkerStore) RecordRegisteredEvents(ctx context.Context, principal, binding string, after, next int64, events []registeredEventProjection) error {
	bindingDigest := s.requestDigest(binding)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer rollbackAuthorityTx(tx)
	var sessionID, turnID, admissionDigest, canonical string
	if err = tx.QueryRowContext(ctx, `SELECT rt.session_id,rt.turn_id,a.admission_task_digest,a.canonical_task_json
		FROM authority_registered_turns rt JOIN authority_registered_admissions a ON a.principal=rt.principal AND a.binding_digest=rt.binding_digest
		WHERE rt.principal=? AND rt.binding_digest=?`, principal, bindingDigest).Scan(&sessionID, &turnID, &admissionDigest, &canonical); err != nil {
		return fmt.Errorf("registered event custody is missing: %w", err)
	}
	var admissionWire struct {
		Task RegisteredTask `json:"registered_task"`
	}
	if err = json.Unmarshal([]byte(canonical), &admissionWire); err != nil {
		return fmt.Errorf("registered event admission is corrupt: %w", err)
	}
	for _, event := range events {
		if event.SessionID != sessionID || event.TurnID != turnID || event.AdmissionTaskDigest != admissionDigest || event.TaskEvidenceDigest != admissionWire.Task.TaskEvidenceDigest {
			return fmt.Errorf("registered event admission mismatch")
		}
	}
	result, err := tx.ExecContext(ctx, `UPDATE authority_registered_turns SET events_after=?
		WHERE principal=? AND binding_digest=? AND events_after=?`, next, principal, s.requestDigest(binding), after)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		return fmt.Errorf("registered event cursor changed concurrently")
	}
	for _, event := range events {
		var known int
		var custodySession, custodyWorker, custodyStorage string
		var custodyFence int64
		err = tx.QueryRowContext(ctx, `SELECT 1,session_id,worker_id,worker_storage_lineage_id,worker_fence_epoch FROM authority_effect_custody WHERE principal=? AND binding_digest=? AND model_effect_id=?`, principal, bindingDigest, event.ModelEffectID).Scan(&known, &custodySession, &custodyWorker, &custodyStorage, &custodyFence)
		if errors.Is(err, sql.ErrNoRows) {
			// agentd creates continuations with a new model effect identity. Bind
			// that identity to the exact durable admission and active worker
			// custody before allowing any receipt for it to be minted.
			if event.Phase != "authorized" {
				return fmt.Errorf("registered continuation effect is not authorized")
			}
			result, insertErr := tx.ExecContext(ctx, `INSERT INTO authority_effect_custody(principal,binding_digest,model_effect_id,session_id,worker_id,worker_storage_lineage_id,worker_fence_epoch,authority_profile,authority_profile_version,policy_digest,registered_task_digest)
				SELECT l.principal,l.binding_digest,?,rt.session_id,l.worker_id,w.worker_storage_lineage_id,w.worker_fence_epoch,l.profile,w.profile_version,w.policy_digest,a.admission_task_digest
				FROM authority_session_leases l
				JOIN authority_registered_turns rt ON rt.principal=l.principal AND rt.binding_digest=l.binding_digest
				JOIN authority_registered_admissions a ON a.principal=l.principal AND a.binding_digest=l.binding_digest
				JOIN authority_workers w ON w.worker_id=l.worker_id
				WHERE l.principal=? AND l.binding_digest=? AND l.released_at='' AND rt.session_id=?
				AND l.worker_id=? AND w.worker_storage_lineage_id=? AND w.worker_fence_epoch=?`, event.ModelEffectID, principal, bindingDigest, event.SessionID, event.WorkerID, event.StorageLineageID, event.FenceEpoch)
			if insertErr != nil {
				return insertErr
			}
			rows, rowsErr := result.RowsAffected()
			if rowsErr != nil || rows != 1 {
				return fmt.Errorf("registered continuation effect custody mismatch")
			}
		} else if err != nil {
			return err
		} else if custodySession != event.SessionID || custodyWorker != event.WorkerID || custodyStorage != event.StorageLineageID || custodyFence != event.FenceEpoch {
			return fmt.Errorf("registered effect custody mismatch")
		}
		if registeredTerminalPhase(event.Phase) {
			result, updateErr := tx.ExecContext(ctx, `UPDATE authority_effect_custody SET terminal_phase=?,terminal_cursor=?
				WHERE principal=? AND binding_digest=? AND model_effect_id=? AND terminal_phase=''`, event.Phase, event.Cursor, principal, bindingDigest, event.ModelEffectID)
			if updateErr != nil {
				return updateErr
			}
			rows, rowsErr := result.RowsAffected()
			if rowsErr != nil || rows != 1 {
				return fmt.Errorf("registered effect is already terminal")
			}
		}
	}
	return tx.Commit()
}

func registeredTerminalPhase(phase string) bool {
	switch phase {
	case "completed", "failed", "green", "refused", "escalated":
		return true
	default:
		return false
	}
}

func (s *AuthorityWorkerStore) AcquireRegistered(ctx context.Context, principal string, r RegisteredAdmissionRequest, generation int64) (AuthorityLease, error) {
	a, err := validateRegisteredAdmission(r)
	if err != nil {
		return AuthorityLease{}, err
	}
	request := AuthorityWorkerRequest{Profile: r.Profile, IdempotencyKey: r.IdempotencyKey, SessionBinding: r.SessionBinding}
	idem, binding := s.requestDigest(request.IdempotencyKey), s.requestDigest(request.SessionBinding)
	fingerprint := s.requestDigest(strings.Join([]string{"registered", coordinatorRegisteredProtocolVersion, principal, request.Profile, request.SessionBinding, a.CanonicalJSON, a.Digest}, "\x00"))
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return AuthorityLease{}, err
	}
	defer closeAuthorityConn(conn)
	if _, err = conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return AuthorityLease{}, err
	}
	committed := false
	defer func() {
		if !committed {
			rollbackAuthorityConn(context.WithoutCancel(ctx), conn)
		}
	}()
	var lease AuthorityLease
	var stored, created, released string
	err = conn.QueryRowContext(ctx, `SELECT l.profile,l.worker_id,l.session_lineage_id,l.binding_digest,l.idempotency_digest,l.request_fingerprint,l.created_at,l.released_at,w.worker_storage_lineage_id,w.worker_fence_epoch,w.profile_version,w.policy_digest FROM authority_session_leases l JOIN authority_workers w ON w.worker_id=l.worker_id WHERE l.principal=? AND l.profile=? AND l.idempotency_digest=?`, principal, request.Profile, idem).Scan(&lease.Profile, &lease.WorkerID, &lease.SessionLineageID, &lease.BindingDigest, &lease.IdempotencyDigest, &stored, &created, &released, &lease.WorkerStorageLineageID, &lease.WorkerFenceEpoch, &lease.ProfileVersion, &lease.PolicyDigest)
	if err == nil {
		if stored != fingerprint {
			return AuthorityLease{}, fmt.Errorf("idempotency conflict")
		}
		var c, d string
		var work, route string
		if err = conn.QueryRowContext(ctx, `SELECT work_item_id,route_snapshot_id,canonical_task_json,admission_task_digest FROM authority_registered_admissions WHERE principal=? AND binding_digest=?`, principal, binding).Scan(&work, &route, &c, &d); err != nil || work != a.Source.WorkItemID || route != a.Source.RouteSnapshotID || c != a.CanonicalJSON || d != a.Digest {
			return AuthorityLease{}, fmt.Errorf("registered admission conflict")
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
		if _, err = conn.ExecContext(ctx, "COMMIT"); err != nil {
			return AuthorityLease{}, err
		}
		committed = true
		return lease, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return AuthorityLease{}, err
	}
	if err = s.checkIssuanceInTransaction(ctx, conn, request.Profile, generation); err != nil {
		return AuthorityLease{}, err
	}
	var worker string
	if err = conn.QueryRowContext(ctx, `SELECT worker_id FROM authority_workers WHERE profile=? AND state=? AND assigned_sessions<capacity ORDER BY generation,created_at,worker_id LIMIT 1`, request.Profile, AuthorityWorkerReady).Scan(&worker); err != nil {
		return AuthorityLease{}, fmt.Errorf("authority profile %q has no ready worker capacity", request.Profile)
	}
	if res, e := conn.ExecContext(ctx, `UPDATE authority_workers SET assigned_sessions=assigned_sessions+1,updated_at=? WHERE worker_id=? AND state=? AND assigned_sessions<capacity`, formatAuthorityTime(safeNow()), worker, AuthorityWorkerReady); e != nil {
		return AuthorityLease{}, e
	} else {
		n, rowsErr := res.RowsAffected()
		if rowsErr != nil {
			return AuthorityLease{}, rowsErr
		}
		if n != 1 {
			return AuthorityLease{}, fmt.Errorf("authority worker capacity changed")
		}
	}
	now := safeNow()
	lineage, e := newOpaqueLineageID("session")
	if e != nil {
		return AuthorityLease{}, e
	}
	if _, e = conn.ExecContext(ctx, `INSERT INTO authority_session_leases(principal,profile,idempotency_digest,request_fingerprint,binding_digest,worker_id,session_lineage_id,created_at) VALUES(?,?,?,?,?,?,?,?)`, principal, request.Profile, idem, fingerprint, binding, worker, lineage, formatAuthorityTime(now)); e != nil {
		return AuthorityLease{}, e
	}
	if _, e = conn.ExecContext(ctx, `INSERT INTO authority_registered_admissions(principal,binding_digest,protocol_version,work_item_id,route_snapshot_id,canonical_task_json,admission_task_digest) VALUES(?,?,?,?,?,?,?)`, principal, binding, coordinatorRegisteredProtocolVersion, a.Source.WorkItemID, a.Source.RouteSnapshotID, a.CanonicalJSON, a.Digest); e != nil {
		return AuthorityLease{}, e
	}
	if _, e = conn.ExecContext(ctx, "COMMIT"); e != nil {
		return AuthorityLease{}, e
	}
	committed = true
	if err = conn.QueryRowContext(ctx, `SELECT worker_storage_lineage_id,worker_fence_epoch,profile_version,policy_digest FROM authority_workers WHERE worker_id=?`, worker).Scan(&lease.WorkerStorageLineageID, &lease.WorkerFenceEpoch, &lease.ProfileVersion, &lease.PolicyDigest); err != nil {
		return AuthorityLease{}, err
	}
	lease.Principal, lease.Profile, lease.WorkerID, lease.SessionLineageID, lease.BindingDigest, lease.IdempotencyDigest, lease.CreatedAt = principal, request.Profile, worker, lineage, binding, idem, now
	return lease, nil
}

func (s *AuthorityWorkerStore) RegisteredAdmission(ctx context.Context, principal, binding string) (registeredAdmission, error) {
	var protocol, profile, workItemID, routeSnapshotID, canonical, digest string
	err := s.db.QueryRowContext(ctx, `SELECT a.protocol_version,l.profile,a.work_item_id,a.route_snapshot_id,a.canonical_task_json,a.admission_task_digest FROM authority_registered_admissions a JOIN authority_session_leases l ON l.principal=a.principal AND l.binding_digest=a.binding_digest WHERE a.principal=? AND a.binding_digest=?`, principal, s.requestDigest(binding)).Scan(&protocol, &profile, &workItemID, &routeSnapshotID, &canonical, &digest)
	if err != nil {
		return registeredAdmission{}, err
	}
	return validateDurableRegisteredAdmission(protocol, profile, workItemID, routeSnapshotID, canonical, digest)
}

func validateDurableRegisteredAdmission(protocol, profile, workItemID, routeSnapshotID, canonical, digest string) (registeredAdmission, error) {
	a := registeredAdmission{Source: RegisteredTaskSource{WorkItemID: workItemID, RouteSnapshotID: routeSnapshotID}, CanonicalJSON: canonical, Digest: digest}
	if protocol != coordinatorRegisteredProtocolVersion {
		return registeredAdmission{}, fmt.Errorf("registered admission state is corrupt: protocol version")
	}
	// Re-validate the durable canonical JSON by decoding it through the same
	// strict request validator; this makes corrupt or partial state fail closed.
	var wire struct {
		Source RegisteredTaskSource `json:"registered_task_source"`
		Task   RegisteredTask       `json:"registered_task"`
	}
	decoder := json.NewDecoder(strings.NewReader(a.CanonicalJSON))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		return registeredAdmission{}, fmt.Errorf("registered admission state is corrupt: JSON: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return registeredAdmission{}, fmt.Errorf("registered admission state is corrupt: trailing JSON")
	}
	validated, err := validateRegisteredAdmission(RegisteredAdmissionRequest{
		Version: coordinatorRegisteredProtocolVersion, Profile: profile, IdempotencyKey: "registered-read",
		SessionBinding: "session:" + wire.Source.WorkItemID, Source: wire.Source, Task: wire.Task,
		AdmissionTaskDigest: a.Digest,
	})
	if err != nil || validated.CanonicalJSON != a.CanonicalJSON || validated.Digest != a.Digest || validated.Source != a.Source {
		return registeredAdmission{}, fmt.Errorf("registered admission state is corrupt: canonical task")
	}
	sum := sha256.Sum256([]byte(a.CanonicalJSON))
	if "sha256:"+hex.EncodeToString(sum[:]) != a.Digest {
		return registeredAdmission{}, fmt.Errorf("registered admission state is corrupt: digest")
	}
	a.Task = validated.Task
	return a, nil
}

func safeNow() time.Time { return time.Now().UTC() }
