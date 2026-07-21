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
	githubGreenPRContractDigest          = "sha256:df72462d2bde6674349b2265d8768c6bba0b3368114cd015195ce66a697fc102"
)

type RegisteredTaskSource struct {
	WorkItemID      string `json:"work_item_id"`
	RouteSnapshotID string `json:"route_snapshot_id"`
}
type RegisteredTaskParameters struct {
	RepositoryID        string `json:"repositoryId"`
	BaseRevision        string `json:"baseRevision"`
	BranchRef           string `json:"branchRef"`
	ValidationSelection string `json:"validationSelection"`
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
	if t.TaskKind != "repository_change_v1" || t.TaskVersion != "1.0.0" || t.CompletionContract != "github_green_pr_v1" || t.VerifierID != "github_green_pr_v1" || t.ContractDigest != githubGreenPRContractDigest || !sha256Digest.MatchString(t.TaskEvidenceDigest) || t.Parameters.RepositoryID != "grubbyhacker/repository-worker-lifecycle-test" || !sha40.MatchString(t.Parameters.BaseRevision) || !githubGreenPRBranch.MatchString(t.Parameters.BranchRef) || t.Parameters.ValidationSelection != "required" {
		return registeredAdmission{}, fmt.Errorf("registered task is invalid")
	}
	// All accepted strings are ASCII-safe identifiers, so this literal is also
	// RFC 8785/JCS canonical JSON (lexicographic keys, no insignificant space).
	c := `{"registered_task":{"completionContract":"` + t.CompletionContract + `","contractDigest":"` + t.ContractDigest + `","parameters":{"baseRevision":"` + t.Parameters.BaseRevision + `","branchRef":"` + t.Parameters.BranchRef + `","repositoryId":"` + t.Parameters.RepositoryID + `","validationSelection":"required"},"taskEvidenceDigest":"` + t.TaskEvidenceDigest + `","taskKind":"` + t.TaskKind + `","taskVersion":"` + t.TaskVersion + `","verifierId":"` + t.VerifierID + `"},"registered_task_source":{"route_snapshot_id":"` + r.Source.RouteSnapshotID + `","work_item_id":"` + r.Source.WorkItemID + `"}}`
	s := sha256.Sum256([]byte(c))
	digest := "sha256:" + hex.EncodeToString(s[:])
	if r.AdmissionTaskDigest != digest {
		return registeredAdmission{}, fmt.Errorf("admission_task_digest mismatch")
	}
	return registeredAdmission{Source: r.Source, Task: t, CanonicalJSON: c, Digest: digest}, nil
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
	var a registeredAdmission
	var protocol, profile string
	err := s.db.QueryRowContext(ctx, `SELECT a.protocol_version,l.profile,a.work_item_id,a.route_snapshot_id,a.canonical_task_json,a.admission_task_digest FROM authority_registered_admissions a JOIN authority_session_leases l ON l.principal=a.principal AND l.binding_digest=a.binding_digest WHERE a.principal=? AND a.binding_digest=?`, principal, s.requestDigest(binding)).Scan(&protocol, &profile, &a.Source.WorkItemID, &a.Source.RouteSnapshotID, &a.CanonicalJSON, &a.Digest)
	if err != nil {
		return registeredAdmission{}, err
	}
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
