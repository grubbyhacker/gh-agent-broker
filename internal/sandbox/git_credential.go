package sandbox

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"
)

const (
	gitCredentialReceiptVersion = "agentd-broker-git-credential-receipt/v1"
	gitCredentialVersion        = "agentd-broker-git-credential/v1"
)

type GitCredentialReceipt struct {
	Version                 string `json:"version"`
	SessionID               string `json:"session_id"`
	EffectID                string `json:"effect_id"`
	ModelEffectID           string `json:"model_effect_id"`
	RegisteredTaskDigest    string `json:"registered_task_digest"`
	AuthorityProfile        string `json:"authority_profile"`
	AuthorityProfileVersion string `json:"authority_profile_version"`
	WorkerID                string `json:"worker_id"`
	WorkerStorageLineageID  string `json:"worker_storage_lineage_id"`
	FenceEpoch              int64  `json:"fence_epoch"`
	JournalCursor           int64  `json:"journal_cursor"`
	JournalRecordDigest     string `json:"journal_record_digest"`
	AuthorizedAt            int64  `json:"authorized_at"`
	DeadlineAt              int64  `json:"deadline_at"`
}
type GitCredential struct {
	Version       string `json:"version"`
	ReceiptDigest string `json:"receipt_digest"`
	AgentID       string `json:"agent_id"`
	AgentSecret   string `json:"agent_secret"`
	ExpiresAt     int64  `json:"expires_at"`
}
type GitCredentialAuthority struct {
	AgentID, Repository, Principal string
	ExpiresAt                      int64
}

var credentialDigest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func (r GitCredentialReceipt) validate() error {
	if r.Version != gitCredentialReceiptVersion || r.EffectID != r.ModelEffectID || !credentialDigest.MatchString(r.RegisteredTaskDigest) || !credentialDigest.MatchString(r.JournalRecordDigest) || r.FenceEpoch < 1 || r.JournalCursor < 1 || r.AuthorizedAt < 0 || r.DeadlineAt <= 0 {
		return fmt.Errorf("invalid credential receipt")
	}
	for _, v := range []string{r.SessionID, r.EffectID, r.ModelEffectID, r.AuthorityProfile, r.AuthorityProfileVersion, r.WorkerID, r.WorkerStorageLineageID} {
		if len(v) == 0 || len(v) > 512 {
			return fmt.Errorf("invalid credential receipt")
		}
	}
	return nil
}

func receiptBytes(r GitCredentialReceipt) ([]byte, string, error) {
	b, e := json.Marshal(r)
	if e != nil {
		return nil, "", e
	}
	h := sha256.Sum256(b)
	return b, "sha256:" + hex.EncodeToString(h[:]), nil
}

func credentialControlToken(secret, worker, storage string, fence int64) string {
	return deriveAgentdValidationToken(secret, worker, storage, fence)
}

func (s *AuthorityWorkerService) MintGitCredential(ctx context.Context, control string, r GitCredentialReceipt) (GitCredential, error) {
	if err := r.validate(); err != nil {
		return GitCredential{}, err
	}
	raw, digest, err := receiptBytes(r)
	if err != nil {
		return GitCredential{}, err
	}
	conn, err := s.store.db.Conn(ctx)
	if err != nil {
		return GitCredential{}, err
	}
	defer closeAuthorityConn(conn)
	if _, err = conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return GitCredential{}, err
	}
	committed := false
	defer func() {
		if !committed {
			rollbackAuthorityConn(context.WithoutCancel(ctx), conn)
		}
	}()
	var principal, binding, canonical, taskDigest, profileVersion, workerStorage string
	var fence int64
	var released, agentdID string
	err = conn.QueryRowContext(ctx, `SELECT l.principal,l.binding_digest,a.canonical_task_json,a.admission_task_digest,w.profile_version,w.worker_storage_lineage_id,w.worker_fence_epoch,l.released_at,ws.agentd_session_id FROM authority_session_leases l JOIN authority_registered_admissions a ON a.principal=l.principal AND a.binding_digest=l.binding_digest JOIN authority_workers w ON w.worker_id=l.worker_id JOIN authority_session_workspaces ws ON ws.binding_digest=l.binding_digest WHERE l.worker_id=? AND ws.agentd_session_id=?`, r.WorkerID, r.SessionID).Scan(&principal, &binding, &canonical, &taskDigest, &profileVersion, &workerStorage, &fence, &released, &agentdID)
	if err != nil || released != "" || agentdID != r.SessionID || taskDigest != r.RegisteredTaskDigest || profileVersion != r.AuthorityProfileVersion || workerStorage != r.WorkerStorageLineageID || fence != r.FenceEpoch {
		return GitCredential{}, fmt.Errorf("credential receipt context denied")
	}
	worker, err := s.store.GetWorker(ctx, r.WorkerID)
	if err != nil {
		return GitCredential{}, err
	}
	profile, ok := s.cfg.AuthorityProfiles[r.AuthorityProfile]
	if !ok || worker.Profile != r.AuthorityProfile {
		return GitCredential{}, fmt.Errorf("credential receipt profile denied")
	}
	secret := profile.BrokerSecretEnv
	key := credentialControlToken(strings.TrimSpace(os.Getenv(secret)), r.WorkerID, r.WorkerStorageLineageID, r.FenceEpoch)
	if !secureTokenEqual(control, key) {
		return GitCredential{}, fmt.Errorf("credential control denied")
	}
	var wire struct {
		Task RegisteredTask `json:"registered_task"`
	}
	if json.Unmarshal([]byte(canonical), &wire) != nil || wire.Task.Parameters.Repository == "" {
		return GitCredential{}, fmt.Errorf("credential admission corrupt")
	}
	var existingRaw, agentID, fp string
	var expiry int64
	err = conn.QueryRowContext(ctx, `SELECT receipt_json,agent_id,secret_fingerprint,expires_at_ms FROM authority_git_credentials WHERE principal=? AND binding_digest=? AND model_effect_id=?`, principal, binding, r.ModelEffectID).Scan(&existingRaw, &agentID, &fp, &expiry)
	if err == nil {
		if existingRaw != string(raw) {
			return GitCredential{}, fmt.Errorf("credential receipt replay conflict")
		}
		return GitCredential{gitCredentialVersion, digest, agentID, s.credentialSecret(digest), expiry}, nil
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return GitCredential{}, err
	}
	expires := minCredentialExpiry(r.AuthorizedAt, r.DeadlineAt)
	if expires <= time.Now().UnixMilli() {
		return GitCredential{}, fmt.Errorf("credential receipt expired")
	}
	agentID = "effect-" + digest[7:31]
	agentSecret := s.credentialSecret(digest)
	sum := sha256.Sum256([]byte(agentSecret))
	fp = hex.EncodeToString(sum[:])
	_, err = conn.ExecContext(ctx, `INSERT INTO authority_git_credentials(receipt_digest,receipt_json,principal,binding_digest,session_id,effect_id,model_effect_id,repository,worker_id,worker_storage_lineage_id,worker_fence_epoch,agent_id,secret_fingerprint,expires_at_ms) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, digest, string(raw), principal, binding, r.SessionID, r.EffectID, r.ModelEffectID, wire.Task.Parameters.Repository, r.WorkerID, r.WorkerStorageLineageID, r.FenceEpoch, agentID, fp, expires)
	if err != nil {
		return GitCredential{}, err
	}
	if _, err = conn.ExecContext(ctx, "COMMIT"); err != nil {
		return GitCredential{}, err
	}
	committed = true
	return GitCredential{gitCredentialVersion, digest, agentID, agentSecret, expires}, nil
}

func minCredentialExpiry(authorized, deadline int64) int64 {
	m := authorized + 30*60*1000
	if deadline < m {
		return deadline
	}
	return m
}

func (s *AuthorityWorkerService) credentialSecret(digest string) string {
	h := hmac.New(sha256.New, s.store.salt)
	_, _ = h.Write([]byte("gh-agent-broker/effect-git-secret/v1\x00" + digest))
	return hex.EncodeToString(h.Sum(nil))
}

// AuthenticateGitCredential verifies only a fingerprint and expiry; the
// credential text is never retained in SQLite or returned by this reader.
func (s *AuthorityWorkerStore) AuthenticateGitCredential(ctx context.Context, agentID, secret, repository string) (GitCredentialAuthority, bool, error) {
	if agentID == "" || secret == "" {
		return GitCredentialAuthority{}, false, nil
	}
	h := sha256.Sum256([]byte(secret))
	var out GitCredentialAuthority
	var fp, revoked string
	err := s.db.QueryRowContext(ctx, `SELECT agent_id,repository,principal,expires_at_ms,secret_fingerprint,revoked_at FROM authority_git_credentials WHERE agent_id=?`, agentID).Scan(&out.AgentID, &out.Repository, &out.Principal, &out.ExpiresAt, &fp, &revoked)
	if err == sql.ErrNoRows {
		return GitCredentialAuthority{}, false, nil
	}
	if err != nil {
		return GitCredentialAuthority{}, false, err
	}
	if revoked != "" || out.ExpiresAt <= time.Now().UnixMilli() || out.Repository != repository || !secureTokenEqual(fp, hex.EncodeToString(h[:])) {
		return GitCredentialAuthority{}, false, nil
	}
	return out, true, nil
}
