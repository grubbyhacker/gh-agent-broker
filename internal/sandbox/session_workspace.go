package sandbox

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type SessionWorkspace struct {
	UID              int    `json:"uid"`
	GID              int    `json:"gid"`
	Path             string `json:"workspace_path"`
	SessionLineageID string `json:"session_lineage_id"`
}

func (s *AuthorityWorkerStore) AllocateSessionWorkspace(ctx context.Context, lease AuthorityLease, policy SessionIsolation) (SessionWorkspace, error) {
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()
	if lease.BindingDigest == "" || lease.WorkerID == "" {
		return SessionWorkspace{}, fmt.Errorf("active authority lease is required")
	}
	var existing SessionWorkspace
	err := s.db.QueryRowContext(ctx, `SELECT uid,gid,workspace_path,session_lineage_id FROM authority_session_workspaces WHERE session_lineage_id=?`, lease.SessionLineageID).Scan(&existing.UID, &existing.GID, &existing.Path, &existing.SessionLineageID)
	if err == nil {
		return existing, nil
	}
	if policy.Primitive != "uid_gid_0700" {
		return SessionWorkspace{}, fmt.Errorf("unsupported session isolation primitive")
	}
	if !validOpaqueLineageID(lease.SessionLineageID) || !validOpaqueLineageID(lease.WorkerStorageLineageID) {
		return SessionWorkspace{}, fmt.Errorf("authority lease lineage is malformed")
	}
	var used int
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM authority_session_workspaces WHERE worker_id=?`, lease.WorkerID).Scan(&used); err != nil {
		return SessionWorkspace{}, err
	}
	workspace := SessionWorkspace{UID: policy.UIDStart + used, GID: policy.GIDStart + used, Path: filepath.Join(policy.WorkspaceRoot, lease.SessionLineageID), SessionLineageID: lease.SessionLineageID}
	hostPath := filepath.Join(policy.WorkspaceRoot, lease.WorkerStorageLineageID, lease.SessionLineageID)
	if err := os.MkdirAll(hostPath, 0o700); err != nil {
		return SessionWorkspace{}, err
	}
	//nolint:gosec // A 0700 directory is the reviewed per-session isolation boundary, not a secret file.
	if err := os.Chmod(hostPath, 0o700); err != nil {
		return SessionWorkspace{}, err
	}
	if err := os.Chown(hostPath, workspace.UID, workspace.GID); err != nil {
		return SessionWorkspace{}, err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO authority_session_workspaces(binding_digest,worker_id,uid,gid,workspace_path,created_at,session_lineage_id) VALUES(?,?,?,?,?,?,?)`, lease.BindingDigest, lease.WorkerID, workspace.UID, workspace.GID, workspace.Path, formatAuthorityTime(time.Now().UTC()), workspace.SessionLineageID)
	if err != nil {
		return SessionWorkspace{}, err
	}
	return workspace, nil
}

func (s *AuthorityWorkerStore) SessionWorkspace(ctx context.Context, binding string) (SessionWorkspace, error) {
	var workspace SessionWorkspace
	err := s.db.QueryRowContext(ctx, `SELECT uid,gid,workspace_path,session_lineage_id FROM authority_session_workspaces WHERE binding_digest=?`, s.requestDigest(binding)).Scan(&workspace.UID, &workspace.GID, &workspace.Path, &workspace.SessionLineageID)
	return workspace, err
}
