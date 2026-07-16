package sandbox

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type SessionWorkspace struct {
	UID, GID  int
	Path      string
	LineageID string `json:"lineage_id"`
}

func (s *AuthorityWorkerStore) AllocateSessionWorkspace(ctx context.Context, lease AuthorityLease, policy SessionIsolation) (SessionWorkspace, error) {
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()
	if lease.BindingDigest == "" || lease.WorkerID == "" {
		return SessionWorkspace{}, fmt.Errorf("active authority lease is required")
	}
	var existing SessionWorkspace
	err := s.db.QueryRowContext(ctx, `SELECT uid,gid,workspace_path,lineage_id FROM authority_session_workspaces WHERE lineage_id=?`, lease.LineageID).Scan(&existing.UID, &existing.GID, &existing.Path, &existing.LineageID)
	if err == nil {
		return existing, nil
	}
	if policy.Primitive != "uid_gid_0700" {
		return SessionWorkspace{}, fmt.Errorf("unsupported session isolation primitive")
	}
	var used int
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM authority_session_workspaces WHERE worker_id=?`, lease.WorkerID).Scan(&used); err != nil {
		return SessionWorkspace{}, err
	}
	workspace := SessionWorkspace{UID: policy.UIDStart + used, GID: policy.GIDStart + used, Path: filepath.Join(policy.WorkspaceRoot, lease.LineageID), LineageID: lease.LineageID}
	if err := os.MkdirAll(workspace.Path, 0o700); err != nil {
		return SessionWorkspace{}, err
	}
	//nolint:gosec // A 0700 directory is the reviewed per-session isolation boundary, not a secret file.
	if err := os.Chmod(workspace.Path, 0o700); err != nil {
		return SessionWorkspace{}, err
	}
	if err := os.Chown(workspace.Path, workspace.UID, workspace.GID); err != nil {
		return SessionWorkspace{}, err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO authority_session_workspaces(binding_digest,worker_id,uid,gid,workspace_path,created_at,lineage_id) VALUES(?,?,?,?,?,?,?)`, lease.BindingDigest, lease.WorkerID, workspace.UID, workspace.GID, workspace.Path, formatAuthorityTime(time.Now().UTC()), workspace.LineageID)
	if err != nil {
		return SessionWorkspace{}, err
	}
	return workspace, nil
}

func (s *AuthorityWorkerStore) SessionWorkspace(ctx context.Context, binding string) (SessionWorkspace, error) {
	var workspace SessionWorkspace
	err := s.db.QueryRowContext(ctx, `SELECT uid,gid,workspace_path,lineage_id FROM authority_session_workspaces WHERE binding_digest=?`, s.requestDigest(binding)).Scan(&workspace.UID, &workspace.GID, &workspace.Path, &workspace.LineageID)
	return workspace, err
}
