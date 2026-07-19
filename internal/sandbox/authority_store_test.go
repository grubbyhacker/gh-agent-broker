package sandbox

import (
	"context"
	"path/filepath"
	"testing"
)

func TestAuthorityWorkerStoreMigratesV1WorkspaceSchema(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "authority-workers.sqlite")
	store, err := OpenAuthorityWorkerStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	migrated, err := OpenAuthorityWorkerStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if closeErr := migrated.Close(); closeErr != nil {
			t.Errorf("close migrated store: %v", closeErr)
		}
	})
	var version, table, reassignmentTable, admissionTable, adoptionColumns, foreignKeyErrors int
	if err := migrated.db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if err := migrated.db.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE type='table' AND name='authority_session_workspaces'`).Scan(&table); err != nil {
		t.Fatal(err)
	}
	if err := migrated.db.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE type='table' AND name='authority_session_reassignments'`).Scan(&reassignmentTable); err != nil {
		t.Fatal(err)
	}
	if err := migrated.db.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE type='table' AND name='authority_registered_admissions'`).Scan(&admissionTable); err != nil {
		t.Fatal(err)
	}
	if err := migrated.db.QueryRowContext(ctx, `SELECT count(*) FROM pragma_foreign_key_check`).Scan(&foreignKeyErrors); err != nil {
		t.Fatal(err)
	}
	if err := migrated.db.QueryRowContext(ctx, `SELECT count(*) FROM pragma_table_info('authority_session_reassignments') WHERE name IN (
		'coordinator_binding','authority_binding','profile_version','policy_digest','session_lineage_id','agentd_session_id',
		'predecessor_storage_lineage_id','predecessor_fence_epoch','replacement_storage_lineage_id','replacement_fence_epoch',
		'rebind_idempotency_key','workspace_ref','workspace_uid','workspace_gid','adoption_state','adoption_error_code','adoption_confirmed_at')`).Scan(&adoptionColumns); err != nil {
		t.Fatal(err)
	}
	if version != authorityStoreSchemaVersion || table != 1 || reassignmentTable != 1 || admissionTable != 1 || adoptionColumns != 17 || foreignKeyErrors != 0 {
		t.Fatalf("migration version=%d workspace_table=%d reassignment_table=%d admission_table=%d adoption_columns=%d foreign_key_errors=%d", version, table, reassignmentTable, admissionTable, adoptionColumns, foreignKeyErrors)
	}
}
