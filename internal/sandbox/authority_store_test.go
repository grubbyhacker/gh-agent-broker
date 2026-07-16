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
	if _, err := store.db.ExecContext(ctx, `PRAGMA user_version=4`); err != nil {
		if closeErr := store.Close(); closeErr != nil {
			t.Fatalf("close store after setup failure: %v", closeErr)
		}
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
	var version, table, reassignmentTable int
	if err := migrated.db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if err := migrated.db.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE type='table' AND name='authority_session_workspaces'`).Scan(&table); err != nil {
		t.Fatal(err)
	}
	if err := migrated.db.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE type='table' AND name='authority_session_reassignments'`).Scan(&reassignmentTable); err != nil {
		t.Fatal(err)
	}
	if version != authorityStoreSchemaVersion || table != 1 || reassignmentTable != 1 {
		t.Fatalf("migration version=%d workspace_table=%d reassignment_table=%d", version, table, reassignmentTable)
	}
}
