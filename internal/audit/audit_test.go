package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRedact(t *testing.T) {
	got := Redact("Authorization: Bearer abc123")
	if got == "Authorization: Bearer abc123" {
		t.Fatalf("expected redaction, got %q", got)
	}
}

func TestLogSuppressesCredentialShapes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	logger, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := logger.Close(); err != nil {
			t.Fatal(err)
		}
	}()
	canary := "PR10-CREDENTIAL-CANARY:audit-only-test"
	logger.Log(Event{OperationID: "op-1", Operation: "pull.create", Decision: "allow", Result: canary})
	b, err := os.ReadFile(path) //nolint:gosec // G304: path is a test-owned temporary audit file.
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	if strings.Contains(got, canary) || !strings.Contains(got, `"operation":"security.egress_blocked"`) || !strings.Contains(got, `"result":"credential_canary"`) {
		t.Fatalf("unsafe audit event = %s", got)
	}
}
