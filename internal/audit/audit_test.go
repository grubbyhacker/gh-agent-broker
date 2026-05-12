package audit

import "testing"

func TestRedact(t *testing.T) {
	got := Redact("Authorization: Bearer abc123")
	if got == "Authorization: Bearer abc123" {
		t.Fatalf("expected redaction, got %q", got)
	}
}
