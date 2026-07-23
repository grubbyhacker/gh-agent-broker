package sandbox

import (
	"path/filepath"
	"testing"
)

func TestC4BilateralRuntimeFixtureRetainsFixedSessionOwnershipAndMode(t *testing.T) {
	root := t.TempDir()
	cfg := c4BilateralBootstrapConfig(root, filepath.Join(root, "authority-workers.sqlite"), c4BilateralRuntimeSessionUID, c4BilateralRuntimeSessionGID)
	profile := cfg.AuthorityProfiles[c4BilateralBootstrapProfile]

	if profile.SessionIsolation.Primitive != "uid_gid_0700" {
		t.Fatalf("C4 runtime isolation primitive = %q, want uid_gid_0700", profile.SessionIsolation.Primitive)
	}
	if profile.SessionIsolation.UIDStart != c4BilateralRuntimeSessionUID || profile.SessionIsolation.GIDStart != c4BilateralRuntimeSessionGID {
		t.Fatalf("C4 runtime session identity = %d:%d, want %d:%d", profile.SessionIsolation.UIDStart, profile.SessionIsolation.GIDStart, c4BilateralRuntimeSessionUID, c4BilateralRuntimeSessionGID)
	}
}
