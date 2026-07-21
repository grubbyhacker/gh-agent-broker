package sandbox

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"testing"
)

func TestEffectTokenFingerprintIsDomainSeparatedHMAC(t *testing.T) {
	store, err := OpenAuthorityWorkerStore(context.Background(), filepath.Join(t.TempDir(), "authority.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if closeErr := store.Close(); closeErr != nil {
			t.Errorf("close store: %v", closeErr)
		}
	})
	secret := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	fingerprint := store.effectTokenFingerprint(secret)
	plain := sha256.Sum256([]byte(secret))
	if fingerprint == hex.EncodeToString(plain[:]) {
		t.Fatal("effect token fingerprint used unkeyed SHA-256")
	}
	if fingerprint != store.effectTokenFingerprint(secret) || fingerprint == store.effectTokenFingerprint(secret+"x") {
		t.Fatal("effect token fingerprint is not a stable keyed verifier")
	}
}
