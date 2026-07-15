package sandbox

// Broker-owned checkpoint evidence is deliberately small in PR 8. It records
// that a lease was durably fenced before a worker drain/replacement; agentd's
// session journal and resume protocol remain PR 9 work.

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const checkpointSchemaVersion = 1

type checkpointEnvelope struct {
	SchemaVersion  int    `json:"schema_version"`
	KeyFingerprint string `json:"key_fingerprint"`
	Nonce          string `json:"nonce"`
	Ciphertext     string `json:"ciphertext"`
}

type checkpointPayload struct {
	SchemaVersion  string `json:"schema_version"`
	WorkerID       string `json:"worker_id"`
	Profile        string `json:"profile"`
	ProfileVersion string `json:"profile_version"`
	PolicyDigest   string `json:"policy_digest"`
	LeaseBinding   string `json:"lease_binding_digest"`
	CreatedAt      string `json:"created_at"`
}

type CheckpointStore struct {
	cfg    Config
	leases *AuthorityWorkerStore
}

func NewCheckpointStore(cfg Config, leases *AuthorityWorkerStore) *CheckpointStore {
	return &CheckpointStore{cfg: cfg, leases: leases}
}

func (s *CheckpointStore) CheckpointWorker(ctx context.Context, worker AuthorityWorker) error {
	leases, err := s.leases.ListActiveLeases(ctx, worker.WorkerID)
	if err != nil {
		return err
	}
	profile, ok := s.cfg.AuthorityProfiles[worker.Profile]
	if !ok {
		return fmt.Errorf("checkpoint unknown authority profile %q", worker.Profile)
	}
	key, fingerprint, err := checkpointKey(profile.Checkpoint.KeyEnv)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(profile.Checkpoint.Directory, 0o700); err != nil {
		return err
	}
	for _, lease := range leases {
		payload := checkpointPayload{SchemaVersion: "authority-checkpoint/v1", WorkerID: worker.WorkerID, Profile: worker.Profile, ProfileVersion: worker.ProfileVersion, PolicyDigest: worker.PolicyDigest, LeaseBinding: lease.BindingDigest, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano)}
		b, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		sealed, err := sealCheckpoint(key, fingerprint, b)
		if err != nil {
			return err
		}
		name := worker.WorkerID + "-" + lease.BindingDigest + ".checkpoint"
		if err := writeCheckpoint(filepath.Join(profile.Checkpoint.Directory, name), sealed); err != nil {
			return err
		}
	}
	return nil
}

func checkpointKey(env string) ([]byte, string, error) {
	raw := strings.TrimSpace(os.Getenv(env))
	key, err := base64.StdEncoding.DecodeString(raw)
	if err != nil || len(key) != 32 {
		return nil, "", fmt.Errorf("checkpoint key %q must be base64-encoded 32 bytes", env)
	}
	sum := sha256.Sum256(key)
	return key, hex.EncodeToString(sum[:]), nil
}

func sealCheckpoint(key []byte, fingerprint string, plaintext []byte) (checkpointEnvelope, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return checkpointEnvelope{}, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return checkpointEnvelope{}, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return checkpointEnvelope{}, err
	}
	return checkpointEnvelope{SchemaVersion: checkpointSchemaVersion, KeyFingerprint: fingerprint, Nonce: base64.StdEncoding.EncodeToString(nonce), Ciphertext: base64.StdEncoding.EncodeToString(gcm.Seal(nil, nonce, plaintext, []byte("authority-checkpoint/v1")))}, nil
}

func writeCheckpoint(path string, envelope checkpointEnvelope) error {
	b, err := json.Marshal(envelope)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func VerifyCheckpoint(path string, profile AuthorityProfile, worker AuthorityWorker) error {
	//nolint:gosec // G304: caller supplies an operator-owned evidence path after exact profile binding.
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var envelope checkpointEnvelope
	if err := json.Unmarshal(b, &envelope); err != nil || envelope.SchemaVersion != checkpointSchemaVersion {
		return fmt.Errorf("checkpoint schema is unsupported")
	}
	key, fingerprint, err := checkpointKey(profile.Checkpoint.KeyEnv)
	if err != nil {
		return err
	}
	if envelope.KeyFingerprint != fingerprint {
		return fmt.Errorf("checkpoint cryptographic material does not match")
	}
	nonce, err := base64.StdEncoding.DecodeString(envelope.Nonce)
	if err != nil {
		return fmt.Errorf("checkpoint nonce is malformed")
	}
	ciphertext, err := base64.StdEncoding.DecodeString(envelope.Ciphertext)
	if err != nil {
		return fmt.Errorf("checkpoint ciphertext is malformed")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	plain, err := gcm.Open(nil, nonce, ciphertext, []byte("authority-checkpoint/v1"))
	if err != nil {
		return fmt.Errorf("checkpoint authentication failed")
	}
	var payload checkpointPayload
	if err := json.Unmarshal(plain, &payload); err != nil || payload.SchemaVersion != "authority-checkpoint/v1" {
		return fmt.Errorf("checkpoint payload schema is unsupported")
	}
	if payload.WorkerID != worker.WorkerID || payload.Profile != worker.Profile || payload.ProfileVersion != worker.ProfileVersion || payload.PolicyDigest != worker.PolicyDigest {
		return fmt.Errorf("checkpoint authority binding does not match")
	}
	return nil
}
