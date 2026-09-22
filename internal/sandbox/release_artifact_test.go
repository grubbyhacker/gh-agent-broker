package sandbox

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func TestValidateDockerArtifactAcceptsCanonicalConfigLayouts(t *testing.T) {
	config := []byte(`{"os":"linux","architecture":"amd64","rootfs":{"type":"layers","diff_ids":[]}}`)
	sum := sha256.Sum256(config)
	digest := hex.EncodeToString(sum[:])

	for _, configName := range []string{
		digest + ".json",
		"blobs/sha256/" + digest,
	} {
		t.Run(configName, func(t *testing.T) {
			artifact := dockerArchiveForTest(t, configName, config)
			imageID, err := validateDockerArtifact(artifact, "linux/amd64")
			if err != nil {
				t.Fatalf("validateDockerArtifact: %v", err)
			}
			if imageID != "sha256:"+digest {
				t.Fatalf("image ID = %q, want sha256:%s", imageID, digest)
			}
		})
	}
}

func TestValidateDockerArtifactRejectsInvalidBuildxConfigIdentity(t *testing.T) {
	config := []byte(`{"os":"linux","architecture":"amd64"}`)
	for _, configName := range []string{
		"blobs/sha512/" + strings.Repeat("a", 64),
		"blobs/sha256/" + strings.Repeat("a", 64) + ".json",
		"blobs/sha256/not-a-digest",
	} {
		t.Run(configName, func(t *testing.T) {
			_, err := validateDockerArtifact(dockerArchiveForTest(t, configName, config), "linux/amd64")
			if err == nil || !strings.Contains(err.Error(), "invalid config identity") {
				t.Fatalf("error = %v, want invalid config identity", err)
			}
		})
	}
}

func TestValidateDockerArtifactRejectsBuildxConfigDigestMismatch(t *testing.T) {
	config := []byte(`{"os":"linux","architecture":"amd64"}`)
	configName := "blobs/sha256/" + strings.Repeat("0", 64)
	_, err := validateDockerArtifact(dockerArchiveForTest(t, configName, config), "linux/amd64")
	if err == nil || !strings.Contains(err.Error(), "digest does not match") {
		t.Fatalf("error = %v, want config digest mismatch", err)
	}
}

func dockerArchiveForTest(t *testing.T, configName string, config []byte) []byte {
	t.Helper()
	manifest, err := json.Marshal([]dockerArchiveManifest{{
		Config: configName, RepoTags: []string{"youknowme-curator:test"}, Layers: []string{},
	}})
	if err != nil {
		t.Fatal(err)
	}
	var artifact bytes.Buffer
	tw := tar.NewWriter(&artifact)
	for _, entry := range []struct {
		name string
		body []byte
	}{{"manifest.json", manifest}, {configName, config}} {
		if err := tw.WriteHeader(&tar.Header{Name: entry.name, Mode: 0o600, Size: int64(len(entry.body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(entry.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return artifact.Bytes()
}
