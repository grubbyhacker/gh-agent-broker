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
			artifact, expectedImageID := dockerArchiveForTest(t, configName, config)
			imageID, err := validateDockerArtifact(artifact, "linux/amd64")
			if err != nil {
				t.Fatalf("validateDockerArtifact: %v", err)
			}
			if imageID != expectedImageID {
				t.Fatalf("image ID = %q, want %q", imageID, expectedImageID)
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
			artifact, _ := dockerArchiveForTest(t, configName, config)
			_, err := validateDockerArtifact(artifact, "linux/amd64")
			if err == nil || !strings.Contains(err.Error(), "invalid config identity") {
				t.Fatalf("error = %v, want invalid config identity", err)
			}
		})
	}
}

func TestValidateDockerArtifactRejectsBuildxConfigDigestMismatch(t *testing.T) {
	config := []byte(`{"os":"linux","architecture":"amd64"}`)
	configName := "blobs/sha256/" + strings.Repeat("0", 64)
	artifact, _ := dockerArchiveForTest(t, configName, config)
	_, err := validateDockerArtifact(artifact, "linux/amd64")
	if err == nil || !strings.Contains(err.Error(), "digest does not match") {
		t.Fatalf("error = %v, want config digest mismatch", err)
	}
}

func dockerArchiveForTest(t *testing.T, configName string, config []byte) ([]byte, string) {
	t.Helper()
	layer := bytes.Repeat([]byte("x"), 1024*1024+1)
	layerSum := sha256.Sum256(layer)
	layerName := "blobs/sha256/" + hex.EncodeToString(layerSum[:])
	dockerManifest, err := json.Marshal([]dockerArchiveManifest{{
		Config: configName, RepoTags: []string{"youknowme-curator:test"}, Layers: []string{layerName},
	}})
	if err != nil {
		t.Fatal(err)
	}
	entries := []struct {
		name string
		body []byte
	}{{layerName, layer}, {"manifest.json", dockerManifest}, {configName, config}}
	expectedImageID := "sha256:" + strings.TrimSuffix(configName, ".json")
	if strings.HasPrefix(configName, "blobs/sha256/") && dockerConfigPath.MatchString(configName) {
		configID := "sha256:" + strings.TrimPrefix(configName, "blobs/sha256/")
		imageManifest, marshalErr := json.Marshal(ociImageManifest{
			SchemaVersion: 2,
			MediaType:     ociManifestMediaType,
			Config: ociDescriptor{
				MediaType: "application/vnd.oci.image.config.v1+json",
				Digest:    configID,
				Size:      int64(len(config)),
			},
		})
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		expectedImageID = digestBytes(imageManifest)
		manifestName := "blobs/sha256/" + strings.TrimPrefix(expectedImageID, "sha256:")
		index, marshalErr := json.Marshal(dockerArchiveIndex{
			SchemaVersion: 2,
			MediaType:     ociIndexMediaType,
			Manifests: []ociDescriptor{{
				MediaType: ociManifestMediaType,
				Digest:    expectedImageID,
				Size:      int64(len(imageManifest)),
				Platform:  ociPlatform{OS: "linux", Architecture: "amd64"},
			}},
		})
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		entries = append(entries, struct {
			name string
			body []byte
		}{manifestName, imageManifest}, struct {
			name string
			body []byte
		}{"index.json", index})
	}

	var artifact bytes.Buffer
	tw := tar.NewWriter(&artifact)
	for _, entry := range entries {
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
	return artifact.Bytes(), expectedImageID
}
