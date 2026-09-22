package sandbox

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"strings"

	"gh-agent-broker/internal/release"
)

const releasePublishProtocol = "docker-archive/v1"

var dockerConfigPath = regexp.MustCompile(`^(?:[0-9a-f]{64}\.json|blobs/sha256/[0-9a-f]{64})$`)

type releaseArtifactImporter interface {
	LoadImage(context.Context, io.Reader) error
	ImageIdentity(context.Context, string) (string, string, error)
}

type dockerArchiveManifest struct {
	Config   string   `json:"Config"`
	RepoTags []string `json:"RepoTags"`
	Layers   []string `json:"Layers"`
}

type dockerImageConfig struct {
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
}

// validateDockerArtifact derives the immutable local image ID from a trusted
// publisher's single-image Docker archive. It checks the parts that determine
// release identity and eligibility; Docker remains the archive parser.
func validateDockerArtifact(data []byte, expectedPlatform string) (string, error) {
	manifestBytes, found, err := readDockerArchiveEntry(data, "manifest.json")
	if err != nil {
		return "", err
	}
	var manifests []dockerArchiveManifest
	if !found || json.Unmarshal(manifestBytes, &manifests) != nil || len(manifests) != 1 {
		return "", fmt.Errorf("docker archive must contain exactly one image manifest")
	}
	manifest := manifests[0]
	if !dockerConfigPath.MatchString(manifest.Config) {
		return "", fmt.Errorf("docker archive manifest has invalid config identity")
	}
	configBytes, found, err := readDockerArchiveEntry(data, manifest.Config)
	if err != nil {
		return "", err
	}
	if !found {
		return "", fmt.Errorf("docker archive config is missing")
	}
	configDigest := strings.TrimPrefix(manifest.Config, "blobs/sha256/")
	configDigest = strings.TrimSuffix(configDigest, ".json")
	sum := sha256.Sum256(configBytes)
	if hex.EncodeToString(sum[:]) != configDigest {
		return "", fmt.Errorf("docker archive config digest does not match its filename")
	}
	var config dockerImageConfig
	if err := json.Unmarshal(configBytes, &config); err != nil {
		return "", fmt.Errorf("docker archive config is invalid")
	}
	platform := strings.Trim(config.OS+"/"+config.Architecture, "/")
	if platform != expectedPlatform {
		return "", fmt.Errorf("docker image platform %q does not match %q", platform, expectedPlatform)
	}
	return "sha256:" + configDigest, nil
}

func readDockerArchiveEntry(data []byte, target string) ([]byte, bool, error) {
	tr := tar.NewReader(bytes.NewReader(data))
	var contents []byte
	found := false
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, false, fmt.Errorf("read Docker archive: %w", err)
		}
		name := strings.TrimSuffix(header.Name, "/")
		if name == "" || path.IsAbs(header.Name) || path.Clean(name) != name || strings.HasPrefix(name, "../") {
			return nil, false, fmt.Errorf("docker archive contains invalid path %q", header.Name)
		}
		if header.Typeflag == tar.TypeDir {
			continue
		}
		if header.Typeflag != tar.TypeReg {
			return nil, false, fmt.Errorf("docker archive entry %q must be a regular file", header.Name)
		}
		if name != target {
			continue
		}
		if found {
			return nil, false, fmt.Errorf("docker archive contains duplicate %q", name)
		}
		contents, err = io.ReadAll(io.LimitReader(tr, 1024*1024+1))
		if err != nil || len(contents) > 1024*1024 {
			return nil, false, fmt.Errorf("docker archive metadata %q is invalid", name)
		}
		found = true
	}
	return contents, found, nil
}

func acquireDockerArtifact(
	ctx context.Context,
	importer releaseArtifactImporter,
	artifact []byte,
	item release.Release,
	expectedImageID string,
) error {
	if err := importer.LoadImage(ctx, bytes.NewReader(artifact)); err != nil {
		return fmt.Errorf("load Docker image: %w", err)
	}
	observedImageID, observedPlatform, err := importer.ImageIdentity(ctx, expectedImageID)
	if err != nil {
		return fmt.Errorf("inspect loaded Docker image: %w", err)
	}
	if observedImageID != expectedImageID {
		return fmt.Errorf("loaded Docker image ID %q does not match %q", observedImageID, expectedImageID)
	}
	if observedPlatform != item.Provenance.Platform {
		return fmt.Errorf("loaded Docker image platform %q does not match %q", observedPlatform, item.Provenance.Platform)
	}
	return nil
}
