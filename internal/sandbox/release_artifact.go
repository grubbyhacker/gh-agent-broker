package sandbox

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"path"
	"regexp"
	"strings"

	"gh-agent-broker/internal/release"
)

const releasePublishProtocol = "oci-layout-tar/v1"

var ociBlobPath = regexp.MustCompile(`^blobs/sha256/[0-9a-f]{64}$`)

type releaseArtifactImporter interface {
	LoadImage(context.Context, io.Reader) error
	ImageAvailable(context.Context, string, string) (bool, error)
	ImageIdentity(context.Context, string) (string, string, error)
}

type ociIndex struct {
	Manifests []struct {
		Digest   string `json:"digest"`
		Size     int64  `json:"size"`
		Platform struct {
			OS           string `json:"os"`
			Architecture string `json:"architecture"`
		} `json:"platform"`
	} `json:"manifests"`
}

func validateOCIArtifact(data []byte, digest, expectedPlatform string) error {
	tr := tar.NewReader(bytes.NewReader(data))
	seen := map[string]bool{}
	files := map[string][]byte{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read OCI tar: %w", err)
		}
		name := strings.TrimSuffix(h.Name, "/")
		if name == "" || path.IsAbs(h.Name) || path.Clean(name) != name || strings.HasPrefix(name, "../") || seen[name] {
			return fmt.Errorf("OCI tar contains unsafe or duplicate path %q", h.Name)
		}
		seen[name] = true
		if h.Typeflag == tar.TypeDir {
			continue
		}
		if h.Typeflag != tar.TypeReg || h.Linkname != "" {
			return fmt.Errorf("OCI tar entry %q must be a regular file or directory", h.Name)
		}
		if name != "oci-layout" && name != "index.json" && !ociBlobPath.MatchString(name) {
			return fmt.Errorf("OCI tar contains unsupported path %q", h.Name)
		}
		b, readErr := io.ReadAll(tr)
		if readErr != nil {
			return fmt.Errorf("read OCI tar entry %q: %w", h.Name, readErr)
		}
		files[name] = b
	}
	if len(files["oci-layout"]) == 0 || len(files["index.json"]) == 0 {
		return fmt.Errorf("OCI tar must contain oci-layout and index.json")
	}
	var index ociIndex
	if err := json.Unmarshal(files["index.json"], &index); err != nil || len(index.Manifests) != 1 {
		return fmt.Errorf("OCI tar must contain exactly one valid index manifest")
	}
	descriptor := index.Manifests[0]
	if descriptor.Digest != digest || descriptor.Size < 1 || descriptor.Platform.OS == "" || descriptor.Platform.Architecture == "" {
		return fmt.Errorf("OCI index descriptor does not match the requested digest and platform")
	}
	platform := descriptor.Platform.OS + "/" + descriptor.Platform.Architecture
	if platform != expectedPlatform {
		return fmt.Errorf("OCI image platform %q does not match declared platform %q", platform, expectedPlatform)
	}
	manifest, ok := files["blobs/sha256/"+strings.TrimPrefix(digest, "sha256:")]
	if !ok || int64(len(manifest)) != descriptor.Size {
		return fmt.Errorf("OCI manifest blob is missing or has the wrong size")
	}
	sum := sha256.Sum256(manifest)
	if "sha256:"+hex.EncodeToString(sum[:]) != digest {
		return fmt.Errorf("OCI manifest blob does not match its digest")
	}
	return nil
}

func acquireOCIArtifact(ctx context.Context, importer releaseArtifactImporter, artifact []byte, item release.Release) error {
	if err := importer.LoadImage(ctx, bytes.NewReader(artifact)); err != nil {
		return fmt.Errorf("load OCI image through Docker: %w", err)
	}
	available, err := importer.ImageAvailable(ctx, item.ImageReference, item.ImageDigest)
	if err != nil {
		return fmt.Errorf("inspect loaded OCI image availability: %w", err)
	}
	if !available {
		return fmt.Errorf("loaded OCI image is absent at requested digest")
	}
	observedDigest, observedPlatform, err := importer.ImageIdentity(ctx, item.ImageReference)
	if err != nil {
		return fmt.Errorf("inspect loaded OCI image identity: %w", err)
	}
	if observedDigest != item.ImageDigest && !strings.HasSuffix(observedDigest, "@"+item.ImageDigest) {
		return fmt.Errorf("loaded OCI image digest %q does not match %q", observedDigest, item.ImageDigest)
	}
	if observedPlatform != item.Provenance.Platform {
		return fmt.Errorf("loaded OCI image platform %q does not match %q", observedPlatform, item.Provenance.Platform)
	}
	return nil
}
