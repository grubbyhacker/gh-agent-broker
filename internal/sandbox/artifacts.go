package sandbox

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gh-agent-broker/internal/securityscan"
)

const defaultInlineLimit = 8 * 1024

type FileManifest struct {
	Path      string `json:"path"`
	Size      int64  `json:"size"`
	SHA256    string `json:"sha256"`
	Inline    string `json:"inline,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
}

type CollectionOutput struct {
	RunID string         `json:"run_id"`
	Files []FileManifest `json:"files"`
}

func collectFiles(base, runID string, redactor Redactor, inlineLimit int64) (CollectionOutput, error) {
	if inlineLimit <= 0 {
		inlineLimit = defaultInlineLimit
	}
	base = filepath.Clean(base)
	root, err := os.OpenRoot(base)
	if err != nil {
		return CollectionOutput{}, err
	}
	defer closeBody(root)
	var files []FileManifest
	err = filepath.WalkDir(base, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == base {
			return nil
		}
		if escapesBase(base, path) {
			return fmt.Errorf("path %q escapes collection root", path)
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if info.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(base, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if finding := securityscan.Fields(map[string]string{"artifact_path": rel}); finding != nil {
			return &securityscan.DetectionError{Finding: *finding}
		}
		// Read once so the scan, hash, and optional inline response describe the
		// same bytes even if the worker is still writing its output directory.
		// Files beyond the bounded scanner capacity fail closed.
		file, err := root.Open(filepath.FromSlash(rel))
		if err != nil {
			return err
		}
		content, readErr := io.ReadAll(io.LimitReader(file, securityscan.MaxStreamBytes+1))
		closeErr := file.Close()
		if readErr != nil {
			return readErr
		}
		if closeErr != nil {
			return closeErr
		}
		if len(content) > securityscan.MaxStreamBytes {
			return &securityscan.DetectionError{Finding: securityscan.Finding{Code: "scan_limit_exceeded", Field: "artifact_content"}}
		}
		finding := securityscan.Reader("artifact_content", bytes.NewReader(content), securityscan.MaxStreamBytes)
		if finding != nil {
			return &securityscan.DetectionError{Finding: *finding}
		}
		hash := sha256.Sum256(content)
		item := FileManifest{Path: rel, Size: int64(len(content)), SHA256: hex.EncodeToString(hash[:])}
		if int64(len(content)) <= inlineLimit && looksText(path) {
			item.Inline = redactor.Redact(string(content))
		} else if int64(len(content)) > inlineLimit {
			item.Truncated = true
		}
		files = append(files, item)
		return nil
	})
	if err != nil {
		return CollectionOutput{}, err
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return CollectionOutput{RunID: runID, Files: files}, nil
}

func looksText(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".md", ".txt", ".json", ".yaml", ".yml", ".log", ".diff", ".patch":
		return true
	default:
		return false
	}
}

func escapesBase(base, path string) bool {
	base = filepath.Clean(base)
	path = filepath.Clean(path)
	rel, err := filepath.Rel(base, path)
	if err != nil {
		return true
	}
	return rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
