package sandbox

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
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
	var files []FileManifest
	err := filepath.WalkDir(base, func(path string, entry os.DirEntry, err error) error {
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
		hash, err := fileSHA256(path)
		if err != nil {
			return err
		}
		item := FileManifest{Path: rel, Size: info.Size(), SHA256: hash}
		if info.Size() <= inlineLimit && looksText(path) {
			// #nosec G304 -- path comes from walking a sandbox run output directory.
			//nolint:gosec // G122: path is rejected if it is a symlink before this read and collection only returns a manifest/snippet.
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			item.Inline = redactor.Redact(string(b))
		} else if info.Size() > inlineLimit {
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

func fileSHA256(path string) (string, error) {
	// #nosec G304 -- path comes from walking a sandbox run output directory.
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer closeBody(f)
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
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
