package sandbox

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type Redactor struct {
	known []string
}

func NewRedactor(values []string) Redactor {
	var known []string
	for _, value := range values {
		value = strings.TrimSpace(value)
		if len(value) >= 6 {
			known = append(known, value)
		}
	}
	return Redactor{known: known}
}

func RedactorForBundle(bundle CredentialBundle) Redactor {
	var values []string
	paths := append([]string{}, bundle.SecretFiles...)
	paths = append(paths, bundle.RedactFiles...)
	for _, rel := range paths {
		if !safeRelativePath(rel) {
			continue
		}
		path := filepath.Join(bundle.SourcePath, rel)
		if escapesBase(bundle.SourcePath, path) {
			continue
		}
		info, err := os.Lstat(path)
		if err != nil || info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Size() > 1<<20 {
			continue
		}
		// #nosec G304 -- files are constrained to operator-configured credential bundle paths.
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		values = append(values, strings.Fields(string(b))...)
		values = append(values, strings.TrimSpace(string(b)))
		values = append(values, jsonStringValues(b)...)
	}
	return NewRedactor(values)
}

func jsonStringValues(b []byte) []string {
	var decoded interface{}
	if err := json.Unmarshal(b, &decoded); err != nil {
		return nil
	}
	var values []string
	var walk func(interface{})
	walk = func(v interface{}) {
		switch x := v.(type) {
		case string:
			values = append(values, x)
		case []interface{}:
			for _, item := range x {
				walk(item)
			}
		case map[string]interface{}:
			for _, item := range x {
				walk(item)
			}
		}
	}
	walk(decoded)
	return values
}

func (r Redactor) Redact(s string) string {
	if s == "" {
		return s
	}
	out := s
	for _, re := range redactionPatterns {
		out = re.ReplaceAllString(out, "${1}[REDACTED]")
	}
	for _, value := range r.known {
		out = strings.ReplaceAll(out, value, "[REDACTED]")
	}
	return out
}

var redactionPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(authorization:\s*(?:bearer|token)?\s+)[^\s]+`),
	regexp.MustCompile(`(?i)((?:bearer|token)\s+)[A-Za-z0-9._~+/=-]+`),
	regexp.MustCompile(`(?i)((?:api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|password)\s*[:=]\s*)[^\s]+`),
}
