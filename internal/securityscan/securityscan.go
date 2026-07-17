// Package securityscan detects credential-shaped material at broker-controlled
// egress boundaries without loading or comparing real secret values.
package securityscan

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

const (
	MaxFieldBytes      = 1 << 20
	MaxStreamBytes     = 16 << 20
	maxCanonicalBytes  = 64 << 20
	maxCanonicalValues = 256
	maxCanonicalDepth  = 2
)

type Finding struct {
	Code  string
	Field string
}

type DetectionError struct {
	Finding Finding
}

type Segment struct {
	Name  string
	Value string
}

func (e *DetectionError) Error() string {
	return fmt.Sprintf("security egress blocked: %s in %s", e.Finding.Code, e.Finding.Field)
}

type detector struct {
	code    string
	pattern *regexp.Regexp
}

var detectors = []detector{
	{code: "credential_canary", pattern: regexp.MustCompile(`(?i)PR10[_-]CREDENTIAL[_-]CANARY(?::|=|[_-])[A-Za-z0-9._~+/-]{6,}`)},
	{code: "github_token", pattern: regexp.MustCompile(`(?:github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9]{20,})`)},
	{code: "openai_api_key", pattern: regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{20,}\b`)},
	{code: "jwt", pattern: regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`)},
	{code: "private_key", pattern: regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----`)},
}

var (
	base64Run = regexp.MustCompile(`[A-Za-z0-9+/_-]{16,}={0,2}`)
	hexRun    = regexp.MustCompile(`(?i)(?:[0-9a-f]{2}){12,}`)
)

// Fields scans deterministic named text fields. It returns only a reason code
// and field name; matched credential-shaped material is never returned.
func Fields(fields map[string]string) *Finding {
	names := make([]string, 0, len(fields))
	for name := range fields {
		names = append(names, name)
	}
	sort.Strings(names)
	segments := make([]Segment, 0, len(names))
	for _, name := range names {
		segments = append(segments, Segment{Name: name, Value: fields[name]})
	}
	return Sequence(segments)
}

// Sequence scans each field and then the exact broker-controlled sequence with
// no separator. The combined pass catches credential material split across
// adjacent chunks or rendered fields.
func Sequence(segments []Segment) *Finding {
	var combined strings.Builder
	for _, segment := range segments {
		if finding := scanValue(segment.Name, segment.Value, MaxFieldBytes); finding != nil {
			return finding
		}
		if combined.Len() > MaxFieldBytes-len(segment.Value) {
			return &Finding{Code: "scan_limit_exceeded", Field: "field_sequence"}
		}
		combined.WriteString(segment.Value)
	}
	if len(segments) > 1 {
		return scanValue("field_sequence", combined.String(), MaxFieldBytes)
	}
	return nil
}

// Reader scans a bounded stream as one sequence. Reading the complete bounded
// value makes matches spanning input read chunks visible to the detector.
func Reader(field string, reader io.Reader, maxBytes int64) *Finding {
	if maxBytes <= 0 || maxBytes > MaxStreamBytes {
		maxBytes = MaxStreamBytes
	}
	value, err := io.ReadAll(io.LimitReader(reader, maxBytes+1))
	if err != nil || int64(len(value)) > maxBytes {
		return &Finding{Code: "scan_limit_exceeded", Field: field}
	}
	return scanValue(field, string(value), int(maxBytes))
}

type canonicalValue struct {
	value string
	depth int
}

func scanValue(field, value string, rawLimit int) *Finding {
	if len(value) > rawLimit {
		return &Finding{Code: "scan_limit_exceeded", Field: field}
	}
	queue := []canonicalValue{{value: value}}
	seen := map[string]struct{}{value: {}}
	totalBytes := len(value)
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		for _, candidate := range detectors {
			if candidate.pattern.MatchString(current.value) {
				return &Finding{Code: candidate.code, Field: field}
			}
		}
		if current.depth >= maxCanonicalDepth {
			continue
		}
		decoded, limited := canonicalDecodings(current.value)
		if limited {
			return &Finding{Code: "canonical_scan_limit_exceeded", Field: field}
		}
		for _, next := range decoded {
			if next == "" || next == current.value {
				continue
			}
			if _, ok := seen[next]; ok {
				continue
			}
			if len(seen) >= maxCanonicalValues || totalBytes > maxCanonicalBytes-len(next) {
				return &Finding{Code: "canonical_scan_limit_exceeded", Field: field}
			}
			seen[next] = struct{}{}
			totalBytes += len(next)
			queue = append(queue, canonicalValue{value: next, depth: current.depth + 1})
		}
	}
	return nil
}

func canonicalDecodings(value string) ([]string, bool) {
	values := make([]string, 0, 16)
	if len(value) > maxCanonicalBytes {
		return nil, true
	}
	if decoded, err := url.PathUnescape(value); err == nil && decoded != value {
		values = append(values, decoded)
	}
	hexMatches := hexRun.FindAllString(value, maxCanonicalValues+1)
	if len(hexMatches) > maxCanonicalValues {
		return nil, true
	}
	for _, match := range hexMatches {
		if len(match) > maxCanonicalBytes {
			return nil, true
		}
		for offset := 0; offset < 2 && len(match)-offset >= 24; offset++ {
			candidate := match[offset:]
			if len(candidate)%2 != 0 {
				candidate = candidate[:len(candidate)-1]
			}
			if decoded, err := hex.DecodeString(candidate); err == nil {
				values = append(values, string(decoded))
			}
		}
	}
	base64Matches := base64Run.FindAllString(value, maxCanonicalValues+1)
	if len(base64Matches) > maxCanonicalValues {
		return nil, true
	}
	for _, match := range base64Matches {
		if len(match) > maxCanonicalBytes {
			return nil, true
		}
		// A credential encoding can be embedded in a larger base64-alphabet run.
		// Trying every alignment trim on both ends makes that bounded subrun
		// visible without admitting attacker-selected quadratic expansion.
		for startTrim := 0; startTrim < 4; startTrim++ {
			for endTrim := 0; endTrim < 4; endTrim++ {
				if len(match)-startTrim-endTrim < 16 {
					continue
				}
				candidate := match[startTrim : len(match)-endTrim]
				for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
					if decoded, err := encoding.DecodeString(candidate); err == nil {
						values = append(values, string(decoded))
					}
				}
			}
		}
	}
	return values, false
}

func Strings(prefix string, values []string) *Finding {
	fields := make(map[string]string, len(values))
	for i, value := range values {
		fields[fmt.Sprintf("%s[%d]", strings.TrimSpace(prefix), i)] = value
	}
	return Fields(fields)
}
