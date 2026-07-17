// Package securityscan detects credential-shaped material at broker-controlled
// egress boundaries without loading or comparing real secret values.
package securityscan

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

const MaxFieldBytes = 1 << 20

type Finding struct {
	Code  string
	Field string
}

type DetectionError struct {
	Finding Finding
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

// Fields scans deterministic named text fields. It returns only a reason code
// and field name; matched credential-shaped material is never returned.
func Fields(fields map[string]string) *Finding {
	names := make([]string, 0, len(fields))
	for name := range fields {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		value := fields[name]
		if len(value) > MaxFieldBytes {
			return &Finding{Code: "scan_limit_exceeded", Field: name}
		}
		for _, candidate := range detectors {
			if candidate.pattern.MatchString(value) {
				return &Finding{Code: candidate.code, Field: name}
			}
		}
	}
	return nil
}

func Strings(prefix string, values []string) *Finding {
	fields := make(map[string]string, len(values))
	for i, value := range values {
		fields[fmt.Sprintf("%s[%d]", strings.TrimSpace(prefix), i)] = value
	}
	return Fields(fields)
}
