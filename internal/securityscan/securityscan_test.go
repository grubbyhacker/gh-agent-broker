package securityscan

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net/url"
	"strings"
	"testing"
)

func TestEffectTokenFingerprintDetectsOnlyRegisteredExactToken(t *testing.T) {
	key := []byte("scanner-test-key")
	token := strings.Repeat("a", 64)
	h := hmac.New(sha256.New, key)
	_, _ = h.Write([]byte(token))
	fingerprint := hex.EncodeToString(h.Sum(nil))
	RegisterEffectTokenFingerprint(fingerprint, key)
	finding := Fields(map[string]string{"output": "prefix " + token + " suffix"})
	if finding == nil || finding.Code != "effect_token_fingerprint" || finding.Fingerprint != fingerprint {
		t.Fatalf("effect token finding = %+v", finding)
	}
	if finding := Fields(map[string]string{"output": strings.Repeat("b", 64)}); finding != nil {
		t.Fatalf("unregistered token finding = %+v", finding)
	}
}

func TestFieldsDetectsCredentialShapesWithoutReturningMaterial(t *testing.T) {
	//nolint:gosec // G101: intentionally synthetic credential shapes exercise the detector.
	tests := map[string]string{
		"credential_canary": "PR10-CREDENTIAL-CANARY:synthetic-only-value",
		"github_token":      "github_pat_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"openai_api_key":    "sk-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"jwt":               "eyJAAAAAAAAAA.BBBBBBBBBB.CCCCCCCCCC",
		"private_key":       "-----BEGIN PRIVATE KEY-----",
	}
	for want, value := range tests {
		finding := Fields(map[string]string{"body": value})
		if finding == nil || finding.Code != want || finding.Field != "body" {
			t.Fatalf("Fields(%q) = %+v, want %s/body", want, finding, want)
		}
		if (&DetectionError{Finding: *finding}).Error() == value {
			t.Fatal("detection error returned matched material")
		}
	}
}

func TestCanonicalEncodingsAndSequencesAreDetected(t *testing.T) {
	canary := "PR10-CREDENTIAL-CANARY:encoded-test-value"
	tests := map[string]string{
		"base64":           base64.StdEncoding.EncodeToString([]byte(canary)),
		"base64url":        base64.RawURLEncoding.EncodeToString([]byte(canary)),
		"base64url-prefix": "AA" + base64.RawURLEncoding.EncodeToString([]byte(canary)),
		"base64url-suffix": base64.RawURLEncoding.EncodeToString([]byte(canary)) + "AA",
		"base64url-subrun": "AA" + base64.RawURLEncoding.EncodeToString([]byte(canary)) + "AA",
		"hex":              hex.EncodeToString([]byte(canary)),
		"url":              url.PathEscape(canary),
		"nested":           base64.RawURLEncoding.EncodeToString([]byte(hex.EncodeToString([]byte(canary)))),
	}
	for name, value := range tests {
		t.Run(name, func(t *testing.T) {
			finding := Fields(map[string]string{"body": "prefix " + value + " suffix"})
			if finding == nil || finding.Code != "credential_canary" {
				t.Fatalf("encoded finding = %+v", finding)
			}
		})
	}
	finding := Sequence([]Segment{{Name: "chunk[0]", Value: "PR10-CREDENTIAL-"}, {Name: "chunk[1]", Value: "CANARY:split-value"}})
	if finding == nil || finding.Code != "credential_canary" || finding.Field != "field_sequence" {
		t.Fatalf("split finding = %+v", finding)
	}
	encoded := "AA" + base64.RawURLEncoding.EncodeToString([]byte(canary)) + "AA"
	finding = Sequence([]Segment{{Name: "chunk[0]", Value: encoded[:len(encoded)/2]}, {Name: "chunk[1]", Value: encoded[len(encoded)/2:]}})
	if finding == nil || finding.Code != "credential_canary" || finding.Field != "field_sequence" {
		t.Fatalf("encoded split finding = %+v", finding)
	}
}

func TestReaderDetectsAcrossChunksAndFailsClosedAtLimit(t *testing.T) {
	reader := &chunkReader{chunks: []string{"prefix PR10-CREDENTIAL-", "CANARY:chunked-value suffix"}}
	if finding := Reader("artifact", reader, 1024); finding == nil || finding.Code != "credential_canary" {
		t.Fatalf("chunked finding = %+v", finding)
	}
	if finding := Reader("artifact", strings.NewReader(strings.Repeat("a", 33)), 32); finding == nil || finding.Code != "scan_limit_exceeded" {
		t.Fatalf("bounded finding = %+v", finding)
	}
}

func TestCanonicalCandidateLimitFailsClosed(t *testing.T) {
	value := strings.Repeat("QUFBQUFBQUFBQUFB ", maxCanonicalValues+1)
	if finding := Fields(map[string]string{"body": value}); finding == nil || finding.Code != "canonical_scan_limit_exceeded" {
		t.Fatalf("canonical limit finding = %+v", finding)
	}
}

type chunkReader struct{ chunks []string }

func (reader *chunkReader) Read(value []byte) (int, error) {
	if len(reader.chunks) == 0 {
		return 0, io.EOF
	}
	chunk := reader.chunks[0]
	reader.chunks = reader.chunks[1:]
	return copy(value, chunk), nil
}

func TestFieldsIsDeterministicAndAllowsOrdinaryText(t *testing.T) {
	if finding := Fields(map[string]string{"summary": "ordinary repository output"}); finding != nil {
		t.Fatalf("ordinary output blocked: %+v", finding)
	}
	finding := Fields(map[string]string{
		"z": "github_pat_ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ",
		"a": "sk-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	})
	if finding == nil || finding.Field != "a" {
		t.Fatalf("field ordering is not deterministic: %+v", finding)
	}
}
