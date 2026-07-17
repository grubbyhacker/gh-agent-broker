package securityscan

import "testing"

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
