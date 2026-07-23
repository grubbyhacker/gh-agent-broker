package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestEnsureBareRepositorySeedsExactMain(t *testing.T) {
	repository := filepath.Join(t.TempDir(), "repos", "fixture.git")
	if err := ensureBareRepository(repository); err != nil {
		t.Fatalf("seed fixture repository: %v", err)
	}
	if err := verifyFixtureMain(repository); err != nil {
		t.Fatalf("verify seeded fixture repository: %v", err)
	}

	paths := gitOutput(t, "--git-dir="+repository, "ls-tree", "-r", "--name-only", "main")
	if got, want := string(paths), fixtureTaskPath+"\n"; got != want {
		t.Fatalf("seeded main paths = %q, want %q", got, want)
	}
	body := gitOutput(t, "--git-dir="+repository, "show", "main:"+fixtureTaskPath)
	if got, want := string(body), fixtureTaskBody; got != want {
		t.Fatalf("seeded task body = %q, want %q", got, want)
	}
}

func TestFixtureTaskBodyMatchesNativeChildContract(t *testing.T) {
	if got, want := fixtureTaskBody, "status: pending\n"; got != want {
		t.Fatalf("fixture task body = %q, want %q", got, want)
	}
}

func TestFixtureAcceptsRealGitProtocolV2(t *testing.T) {
	for _, test := range []struct {
		name string
		in   []string
		want string
		ok   bool
	}{
		{"no header", nil, "", true},
		{"v1", []string{"version=1"}, "version=1", true},
		{"v2", []string{"version=2"}, "version=2", true},
		{"invalid", []string{"version=3"}, "", false},
		{"multiple", []string{"version=2", "version=1"}, "", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, ok := acceptedFixtureGitProtocol(test.in)
			if got != test.want || ok != test.ok {
				t.Fatalf("acceptedFixtureGitProtocol(%q) = %q, %t; want %q, %t", test.in, got, ok, test.want, test.ok)
			}
		})
	}
}

func TestBoundedBackendStderrIsSanitized(t *testing.T) {
	input := []byte("fatal: " + fixtureToken + "\x00\n")
	got := boundedBackendStderr(input)
	if got.text != "fatal: [redacted]?\n" || got.truncated {
		t.Fatalf("boundedBackendStderr() = %#v", got)
	}
	tooLong := boundedBackendStderr([]byte(strings.Repeat("x", backendStderrLimit+1)))
	if len(tooLong.text) != backendStderrLimit || !tooLong.truncated {
		t.Fatalf("long boundedBackendStderr() = %#v", tooLong)
	}
}

func TestEnsureBareRepositoryRejectsMainThatIsNotExactSeed(t *testing.T) {
	repository := filepath.Join(t.TempDir(), "fixture.git")
	if err := ensureBareRepository(repository); err != nil {
		t.Fatalf("seed fixture repository: %v", err)
	}

	taskBlob := strings.TrimSpace(string(fixtureGit(t, strings.NewReader(fixtureTaskBody), "--git-dir="+repository, "hash-object", "-w", "--stdin")))
	extraBlob := strings.TrimSpace(string(fixtureGit(t, strings.NewReader("unexpected fixture state\n"), "--git-dir="+repository, "hash-object", "-w", "--stdin")))
	treeInput := "100644 blob " + taskBlob + "\t" + fixtureTaskPath + "\n" +
		"100644 blob " + extraBlob + "\textra.md\n"
	tree := strings.TrimSpace(string(fixtureGit(t, strings.NewReader(treeInput), "--git-dir="+repository, "mktree")))
	commit := strings.TrimSpace(string(fixtureGit(t, nil, "--git-dir="+repository, "-c", "user.name=C4 Fixture", "-c", "user.email=c4-fixture@example.invalid", "commit-tree", tree, "-m", "add unexpected fixture state")))
	fixtureGit(t, nil, "--git-dir="+repository, "update-ref", "refs/heads/main", commit)

	if err := ensureBareRepository(repository); err == nil {
		t.Fatal("ensureBareRepository accepted a main branch with an extra tracked path")
	}
}

func TestEnsureBareRepositoryRejectsAlteredFixtureTask(t *testing.T) {
	repository := filepath.Join(t.TempDir(), "fixture.git")
	if err := ensureBareRepository(repository); err != nil {
		t.Fatalf("seed fixture repository: %v", err)
	}

	alteredBlob := strings.TrimSpace(string(fixtureGit(t, strings.NewReader("# C4 bilateral fixture task\n\nstatus: complete\n"), "--git-dir="+repository, "hash-object", "-w", "--stdin")))
	tree := strings.TrimSpace(string(fixtureGit(t, strings.NewReader("100644 blob "+alteredBlob+"\t"+fixtureTaskPath+"\n"), "--git-dir="+repository, "mktree")))
	commit := strings.TrimSpace(string(fixtureGit(t, nil, "--git-dir="+repository, "-c", "user.name=C4 Fixture", "-c", "user.email=c4-fixture@example.invalid", "commit-tree", tree, "-m", "alter fixture task")))
	fixtureGit(t, nil, "--git-dir="+repository, "update-ref", "refs/heads/main", commit)

	if err := ensureBareRepository(repository); err == nil {
		t.Fatal("ensureBareRepository accepted an altered pending fixture task")
	}
}

func TestFixtureJWTVerifierValidAndInvalidClaims(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	now := time.Unix(1_700_000_000, 0)
	verifier := fixtureJWTVerifier{publicKey: &key.PublicKey, issuer: "4292923", now: func() time.Time { return now }}

	tests := []struct {
		name   string
		claims map[string]any
		key    *rsa.PrivateKey
		want   bool
	}{
		{name: "valid", claims: jwtClaims("4292923", now.Add(-time.Minute), now.Add(9*time.Minute)), key: key, want: true},
		{name: "bad signature", claims: jwtClaims("4292923", now.Add(-time.Minute), now.Add(9*time.Minute)), key: otherPrivateKey(t), want: false},
		{name: "wrong issuer", claims: jwtClaims("other", now.Add(-time.Minute), now.Add(9*time.Minute)), key: key, want: false},
		{name: "future issued at", claims: jwtClaims("4292923", now.Add(time.Second), now.Add(9*time.Minute)), key: key, want: false},
		{name: "expired", claims: jwtClaims("4292923", now.Add(-2*time.Minute), now.Add(-time.Minute)), key: key, want: false},
		{name: "expiration too far ahead", claims: jwtClaims("4292923", now.Add(-time.Minute), now.Add(10*time.Minute+time.Second)), key: key, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := verifier.valid(signedJWT(t, tt.key, tt.claims)); got != tt.want {
				t.Fatalf("valid() = %t, want %t", got, tt.want)
			}
		})
	}
}

func jwtClaims(issuer string, issuedAt, expiresAt time.Time) map[string]any {
	return map[string]any{"iss": issuer, "iat": issuedAt.Unix(), "exp": expiresAt.Unix()}
}

func otherPrivateKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate alternate RSA key: %v", err)
	}
	return key
}

func signedJWT(t *testing.T, key *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	header, err := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	if err != nil {
		t.Fatalf("marshal JWT header: %v", err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal JWT claims: %v", err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256Sum([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest)
	if err != nil {
		t.Fatalf("sign JWT: %v", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func sha256Sum(input []byte) []byte {
	sum := sha256.Sum256(input)
	return sum[:]
}

func gitOutput(t *testing.T, args ...string) []byte {
	t.Helper()
	return fixtureGit(t, nil, args...)
}

func fixtureGit(t *testing.T, input io.Reader, args ...string) []byte {
	t.Helper()
	output, err := runGit(input, args...)
	if err != nil {
		t.Fatalf("git %s: %v", strings.Join(args, " "), err)
	}
	return output
}
