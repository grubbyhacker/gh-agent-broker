package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParseGitPath(t *testing.T) {
	repo, suffix, ok := parseGitPath("/git/owner/repo.git/info/refs")
	if !ok {
		t.Fatalf("parseGitPath() failed")
	}
	if repo != "owner/repo" || suffix != "/info/refs" {
		t.Fatalf("repo=%q suffix=%q", repo, suffix)
	}
}

func TestGitOperation(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/git/owner/repo.git/info/refs?service=git-upload-pack", nil)
	if got := gitOperation(req, "/info/refs"); got != "git.upload-pack" {
		t.Fatalf("gitOperation() = %q", got)
	}

	req = httptest.NewRequest(http.MethodPost, "/git/owner/repo.git/git-receive-pack", nil)
	if got := gitOperation(req, "/git-receive-pack"); got != "git.receive-pack" {
		t.Fatalf("gitOperation() = %q", got)
	}
}

func TestReceivePackBranch(t *testing.T) {
	line := "0000000000000000000000000000000000000000 1111111111111111111111111111111111111111 refs/heads/agent/a1/test\x00 report-status\n"
	body := append(pktLine(line), []byte("0000")...)

	if got := receivePackBranch(body); got != "refs/heads/agent/a1/test" {
		t.Fatalf("receivePackBranch() = %q", got)
	}
}

func TestValidateListenAddressRejectsPublicBind(t *testing.T) {
	if err := ValidateListenAddress(":8080"); err == nil {
		t.Fatalf("ValidateListenAddress() error = nil")
	}
}

func pktLine(line string) []byte {
	n := len(line) + 4
	return []byte(string([]byte{
		hexDigit(n >> 12),
		hexDigit(n >> 8),
		hexDigit(n >> 4),
		hexDigit(n),
	}) + line)
}

func hexDigit(n int) byte {
	n &= 0xf
	if n < 10 {
		return byte('0' + n)
	}
	return byte('a' + n - 10)
}
