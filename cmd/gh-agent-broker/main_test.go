package main

import (
	"bytes"
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCommonFlagsDoesNotExposeSecretAsDefault(t *testing.T) {
	t.Setenv("BROKER_AGENT_SECRET", "super-secret")
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	_, _, secret := commonFlags(fs)
	if *secret != "" {
		t.Fatalf("secret flag default = %q, want empty", *secret)
	}
	resolveSecret(secret)
	if *secret != "super-secret" {
		t.Fatalf("resolved secret = %q", *secret)
	}
}

func TestCredentialHelperGetWritesBrokerCredentialsFromEnv(t *testing.T) {
	var out bytes.Buffer
	getenv := func(key string) string {
		switch key {
		case "BROKER_AGENT_ID":
			return "agent-1"
		case "BROKER_AGENT_SECRET":
			return "agent-secret"
		default:
			return ""
		}
	}

	err := runCredentialHelper("get", strings.NewReader("protocol=http\nhost=broker\n\n"), &out, getenv)
	if err != nil {
		t.Fatalf("runCredentialHelper returned error: %v", err)
	}
	if got, want := out.String(), "username=agent-1\npassword=agent-secret\n\n"; got != want {
		t.Fatalf("credential helper output = %q, want %q", got, want)
	}
}

func TestCredentialHelperGetRequiresEnv(t *testing.T) {
	var out bytes.Buffer
	err := runCredentialHelper("get", strings.NewReader("\n"), &out, func(string) string { return "" })
	if err == nil {
		t.Fatal("runCredentialHelper returned nil error, want missing env error")
	}
	if out.Len() != 0 {
		t.Fatalf("credential helper output = %q, want empty", out.String())
	}
	if got := err.Error(); !strings.Contains(got, "BROKER_AGENT_ID") || !strings.Contains(got, "BROKER_AGENT_SECRET") {
		t.Fatalf("error = %q, want both missing env names", got)
	}
}

func TestCredentialHelperIgnoresStoreAndErase(t *testing.T) {
	for _, operation := range []string{"store", "erase", ""} {
		t.Run(operation, func(t *testing.T) {
			var out bytes.Buffer
			err := runCredentialHelper(operation, strings.NewReader("password=secret\n\n"), &out, func(string) string {
				t.Fatal("getenv should not be called")
				return ""
			})
			if err != nil {
				t.Fatalf("runCredentialHelper returned error: %v", err)
			}
			if out.Len() != 0 {
				t.Fatalf("credential helper output = %q, want empty", out.String())
			}
		})
	}
}

func TestCmdWhoamiUsesAuthenticatedWhoamiEndpoint(t *testing.T) {
	t.Setenv("BROKER_AGENT_ID", "agent-1")
	t.Setenv("BROKER_AGENT_SECRET", "agent-secret")

	var sawWhoami bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawWhoami = true
		if r.URL.Path != "/whoami" {
			t.Errorf("path = %q, want /whoami", r.URL.Path)
		}
		user, pass, ok := r.BasicAuth()
		if !ok || user != "agent-1" || pass != "agent-secret" {
			t.Errorf("BasicAuth = %q/%q/%v, want agent credentials", user, pass, ok)
		}
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte(`{"agent_id":"agent-1","branch_patterns":["^agent/agent-1/.+$"]}`)); err != nil {
			t.Errorf("write response: %v", err)
		}
	}))
	t.Cleanup(server.Close)

	cmdWhoami([]string{"-broker", server.URL})

	if !sawWhoami {
		t.Fatal("whoami endpoint was not called")
	}
}

func TestConfigureCredentialHelperWritesRepoLocalGitConfig(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}

	dir := t.TempDir()
	gitInit := exec.Command("git", "init", "-q")
	gitInit.Dir = dir
	if err := gitInit.Run(); err != nil {
		t.Fatalf("git init: %v", err)
	}

	oldwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("get working directory: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir temp repo: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(oldwd); err != nil {
			t.Fatalf("restore working directory: %v", err)
		}
	})

	url := "http://gh-agent-broker:8080/git/owner/repo.git"
	if err := configureCredentialHelper(url); err != nil {
		t.Fatalf("configureCredentialHelper returned error: %v", err)
	}

	helper := gitConfigGetURLMatch(t, dir, "credential.helper", url)
	if !strings.HasPrefix(helper, "!") || !strings.HasSuffix(helper, " credential-helper") {
		t.Fatalf("credential helper = %q, want shell helper command", helper)
	}
	if strings.Contains(helper, "agent-secret") {
		t.Fatalf("credential helper must not store broker secrets: %q", helper)
	}
	if got := gitConfigGetURLMatch(t, dir, "credential.useHttpPath", url); got != "true" {
		t.Fatalf("credential useHttpPath = %q, want true", got)
	}
}

func TestShellQuote(t *testing.T) {
	if got, want := shellQuote("/usr/local/bin/gh-agent-broker-cli"), "/usr/local/bin/gh-agent-broker-cli"; got != want {
		t.Fatalf("shellQuote safe path = %q, want %q", got, want)
	}
	if got, want := shellQuote(filepath.Join("/tmp", "broker cli")), "'/tmp/broker cli'"; got != want {
		t.Fatalf("shellQuote path with space = %q, want %q", got, want)
	}
}

func gitConfigGetURLMatch(t *testing.T, dir, key, url string) string {
	t.Helper()
	// #nosec G204 -- test invokes git with fixed option names and caller-provided test values only.
	cmd := exec.Command("git", "config", "--local", "--get-urlmatch", key, url)
	cmd.Dir = dir
	b, err := cmd.Output()
	if err != nil {
		t.Fatalf("git config --get-urlmatch %s: %v", key, err)
	}
	return strings.TrimSpace(string(b))
}
