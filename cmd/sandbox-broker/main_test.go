package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"gh-agent-broker/internal/sandbox"
)

func TestAuthorityOnlyMuxExposesNoLegacyRoutes(t *testing.T) {
	authority := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	legacy := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("legacy handler was called")
	})
	mux := newServerMux(sandbox.Config{AuthorityOnly: true, MCPPath: "/mcp"}, legacy, legacy, authority)

	for _, path := range []string{"/mcp", "/v1/launch"} {
		recorder := httptest.NewRecorder()
		mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, path, nil))
		if recorder.Code != http.StatusNotFound {
			t.Fatalf("%s status = %d, want 404", path, recorder.Code)
		}
	}

	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/v1/authority-workers", nil))
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("authority status = %d, want 204", recorder.Code)
	}
}

func TestParseSubcommand(t *testing.T) {
	command, args, ok := parseSubcommand([]string{})
	if ok || command != "" || len(args) != 0 {
		t.Fatalf("parseSubcommand(%q) = %q, %v, %v, want false", []string{}, command, args, ok)
	}
	_, _, ok = parseSubcommand([]string{"-config", "configs/sandbox.example.yaml"})
	if ok {
		t.Fatalf("parseSubcommand(flag) ok = true, want false")
	}
	command, args, ok = parseSubcommand([]string{"prune-runs", "-max-age", "2h"})
	if !ok || command != "prune-runs" || len(args) == 0 || args[0] != "prune-runs" {
		t.Fatalf("parseSubcommand(prune) = %s, %v, %v, want prune-runs", command, args, ok)
	}
}

func TestParsePruneCommandDefaults(t *testing.T) {
	cmd, err := parsePruneCommand([]string{"prune-runs"})
	if err != nil {
		t.Fatalf("parsePruneCommand() error = %v", err)
	}
	if got := cmd.Policy.MaxAge; got != 24*time.Hour {
		t.Fatalf("max_age = %v, want %v", got, 24*time.Hour)
	}
	if got := cmd.Policy.KeepNewest; got != 20 {
		t.Fatalf("keep_newest = %d, want 20", got)
	}
	if !cmd.Policy.TerminalOnly {
		t.Fatalf("terminal-only = %v, want true", cmd.Policy.TerminalOnly)
	}
	if cmd.Policy.MaxOutput != 200 {
		t.Fatalf("max_output = %d, want 200", cmd.Policy.MaxOutput)
	}
}

func TestParsePruneCommandOverride(t *testing.T) {
	cmd, err := parsePruneCommand([]string{
		"prune-runs",
		"-max-age", "2h",
		"-keep-newest", "3",
		"-terminal-only=false",
		"-max-bytes", "1073741824",
		"-dry-run",
		"-max-output", "77",
		"-config", "/tmp/config.yaml",
		"-docker-socket", "/var/run/d.sock",
	})
	if err != nil {
		t.Fatalf("parsePruneCommand() error = %v", err)
	}
	if got := cmd.Policy.MaxAge; got != 2*time.Hour {
		t.Fatalf("max_age = %v, want %v", got, 2*time.Hour)
	}
	if got := cmd.Policy.KeepNewest; got != 3 {
		t.Fatalf("keep_newest = %d, want 3", got)
	}
	if got := cmd.Policy.TerminalOnly; got {
		t.Fatalf("terminal-only = true, want false")
	}
	if got := cmd.Policy.MaxBytes; got != 1<<30 {
		t.Fatalf("max_bytes = %d, want %d", got, int64(1<<30))
	}
	if got := cmd.Policy.DryRun; !got {
		t.Fatalf("dry-run = %v, want true", got)
	}
	if got := cmd.ConfigPath; got != "/tmp/config.yaml" {
		t.Fatalf("config = %q, want /tmp/config.yaml", got)
	}
	if got := cmd.DockerSocket; got != "/var/run/d.sock" {
		t.Fatalf("docker socket = %q, want /var/run/d.sock", got)
	}
	if got := cmd.Policy.MaxOutput; got != 77 {
		t.Fatalf("max_output = %d, want 77", got)
	}
}

func TestParseSlimCommandDefaults(t *testing.T) {
	cmd, err := parseSlimCommand([]string{"slim-runs"})
	if err != nil {
		t.Fatalf("parseSlimCommand() error = %v", err)
	}
	if got := cmd.Policy.MaxAge; got != 24*time.Hour {
		t.Fatalf("max_age = %v, want %v", got, 24*time.Hour)
	}
	if !cmd.Policy.TerminalOnly {
		t.Fatalf("terminal-only = %v, want true", cmd.Policy.TerminalOnly)
	}
	if cmd.Policy.MaxOutput != 200 {
		t.Fatalf("max_output = %d, want 200", cmd.Policy.MaxOutput)
	}
}

func TestParseSlimCommandOverride(t *testing.T) {
	cmd, err := parseSlimCommand([]string{
		"slim-runs",
		"-max-age", "2h",
		"-keep-newest", "3",
		"-terminal-only=false",
		"-max-bytes", "1073741824",
		"-dry-run",
		"-max-output", "77",
		"-config", "/tmp/config.yaml",
		"-docker-socket", "/var/run/d.sock",
	})
	if err != nil {
		t.Fatalf("parseSlimCommand() error = %v", err)
	}
	if got := cmd.Policy.MaxAge; got != 2*time.Hour {
		t.Fatalf("max_age = %v, want %v", got, 2*time.Hour)
	}
	if got := cmd.Policy.KeepNewest; got != 3 {
		t.Fatalf("keep_newest = %d, want %d", got, 3)
	}
	if got := cmd.Policy.TerminalOnly; got {
		t.Fatalf("terminal-only = true, want false")
	}
	if got := cmd.Policy.MaxBytes; got != 1<<30 {
		t.Fatalf("max_bytes = %d, want %d", got, int64(1<<30))
	}
	if got := cmd.Policy.DryRun; !got {
		t.Fatalf("dry-run = %v, want true", got)
	}
	if got := cmd.ConfigPath; got != "/tmp/config.yaml" {
		t.Fatalf("config = %q, want /tmp/config.yaml", got)
	}
	if got := cmd.DockerSocket; got != "/var/run/d.sock" {
		t.Fatalf("docker socket = %q, want /var/run/d.sock", got)
	}
	if got := cmd.Policy.MaxOutput; got != 77 {
		t.Fatalf("max_output = %d, want 77", got)
	}
}
