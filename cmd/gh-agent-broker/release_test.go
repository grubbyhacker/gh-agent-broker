package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildReleasePublishBodyUsesDockerArchiveV1Protocol(t *testing.T) {
	metadata := releasePublishMetadata{
		AgentType: "coder",
		Provenance: releaseProvenance{
			SourceRevision: "abc123",
			Platform:       "linux/amd64",
		},
	}
	artifact := []byte("fake-docker-archive-bytes")

	body, contentType, err := buildReleasePublishBody(metadata, artifact)
	if err != nil {
		t.Fatalf("buildReleasePublishBody returned error: %v", err)
	}

	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil || mediaType != "multipart/form-data" {
		t.Fatalf("content type = %q, want multipart/form-data", contentType)
	}

	parts := readMultipartParts(t, body, params["boundary"])
	if parts["protocol"] != releasePublishProtocol {
		t.Errorf("protocol part = %q, want %q", parts["protocol"], releasePublishProtocol)
	}
	if releasePublishProtocol != "docker-archive/v1" {
		t.Errorf("release publish protocol = %q, want docker-archive/v1", releasePublishProtocol)
	}
	if parts["artifact"] != string(artifact) {
		t.Errorf("artifact part mismatch")
	}

	var gotMeta releasePublishMetadata
	if err := json.Unmarshal([]byte(parts["metadata"]), &gotMeta); err != nil {
		t.Fatalf("decode metadata part: %v", err)
	}
	if gotMeta.AgentType != "coder" || gotMeta.Provenance.SourceRevision != "abc123" || gotMeta.Provenance.Platform != "linux/amd64" {
		t.Errorf("metadata = %+v, want agent_type/source_revision/platform preserved", gotMeta)
	}
}

func TestCmdReleasePublishSendsBearerTokenAndPrintsGeneration(t *testing.T) {
	dir := t.TempDir()
	archivePath := filepath.Join(dir, "image.tar")
	if err := os.WriteFile(archivePath, []byte("archive-data"), 0o600); err != nil {
		t.Fatalf("write archive: %v", err)
	}

	var sawAuth string
	var sawProtocol string
	var sawMetadata releasePublishMetadata
	var sawBasicAuth bool

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %q, want POST", r.Method)
		}
		if r.URL.Path != "/v1/releases/publish" {
			t.Errorf("path = %q, want /v1/releases/publish", r.URL.Path)
		}
		sawAuth = r.Header.Get("Authorization")
		if _, _, ok := r.BasicAuth(); ok {
			sawBasicAuth = true
		}
		_, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil {
			t.Fatalf("parse content type: %v", err)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		parts := readMultipartParts(t, body, params["boundary"])
		sawProtocol = parts["protocol"]
		if err := json.Unmarshal([]byte(parts["metadata"]), &sawMetadata); err != nil {
			t.Fatalf("decode metadata: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		if _, err := w.Write([]byte(`{"Generation":7,"AgentType":"coder","State":"verified","Available":true,"ImageDigest":"sha256:deadbeef"}`)); err != nil {
			t.Errorf("write response: %v", err)
		}
	}))
	t.Cleanup(server.Close)

	stdout := captureStdout(t, func() {
		cmdReleasePublish([]string{
			"-broker", server.URL,
			"-agent-type", "coder",
			"-archive", archivePath,
			"-source-revision", "abc123",
			"-platform", "linux/amd64",
			"-publisher-token", "pub-secret",
		})
	})

	if sawAuth != "Bearer pub-secret" {
		t.Errorf("Authorization = %q, want Bearer pub-secret", sawAuth)
	}
	if sawBasicAuth {
		t.Error("publish must not use agent basic authentication")
	}
	if sawProtocol != "docker-archive/v1" {
		t.Errorf("protocol = %q, want docker-archive/v1", sawProtocol)
	}
	if sawMetadata.AgentType != "coder" {
		t.Errorf("agent_type = %q, want coder", sawMetadata.AgentType)
	}
	if !strings.Contains(stdout, "generation=7") {
		t.Errorf("stdout %q missing generation=7", stdout)
	}
	if !strings.Contains(stdout, "ready=true") {
		t.Errorf("stdout %q missing ready=true", stdout)
	}
	if strings.Contains(stdout, "pub-secret") {
		t.Errorf("stdout must never contain the publisher token")
	}
}

func TestCmdReleasePublishWritesGitHubOutput(t *testing.T) {
	dir := t.TempDir()
	archivePath := filepath.Join(dir, "image.tar")
	if err := os.WriteFile(archivePath, []byte("archive-data"), 0o600); err != nil {
		t.Fatalf("write archive: %v", err)
	}
	outputPath := filepath.Join(dir, "gh-output")
	t.Setenv("GITHUB_OUTPUT", outputPath)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		if _, err := w.Write([]byte(`{"Generation":12,"AgentType":"coder","State":"verified","Available":true}`)); err != nil {
			t.Errorf("write response: %v", err)
		}
	}))
	t.Cleanup(server.Close)

	_ = captureStdout(t, func() {
		cmdReleasePublish([]string{
			"-broker", server.URL,
			"-agent-type", "coder",
			"-archive", archivePath,
			"-source-revision", "abc123",
			"-platform", "linux/amd64",
			"-publisher-token", "pub-secret",
			"-github-output",
		})
	})

	// #nosec G304 -- outputPath is a test-owned temporary file created above.
	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read GITHUB_OUTPUT: %v", err)
	}
	got := string(data)
	if !strings.Contains(got, "generation=12") || !strings.Contains(got, "ready=true") {
		t.Errorf("GITHUB_OUTPUT = %q, want generation=12 and ready=true", got)
	}
}

func TestCmdReleasePromoteSendsGenerationOnlyWithBearerToken(t *testing.T) {
	var sawPath string
	var sawAuth string
	var sawBody []byte

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %q, want POST", r.Method)
		}
		sawPath = r.URL.Path
		sawAuth = r.Header.Get("Authorization")
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
		}
		sawBody = body
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)

	stdout := captureStdout(t, func() {
		cmdReleasePromote([]string{
			"-broker", server.URL,
			"-generation", "5",
			"-promoter-token", "promote-secret",
		})
	})

	if sawPath != "/v1/releases/5/promote" {
		t.Errorf("path = %q, want /v1/releases/5/promote", sawPath)
	}
	if sawAuth != "Bearer promote-secret" {
		t.Errorf("Authorization = %q, want Bearer promote-secret", sawAuth)
	}
	if strings.Contains(string(sawBody), "image") {
		t.Errorf("promote body %q must not carry an image reference", string(sawBody))
	}
	if !strings.Contains(stdout, "promoted generation 5") {
		t.Errorf("stdout %q missing confirmation", stdout)
	}
	if strings.Contains(stdout, "promote-secret") {
		t.Errorf("stdout must never contain the promoter token")
	}
}

func TestResolvePublisherAndPromoterTokensFromEnv(t *testing.T) {
	t.Setenv("BROKER_PUBLISHER_TOKEN", "env-pub")
	t.Setenv("BROKER_PROMOTER_TOKEN", "env-promote")

	pub := ""
	resolvePublisherToken(&pub)
	if pub != "env-pub" {
		t.Errorf("publisher token = %q, want env-pub", pub)
	}
	promote := ""
	resolvePromoterToken(&promote)
	if promote != "env-promote" {
		t.Errorf("promoter token = %q, want env-promote", promote)
	}

	explicit := "flag-pub"
	resolvePublisherToken(&explicit)
	if explicit != "flag-pub" {
		t.Errorf("explicit publisher token overwritten to %q", explicit)
	}
}

func TestValidateReleasePublishFlagsRequiresFields(t *testing.T) {
	if err := validateReleasePublishFlags("coder", "img.tar", "abc", "linux/amd64", "tok"); err != nil {
		t.Fatalf("valid flags rejected: %v", err)
	}
	if err := validateReleasePublishFlags("", "img.tar", "abc", "linux/amd64", "tok"); err == nil {
		t.Error("missing agent-type accepted")
	}
	if err := validateReleasePublishFlags("coder", "img.tar", "abc", "linux/amd64", ""); err == nil {
		t.Error("missing publisher token accepted")
	}
}

func readMultipartParts(t *testing.T, body []byte, boundary string) map[string]string {
	t.Helper()
	reader := multipart.NewReader(bytes.NewReader(body), boundary)
	parts := map[string]string{}
	for {
		part, err := reader.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("read multipart part: %v", err)
		}
		b, err := io.ReadAll(part)
		if err != nil {
			t.Fatalf("read part body: %v", err)
		}
		parts[part.FormName()] = string(b)
	}
	return parts
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		if _, copyErr := io.Copy(&buf, r); copyErr != nil {
			done <- ""
			return
		}
		done <- buf.String()
	}()
	defer func() {
		os.Stdout = orig
	}()
	fn()
	if err := w.Close(); err != nil {
		t.Fatalf("close pipe writer: %v", err)
	}
	return <-done
}
