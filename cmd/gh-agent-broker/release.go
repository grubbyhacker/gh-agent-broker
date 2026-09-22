package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"strconv"
	"strings"
)

// releasePublishProtocol is the versioned multipart protocol the broker's
// POST /v1/releases/publish endpoint accepts. It must match
// internal/sandbox releasePublishProtocol.
const releasePublishProtocol = "docker-archive/v1"

// releaseProvenance is the caller-supplied provenance in a publish request.
// Field names mirror internal/release.Provenance JSON tags; the broker derives
// and overrides deployment-owned fields, so only source_revision and platform
// are load-bearing here.
type releaseProvenance struct {
	SourceRevision           string `json:"source_revision"`
	DependencyManifestSHA256 string `json:"dependency_manifest_sha256,omitempty"`
	Platform                 string `json:"platform"`
}

// releasePublishMetadata is the JSON metadata part of a publish request.
type releasePublishMetadata struct {
	AgentType  string            `json:"agent_type"`
	Provenance releaseProvenance `json:"provenance"`
}

// publishResponse is the broker-assigned release the publish endpoint returns.
// The broker owns the generation and readiness; only the fields a caller (and
// GitHub Actions) needs are decoded. State "verified" with available=true is
// the ready state a subsequent promote requires.
type publishResponse struct {
	Generation  int64  `json:"Generation"`
	AgentType   string `json:"AgentType"`
	State       string `json:"State"`
	Available   bool   `json:"Available"`
	ImageDigest string `json:"ImageDigest"`
}

// cmdReleasePublish uploads a trusted single-image Docker archive plus
// provenance to the broker's release publish endpoint using the
// docker-archive/v1 multipart protocol, and prints the broker-assigned
// generation and ready state.
func cmdReleasePublish(args []string) {
	fs := flag.NewFlagSet("release-publish", flag.ExitOnError)
	broker := fs.String("broker", envDefault("BROKER_URL", "http://127.0.0.1:8080"), "broker base URL")
	agentType := fs.String("agent-type", "", "agent type the release is published for")
	archive := fs.String("archive", "", "path to a single-image Docker archive (docker save output)")
	sourceRevision := fs.String("source-revision", "", "provenance: source revision (commit) the image was built from")
	platform := fs.String("platform", "", "provenance: image platform, e.g. linux/amd64")
	depManifest := fs.String("dependency-manifest-sha256", "", "provenance: optional dependency manifest sha256")
	token := fs.String("publisher-token", "", "publisher bearer token (defaults to BROKER_PUBLISHER_TOKEN); never logged")
	githubOutput := fs.Bool("github-output", false, "additionally emit generation/ready key=value lines to $GITHUB_OUTPUT for GitHub Actions")
	if err := fs.Parse(args); err != nil {
		fatal(err)
	}

	resolvePublisherToken(token)
	if err := validateReleasePublishFlags(*agentType, *archive, *sourceRevision, *platform, *token); err != nil {
		fatal(err)
	}

	// #nosec G304 -- archive path is an explicit operator-supplied CLI flag.
	artifact, err := os.ReadFile(*archive)
	if err != nil {
		fatal(fmt.Errorf("read Docker archive: %w", err))
	}
	if len(artifact) == 0 {
		fatal(errors.New("docker archive is empty"))
	}

	metadata := releasePublishMetadata{
		AgentType: *agentType,
		Provenance: releaseProvenance{
			SourceRevision:           *sourceRevision,
			DependencyManifestSHA256: *depManifest,
			Platform:                 *platform,
		},
	}
	body, contentType, err := buildReleasePublishBody(metadata, artifact)
	if err != nil {
		fatal(err)
	}

	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(*broker, "/")+"/v1/releases/publish", bytes.NewReader(body))
	if err != nil {
		fatal(err)
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Authorization", "Bearer "+*token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fatal(err)
	}
	defer closeBody(resp.Body)
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		fatal(err)
	}
	if resp.StatusCode >= 300 {
		fmt.Fprintln(os.Stderr, string(respBody))
		os.Exit(1)
	}

	var release publishResponse
	if err := json.Unmarshal(respBody, &release); err != nil {
		fatal(fmt.Errorf("decode publish response: %w", err))
	}
	if err := emitPublishResult(os.Stdout, release, respBody); err != nil {
		fatal(err)
	}
	if *githubOutput {
		if err := writeGitHubOutput(os.Getenv("GITHUB_OUTPUT"), release); err != nil {
			fatal(err)
		}
	}
}

// cmdReleasePromote promotes a broker-assigned generation. It accepts only a
// positive generation, never an image reference; rollback is a separate,
// deliberately unimplemented operation here.
func cmdReleasePromote(args []string) {
	fs := flag.NewFlagSet("release-promote", flag.ExitOnError)
	broker := fs.String("broker", envDefault("BROKER_URL", "http://127.0.0.1:8080"), "broker base URL")
	generation := fs.Int64("generation", 0, "positive broker-assigned generation to promote")
	token := fs.String("promoter-token", "", "promoter bearer token (defaults to BROKER_PROMOTER_TOKEN); never logged")
	if err := fs.Parse(args); err != nil {
		fatal(err)
	}

	resolvePromoterToken(token)
	if *generation <= 0 {
		fatal(errors.New("-generation must be a positive broker-assigned generation"))
	}
	if *token == "" {
		fatal(errors.New("promoter token is required (set -promoter-token or BROKER_PROMOTER_TOKEN)"))
	}

	path := "/v1/releases/" + strconv.FormatInt(*generation, 10) + "/promote"
	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(*broker, "/")+path, nil)
	if err != nil {
		fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+*token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fatal(err)
	}
	defer closeBody(resp.Body)
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		fatal(err)
	}
	if resp.StatusCode >= 300 {
		fmt.Fprintln(os.Stderr, string(respBody))
		os.Exit(1)
	}
	fmt.Printf("promoted generation %d\n", *generation)
}

func validateReleasePublishFlags(agentType, archive, sourceRevision, platform, token string) error {
	var missing []string
	if agentType == "" {
		missing = append(missing, "-agent-type")
	}
	if archive == "" {
		missing = append(missing, "-archive")
	}
	if sourceRevision == "" {
		missing = append(missing, "-source-revision")
	}
	if platform == "" {
		missing = append(missing, "-platform")
	}
	if len(missing) > 0 {
		return fmt.Errorf("release publish requires %s", strings.Join(missing, ", "))
	}
	if token == "" {
		return errors.New("publisher token is required (set -publisher-token or BROKER_PUBLISHER_TOKEN)")
	}
	return nil
}

// buildReleasePublishBody assembles the docker-archive/v1 multipart body with
// the protocol, metadata, and artifact parts the broker requires.
func buildReleasePublishBody(metadata releasePublishMetadata, artifact []byte) ([]byte, string, error) {
	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return nil, "", err
	}
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	if err := mw.WriteField("protocol", releasePublishProtocol); err != nil {
		return nil, "", err
	}
	if err := mw.WriteField("metadata", string(metadataJSON)); err != nil {
		return nil, "", err
	}
	part, err := mw.CreateFormField("artifact")
	if err != nil {
		return nil, "", err
	}
	if _, err := part.Write(artifact); err != nil {
		return nil, "", err
	}
	if err := mw.Close(); err != nil {
		return nil, "", err
	}
	return buf.Bytes(), mw.FormDataContentType(), nil
}

// emitPublishResult prints a stable, machine-readable summary of the broker's
// assignment so GitHub Actions can consume the generation and ready state, then
// the raw broker response for humans and audit.
func emitPublishResult(w io.Writer, release publishResponse, raw []byte) error {
	ready := release.State == "verified" && release.Available
	_, err := fmt.Fprintf(w, "generation=%d\nready=%t\nstate=%s\n%s\n", release.Generation, ready, release.State, string(raw))
	return err
}

// writeGitHubOutput appends generation/ready/state to the file named by
// $GITHUB_OUTPUT so downstream Actions steps can gate on them.
func writeGitHubOutput(path string, release publishResponse) error {
	if path == "" {
		return errors.New("-github-output set but GITHUB_OUTPUT is not defined")
	}
	ready := release.State == "verified" && release.Available
	line := fmt.Sprintf("generation=%d\nready=%t\nstate=%s\n", release.Generation, ready, release.State)
	// #nosec G703 G304 -- path is GitHub Actions' own $GITHUB_OUTPUT file supplied by the trusted runner environment, not request input.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.WriteString(f, line); err != nil {
		if closeErr := f.Close(); closeErr != nil {
			return closeErr
		}
		return err
	}
	return f.Close()
}

func resolvePublisherToken(token *string) {
	if *token == "" {
		*token = os.Getenv("BROKER_PUBLISHER_TOKEN")
	}
}

func resolvePromoterToken(token *string) {
	if *token == "" {
		*token = os.Getenv("BROKER_PROMOTER_TOKEN")
	}
}
