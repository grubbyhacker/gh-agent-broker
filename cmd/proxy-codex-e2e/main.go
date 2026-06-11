package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	proxyToken = "codex-executor-token-e2e"
	// #nosec G101 -- fixed fake credential used only inside this local E2E harness.
	upstreamToken    = "litellm-codex-virtual-key-e2e"
	privatePrompt    = "private proxy codex e2e prompt"
	codexSentinel    = "CODEX_PROXY_E2E_OK"
	rawRunID         = "proxy-raw-e2e"
	streamRunID      = "proxy-stream-e2e"
	codexRunID       = "proxy-codex-cli-e2e"
	haikuAlias       = "ykm-codex-haiku"
	sonnetAlias      = "ykm-codex-sonnet"
	haikuUpstream    = "anthropic/claude-haiku-4.5"
	sonnetUpstream   = "anthropic/claude-sonnet-4.5"
	responseID       = "resp_proxy_e2e"
	responseMessage  = "msg_proxy_e2e"
	requestByteLimit = 262144
)

type upstreamServer struct {
	server   *http.Server
	baseURL  string
	requests chan upstreamRequest
}

type upstreamRequest struct {
	Path          string
	Authorization string
	Model         string
	Stream        bool
	Body          string
}

func main() {
	log.SetFlags(0)
	repoRoot := flag.String("repo-root", ".", "repository root")
	skipCodex := flag.Bool("skip-codex", false, "skip the real codex exec CLI check")
	flag.Parse()

	root, err := filepath.Abs(*repoRoot)
	if err != nil {
		log.Fatal(err)
	}
	tmp, err := os.MkdirTemp("", "gh-agent-proxy-codex-e2e-*")
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if err := os.RemoveAll(tmp); err != nil {
			log.Printf("remove temp dir: %v", err)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	upstream, err := startUpstream()
	if err != nil {
		log.Fatal(err)
	}
	defer upstream.shutdown(context.Background())

	proxyAddr, err := freeAddr()
	if err != nil {
		log.Fatal(err)
	}
	configPath := filepath.Join(tmp, "proxy.yaml")
	auditPath := filepath.Join(tmp, "proxy-audit.jsonl")
	statePath := filepath.Join(tmp, "proxy-budget-state.json")
	if err := writeProxyConfig(configPath, proxyAddr, upstream.baseURL, auditPath, statePath); err != nil {
		log.Fatal(err)
	}

	proxyBin := filepath.Join(tmp, "gh-agent-proxy-e2e")
	// #nosec G204 -- command and package are fixed; only the temp output path varies.
	buildCmd := exec.CommandContext(ctx, "go", "build", "-o", proxyBin, "./cmd/gh-agent-proxy")
	buildCmd.Dir = root
	var buildLog bytes.Buffer
	buildCmd.Stdout = &buildLog
	buildCmd.Stderr = &buildLog
	if err := buildCmd.Run(); err != nil {
		log.Fatalf("build gh-agent-proxy: %v\n%s", err, buildLog.String())
	}

	// #nosec G204 -- proxyBin and configPath are generated under this harness temp dir.
	proxyCmd := exec.CommandContext(ctx, proxyBin, "-config", configPath)
	proxyCmd.Dir = root
	var proxyLog bytes.Buffer
	proxyCmd.Stdout = &proxyLog
	proxyCmd.Stderr = &proxyLog
	if err := proxyCmd.Start(); err != nil {
		log.Fatal(err)
	}
	defer stopProcess(proxyCmd)

	proxyURL := "http://" + proxyAddr
	if err := waitHealth(ctx, proxyURL); err != nil {
		log.Printf("proxy output:\n%s", proxyLog.String())
		log.Fatal(err)
	}

	if err := verifyRawHTTP(ctx, proxyURL, upstream); err != nil {
		log.Printf("proxy output:\n%s", proxyLog.String())
		log.Fatal(err)
	}
	if !*skipCodex {
		if err := verifyCodexExec(ctx, root, tmp, proxyURL, upstream); err != nil {
			log.Printf("proxy output:\n%s", proxyLog.String())
			log.Fatal(err)
		}
	}
	if err := verifyAuditAndBudget(auditPath, statePath, !*skipCodex); err != nil {
		log.Fatal(err)
	}
	fmt.Println("proxy Codex E2E completed successfully")
}

func startUpstream() (*upstreamServer, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	upstream := &upstreamServer{
		baseURL:  "http://" + listener.Addr().String() + "/v1",
		requests: make(chan upstreamRequest, 20),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/responses", upstream.handleResponses)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	upstream.server = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		if err := upstream.server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("fake upstream failed: %v", err)
		}
	}()
	return upstream, nil
}

func (u *upstreamServer) shutdown(ctx context.Context) {
	if u == nil || u.server == nil {
		return
	}
	if err := u.server.Shutdown(ctx); err != nil {
		log.Printf("shutdown fake upstream: %v", err)
	}
}

func (u *upstreamServer) handleResponses(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, requestByteLimit))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	var decoded struct {
		Model  string          `json:"model"`
		Stream bool            `json:"stream"`
		Input  json.RawMessage `json:"input"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	u.requests <- upstreamRequest{
		Path:          r.URL.Path,
		Authorization: r.Header.Get("Authorization"),
		Model:         decoded.Model,
		Stream:        decoded.Stream,
		Body:          string(body),
	}
	if decoded.Stream {
		writeStreamingResponse(w, decoded.Model)
		return
	}
	writeJSON(w, http.StatusOK, responseObject(decoded.Model, codexSentinel))
}

func writeStreamingResponse(w http.ResponseWriter, model string) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	flusher, canFlush := w.(http.Flusher)
	writeSSE := func(event string, payload map[string]interface{}) error {
		b, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "event: %s\n", event); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "data: %s\n\n", b); err != nil {
			return err
		}
		if canFlush {
			flusher.Flush()
		}
		return nil
	}
	response := responseObject(model, codexSentinel)
	if err := writeSSE("response.created", map[string]interface{}{
		"type":     "response.created",
		"response": responseBase(model, "in_progress", nil),
	}); err != nil {
		return
	}
	if err := writeSSE("response.output_item.added", map[string]interface{}{
		"type":         "response.output_item.added",
		"output_index": 0,
		"item":         messageObject("in_progress", nil),
	}); err != nil {
		return
	}
	if err := writeSSE("response.content_part.added", map[string]interface{}{
		"type":          "response.content_part.added",
		"item_id":       responseMessage,
		"output_index":  0,
		"content_index": 0,
		"part":          map[string]interface{}{"type": "output_text", "text": "", "annotations": []interface{}{}},
	}); err != nil {
		return
	}
	if err := writeSSE("response.output_text.delta", map[string]interface{}{
		"type":          "response.output_text.delta",
		"item_id":       responseMessage,
		"output_index":  0,
		"content_index": 0,
		"delta":         codexSentinel,
	}); err != nil {
		return
	}
	if err := writeSSE("response.output_text.done", map[string]interface{}{
		"type":          "response.output_text.done",
		"item_id":       responseMessage,
		"output_index":  0,
		"content_index": 0,
		"text":          codexSentinel,
	}); err != nil {
		return
	}
	if err := writeSSE("response.content_part.done", map[string]interface{}{
		"type":          "response.content_part.done",
		"item_id":       responseMessage,
		"output_index":  0,
		"content_index": 0,
		"part":          outputText(codexSentinel),
	}); err != nil {
		return
	}
	if err := writeSSE("response.output_item.done", map[string]interface{}{
		"type":         "response.output_item.done",
		"output_index": 0,
		"item":         messageObject("completed", []interface{}{outputText(codexSentinel)}),
	}); err != nil {
		return
	}
	if err := writeSSE("response.completed", map[string]interface{}{
		"type":     "response.completed",
		"response": response,
	}); err != nil {
		return
	}
	if _, err := fmt.Fprint(w, "data: [DONE]\n\n"); err != nil {
		return
	}
	if canFlush {
		flusher.Flush()
	}
}

func responseObject(model, text string) map[string]interface{} {
	output := []interface{}{messageObject("completed", []interface{}{outputText(text)})}
	resp := responseBase(model, "completed", output)
	resp["usage"] = map[string]interface{}{
		"input_tokens":  11,
		"output_tokens": 7,
		"total_tokens":  18,
	}
	return resp
}

func responseBase(model, status string, output []interface{}) map[string]interface{} {
	if output == nil {
		output = []interface{}{}
	}
	return map[string]interface{}{
		"id":                  responseID,
		"object":              "response",
		"created_at":          time.Now().Unix(),
		"status":              status,
		"model":               model,
		"output":              output,
		"parallel_tool_calls": false,
	}
}

func messageObject(status string, content []interface{}) map[string]interface{} {
	if content == nil {
		content = []interface{}{}
	}
	return map[string]interface{}{
		"id":      responseMessage,
		"type":    "message",
		"status":  status,
		"role":    "assistant",
		"content": content,
	}
}

func outputText(text string) map[string]interface{} {
	return map[string]interface{}{
		"type":        "output_text",
		"text":        text,
		"annotations": []interface{}{},
	}
}

func freeAddr() (string, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	defer func() {
		if err := listener.Close(); err != nil {
			log.Printf("close listener: %v", err)
		}
	}()
	return listener.Addr().String(), nil
}

func writeProxyConfig(path, listen, upstream, audit, state string) error {
	config := fmt.Sprintf(`listen: %q
auth_token: "legacy-proxy-token-e2e"
codex_auth_token: %q
upstream_url: %q
upstream_key: "legacy-upstream-key-e2e"
codex_upstream_key: %q
allowed_models:
  - "legacy-model-e2e"
codex_allowed_models:
  - name: %q
    upstream_model: %q
  - name: %q
    upstream_model: %q
state_path: %q
audit_path: %q
max_calls_per_run: 20
max_tokens_per_run: 200000
max_request_bytes: 262144
max_response_bytes: 524288
timeout: "30s"
log_prompts: false
`, listen, proxyToken, upstream, upstreamToken, haikuAlias, haikuUpstream, sonnetAlias, sonnetUpstream, state, audit)
	return os.WriteFile(path, []byte(config), 0o600)
}

func waitHealth(ctx context.Context, proxyURL string) error {
	client := &http.Client{Timeout: time.Second}
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, proxyURL+"/healthz", nil)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err == nil {
			if closeErr := resp.Body.Close(); closeErr != nil {
				log.Printf("close health response body: %v", closeErr)
			}
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("proxy did not become healthy: %w", ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func verifyRawHTTP(ctx context.Context, proxyURL string, upstream *upstreamServer) error {
	client := &http.Client{Timeout: 10 * time.Second}
	modelsReq, err := http.NewRequestWithContext(ctx, http.MethodGet, proxyURL+"/v1/models", nil)
	if err != nil {
		return err
	}
	modelsReq.Header.Set("Authorization", "Bearer "+proxyToken)
	modelsResp, err := client.Do(modelsReq)
	if err != nil {
		return err
	}
	modelsBodyBytes, err := io.ReadAll(modelsResp.Body)
	if closeErr := modelsResp.Body.Close(); closeErr != nil {
		return closeErr
	}
	if err != nil {
		return err
	}
	modelsBody := string(modelsBodyBytes)
	if modelsResp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET /v1/models status %d: %s", modelsResp.StatusCode, modelsBody)
	}
	for _, want := range []string{haikuAlias, sonnetAlias} {
		if !strings.Contains(modelsBody, want) {
			return fmt.Errorf("models response missing %q: %s", want, modelsBody)
		}
	}
	if strings.Contains(modelsBody, "anthropic/claude") {
		return fmt.Errorf("models response exposed upstream model ids: %s", modelsBody)
	}

	if err := postResponse(ctx, client, proxyURL, sonnetAlias, rawRunID, false); err != nil {
		return err
	}
	if err := assertUpstreamRequest(upstream, sonnetUpstream, false); err != nil {
		return err
	}
	if err := postResponse(ctx, client, proxyURL, haikuAlias, streamRunID, true); err != nil {
		return err
	}
	if err := assertUpstreamRequest(upstream, haikuUpstream, true); err != nil {
		return err
	}
	deniedReq, err := http.NewRequestWithContext(ctx, http.MethodPost, proxyURL+"/v1/responses", strings.NewReader(`{"model":"forbidden","input":"x"}`))
	if err != nil {
		return err
	}
	deniedReq.Header.Set("Authorization", "Bearer "+proxyToken)
	deniedReq.Header.Set("X-GH-Agent-Run-ID", "proxy-deny-e2e")
	deniedResp, err := client.Do(deniedReq)
	if err != nil {
		return err
	}
	deniedBodyBytes, err := io.ReadAll(deniedResp.Body)
	if closeErr := deniedResp.Body.Close(); closeErr != nil {
		return closeErr
	}
	if err != nil {
		return err
	}
	deniedBody := string(deniedBodyBytes)
	if deniedResp.StatusCode != http.StatusForbidden {
		return fmt.Errorf("forbidden model status %d: %s", deniedResp.StatusCode, deniedBody)
	}
	missingRunReq, err := http.NewRequestWithContext(ctx, http.MethodPost, proxyURL+"/v1/responses", strings.NewReader(`{"model":"`+haikuAlias+`","input":"x"}`))
	if err != nil {
		return err
	}
	missingRunReq.Header.Set("Authorization", "Bearer "+proxyToken)
	missingRunResp, err := client.Do(missingRunReq)
	if err != nil {
		return err
	}
	missingRunBodyBytes, err := io.ReadAll(missingRunResp.Body)
	if closeErr := missingRunResp.Body.Close(); closeErr != nil {
		return closeErr
	}
	if err != nil {
		return err
	}
	missingRunBody := string(missingRunBodyBytes)
	if missingRunResp.StatusCode != http.StatusBadRequest {
		return fmt.Errorf("missing run id status %d: %s", missingRunResp.StatusCode, missingRunBody)
	}
	return nil
}

func postResponse(ctx context.Context, client *http.Client, proxyURL, model, runID string, stream bool) error {
	body := fmt.Sprintf(`{"model":%q,"stream":%t,"input":%q}`, model, stream, privatePrompt)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, proxyURL+"/v1/responses", strings.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+proxyToken)
	req.Header.Set("X-GH-Agent-Run-ID", runID)
	if stream {
		req.Header.Set("Accept", "text/event-stream")
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	respBodyBytes, err := io.ReadAll(resp.Body)
	if closeErr := resp.Body.Close(); closeErr != nil {
		return closeErr
	}
	if err != nil {
		return err
	}
	respBody := string(respBodyBytes)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("POST /v1/responses status %d: %s", resp.StatusCode, respBody)
	}
	if !strings.Contains(respBody, codexSentinel) {
		return fmt.Errorf("response missing sentinel %q: %s", codexSentinel, respBody)
	}
	return nil
}

func assertUpstreamRequest(upstream *upstreamServer, wantModel string, wantStream bool) error {
	select {
	case got := <-upstream.requests:
		if got.Path != "/v1/responses" {
			return fmt.Errorf("upstream path = %q", got.Path)
		}
		if got.Authorization != "Bearer "+upstreamToken {
			return fmt.Errorf("upstream authorization = %q", got.Authorization)
		}
		if strings.Contains(got.Authorization, proxyToken) {
			return fmt.Errorf("executor token was forwarded upstream")
		}
		if got.Model != wantModel {
			return fmt.Errorf("upstream model = %q, want %q", got.Model, wantModel)
		}
		if got.Stream != wantStream {
			return fmt.Errorf("upstream stream = %t, want %t", got.Stream, wantStream)
		}
		if !strings.Contains(got.Body, privatePrompt) && !strings.Contains(got.Body, codexSentinel) {
			return fmt.Errorf("upstream body did not contain expected prompt/test context")
		}
		return nil
	case <-time.After(5 * time.Second):
		return fmt.Errorf("timed out waiting for upstream request")
	}
}

func verifyCodexExec(ctx context.Context, root, tmp, proxyURL string, upstream *upstreamServer) error {
	codexPath, err := exec.LookPath("codex")
	if err != nil {
		return fmt.Errorf("codex CLI not found: %w", err)
	}
	codexHome := filepath.Join(tmp, "codex-home")
	workDir := filepath.Join(tmp, "codex-work")
	if err := os.MkdirAll(codexHome, 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		return err
	}
	config := fmt.Sprintf(`model = %q
model_provider = "ykm-proxy"
approval_policy = "never"

[model_providers.ykm-proxy]
name = "YKM Proxy"
base_url = %q
env_key = "OPENAI_API_KEY"
wire_api = "responses"
env_http_headers = { "X-GH-Agent-Run-ID" = "GH_AGENT_RUN_ID" }
`, haikuAlias, proxyURL+"/v1")
	if err := os.WriteFile(filepath.Join(codexHome, "config.toml"), []byte(config), 0o600); err != nil {
		return err
	}

	outputPath := filepath.Join(tmp, "codex-final.txt")
	// #nosec G204 -- codexPath comes from PATH lookup and args are fixed by this E2E harness.
	cmd := exec.CommandContext(ctx, codexPath,
		"exec",
		"--ephemeral",
		"--json",
		"--sandbox", "read-only",
		"--skip-git-repo-check",
		"--ignore-rules",
		"-C", workDir,
		"-o", outputPath,
		"Reply with exactly: "+codexSentinel,
	)
	cmd.Dir = root
	cmd.Env = append(os.Environ(),
		"CODEX_HOME="+codexHome,
		"OPENAI_API_KEY="+proxyToken,
		"GH_AGENT_RUN_ID="+codexRunID,
	)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("codex exec failed: %w\nstdout:\n%s\nstderr:\n%s", err, stdout.String(), stderr.String())
	}
	// #nosec G304 -- outputPath is generated under this harness temp dir.
	final, err := os.ReadFile(outputPath)
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(final)) != codexSentinel {
		return fmt.Errorf("codex final output = %q, want %q\nstdout:\n%s\nstderr:\n%s", strings.TrimSpace(string(final)), codexSentinel, stdout.String(), stderr.String())
	}
	if err := assertUpstreamRequest(upstream, haikuUpstream, true); err != nil {
		return fmt.Errorf("codex exec upstream request: %w", err)
	}
	return nil
}

func verifyAuditAndBudget(auditPath, statePath string, expectCodex bool) error {
	// #nosec G304 -- auditPath is generated under this harness temp dir.
	audit, err := os.ReadFile(auditPath)
	if err != nil {
		return err
	}
	auditText := string(audit)
	for _, want := range []string{rawRunID, streamRunID, `"endpoint":"/v1/responses"`, `"decision":"allow"`} {
		if !strings.Contains(auditText, want) {
			return fmt.Errorf("audit missing %q:\n%s", want, auditText)
		}
	}
	if expectCodex && !strings.Contains(auditText, codexRunID) {
		return fmt.Errorf("audit missing Codex CLI run %q:\n%s", codexRunID, auditText)
	}
	for _, secret := range []string{proxyToken, upstreamToken, privatePrompt} {
		if strings.Contains(auditText, secret) {
			return fmt.Errorf("audit leaked secret/private text %q", secret)
		}
	}

	// #nosec G304 -- statePath is generated under this harness temp dir.
	state, err := os.ReadFile(statePath)
	if err != nil {
		return err
	}
	stateText := string(state)
	for _, want := range []string{rawRunID, streamRunID} {
		if !strings.Contains(stateText, want) {
			return fmt.Errorf("budget state missing %q:\n%s", want, stateText)
		}
	}
	if expectCodex && !strings.Contains(stateText, codexRunID) {
		return fmt.Errorf("budget state missing Codex CLI run %q:\n%s", codexRunID, stateText)
	}
	return nil
}

func stopProcess(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	if err := cmd.Process.Signal(os.Interrupt); err != nil {
		log.Printf("interrupt proxy: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		if err := cmd.Process.Kill(); err != nil {
			log.Printf("kill proxy: %v", err)
		}
		<-done
	}
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("write json: %v", err)
	}
}
