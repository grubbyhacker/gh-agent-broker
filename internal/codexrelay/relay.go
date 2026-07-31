// Package codexrelay exposes the exact ChatGPT subscription API surface needed
// by the pinned Codex CLI without giving execution containers general egress.
package codexrelay

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	CodexVersion = "0.146.0"
	Origin       = "https://chatgpt.com"

	maxRequestBody  = 16 * 1024 * 1024
	maxResponseBody = 64 * 1024 * 1024
	maxHeaderValue  = 16 * 1024
)

var allowed = map[string]string{
	"/backend-api/codex/models":            http.MethodGet,
	"/backend-api/codex/responses":         http.MethodPost,
	"/backend-api/codex/responses/compact": http.MethodPost,
}

type Service struct {
	client *http.Client
}

func NewService(client *http.Client) *Service {
	if client == nil {
		client = &http.Client{
			Transport: http.DefaultTransport,
			Timeout:   10 * time.Minute,
		}
	}
	copyClient := *client
	copyClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &Service{client: &copyClient}
}

func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	method, ok := allowed[r.URL.Path]
	if !ok || r.Method != method || r.URL.RawPath != "" || r.URL.IsAbs() || r.URL.Host != "" {
		http.Error(w, "denied", http.StatusForbidden)
		return
	}
	if !validQuery(r) || r.Header.Get("Authorization") == "" ||
		len(r.Header.Get("Authorization")) > maxHeaderValue ||
		!strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
		http.Error(w, "denied", http.StatusForbidden)
		return
	}
	if r.Method == http.MethodPost && r.Header.Get("Content-Type") != "application/json" {
		http.Error(w, "denied", http.StatusForbidden)
		return
	}
	body, err := readRequestBody(r)
	if err != nil {
		http.Error(w, "request body exceeds limit", http.StatusRequestEntityTooLarge)
		return
	}
	target := Origin + r.URL.EscapedPath()
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	// #nosec G704 -- method and path passed validation against the closed table
	// above, and target always begins with the compiled fixed Origin.
	req, err := http.NewRequestWithContext(r.Context(), r.Method, target, bytes.NewReader(body))
	if err != nil {
		http.Error(w, "upstream request failed", http.StatusBadGateway)
		return
	}
	if !copyRequestHeaders(req.Header, r.Header) {
		http.Error(w, "denied", http.StatusForbidden)
		return
	}
	// #nosec G704 -- req was constructed solely from the compiled fixed Origin
	// and the exact allowlisted path/query contract.
	resp, err := s.client.Do(req)
	if err != nil {
		http.Error(w, "upstream request failed", http.StatusBadGateway)
		return
	}
	defer closeBody(resp.Body)
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		http.Error(w, "upstream redirect denied", http.StatusBadGateway)
		return
	}
	copyResponseHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	streamBounded(w, resp.Body)
}

func validQuery(r *http.Request) bool {
	query := r.URL.Query()
	if r.URL.Path == "/backend-api/codex/models" {
		values, ok := query["client_version"]
		return r.URL.RawQuery == "client_version="+CodexVersion &&
			ok && len(query) == 1 && len(values) == 1 && values[0] == CodexVersion
	}
	return len(query) == 0
}

func readRequestBody(r *http.Request) ([]byte, error) {
	if r.Method == http.MethodGet {
		if r.Body == nil {
			return nil, nil
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 1))
		if err != nil || len(body) != 0 {
			return nil, fmt.Errorf("GET body is forbidden")
		}
		return nil, nil
	}
	if r.ContentLength > maxRequestBody {
		return nil, fmt.Errorf("request too large")
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBody+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxRequestBody {
		return nil, fmt.Errorf("request too large")
	}
	return body, nil
}

func copyRequestHeaders(dst, src http.Header) bool {
	for _, name := range []string{
		"Authorization", "Accept", "Content-Type", "User-Agent", "Originator",
		"ChatGPT-Account-ID", "OpenAI-Beta", "X-Codex-Turn-Metadata",
	} {
		values := src.Values(name)
		if len(values) > 1 {
			return false
		}
		if len(values) == 1 {
			if len(values[0]) > maxHeaderValue || strings.ContainsAny(values[0], "\r\n") {
				return false
			}
			dst.Set(name, values[0])
		}
	}
	return true
}

func copyResponseHeaders(dst, src http.Header) {
	for _, name := range []string{"Content-Type", "Cache-Control", "X-Request-ID", "OpenAI-Processing-Ms"} {
		if value := src.Get(name); value != "" && len(value) <= maxHeaderValue {
			dst.Set(name, value)
		}
	}
}

func streamBounded(w http.ResponseWriter, body io.Reader) {
	reader := io.LimitReader(body, maxResponseBody+1)
	buffer := make([]byte, 32*1024)
	var written int64
	for {
		n, err := reader.Read(buffer)
		if n > 0 {
			if written+int64(n) > maxResponseBody {
				return
			}
			if _, writeErr := w.Write(buffer[:n]); writeErr != nil {
				return
			}
			written += int64(n)
			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}
		}
		if err != nil {
			return
		}
	}
}

func closeBody(body io.Closer) {
	//nolint:errcheck // Response close errors cannot affect an already completed relay response.
	_ = body.Close()
}

// FixedOriginTransport is useful for contract tests while preserving the
// production invariant that requests are always addressed to Origin.
type FixedOriginTransport func(*http.Request) (*http.Response, error)

func (f FixedOriginTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme != "https" || req.URL.Host != "chatgpt.com" {
		return nil, errors.New("non-fixed upstream origin")
	}
	return f(req)
}

func ListenAndServe(ctx context.Context, address string, service *Service) error {
	server := &http.Server{
		Addr:              address,
		Handler:           service,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      0,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    32 * 1024,
	}
	//nolint:gosec // G118: shutdown must outlive any individual request context.
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		//nolint:errcheck // ListenAndServe returns the authoritative shutdown result.
		_ = server.Shutdown(shutdownCtx)
	}()
	err := server.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
