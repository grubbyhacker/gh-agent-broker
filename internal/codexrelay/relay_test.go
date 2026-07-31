package codexrelay

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRelayAllowsOnlyPinnedCodexSubscriptionSurface(t *testing.T) {
	t.Parallel()
	var requests []*http.Request
	service := NewService(&http.Client{Transport: FixedOriginTransport(func(req *http.Request) (*http.Response, error) {
		requests = append(requests, req)
		body := "ok"
		if req.URL.Path == "/backend-api/codex/responses" {
			body = "data: first\n\ndata: second\n\n"
		}
		return response(http.StatusOK, body), nil
	})})
	for _, test := range []struct {
		method string
		target string
		body   string
	}{
		{http.MethodGet, "/backend-api/codex/models?client_version=0.146.0", ""},
		{http.MethodPost, "/backend-api/codex/responses", `{"model":"gpt-5.6-terra"}`},
		{http.MethodPost, "/backend-api/codex/responses/compact", `{}`},
	} {
		req := httptest.NewRequest(test.method, test.target, strings.NewReader(test.body))
		req.Header.Set("Authorization", "Bearer subscription-access")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Unreviewed-Secret", "must-not-forward")
		recorder := &flushRecorder{ResponseRecorder: httptest.NewRecorder()}
		service.ServeHTTP(recorder, req)
		if recorder.Code != http.StatusOK {
			t.Fatalf("%s %s status=%d body=%q", test.method, test.target, recorder.Code, recorder.Body.String())
		}
	}
	if len(requests) != 3 {
		t.Fatalf("forwarded requests=%d", len(requests))
	}
	for _, req := range requests {
		if req.URL.Scheme != "https" || req.URL.Host != "chatgpt.com" {
			t.Fatalf("non-fixed upstream URL %s", req.URL)
		}
		if req.Header.Get("Authorization") != "Bearer subscription-access" {
			t.Fatal("required Authorization was not preserved")
		}
		if req.Header.Get("X-Unreviewed-Secret") != "" {
			t.Fatal("unreviewed header was forwarded")
		}
	}
}

func TestRelayDeniesEveryOtherMethodPathQueryAndHost(t *testing.T) {
	t.Parallel()
	var forwarded int
	service := NewService(&http.Client{Transport: FixedOriginTransport(func(req *http.Request) (*http.Response, error) {
		forwarded++
		return response(http.StatusOK, "unexpected"), nil
	})})
	for _, test := range []struct {
		method string
		target string
	}{
		{http.MethodPost, "/backend-api/codex/models?client_version=0.146.0"},
		{http.MethodGet, "/backend-api/codex/models"},
		{http.MethodGet, "/backend-api/codex/models?client_version=0.146.0&other=1"},
		{http.MethodGet, "/backend-api/codex/models?client_version=0.145.0"},
		{http.MethodGet, "/backend-api/codex/responses"},
		{http.MethodPost, "/backend-api/codex/responses?x=1"},
		{http.MethodPost, "/backend-api/codex/responses/compact/"},
		{http.MethodPost, "/backend-api/codex/analytics"},
		{http.MethodPost, "/backend-api/codex/responses%2fcompact"},
		{http.MethodPost, "http://attacker.example/backend-api/codex/responses"},
	} {
		req := httptest.NewRequest(test.method, test.target, strings.NewReader(`{}`))
		req.Header.Set("Authorization", "Bearer access")
		recorder := httptest.NewRecorder()
		service.ServeHTTP(recorder, req)
		if recorder.Code != http.StatusForbidden {
			t.Errorf("%s %s status=%d, want 403", test.method, test.target, recorder.Code)
		}
	}
	if forwarded != 0 {
		t.Fatalf("forwarded %d denied requests", forwarded)
	}
}

func TestRelayRejectsRedirectsAndStreamsWithoutSensitiveResponseHeaders(t *testing.T) {
	t.Parallel()
	t.Run("redirect", func(t *testing.T) {
		service := NewService(&http.Client{Transport: FixedOriginTransport(func(req *http.Request) (*http.Response, error) {
			resp := response(http.StatusFound, "")
			resp.Header.Set("Location", "https://attacker.example/")
			return resp, nil
		})})
		req := authorizedRequest(http.MethodPost, "/backend-api/codex/responses")
		recorder := httptest.NewRecorder()
		service.ServeHTTP(recorder, req)
		if recorder.Code != http.StatusBadGateway || recorder.Header().Get("Location") != "" {
			t.Fatalf("redirect status=%d headers=%v", recorder.Code, recorder.Header())
		}
	})
	t.Run("stream", func(t *testing.T) {
		service := NewService(&http.Client{Transport: FixedOriginTransport(func(req *http.Request) (*http.Response, error) {
			resp := response(http.StatusOK, "data: one\n\ndata: two\n\n")
			resp.Header.Set("Content-Type", "text/event-stream")
			resp.Header.Set("Authorization", "Bearer must-not-return")
			resp.Header.Set("Set-Cookie", "session=must-not-return")
			return resp, nil
		})})
		req := authorizedRequest(http.MethodPost, "/backend-api/codex/responses")
		recorder := &flushRecorder{ResponseRecorder: httptest.NewRecorder()}
		service.ServeHTTP(recorder, req)
		if recorder.Code != http.StatusOK || recorder.flushes == 0 ||
			recorder.Body.String() != "data: one\n\ndata: two\n\n" {
			t.Fatalf("stream status=%d flushes=%d body=%q", recorder.Code, recorder.flushes, recorder.Body.String())
		}
		if recorder.Header().Get("Authorization") != "" || recorder.Header().Get("Set-Cookie") != "" {
			t.Fatalf("sensitive response headers escaped: %v", recorder.Header())
		}
	})
}

func TestRelayHTTPContractE2E(t *testing.T) {
	t.Parallel()
	service := NewService(&http.Client{Transport: FixedOriginTransport(func(req *http.Request) (*http.Response, error) {
		return response(http.StatusOK, "data: e2e\n\n"), nil
	})})
	server := httptest.NewServer(service)
	t.Cleanup(server.Close)

	req, err := http.NewRequest(http.MethodPost, server.URL+"/backend-api/codex/responses", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer e2e-access")
	req.Header.Set("Content-Type", "application/json")
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	if closeErr := resp.Body.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || string(body) != "data: e2e\n\n" {
		t.Fatalf("allowed response status=%d body=%q", resp.StatusCode, body)
	}

	denied, err := http.NewRequest(http.MethodPost, server.URL+"/backend-api/codex/analytics", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	denied.Header.Set("Authorization", "Bearer e2e-access")
	denied.Header.Set("Content-Type", "application/json")
	deniedResp, err := server.Client().Do(denied)
	if err != nil {
		t.Fatal(err)
	}
	if err := deniedResp.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if deniedResp.StatusCode != http.StatusForbidden {
		t.Fatalf("denied status=%d", deniedResp.StatusCode)
	}
}

func authorizedRequest(method, target string) *http.Request {
	req := httptest.NewRequest(method, target, strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer access")
	req.Header.Set("Content-Type", "application/json")
	return req
}

func response(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

type flushRecorder struct {
	*httptest.ResponseRecorder
	flushes int
}

func (r *flushRecorder) Flush() {
	r.flushes++
	r.ResponseRecorder.Flush()
}
