package githubapp

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"gh-agent-broker/internal/config"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func testClient(rt http.RoundTripper) *Client {
	return &Client{
		cfg:  config.GitHubConfig{APIBaseURL: "https://api.github.test"},
		http: &http.Client{Transport: rt},
		apps: map[string]*appClient{"app": {tokens: map[int64]cachedToken{1: {Token: "installation-token", ExpireAt: time.Now().Add(time.Hour)}}}},
	}
}

func response(status int, body string, headers http.Header) *http.Response {
	return &http.Response{StatusCode: status, Header: headers, Body: io.NopCloser(strings.NewReader(body))}
}

func TestListCheckRunAnnotationsPaginatesAndFailsClosedAtBounds(t *testing.T) {
	t.Run("pagination", func(t *testing.T) {
		calls := 0
		client := testClient(roundTripFunc(func(r *http.Request) (*http.Response, error) {
			calls++
			page := r.URL.Query().Get("page")
			if r.URL.Path != "/repos/owner/repo/check-runs/9/annotations" || r.URL.Query().Get("per_page") != "100" {
				t.Fatalf("request=%s", r.URL.String())
			}
			if page == "1" {
				return response(http.StatusOK, "["+strings.Repeat(`{"path":"a"},`, 99)+`{"path":"a"}]`, nil), nil
			}
			if page == "2" {
				return response(http.StatusOK, `[{"path":"b"}]`, nil), nil
			}
			t.Fatalf("unexpected page %q", page)
			return response(http.StatusInternalServerError, "", nil), nil
		}))
		annotations, err := client.ListCheckRunAnnotations("app", "owner/repo", 1, 9, 101, 1<<20)
		if err != nil || len(annotations) != 101 || calls != 2 {
			t.Fatalf("annotations=%d calls=%d err=%v", len(annotations), calls, err)
		}
	})

	t.Run("item overflow", func(t *testing.T) {
		client := testClient(roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.URL.Query().Get("page") == "1" {
				return response(http.StatusOK, "["+strings.Repeat(`{"path":"a"},`, 99)+`{"path":"a"}]`, nil), nil
			}
			return response(http.StatusOK, `[{"path":"b"}]`, nil), nil
		}))
		if _, err := client.ListCheckRunAnnotations("app", "owner/repo", 1, 9, 100, 1<<20); err == nil {
			t.Fatal("item overflow returned partial annotations")
		}
	})

	t.Run("byte overflow", func(t *testing.T) {
		client := testClient(roundTripFunc(func(*http.Request) (*http.Response, error) {
			return response(http.StatusOK, `[{"path":"a","message":"large"}]`, nil), nil
		}))
		if _, err := client.ListCheckRunAnnotations("app", "owner/repo", 1, 9, 10, 1); err == nil {
			t.Fatal("byte overflow returned partial annotations")
		}
	})
}

func TestGetWorkflowJobLogRedirectSafetyAndIntegrity(t *testing.T) {
	for _, tc := range []struct {
		name, location, body string
		limit                int64
		wantErr              bool
	}{
		{"approved redirect", "https://results-receiver.actions.githubusercontent.com/log", "exact log\n", 1024, false},
		{"non https", "http://results-receiver.actions.githubusercontent.com/log", "", 1024, true},
		{"unapproved host", "https://evil.example/log", "", 1024, true},
		{"arbitrary github subdomain", "https://evil.github.com/log", "", 1024, true},
		{"oversize", "https://pipelines.actions.githubusercontent.com/log", "12345", 4, true},
		{"invalid utf8", "https://pipelines.actions.githubusercontent.com/log", string([]byte{0xff}), 1024, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			client := testClient(roundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				if calls == 1 {
					if r.Header.Get("Authorization") != "Bearer installation-token" {
						t.Fatalf("initial Authorization=%q", r.Header.Get("Authorization"))
					}
					return response(http.StatusFound, "", http.Header{"Location": []string{tc.location}}), nil
				}
				if r.Header.Get("Authorization") != "" {
					t.Fatalf("redirect forwarded Authorization=%q", r.Header.Get("Authorization"))
				}
				return response(http.StatusOK, tc.body, nil), nil
			}))
			got, err := client.GetWorkflowJobLog("app", "owner/repo", 1, 7, tc.limit)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("success=%+v, want error", got)
				}
				return
			}
			if err != nil || got.Text != tc.body || got.SizeBytes != int64(len(tc.body)) || got.SHA256 == "" || calls != 2 {
				t.Fatalf("log=%+v calls=%d err=%v", got, calls, err)
			}
		})
	}
}

func TestSafeActionsLogHostMatchesOnlyDocumentedDeliveryHosts(t *testing.T) {
	for _, host := range []string{"results-receiver.actions.githubusercontent.com", "pipelines.actions.githubusercontent.com"} {
		if !safeActionsLogHost(host) {
			t.Fatalf("approved host %q rejected", host)
		}
	}
	for _, host := range []string{"github.com", "evil.github.com", "actions.githubusercontent.com", "evil.actions.githubusercontent.com"} {
		if safeActionsLogHost(host) {
			t.Fatalf("unapproved host %q accepted", host)
		}
	}
}
