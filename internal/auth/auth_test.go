package auth

import (
	"net/http/httptest"
	"testing"

	"gh-agent-broker/internal/config"
)

func TestAuthenticateAgentBasicAuth(t *testing.T) {
	cfg := testConfig()
	req := httptest.NewRequest("GET", "/", nil)
	req.SetBasicAuth("agent-1", "secret")

	principal, ok := AuthenticateAgent(req, cfg)
	if !ok {
		t.Fatalf("AuthenticateAgent() failed")
	}
	if principal.ID != "agent-1" {
		t.Fatalf("principal ID = %q", principal.ID)
	}
}

func TestAuthenticateAgentRejectsDisabled(t *testing.T) {
	cfg := testConfig()
	cfg.Agents[0].Enabled = false
	req := httptest.NewRequest("GET", "/", nil)
	req.SetBasicAuth("agent-1", "secret")

	if _, ok := AuthenticateAgent(req, cfg); ok {
		t.Fatalf("AuthenticateAgent() succeeded for disabled agent")
	}
}

func TestAuthenticateAdmin(t *testing.T) {
	cfg := testConfig()
	req := httptest.NewRequest("POST", "/", nil)
	req.Header.Set("X-Admin-Secret", "admin-secret")

	if !AuthenticateAdmin(req, cfg) {
		t.Fatalf("AuthenticateAdmin() failed")
	}
}

func testConfig() *config.Config {
	return &config.Config{
		Server: config.ServerConfig{AdminSecret: "admin-secret"},
		Agents: []config.Agent{{
			ID:      "agent-1",
			Enabled: true,
			Secret:  "secret",
		}},
	}
}
