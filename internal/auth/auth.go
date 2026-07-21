// Package auth authenticates broker agents and local admin requests.
package auth

import (
	"crypto/subtle"
	"net/http"
	"strings"

	"gh-agent-broker/internal/config"
)

type Principal struct {
	Agent              config.Agent
	ID                 string
	TransportPrincipal string
}

func AuthenticateAgent(r *http.Request, cfg *config.Config) (Principal, bool) {
	id := r.Header.Get("X-Agent-ID")
	secret := r.Header.Get("X-Agent-Secret")
	if id == "" || secret == "" {
		u, p, ok := r.BasicAuth()
		if ok {
			id, secret = u, p
		}
	}
	id = strings.TrimSpace(id)
	if id == "" || secret == "" {
		return Principal{}, false
	}
	agent, ok := cfg.AgentByID(id)
	if !ok || !agent.Enabled || agent.Secret == "" {
		return Principal{}, false
	}
	if subtle.ConstantTimeCompare([]byte(secret), []byte(agent.Secret)) != 1 {
		return Principal{}, false
	}
	return Principal{Agent: agent, ID: id, TransportPrincipal: id}, true
}

func AuthenticateAdmin(r *http.Request, cfg *config.Config) bool {
	if cfg.Server.AdminSecret == "" {
		return false
	}
	got := r.Header.Get("X-Admin-Secret")
	if got == "" {
		_, got, _ = r.BasicAuth()
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(cfg.Server.AdminSecret)) == 1
}
