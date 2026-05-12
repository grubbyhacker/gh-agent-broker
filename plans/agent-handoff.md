# Agent Handoff

## Current State

The repository is a greenfield Go implementation of a GitHub Agent Access Broker.

Public repo:

- `https://github.com/grubbyhacker/gh-agent-broker.git`
- Initial commit pushed on `main`: `048eae0 Initial GitHub agent broker`

Implemented plan target:

- Broker service and CLI in Go.
- YAML config.
- Per-agent static broker authentication.
- Deny-by-default policy.
- Generic metadata assertions with `off`, `warn`, and `enforce` modes.
- Structured self-correction responses for denials.
- JSONL audit logs with secret redaction.
- GitHub App installation token minting inside the broker.
- HTTP Git smart proxy for clone/fetch/push.
- REST endpoints for repo probe, PR creation, comments, policy dry-run, health, readiness, and config reload.
- Sanitized Hermes VPS integration runbook, production config example, container smoke target, and fake GitHub REST/Git smart-HTTP integration tests.

Real GitHub e2e status:

- E2E was validated against `grubbyhacker/research` using local ignored config and key material.
- Broker-mediated health, repo probe, policy dry-run, clone/fetch, allowed branch push, PR creation, comment creation, and disallowed branch rejection all worked.
- Latest E2E artifacts created before the initial public push:
  - Branch: `agent/hermes-coder-01/e2e-precommit-20260511-171026`
  - PR: `https://github.com/grubbyhacker/research/pull/2`
  - Comment: `https://github.com/grubbyhacker/research/pull/2#issuecomment-4426177733`
- Local runtime artifacts are intentionally ignored: `/audit/`, `configs/e2e.local.yaml`, `secrets/`, and `.tools/`.

Code hygiene baseline:

- Target Go toolchain is Go 1.26.3.
- `.mise.toml` pins local tools and `.devcontainer/devcontainer.json` defines a containerized dev environment.
- `make check` is the local/CI gate.
- Gate includes format check, `go mod tidy` drift check, `golangci-lint`, unit tests, race tests, `govulncheck`, and builds.
- CI runs `make ci` on pushes to `main` and pull requests.
- Dependabot tracks Go modules and GitHub Actions.

## Important Design Choices

- V1 uses HTTP Git, not SSH Git.
- V1 proxies Git to GitHub and injects GitHub App installation tokens upstream only.
- V1 does not expose a general token minting API.
- V1 enforces metadata assertions on broker REST operations and dry-runs.
- Server-side rejection of pushed commits based on commit trailers is deferred because it requires broker-terminated Git receive for strong enforcement.
- Hermes-specific metadata is represented in example config only.
- First Hermes VPS integration is documented as a separate Docker Compose broker project, not a Hermes sidecar or systemd-managed container.
- Git policy denials default to a Git-friendly plain-text response with operation ID and safe self-correction details; explicit `Accept: application/json` still returns structured JSON.
- Hermes agreed that same-permission subagents can share a broker identity with distinct `Hermes-Run-Id` values, while different permission sets should become separate broker principals and preferably separate containers.
- Hermes discovered that raw REST routes were not self-describing; discovery endpoints now document the `/v1` routes at `/`, `/docs`, `/operations`, `/api/operations`, `/openapi.json`, `/whoami`, and `/api/whoami`.

## Next Agent Checklist

- Read `plans/phase1.md` first.
- Use `mise trust && mise install`, then run `mise run check`.
- If sandboxed caches are read-only, run with writable temp caches: `GOCACHE=/tmp/gh-agent-broker-gocache GOLANGCI_LINT_CACHE=/tmp/gh-agent-broker-golangci-cache mise run check`.
- Before live Hermes integration, copy `configs/production.example.yaml` to a private config path and fill in real GitHub App IDs, installation IDs, repo names, agent IDs, and secrets.
- Run `make smoke-container` when Docker is available; the broker image runs as UID 65532, so mounted audit directories must be writable by that UID.
- Update this handoff before ending work.

## Hermes VPS Integration Prep

- `plans/hermes-vps-integration.md` now documents topology, ports, volumes, secrets, first install, and rollback with public-safe placeholders.
- `configs/production.example.yaml` documents required GitHub App permissions and keeps Hermes metadata names as config examples only.
- README now includes Hermes CLI usage for remotes, broker env vars, PRs, comments, and metadata.
- Dockerfile now creates `/var/log/gh-agent-broker` owned by UID 65532, and the Compose example uses a named audit volume by default.
- `internal/server/integration_test.go` covers fake GitHub REST operations, fake Git smart-HTTP proxying, auth-header filtering, and Git denial UX.
- `make smoke-container` builds the image, validates config-check failure behavior, starts the broker with generated test key/config, and checks health.
- Latest verification in this handoff: `mise exec -- go test ./...`, `mise exec -- make check`, and `make smoke-container` passed.

## VPS Deployment Status

- `hermes-vps` has a running broker Compose project at `/docker/gh-agent-broker`.
- Broker health is reachable from the host at `http://127.0.0.1:8080/healthz` and from the Hermes Docker network at `http://gh-agent-broker:8080/healthz`.
- Hermes container env now includes `BROKER_URL`, `BROKER_AGENT_ID`, and `BROKER_AGENT_SECRET`.
- Secrets were not committed; VPS private config/key/env live outside git under `/docker/gh-agent-broker`.
- Hermes session `20260512_005558_19ac2d` discussed broker usage and recommended a Hermes skill/runbook for broker remotes, metadata, branch rules, subagent identity, and secret safety.
