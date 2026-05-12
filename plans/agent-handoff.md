# Agent Handoff

## Current State

The repository is a greenfield Go implementation of a GitHub Agent Access Broker.

Latest Hermes retest result:

- GO for the first controlled research-agent project using `BROKER_AGENT_ID=hermes-coder-01` and `grubbyhacker/research`.
- Hermes focused v1 REST/readiness suite passed: 24 pass, 0 fail.
- Dry-run shape tests passed for `repo`, `repository`, and `owner`+`repo` forms.
- Git `GIT_ASKPASS` works after the `WWW-Authenticate` fix.
- Git clone/fetch, allowed branch push, unauthorized branch denial, repo probe, PR creation, and issue comment creation all pass through the broker.
- Latest Hermes readiness side effects:
  - Branch: `agent/hermes-coder-01/research-agent-readiness-20260512-014725`
  - Pull request: `#5`
  - Comment: created on PR `#5` through broker `issue.comment`.

Remaining after this attempt:

- Decide whether to enforce `Hermes-Run-Id` on Git `receive-pack` for stronger audit metadata.
- Move `issue.comment` metadata assertions from warn mode to enforce mode before broader autonomous usage.
- Design multi-principal or delegated scoped credentials for subagents with different permission sets.
- Confirm the first GHCR image publish after this workflow lands on `main`, then switch the production Compose project to the pinned image template.
- Confirm the GHCR package is public after first publish if deployment hosts should pull without registry credentials.
- Confirm the first semver release uploads standalone Linux binaries and `SHA256SUMS`.

Tonight's recommended research-agent pattern:

- Broker URL: `http://gh-agent-broker:8080`
- Git remote: `http://gh-agent-broker:8080/git/grubbyhacker/research.git`
- Branches: `agent/hermes-coder-01/<task-slug>`
- Base branch: `main`
- Start each run with `GET /readyz` and authenticated `GET /whoami`.
- Before PR creation, run `POST /v1/policy/dry-run` with `operation: pull.create`, `owner: grubbyhacker`, `repo: research`, `branch`, `base_branch: main`, and metadata fields `Agent-Id` and `Hermes-Run-Id`.
- Use one broker identity only for same-permission subagents; distinguish them with `Hermes-Run-Id` suffixes such as `research-run-001:planner`.
- Use separate broker identities, and preferably separate sandbox containers, for subagents with different permission sets.

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
- Sanitized Compose production deployment runbook, production config example, container smoke target, and fake GitHub REST/Git smart-HTTP integration tests.

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
- CI now runs the Go hygiene gate, a Docker container smoke test, and publishes the primary deploy artifact to GHCR after successful `main` or semver tag pushes.
- Published image tags are immutable `sha-<commit>`, the `main` convenience tag, and semver release tags; production deployments should pin SHA or semver tags, not `main` or `latest`.
- Semver tag builds also publish `gh-agent-broker-linux-amd64`, `gh-agent-broker-cli-linux-amd64`, and `SHA256SUMS` as GitHub Release artifacts.

## Important Design Choices

- V1 uses HTTP Git, not SSH Git.
- V1 proxies Git to GitHub and injects GitHub App installation tokens upstream only.
- V1 does not expose a general token minting API.
- V1 enforces metadata assertions on broker REST operations and dry-runs.
- Server-side rejection of pushed commits based on commit trailers is deferred because it requires broker-terminated Git receive for strong enforcement.
- Hermes-specific metadata is represented in example config only.
- The first Hermes integration is documented as a separate Docker Compose broker project, not a Hermes sidecar or systemd-managed container.
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

## Compose Deployment Prep

- `plans/compose-production-deploy.md` now documents topology, ports, volumes, secrets, first install, and rollback with public-safe placeholders.
- Production Compose deployment should use `docker-compose.production.example.yml` with `BROKER_IMAGE=ghcr.io/grubbyhacker/gh-agent-broker:sha-COMMIT`; local development can keep using the source-build `docker-compose.example.yml`.
- The production Compose template reads host-owned secrets from `.env` by default and keeps private config/key mounts outside git; `.env` is ignored by git and excluded from the Docker build context.
- Agent runtimes should install or bind-mount `gh-agent-broker-cli`; compatible agents can use the generic `skills/gh-agent-broker` skill to prefer CLI commands over raw REST calls.
- `configs/production.example.yaml` documents required GitHub App permissions and keeps Hermes metadata names as config examples only.
- README now includes Hermes CLI usage for remotes, broker env vars, PRs, comments, and metadata.
- Dockerfile now creates `/var/log/gh-agent-broker` owned by UID 65532, and the Compose example uses a named audit volume by default.
- `internal/server/integration_test.go` covers fake GitHub REST operations, fake Git smart-HTTP proxying, auth-header filtering, and Git denial UX.
- `make smoke-container` builds the image, validates config-check failure behavior, starts the broker with generated test key/config, and checks health.
- Latest verification in this handoff: `git diff --check`, production Compose config rendering with a dummy pinned image, `mise exec -- make ci`, and `make smoke-container` passed. Plain `make ci` with the system `go1.18.1` fails before tests because the repo requires the `.mise.toml` Go toolchain.

## VPS Deployment Status

- `hermes-vps` has a running broker Compose project at `/docker/gh-agent-broker`.
- Broker Compose now consumes `BROKER_IMAGE` from `/docker/gh-agent-broker/.env`
  and is pinned to
  `ghcr.io/grubbyhacker/gh-agent-broker:sha-14f02d5de334f8f54123edcff934466631b9306e`.
- Broker health is reachable from the host at `http://127.0.0.1:8080/healthz` and from the Hermes Docker network at `http://gh-agent-broker:8080/healthz`.
- Hermes container env now includes `BROKER_URL`, `BROKER_AGENT_ID`, and `BROKER_AGENT_SECRET`.
- Hermes Compose project at `/docker/hermes-agent-6aso` now has separate
  `hermes-agent` and `hermes-gateway` services. `hermes-gateway` runs
  `gateway run` through `/opt/hermes/docker/entrypoint.sh`, has no published
  port, and reports `Gateway is running`.
- Secrets were not committed; VPS private config/key/env live outside git under `/docker/gh-agent-broker`.
- Hermes session `20260512_005558_19ac2d` discussed broker usage and recommended a Hermes skill/runbook for broker remotes, metadata, branch rules, subagent identity, and secret safety.
