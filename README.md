# GitHub Agent Access Broker

A Go broker that lets agent containers use GitHub App access without receiving
GitHub credentials.

The broker owns the GitHub App private key, authenticates agents with broker
credentials, enforces deny-by-default policy, proxies approved Git smart-HTTP
requests, performs approved GitHub REST operations, and writes redacted JSONL
audit events.

## Components

- `gh-agent-broker`: the main HTTP service. It handles Git smart-HTTP proxying,
  GitHub REST operations, policy checks, audit logging, health/readiness, and
  OpenAPI-style discovery.
- `gh-agent-broker-cli`: the stable agent-facing CLI for health checks, config
  checks, repo probes, policy dry-runs, PRs, comments, and broker Git remote
  setup.
- `broker-issue-reporter`: a host-side MCP reporter service for issue creation
  through a narrow reporter broker identity. It exposes
  `broker_reporter_capabilities` and `broker_report_issue`.
- `sandbox-broker`: a separate MCP service that launches task-scoped worker
  containers from operator-defined templates.
- `gh-agent-proxy`: a narrow self-hosted model-call facade for sandboxed
  workers. It keeps provider keys in the proxy/LiteLLM service, enforces
  per-run budgets, and avoids prompt-body logging by default.

GitHub App installation tokens stay inside the broker. Agents receive only
broker credentials or MCP access to a host-side service.

## Current Capabilities

- Per-agent static broker authentication.
- GitHub App installation token minting inside the broker only.
- HTTP Git proxy for clone, fetch, and push.
- REST endpoints for repo probe, policy dry-run, PR creation, issue creation,
  issue/PR comments, PR/issue/status/check reads, health/readiness, discovery,
  and config reload.
- Generic metadata assertions with `off`, `warn`, and `enforce` modes.
- Structured denial responses with self-correction guidance.
- YAML config, JSONL audit logs, and redaction of known secret values.
- Optional MCP issue reporter and sandbox broker services.

V1 validates operation, repo, branch, base branch, permissions, and configurable
metadata. It does not hard-code Hermes metadata names; fields such as
`Hermes-Run-Id` are sample policy fields in the example configs.

## Quick Start

Create GitHub App private keys under `./secrets/`, update
`configs/example.yaml` with real App IDs, installation IDs, repos, and policy,
then run:

```sh
docker compose -f docker-compose.example.yml up --build
```

For local development:

```sh
make check
go run ./cmd/broker -config configs/example.yaml
```

The example configs read agent, admin, reporter, and sandbox secrets from
environment variables.

## Development

This repo targets Go 1.26.x. `make check` is the source of truth for local and
CI hygiene:

```sh
make fmt
make check
```

`make check` runs formatting checks, `go mod tidy` drift detection,
`golangci-lint`, unit tests, race tests, `govulncheck`, and binary builds.

Docker-dependent checks are separate:

```sh
make smoke-container
make sandbox-e2e
```

Supported setup paths are `.mise.toml` and `.devcontainer/devcontainer.json`.
With `mise` installed:

```sh
mise trust
mise install
mise run check
```

## Agent Usage

Agents should prefer `gh-agent-broker-cli` for broker REST workflows and broker
Git remote setup. Reusable agent guidance lives in `skills/gh-agent-broker`.

```sh
export BROKER_URL=http://127.0.0.1:8080
export BROKER_AGENT_ID=hermes-coder-01
export BROKER_AGENT_SECRET=replace-me-agent-secret

gh-agent-broker-cli configure -repo example-org/example-repo
gh-agent-broker-cli whoami
gh-agent-broker-cli probe -repo example-org/example-repo
gh-agent-broker-cli pr \
  -repo example-org/example-repo \
  -title "Agent change" \
  -head agent/hermes-coder-01/demo \
  -base main \
  -metadata Agent-Id=hermes-coder-01 \
  -metadata Hermes-Run-Id=run-123
```

Broker Git remotes use this shape:

```text
http://127.0.0.1:8080/git/example-org/example-repo.git
```

`gh-agent-broker-cli configure` installs a repo-local Git credential helper that
reads `BROKER_AGENT_ID` and `BROKER_AGENT_SECRET` at fetch/push time. It does
not store the broker secret in Git config. Standard Git credential helpers and
`GIT_ASKPASS` can also provide broker credentials.

Do not put GitHub tokens, GitHub App private keys, GitHub App JWTs, or
installation tokens inside the agent container.

## HTTP API

Unauthenticated discovery routes:

```text
GET /docs
GET /operations
GET /openapi.json
```

Broker-agent authenticated routes:

```text
GET  /whoami
GET  /v1/repos/OWNER/REPO/probe
POST /v1/policy/dry-run
GET  /v1/repos/OWNER/REPO/pulls
GET  /v1/repos/OWNER/REPO/pulls/NUMBER
GET  /v1/repos/OWNER/REPO/pulls/NUMBER/files
GET  /v1/repos/OWNER/REPO/pulls/NUMBER/comments
GET  /v1/repos/OWNER/REPO/pulls/NUMBER/reviews
GET  /v1/repos/OWNER/REPO/pulls/NUMBER/review-comments
GET  /v1/repos/OWNER/REPO/pulls/NUMBER/review-threads
POST /v1/repos/OWNER/REPO/pulls
GET  /v1/repos/OWNER/REPO/issues
GET  /v1/repos/OWNER/REPO/issues/NUMBER
GET  /v1/repos/OWNER/REPO/issues/NUMBER/comments
POST /v1/repos/OWNER/REPO/issues
POST /v1/repos/OWNER/REPO/issues/NUMBER/comments
GET  /v1/repos/OWNER/REPO/commits/SHA/status
GET  /v1/repos/OWNER/REPO/commits/SHA/check-runs
```

For `policy.dry-run`, the repository may be supplied as `repo: "OWNER/REPO"`,
`repository: "OWNER/REPO"`, or `owner: "OWNER"` plus `repo: "REPO"`.

## Reporter MCP Service

Issue creation should normally go through the host-side MCP reporter. The
reporter runs outside the agent container, owns a reporter broker credential,
and should use a separate issues-only GitHub App context.

```sh
broker-issue-reporter -config configs/reporter.example.yaml
```

Reporter tools:

- `broker_reporter_capabilities`: returns allowed repositories, allowed
  optional labels, forced labels, title/body limits, and dedupe requirements.
- `broker_report_issue`: creates an allowlisted GitHub issue with `repo`,
  `title`, `body`, `dedupe_key`, optional source metadata, and optional
  allowlisted labels.
- `broker_get_issue`, `broker_search_issues`, and
  `broker_list_issue_comments`: read/query allowlisted issues through the
  reporter identity.

The reporter always applies the configured default label, enforces explicit
repo and label allowlists, and never returns broker or GitHub credentials.

## Model Proxy

`gh-agent-proxy` is intended for sandboxed workers that need model calls without
receiving provider keys. It exposes `POST /v1/model/call`, requires a private
bearer token, forwards to a configured LiteLLM-compatible upstream, and tracks
per-run call/token budgets in a file-backed state store.

The proxy logs run ID, model, decision, and token counts only. Keep
`log_prompts: false` in production because prompts and responses may contain
private corpus, upload, feedback, or log excerpts.

## Sandbox MCP Broker

The sandbox broker is a separate process in the same OCI image:

```sh
sandbox-broker -config configs/sandbox.example.yaml
```

It exposes MCP at `/mcp` and requires `X-Sandbox-Token` or
`Authorization: Bearer ...`. Agent runtimes should receive only the MCP URL and
token. Do not give them the Docker socket, host root, parent data directories,
session files, credential stores, or arbitrary host mounts.

`configs/sandbox.example.yaml` defines repository allowlists, Docker network
policies, credential bundles, and fixed templates. Launch requests provide
intent only: template, task, repo, base branch, optional branch, optional max
runtime, deliverables, and focus. Callers cannot choose images, commands,
environment, mounts, privileged mode, host paths, or network overrides.

Every launch gets a read-only `/input` task contract and required deliverables
under `/output` or `/lessons`. Worker wrappers should fail nonzero when required
sandbox filesystem deliverables are missing.

Hermes worker templates use read-only credential bundles, copy minimal auth into
task-local `/work/hermes`, set `HERMES_HOME=/work/hermes`, and run Hermes there.
Do not send OAuth JSON or API keys in MCP launch requests.

The sandbox broker image runs as UID/GID `65532`. When mounting
`/var/run/docker.sock`, set
`DOCKER_SOCK_GID=$(stat -c '%g' /var/run/docker.sock)` for Compose so
`group_add` grants Docker Engine access without running the broker container as
root.

## Deploy

CI publishes the primary deploy artifact as an OCI image:

```text
ghcr.io/grubbyhacker/gh-agent-broker
```

Images are tagged with immutable commit tags such as `sha-fcd5400...`, `main`
for main-branch builds, and semver tags such as `v1.0.0`. Production should pin
a SHA or semver tag, not `main` or `latest`.

Semver tag builds also publish Linux amd64 binaries for `gh-agent-broker`,
`gh-agent-broker-cli`, `broker-issue-reporter`, and `sandbox-broker`, plus
`SHA256SUMS`.

Use the OCI image for the broker, reporter, and sandbox-broker services. Use
the CLI binary as an agent runtime artifact when an agent container should call
stable broker commands.

For production deployment, keep private config, `.env`, and PEM files outside
git. Use `.env.example` only as a variable-name template, then deploy with the
production Compose template:

```sh
BROKER_IMAGE=ghcr.io/grubbyhacker/gh-agent-broker:sha-REPLACE_WITH_COMMIT_SHA \
  docker compose -f docker-compose.production.example.yml pull
BROKER_IMAGE=ghcr.io/grubbyhacker/gh-agent-broker:sha-REPLACE_WITH_COMMIT_SHA \
  docker compose -f docker-compose.production.example.yml up -d
```

Rollback is the same command sequence with the previous known-good image tag.

For Compose deployments that include sandbox workers, mount `runs_dir` and
credential bundle source paths at the same absolute paths seen by the Docker
host.

See `plans/compose-production-deploy.md` for the sanitized production topology,
volume, secret, and rollback runbook.

## Notes

Strict server-side rejection of commits based on commit trailers is
intentionally deferred. Doing that robustly requires broker-terminated Git
receive rather than transparent proxying.
