# GitHub Agent Access Broker

A small Go broker that lets agent containers use GitHub App access without receiving GitHub credentials.

The broker runs separately from Hermes, owns the GitHub App private key, authenticates agents with broker credentials, enforces deny-by-default policy, proxies approved Git smart-HTTP requests to GitHub, performs approved GitHub REST operations, and writes JSONL audit events.

## V1 Capabilities

- GitHub App installation token minting inside the broker only.
- Per-agent static broker authentication.
- HTTP Git proxy for clone/fetch/push.
- REST endpoints for repo probe, PR creation, issue creation, issue/PR comments, policy dry-run, health, readiness, and config reload.
- Optional host-side MCP issue reporter that exposes a single `broker_report_issue` tool.
- Generic metadata assertions with `off`, `warn`, and `enforce` modes.
- Structured denial responses with self-correction guidance.
- YAML config and JSONL audit logs.

## Run

Create GitHub App private keys under `./secrets/`, update `configs/example.yaml` with the real App IDs, installation IDs, repos, and policy, then run:

```sh
docker compose -f docker-compose.example.yml up --build
```

For local development:

```sh
make check
go run ./cmd/broker -config configs/example.yaml
```

The example config reads agent/admin secrets from environment variables.

## Container Artifacts And Deploy

CI publishes the primary deploy artifact as an OCI image at:

```text
ghcr.io/grubbyhacker/gh-agent-broker
```

Images are tagged with immutable commit tags such as `sha-fcd5400...`, the `main` convenience tag for main-branch builds, and semver tags such as `v0.1.0` for intentional releases. Production should pin a SHA or semver tag, not `main` or `latest`.

Semver tag builds also publish GitHub Release binaries:

- `gh-agent-broker-linux-amd64`
- `gh-agent-broker-cli-linux-amd64`
- `broker-issue-reporter-linux-amd64`
- `SHA256SUMS`

Use the OCI image for the broker service and the reporter service. Use the CLI binary as an agent runtime artifact when an agent container should call stable broker commands instead of constructing raw REST requests.

For production deployment, keep private config, `.env`, and PEM files outside git. Use `.env.example` only as a variable-name template, then deploy with the production Compose template:

```sh
BROKER_IMAGE=ghcr.io/grubbyhacker/gh-agent-broker:sha-REPLACE_WITH_COMMIT_SHA \
  docker compose -f docker-compose.production.example.yml pull
BROKER_IMAGE=ghcr.io/grubbyhacker/gh-agent-broker:sha-REPLACE_WITH_COMMIT_SHA \
  docker compose -f docker-compose.production.example.yml up -d
```

Rollback is the same command sequence with the previous known-good image tag.

## Code Hygiene

This repo uses a strict local and CI gate:

```sh
make fmt
make check
```

`make check` runs formatting checks, `go mod tidy` drift detection, `golangci-lint`, unit tests, race tests, `govulncheck`, and binary builds. The project targets Go 1.26.x.

Docker container smoke testing is intentionally separate from `make check` because it requires a local Docker daemon:

```sh
make smoke-container
```

## Development Environment

The repo exposes two supported setup paths:

- `.devcontainer/devcontainer.json` for VS Code Dev Containers and GitHub Codespaces.
- `.mise.toml` for local tool version management with `mise`.

With `mise` installed:

```sh
mise trust
mise install
mise run check
```

The dev container runs `mise install`, installs repo tools, and runs `make check` during creation. Secrets and local e2e files are not mounted or created by default.

## Agent CLI Examples

Agents should prefer `gh-agent-broker-cli` for broker REST workflows. A reusable
agent skill is available at `skills/gh-agent-broker`; install or copy that skill
into compatible agent runtimes so agents use the broker CLI consistently.

```sh
export BROKER_URL=http://127.0.0.1:8080
export BROKER_AGENT_ID=hermes-coder-01
export BROKER_AGENT_SECRET=replace-me-agent-secret

gh-agent-broker-cli configure -repo example-org/example-repo
gh-agent-broker-cli probe -repo example-org/example-repo
gh-agent-broker-cli dry-run -repo example-org/example-repo -operation pull.create -branch agent/hermes-coder-01/demo -base main -metadata Agent-Id=hermes-coder-01 -metadata Hermes-Run-Id=run-123
gh-agent-broker-cli pr -repo example-org/example-repo -title "Agent change" -head agent/hermes-coder-01/demo -base main -metadata Agent-Id=hermes-coder-01 -metadata Hermes-Run-Id=run-123
```

Git remotes should point at broker URLs such as:

```text
http://127.0.0.1:8080/git/example-org/example-repo.git
```

Use the agent ID and broker secret for Git HTTP basic auth. Do not place GitHub tokens in the agent container.

`gh-agent-broker-cli configure` also installs a repo-local Git credential helper
for the broker remote. The helper reads `BROKER_AGENT_ID` and
`BROKER_AGENT_SECRET` at fetch/push time and does not store the broker secret in
Git config. Unauthenticated broker responses include
`WWW-Authenticate: Basic realm="gh-agent-broker"` so other standard Git
credential helpers and `GIT_ASKPASS` can still provide broker credentials.

For Hermes agents on the same deployment host, prefer a dedicated broker Compose project and point the agent at the broker over `127.0.0.1` or a private Docker network. A production-oriented config template is available at `configs/production.example.yaml`; copy it to a private path and replace all placeholders before use. The coder GitHub App needs repository permissions for Contents read/write, Pull requests read/write, Issues read/write, and Metadata read. The reporter GitHub App should be separate and limited to Issues read/write plus Metadata read.

Hermes should provide only broker credentials:

```sh
export BROKER_URL=http://127.0.0.1:8080
export BROKER_AGENT_ID=hermes-agent-01
export BROKER_AGENT_SECRET=replace-me-agent-secret
```

Configure a repository remote through the broker:

```sh
gh-agent-broker-cli configure -repo OWNER/REPO -remote origin
git remote -v
GIT_TERMINAL_PROMPT=0 git fetch origin main
```

The broker also exposes unauthenticated discovery routes so agents can find the raw REST API:

```text
GET /docs
GET /operations
GET /openapi.json
GET /whoami
```

The raw REST routes use the `/v1` prefix and broker agent basic auth:

```text
GET  /v1/repos/OWNER/REPO/probe
POST /v1/policy/dry-run
POST /v1/repos/OWNER/REPO/pulls
POST /v1/repos/OWNER/REPO/issues
POST /v1/repos/OWNER/REPO/issues/NUMBER/comments
```

Issue creation should normally be exposed to agents through the host-side MCP
reporter instead of the CLI. The reporter runs outside the agent container,
owns the `broker-reporter-01` broker credential, and should use a separate
issues-only GitHub App context:

```sh
broker-issue-reporter -config configs/reporter.example.yaml
```

Configure compatible agent runtimes to connect to the reporter MCP URL, for
example `http://broker-issue-reporter:8090/mcp`, and call
`broker_report_issue` with `repo`, `title`, `body`, and `dedupe_key`. The
reporter always adds `agent-reported`, enforces an explicit repo allowlist, and
only accepts configured extra labels.

For `policy.dry-run`, the repository may be supplied as `repo: "OWNER/REPO"`, `repository: "OWNER/REPO"`, or `owner: "OWNER"` plus `repo: "REPO"`. Dry-run simulates broker-injected metadata such as `Broker-Operation-Id` and `GitHub-App-Installation-Id`; agents should not supply those fields.

Create PRs and comments with metadata fields that match the configured policy. The names below are examples from the sample config, not hard-coded broker fields:

```sh
gh-agent-broker-cli pr \
  -repo OWNER/REPO \
  -title "Hermes agent change" \
  -head agent/hermes-agent-01/run-123 \
  -base main \
  -metadata Agent-Id=hermes-agent-01 \
  -metadata Hermes-Run-Id=run-123

gh-agent-broker-cli comment \
  -repo OWNER/REPO \
  -issue 123 \
  -body "Hermes finished this run." \
  -metadata Agent-Id=hermes-agent-01 \
  -metadata Hermes-Run-Id=run-123
```

Hermes subagents that use the same GitHub permission set can share the same broker identity, but should use distinct `Hermes-Run-Id` values for auditability. Subagents that need different repository access, branch rules, or GitHub permissions should be modeled as separate broker agents with separate secrets and policy blocks; for stronger runtime isolation, run those subagents in separate containers. A future broker delegated-credential flow may make same-container scoped delegation safer, but V1 keeps the boundary at the broker principal.

See `plans/compose-production-deploy.md` for the sanitized Compose topology, volume, secret, and rollback runbook.

## Notes

V1 validates operation, repo, branch, base branch, permissions, and configurable metadata. It does not hard-code Hermes metadata names; those are sample policy fields in `configs/example.yaml`.

Strict server-side rejection of commits based on commit trailers is intentionally deferred. Doing that robustly requires broker-terminated Git receive rather than transparent proxying.
