# GitHub Agent Access Broker

A small Go broker that lets agent containers use GitHub App access without receiving GitHub credentials.

The broker runs separately from Hermes, owns the GitHub App private key, authenticates agents with broker credentials, enforces deny-by-default policy, proxies approved Git smart-HTTP requests to GitHub, performs approved GitHub REST operations, and writes JSONL audit events.

## V1 Capabilities

- GitHub App installation token minting inside the broker only.
- Per-agent static broker authentication.
- HTTP Git proxy for clone/fetch/push.
- REST endpoints for repo probe, PR creation, issue/PR comments, policy dry-run, health, readiness, and config reload.
- Generic metadata assertions with `off`, `warn`, and `enforce` modes.
- Structured denial responses with self-correction guidance.
- YAML config and JSONL audit logs.

## Run

Create a GitHub App private key at `./secrets/github-app.pem`, update `configs/example.yaml` with the real App ID, installation ID, repo, and policy, then run:

```sh
docker compose -f docker-compose.example.yml up --build
```

For local development:

```sh
make check
go run ./cmd/broker -config configs/example.yaml
```

The example config reads agent/admin secrets from environment variables.

## Code Hygiene

This repo uses a strict local and CI gate:

```sh
make fmt
make check
```

`make check` runs formatting checks, `go mod tidy` drift detection, `golangci-lint`, unit tests, race tests, `govulncheck`, and binary builds. The project targets Go 1.26.x.

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

## Notes

V1 validates operation, repo, branch, base branch, permissions, and configurable metadata. It does not hard-code Hermes metadata names; those are sample policy fields in `configs/example.yaml`.

Strict server-side rejection of commits based on commit trailers is intentionally deferred. Doing that robustly requires broker-terminated Git receive rather than transparent proxying.
