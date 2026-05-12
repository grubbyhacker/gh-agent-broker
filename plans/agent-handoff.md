# Agent Handoff

## Current State

The repository starts as a greenfield Go implementation of a GitHub Agent Access Broker.

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

## Next Agent Checklist

- Read `plans/phase1.md` first.
- Run `make check`.
- Update this handoff before ending work.
