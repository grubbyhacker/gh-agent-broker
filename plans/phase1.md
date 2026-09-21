> **STATUS: IMPLEMENTED — HISTORICAL PLAN.** The v1 broker (config, agent auth,
> deny-by-default policy, GitHub App JWT/token exchange, Git smart-HTTP proxy,
> CLI, Dockerfile/compose) shipped and is the current production surface; this
> is the original v1 scope record.

# Phase 1 Plan

## Goal

Deliver a runnable v1 broker that proves agents can clone/fetch/push and create PRs/comments through a separate service using GitHub App authentication, without placing GitHub credentials inside the Hermes container.

## Build

- Create Go module and package layout.
- Implement YAML config, agent auth, policy checks, metadata assertions, structured errors, and audit logs.
- Implement GitHub App JWT/token exchange and minimal GitHub REST client.
- Implement HTTP Git proxy endpoints for Git smart-HTTP.
- Implement CLI commands for agent-facing workflows.
- Add Dockerfile, example config, and example Compose wiring.

## Acceptance

- `go test ./...` passes.
- Broker starts with example config structure.
- Denied requests return machine-readable repair guidance.
- Audit logs contain request/decision/result data without secrets.

