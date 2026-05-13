# AGENTS.md

This repository is intended to be worked on by coding agents. Keep this file current when implementation conventions change.

## Project Goal

Build a GitHub Agent Access Broker that lets agent containers use GitHub App access without receiving GitHub credentials. The broker runs separately from Hermes, owns the GitHub App private key, authenticates agents, enforces policy, proxies approved Git operations, performs approved GitHub REST operations, and writes audit logs.

## Operating Rules

- Do not add code paths that return GitHub App installation tokens to agents by default.
- Keep Hermes-specific fields configurable. Do not hard-code `Hermes-Run-Id`, `Agent-Id`, or similar metadata names into policy logic.
- Use deny-by-default policy behavior.
- Return structured denial details that give agents enough information to self-correct without exposing secrets or unrelated policy.
- Never log GitHub private keys, JWTs, installation tokens, broker agent secrets, or authorization headers.
- Keep `plans/agent-handoff.md` updated with the latest useful context before handing off to another agent.

## Development

- Language: Go.
- Target toolchain: Go 1.26.x.
- Prefer small packages under `internal/` with unit tests for policy, metadata, auth, and audit behavior.
- Use `make fmt` on changed Go files.
- Run `make check` before handoff when possible.
- Do not add broad lint suppressions. Any `//nolint` must name the exact linter and include a reason.
- Do not hide Go or other source code in shell heredocs, generated temp files, or compiler stdin to bypass formatting, tests, review, or linting. Test harnesses and helper clients must be checked-in source files unless the generated file is a small data/config fixture.
- Keep `go.mod` and `go.sum` tidy.
- Use `.mise.toml` or the dev container to satisfy repo toolchain requirements; keep `make check` as the source of truth.
