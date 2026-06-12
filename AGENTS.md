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

- Make code and documentation changes on feature branches, not directly on `main`.
- Use the normal flow: feature branch, pull request, CI pass, then merge.
- Do not push directly to `main`.
- Never merge your own pull requests unless the human-in-the-loop explicitly instructs you to merge.
- Language: Go.
- Target toolchain: Go 1.26.x.
- Prefer small packages under `internal/` with unit tests for policy, metadata, auth, and audit behavior.
- Use `make fmt` on changed Go files.
- Run `make check` before handoff when possible.
- Do not add broad lint suppressions. Any `//nolint` must name the exact linter and include a reason.
- Do not hide Go or other source code in shell heredocs, generated temp files, or compiler stdin to bypass formatting, tests, review, or linting. Test harnesses and helper clients must be checked-in source files unless the generated file is a small data/config fixture.
- Keep `go.mod` and `go.sum` tidy.
- Use `.mise.toml` or the dev container to satisfy repo toolchain requirements; keep `make check` as the source of truth.

## Deployment

- Production deploys through GitHub Actions on pushes to `main`, after CI passes.
- The production deployment workflow has an environment approval gate; deployment requires approval before production changes are applied.
- Ansible runs from the `grubbyhacker/vps-ops` repository over SSH to `hermes-vps` (`srv1656293.hstgr.cloud`).
- The production deploy user is `github-deployer`.
- Agents must not SSH directly to `hermes-vps` for production changes. All production changes must go through the GitHub Actions deployment pipeline.
- Diagnostic read-only SSH checks against `hermes-vps` are acceptable only when explicitly authorized.

## Local Staging

- Run local staging from the `vps-ops` repository with `mise run deploy:staging -- gh-agent-broker`.
- In local staging, the broker REST and health API is available at `http://127.0.0.1:8080`.
- In local staging, the issue-reporter MCP endpoint is available at `http://127.0.0.1:8090/mcp`.
- `sandbox-broker` is disabled in local staging because `local.yml` sets `sandbox_broker_enabled: false`.

## Compose Services

- `broker` on port `8080`: main REST and health API.
- `issue-reporter` on port `8090` internal, published locally: MCP endpoint.
- `gh-agent-proxy` on port `8092`: token proxy.
- `litellm` on port `4000` internal: model proxy.
- `sandbox-broker`: sandbox orchestrator, production only.

## Configuration

- Runtime config files are managed by Ansible in `vps-ops/roles/gh-agent-broker/files/configs/`.
- Do not edit config files directly on the VPS. Configuration changes must go through `vps-ops` and the deployment pipeline.
