# Operator REST Launch Profiles For Sandbox Jobs

## Summary

Add host-local, operator-authenticated REST launch profiles to `sandbox-broker`.
`systemd.timer` units and manual operators can trigger fixed launch profiles
with `curl`, while `sandbox-broker` continues to own Docker execution, template
policy, run dirs, audit, redaction, and credential handling.

This stays sandbox-broker only. The main GitHub broker does not gain
Docker-launch functionality.

## Key Changes

- Add `launch_profiles` to sandbox config. Each profile defines a default launch
  request: `template`, `repo`, `base_branch`, `task`, optional `focus`,
  `deliverables`, `branch`, and `max_runtime_minutes`.
- Add scoped operator principals separate from MCP auth:
  - Prefer `token_env`; allow inline `token` only for tests/examples.
  - Each principal has a name, allowed profiles, and allowed actions.
  - Supported actions: `launch`, `dry_run`, `status`, `logs`, `artifacts`,
    `stop`, `cleanup`.
- Add host-local REST endpoints on `sandbox-broker`:
  - `GET /v1/launch-profiles`
  - `POST /v1/launch-profiles/{name}/dry-run`
  - `POST /v1/launch-profiles/{name}/launch`
  - `GET /v1/runs`
  - `GET /v1/runs/{run_id}`
  - `GET /v1/runs/{run_id}/logs?max_bytes=...`
  - `GET /v1/runs/{run_id}/artifacts`
  - `GET /v1/runs/{run_id}/lessons`
  - `POST /v1/runs/{run_id}/stop`
  - `POST /v1/runs/{run_id}/cleanup`
- Requests default to no body and no overrides. Profile overrides must be
  explicitly allowlisted by field, merged into the profile request, then
  validated through existing `LaunchAgentInput` validation. No caller-supplied
  template, repo, or branch unless the profile explicitly allows that field.

## Behavior

- systemd can trigger a profile with:
  `curl -fsS -X POST -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8091/v1/launch-profiles/profile-name/launch`
- A timer token can be scoped to `launch,dry_run` only. A human operator token
  can separately receive read/stop/cleanup actions.
- REST handlers reuse existing `sandbox.Service` methods. Do not duplicate
  Docker, artifact, log, redaction, or launch policy logic.
- Logs keep existing byte caps. Artifact and lesson collection reuse existing
  path traversal checks, symlink handling, redaction, hashing, and inline byte
  limits exactly.
- V1 does not add profile-level concurrency dedupe. Repeated launches remain
  auditable and rely on worker-level locking plus existing sandbox run tracking.
- Audit records include operation, token principal name, profile name, run ID
  when available, decision, repo, template, and branch. Do not log tokens, auth
  headers, broker secrets, provider credentials, or credential bundle contents.
  If a token fingerprint is later useful, use only a short one-way digest.

## Test Plan

- Config validation:
  - production examples prefer `token_env`;
  - missing token material rejects enabled operator principals;
  - unknown profile/action in a principal scope is rejected;
  - invalid override fields are rejected.
- REST auth and authorization:
  - missing/bad token returns 401;
  - token without profile scope returns 403;
  - token with `launch` but not `logs` cannot read logs;
  - timer-style token can launch/dry-run but cannot read artifacts or
    stop/cleanup.
- Launch behavior:
  - profile launch calls existing `LaunchAgent`;
  - dry-run does not create a run directory or container;
  - body overrides are rejected when `allow_overrides` is empty;
  - allowed overrides are merged and then validated by existing launch
    validation.
- Collection/status behavior:
  - run status/log/artifact/lesson endpoints call existing service methods;
  - REST collection endpoints preserve existing traversal protections,
    redaction, and byte caps.
- Existing MCP tests continue to pass unchanged.
- Run `make fmt`, focused sandbox/sandbox-broker tests, then `make check`.

## Assumptions

- V1 uses `systemd.timer` or manual `curl`; cron remains mechanically compatible
  but is not the recommended deployment language.
- REST profile endpoints bind on the existing sandbox-broker listener, which
  remains host-local in production.
- Curator/YKM-specific behavior stays in private config and worker code, not
  hard-coded into broker code.
