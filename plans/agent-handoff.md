# Agent Handoff

## Current State

`gh-agent-broker` provides deny-by-default GitHub policy enforcement, sandbox
lifecycle management, fixed operator launch profiles, durable idempotent launch
intents, recovery/reconciliation, scoped run visibility, and brokered GitHub
operations without returning installation credentials to workers.

### Curator lifecycle incident remediation

Sandbox lifecycle audit records carry the Docker container ID and stable
lifecycle stages. On a deadline, the broker records whether the worker was
still running, captures a redacted bounded worker-log tail in terminal
diagnostics, and records inspect/stop failures instead of replacing the cause
with a bare timeout. The configured deadline remains unchanged. This makes a
stalled Curator worker distinguishable from Docker inspect, wait, create, or
stop failures in audit-derived metrics and the run status artifact.

Runtime broker and sandbox configuration is owned by `vps-ops`. This repository
owns the broker implementation, public examples, worker images, deploy workflow
interface, and deterministic deploy-contract tests.

## Signal Plane Proof Retirement

The narrow Phase 5 webhook-derived Codex worker proof is retired:

- the production deploy workflow no longer exports the retired Signal Plane
  dispatcher broker token or the proof-only Codex worker credential/operator
  secrets to `vps-ops`;
- the deploy-contract test rejects all three retired exports;
- the former milestone document is retained only as an explicitly retired
  historical record and cannot be used as active configuration or future
  implementation guidance;
- public examples use the synthetic, non-production repository
  `example/automation-target`; and
- generic idempotency documentation no longer names the retired launch profile.

The existing `fleiglabs-repo-agent` deploy credentials remain part of the
deploy interface because the settled architecture evolves that identity into
the general implementation and revision writer. Repository authorization for
that identity remains a `vps-ops` policy concern.

The resident Hermes identity's legacy access to `apple-jobs-matcher` is not
owned or weakened by this broker-repository retirement. `vps-ops` must preserve
that identity as the sole remaining authority for the repository.

## Preserved Broker Contracts

- Automated launch profiles can require `Idempotency-Key`; keys are validated,
  HMAC-digested at rest, and scoped by principal and profile.
- Canonically identical requests replay the original run; conflicting reuse is
  rejected with structured `409 idempotency_conflict`.
- The SQLite launch-intent store preserves durable run/container correlation and
  supports safe reconciliation after ambiguous create/start responses.
- Launch principal ownership and profile scope constrain run list/status access.
- Existing Curator identities and credentials remain unchanged. The reusable
  Codex worker image, its noninteractive authority contract tests, and broker
  recovery tests remain available without the retired production profile or
  credential bundle.

## Next Slice: Authority Bootstrap Inputs

Before the batched GitHub owner ceremony, `vps-ops` needs reviewed non-secret
manifests that settle these exact inputs:

1. Stable App name/slug and permission/event envelope for the general writer,
   reviewer, and intake/release-reader identities.
2. Initial selected-repository installation list for each identity. The writer
   list must include only repositories explicitly opting into agent-authored
   changes; `apple-jobs-matcher` must not be included.
3. Broker principal names, allowed operations, repository scopes, and Go-regexp
   branch namespaces for each identity. Reviewer policy must exclude push and
   merge; intake policy must exclude repository mutation.
4. Doppler project/config and environment-variable mapping for each private key,
   broker principal secret, and any provider webhook secret.
5. Provider-generated App ID/client ID, installation ID per selected repository,
   and private key captured during the ceremony directly into the approved
   secret store, never into Git or OpenTofu state.
6. Deterministic catalog-to-installation-to-broker-policy validation and the
   deploy-secret export names consumed by this repository's production deploy
   workflow.

Leave all new authorities inert until their consuming routes are separately
reviewed and activated. The merge-capable App is explicitly deferred.

## Authority-Worker Groundwork

The broker now has an internal, inert authority-worker domain separate from
run-oriented `Template` and `LaunchProfile` behavior. It defines reviewed
authority profiles, immutable profile and repository-operation policy digests,
durable SQLite worker and session-lease records, atomic capacity admission,
principal/profile/action scoping, health state, draining, idempotent release,
and retry-safe replacement generations that keep the old worker available
until the replacement reports ready.

Replacement reconciliation uses the durable worker ID as the runtime identity:
retrying a persisted provisioning intent must ensure the same physical worker.
The ready transition requires the replacement's durable predecessor link and
atomically moves the predecessor to draining; hung or unhealthy replacements
therefore cannot remove the old worker from capacity admission.

No public REST or MCP operation, production profile, startup wiring, real
worker runtime, or `agentd` readiness claim is included. The synthetic runtime
interface deliberately omits both an `agentd` command and a session-isolation
primitive. Those remain blocked on the versioned `agentd` owner/image,
transport and health contract, and the accepted distinct-UID/GID or stronger
isolation decision. `ImageReference` records reviewed configuration while
`ImageDigest` remains empty until a runtime resolves the created image.

## Validation

Run `make fmt` after changing Go code and `make check` before handoff. Also run
`git diff --check` and confirm searches for retired dispatcher/profile names do
not find active configuration or future-facing guidance.
