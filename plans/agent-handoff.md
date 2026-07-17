# Agent Handoff

## Current State

`gh-agent-broker` provides deny-by-default GitHub policy enforcement, sandbox
lifecycle management, fixed operator launch profiles, durable idempotent launch
intents, recovery/reconciliation, scoped run visibility, and brokered GitHub
operations without returning installation credentials to workers.

### Roadmap PR10 broker coordinator surface

The private `broker/coordinator/v1` REST surface now mediates the complete
authority session command set: acquire, create, submit, events, checkpoint,
resume, cancel, status, reassign, and reassignment status. Signal Plane supplies
only a logical binding and operation-specific typed data. The broker resolves
the immutable profile version, policy digest, worker/session/storage lineages,
fence epoch, agentd identity, and fixed Docker endpoint; callers cannot address
agentd or select runtime authority.

Authority store schema v8 keys reassignment history by binding plus predecessor
fence epoch, allowing the same logical session to survive repeated worker
generations. Durable adoption status is principal-scoped and retains pending,
confirmed, conflict, and legacy-unresolved reconciliation states. Stable wire
fixtures live under `testdata/coordinator-wire/`. This slice does not implement
the credential holder or app-server boundary, change deployment configuration,
or activate production authority.

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

## PR 8 Authority-Worker Lifecycle

Authority profiles are now production-wired only when `authority_profiles` is
nonempty. The sandbox broker starts a Docker authority runtime and exposes
authenticated lifecycle controls under `/v1/authority-workers`; caller JSON
can select only a reviewed profile and is rejected if it tries to supply an
image, command, credential, mount, network, repository, operation, user, or
isolation field.

Each profile fixes the digest-pinned `agentd` image and exact
`bun run src/cli.ts serve` command, broker credential, mount set, network,
repository and operation policy, resources, capacity, distinct UID/GID 0700
session-isolation allocation, and named session/checkpoint/evidence volumes.
Drain writes AES-GCM encrypted broker checkpoint evidence for extant leases
before rejecting new admission. Verification binds schema, key fingerprint,
worker ID, profile version, and policy digest and fails closed on a mismatch.

`agentd /healthz` may establish worker lifecycle liveness. Its bootstrap
`/readyz` intentionally remains unavailable, so the public lease endpoint
returns `session_admission_deferred_until_pr9`: PR 8 has no coordinator,
logical session, turn, runtime adapter, or Fleet package dependency. PR 9 can
consume the fixed profile, lifecycle, storage, checkpoint, and isolation
contract after the versioned agentd session protocol is released.

## PR 9 Coordinator Reassignment and Fencing Contract

The authenticated authority-worker REST surface exposes
`POST /v1/authority-workers/leases/reassign`. Its bounded request contains a
logical `session_binding`, the coordinator-observed `predecessor_worker_id`,
the predecessor's `prior_fence_epoch`, and an idempotency key. It cannot select a replacement, image, authority,
credential, mount, network, or policy. The broker derives the destination from
the predecessor's durable replacement link and requires that replacement to be
ready, profile-compatible, and within capacity.

Schema v4 gives every logical lease an opaque durable `lineage_id` and a
monotonic `fence_epoch`. It atomically CASes predecessor worker plus prior
epoch to successor worker plus incremented epoch, transfers capacity, and
keeps the workspace keyed by lineage rather than worker generation. The typed
admission and reassignment responses include both values, and agentd session
creation receives broker-selected uid, gid, workspace path, lineage, and
epoch; callers cannot choose them. Replacement and reassignment assert the
full immutable profile digest (including storage), policy digest, image, and
capacity identity.

`POST /v1/authority-workers/agentd/session-validation` is the minimal
broker-secret-authenticated, fail-closed fencing contract for agentd. Before
journal/workspace/launcher state access, agentd must validate its worker,
lineage, and epoch. A predecessor or old epoch is denied after CAS. Current
Docker liveness is explicitly not agentd readiness: reconciliation requires a
future authenticated agentd readiness probe covering journal/runtime/launcher/
fence configuration, and Docker returns unavailable until that protocol lands.
Checkpoint files remain lease-observation evidence only, not an agentd
recovery manifest or a recovery guarantee.

The current broker/agentd integration matches the agentd PR 10 source contract:
authenticated `/readyz` uses `agentd/control/v1` and the camelCase
`workerId`, `storageLineageId`, and `fenceEpoch` identity fields plus the
`components` object. Create-session projects the exact agentd/v1 camelCase
fields and the workspace object contains only `workspaceRef`, `uid`, and `gid`.
Profiles without the authenticated agentd readiness contract retain their
existing liveness behavior; the stricter readiness gate applies only to the
profile that opts into it.

Worker journal/session, checkpoint, and evidence named volumes are mounted
with Docker `VolumeOptions.Subpath` set to the opaque worker storage lineage.
A root-run initializer creates and secures those lineage directories before
the worker container is created. The lineage root remains `bun:bun 0711` so
distinct session UIDs/GIDs can traverse to their own `0700` workspaces. A
second broker-managed initializer creates `.agentd-state` inside the session
lineage root as `bun:bun 0700`; agentd keeps its SQLite journal file `0600` at
`.agentd-state/agentd.sqlite3`. Authority workers never receive the full backing
volume. Replacements inherit the storage lineage and therefore reuse that same
private state directory while advancing its worker
fence epoch by exactly one, while logical session lineage remains unchanged and
separate. Journal continuation therefore comes from inherited fenced storage,
not from broker checkpoint artifacts.

The root-owned authority volume initializer is a distinct, fixed `install`
helper. It retains `no-new-privileges`, non-privileged mode, no network, and
`CapDrop: ALL`, adding only `CAP_CHOWN` and `CAP_FOWNER`: `install -o bun -g
bun` first needs `CAP_CHOWN` for its `chown(2)` ownership transition, then
needs `CAP_FOWNER` because it applies the requested mode after the directory is
owned by `bun`. A real Docker proof showed that `CAP_CHOWN` alone fails at that
post-chown mode change. The separate state initializer then runs as `bun` with
zero added capabilities, creating `.agentd-state` under the now bun-owned
lineage root. These root-helper capabilities are package-private; ordinary
workers retain zero added capabilities and the authority runtime retains only
`SETUID` and `SETGID`.

The reviewed agentd authority runtime keeps the server process explicitly on
Docker user `bun`, remains non-privileged, drops all capabilities, and restores
only `SETUID` and `SETGID` to the bounding set. Its
immutable root-owned setuid launcher is the sole RuntimeSpec exception to the
default `no-new-privileges` option because the launcher must obtain euid 0
during exec before dropping into the turn's allocated UID/GID. Ordinary
sandboxes, helpers, volume initializers, and legacy paths retain
`no-new-privileges`; authenticated readiness is not treated as proof that the
actual launch spec permits this transition.

Profiles selecting `agentd/control/v1` now fail closed unless
`workspace_root` is exactly `/var/lib/agentd/workspaces`, matching agentd's
fixed immediate-child launcher boundary. `AGENTD_SESSION_ROOT` remains that
exact path, while `AGENTD_STATE_PATH` is
`/var/lib/agentd/workspaces/.agentd-state/agentd.sqlite3`. The hidden state
directory cannot be allocated as a session workspace: broker lineages are
exactly 32 hexadecimal characters, and agentd accepts only the exact
broker-projected lineage child rather than discovering directory entries. The
follow-on vps-ops integration PR must change the managed profile from
`/var/lib/agentd/sessions` and update its reviewed digest.

The authority Docker create contract keeps `USER bun`, non-privileged and the
existing read-only constraints, drops `ALL`, then adds only `SETUID` and
`SETGID` to the capability bounding set. Only this immutable authority spec
omits `no-new-privileges`; ordinary Bun processes retain no general root path,
while the root-owned fixed setuid launcher owns the reviewed transition. Agentd
PR 10 independently exercises that image-side launcher transition and its
negative Bun control. A
staging-only credential bundle may select a fixed named Docker volume, mounted
read-only at `/var/empty/.codex`; host-path credential bundles are unchanged,
and production authority profiles reject credentials.

Authority workers now receive the fixed broker validation URL
`http://broker:8080/v1/authority-workers/agentd/session-validation` and a
domain-separated HMAC validation token derived from the reviewed broker-agent
secret and bound to the exact worker ID, storage lineage ID, and fence epoch.
The raw broker secret is never reused as the validation token. Validation uses
a constant-time comparison and returns the same `unauthorized` result for an
unknown worker and an invalid token before checking lease/session fences.
Agentd PR 10 head `cf2d5f475daf3a7defb2595486338610a310c82d`
finalizes `/readyz` with the additional required
`components.brokerFenceValidatorConfigured` field. Broker decoding requires
that exact field while retaining the journal, runtime, launcher, and isolation
claims; the retired `brokerFenceValidator` spelling and missing components fail
closed.

Reassignment now completes the durable broker-to-agentd half of the fencing
contract. Agentd's generated `sessionId` is recorded against the broker-owned
workspace during authenticated session creation. After the exact predecessor
to recorded-successor lease CAS, the broker calls only that successor's
Docker-inspected endpoint at `POST /v1/sessions/<sessionId>/rebind` with the
existing coordinator bearer token. The body contains only a broker-derived
stable idempotency key and the exact predecessor/successor worker, storage
lineage, and epoch bindings. A strict full `agentd/v1` status matching the
durable coordinator binding, session identity, lineage, worker, and epoch is
required before predecessor retirement or reassignment success.

Timeouts, malformed or mismatched success bodies, and agentd 5xx/validator/
storage failures return `reassignment_rebind_retryable` with HTTP 503 after
the CAS and never roll it back. Exact-transition retries resume the same agentd
command without another lease effect, even when the coordinator supplies a
fresh transport request key. Agentd `rebind_conflict` and `session_fenced` 409
responses return terminal `reassignment_rebind_conflict`; other 4xx responses
are never accepted as success. Audit errors remain bounded and do not include
the coordinator token, successor endpoint, or agentd response body.

Config versioning retains the exact pre-`source_volume` canonical digest shape
when that field is empty, so ordinary-worker nonterminal launch intents remain
reconcilable across upgrade. A nonempty named source volume is included in the
digest. Runtime launch-spec labels likewise retain their pre-authority-field
canonical representation only for ordinary specs whose platform, entrypoint,
volume/subpath mounts, and privilege-transition flag are all absent. This lets
a persisted `create_pending` intent adopt its exact pre-upgrade Docker
container; authority specs always use the full current representation.
Staging credential source volumes must be distinct from every configured
authority profile's broker-managed session, checkpoint, and evidence volumes,
regardless of which profiles the credential bundle is allowed to reference.

The production deploy workflow grants `packages: read` and passes the
ephemeral `github.token` plus `github.actor` to only the vps-ops deploy step as
the GHCR pull credential interface expected after vps-ops #244. No PAT,
repository secret, Doppler credential, or container environment projection is
introduced by this repository.

A schema-v7 reassignment row now captures the raw coordinator binding,
authority profile, agentd/session lineage IDs, exact predecessor and successor
worker/storage/epoch bindings, broker-derived rebind idempotency key, and
workspace identity in the same transaction as the lease/workspace CAS. Its
agentd adoption state starts `pending`; only a strictly matching HTTP 200
status atomically changes it to `confirmed`. Semantic agentd conflicts are
persisted as `conflict`, and migrated pre-v7 rows are `legacy_unresolved`
because their hashed coordinator bindings cannot reconstruct an exact status
check. Both states remain actionable and block automatic retirement.

Reconciliation enumerates every non-confirmed transition and replays pending
rows to the recorded successor with the exact stored body, independent of the
original coordinator request key. A crash before the call or after agentd
success is therefore recovered by the same idempotent command. Retryable,
malformed, and mismatched responses remain pending. All predecessor retirement
lookups and the final conditional stopped-state update require every transition
from that predecessor to be confirmed; readiness and zero lease count alone
are insufficient. Concurrent health/reconcile retirement is serialized within
the service, and multiple sessions block retirement until all adoptions are
confirmed.

REST errors remain structured as
`reassignment_not_ready`, `reassignment_stale_predecessor`,
`reassignment_conflicting_replacement`, `reassignment_capacity`, and
`reassignment_replay`, plus retryable `reassignment_rebind_retryable` and
terminal `reassignment_rebind_conflict`. This does not activate any generic
production route or alter an authority profile.

## Validation

Issue #112 introduces a tiered sandbox E2E gate. Relevant pull requests run
the representative `make sandbox-e2e-fast` lifecycle in parallel with the Go
gate. Relevant `main` pushes and every version tag retain the complete
`make sandbox-e2e` suite, and `.github/workflows/sandbox-e2e-scheduled.yml`
runs it weekly or on demand. The contract-aware path filter follows the local
dependency closure of the sandbox broker and E2E client instead of all
`cmd/**` and `internal/**`; update that filter whenever either command imports
a new local package. CI uses the BuildKit Actions cache for the sandbox image,
starts independent container smoke work without waiting for `check`, and limits
the Codex worker image to its broker CLI/config dependency. Image publication
still waits for every applicable gate. `docs/sandbox-e2e-ci.md` records the
measured baseline, scenario coverage, and invalidation rules.

Run `make fmt` after changing Go code and `make check` before handoff. Also run
`git diff --check` and confirm searches for retired dispatcher/profile names do
not find active configuration or future-facing guidance.
