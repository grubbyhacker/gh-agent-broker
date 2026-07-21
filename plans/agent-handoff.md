# Agent Handoff

## Current State

### GitHub green-PR completion observation

The registered v2 admission now accepts only the settled
`github_green_pr_v1` task values for
`grubbyhacker/repository-worker-lifecycle-test`, `main`, and the anchored
`agent/fleiglabs-repo-agent/...` branch namespace. The broker's
`POST /v1/registered/github-green-pr/create` and
`POST /v1/registered/github-green-pr/observe` accept no request body or caller
completion facts. Both derive the immutable task digest and exact pushed head
from the active durable lease and completed broker smart-HTTP operation. Create
uses the configured App installation and fixed broker-owned title/head/base/body
and ready state, returning an existing exact ready PR idempotently while
refusing ambiguous or mismatched rows; it does not use the generic caller-shaped
`pull.create` route. Observe emits `github-green-pr-observation/v1` using authenticated App reads of
the immutable target repository, ready PR, active branch rules, and complete
paginated evaluation-SHA checks/statuses. It records the target repository
database ID, node ID, and full name even for missing or draft PRs; a positive
verdict requires the PR head repository to match all three identities exactly.
Where GitHub exposes a test-merge SHA, the broker uses it only when required
contexts are applicable there; otherwise it evaluates the PR head. Copied,
forked, mismatched, stale, duplicate, or wrong-App-source observations refuse;
absent rows remain pending, legacy pending statuses are pollable, and only
GitHub-accepted success/skipped/neutral conclusions satisfy. The endpoint stays
staging-configured through the existing transport observation mapping; it does
not activate production.

### Durable registered-task admission (candidate A)

The configured registered coordinator principal is refused at the legacy
`POST /v1/authority-workers/coordinator/v1/leases` boundary before request
decoding or admission effects; it must use the durable registered v2
acquisition path. Separately authorized non-registered principals retain the
legacy v1 behavior.

The authority store schema v11 atomically migrates the released v10 schema to
a registered-admission table with a principal-plus-binding composite foreign
key to the lease. It enables SQLite foreign-key enforcement on every store open.
Registered durable reads fetch and verify the stored protocol version, strict
canonical JSON, source columns, canonical bytes, and digest, failing closed on
any mismatch. `POST /v1/authority-workers/coordinator/v2/leases` requires the
exact top-level `broker/coordinator/v2` version and rejects unknown or trailing
JSON. The authority store adds a fail-closed registered-admission snapshot
table. `POST /v1/authority-workers/coordinator/v2/leases` accepts only the
settled `broker/coordinator/v2` registered task/source shape, verifies its
lowercase SHA-256 JCS digest, requires `session:<work_item_id>`, and atomically
persists the snapshot alongside the lease admission. Registered admission is
gated by the configured `registered_coordinator_principal`; production remains
unconfigured and inactive. Existing v1 leases have no snapshot and registered
create/turn paths refuse before agentd routing. Broker-derived registered open
and turn payloads use only the stored snapshot and broker lineage/workspace
identities. Registered coordinator commands use the exact versioned
registered-lifecycle routes and refuse resume; registered reassignment uses
`/adopt`, while legacy reassignment retains `/rebind`.
Registered submit validates its turn-status response, while registered cancel,
checkpoint, and status validate the exact canonical session status against the
binding, workspace, and worker fence; legacy cancel retains its turn-status
contract.

### Settled 2a/2b repository transport journal

The authority SQLite store schema v10 adds the broker-owned append-only
`repository_transport_events` table with the settled 2b reader columns. The
main broker can enable the staging-only `transport_observation` configuration,
which opens the existing authority store, resolves exactly one unreleased lease
through a reviewed profile-to-agent mapping, and persists `received`,
`forwarded`, and terminal `denied`/`completed`/`failed` phases before the
corresponding policy, backend, or client response. It stores only normalized
metadata and digests; credential values and Git pack bodies are excluded.

This path is disabled by default and configuration rejects it in production.
The evidence runner has no broker write API; its settled database mount/query
remains read-only work owned by the topology. Focused tests cover no-op state,
internal authority resolution, append failure, incomplete/denied/failed/success
phase chains, replay, digest linkage, and ambiguous leases.

### Repository-route-policy/v1 and local smart HTTP backend

The broker and sandbox now load the same optional
`repository_route_policy_path` YAML manifest (`repository-route-policy/v1`).
Its canonical SHA-256 digest is included in each authority profile policy
digest. Local `local/...` routes are authenticated and policy-checked before
any GitHub installation or token resolution, then forward only to their fixed
backend URL without forwarding authorization or broker authority headers.

`cmd/repository-backend` serves only health plus smart-HTTP discovery/RPC for
the fixed `repository-agent-lifecycle-fixture` bare repository. Its container
pins Git's hidden-ref, object-want, delete, and non-fast-forward settings and
installs a pre-receive hook that rejects deletes, out-of-namespace writes, and
non-ancestor updates. The HTTP boundary accepts only protocol v0 (no
`Git-Protocol`) and v1 (`Git-Protocol: version=1`), rejecting v2 instead of
silently downgrading it. Discovery accepts exactly one `service` query key with
exactly one `git-upload-pack` or `git-receive-pack` value; malformed query
encoding, extra query keys, and duplicate values are denied. Both smart-HTTP
RPC paths require an empty query. Deployment
configuration remains owned by `vps-ops`; use the exact manifest key above and
the example in `configs/repository-route-policy.example.yaml`. The repository
root and bare repository are both owned by `65532:65532` with exact `0750`
mode; health fails closed on either mismatch.

The route manifest is strict YAML and binds exact readable refs
`refs/heads/main` and `refs/heads/agent/repository-proof/**`, exact writable
`refs/heads/agent/repository-proof/**`, plus `fast_forward_only` and
`no_delete`; backend URLs are origin-only and cannot carry credentials, a path,
query, or fragment. Health checks stat only the configured repository root and
bare repository, verifying mode, Linux ownership, and read/write access without
enumerating refs or mutating the repository. `make repository-backend-image-proof`
builds the target image and exercises health/mode negatives plus real smart-HTTP
v0/v1 advertisements, hidden-tip rejection, deletion, non-fast-forward, and
stale expected-old update rejection.

`gh-agent-broker` provides deny-by-default GitHub policy enforcement, sandbox
lifecycle management, fixed operator launch profiles, durable idempotent launch
intents, recovery/reconciliation, scoped run visibility, and brokered GitHub
operations without returning installation credentials to workers.

### Roadmap PR10 broker coordinator surface

The private `broker/coordinator/v1` REST surface now mediates the complete
authority session command set: acquire, create, submit, events, checkpoint,
resume, cancel, status, reassign, and reassignment status. Signal Plane supplies
only a logical binding and operation-specific typed data. Legacy v1 lease
bindings remain mediated through the legacy `/v1/sessions` agentd routes and
continue to require a prompt for submit. Only bindings with the durable v2
admission snapshot use `/v1/registered-sessions`; their submit derives task
data from the snapshot and rejects caller prompts. The broker resolves
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

### Roadmap PR10 egress security subset

Broker-owned textual GitHub mutations, sandbox logs and inline text
artifact/lesson responses, raw coordinator agentd results, and both audit
serializers now fail closed on the synthetic PR10 canary or common
credential-shaped material. Findings expose only a stable code and field,
produce sanitized `security.egress_blocked` audit events, and stop GitHub
installation-token issuance for the attempted mutation. The implementation
does not load or compare real secret values and does not activate production.

Canonical decoding covers bounded URL, hex, base64, and base64url forms plus
broker-controlled split sequences. All artifact bytes are scanned within a
16 MiB per-file bound; larger files fail closed. Git smart-HTTP commit packfiles
remain opaque, so credential-bearing authority identities must set
`git_receive_pack_policy: deny_opaque`, which denies before token issuance while
leaving legacy identities compatible. Durable worker quarantine, maximum-age
policy, global credential halt/revocation, semantic pack inspection, and
production wiring remain explicit later seams. See
`docs/pr10-egress-security.md` for the exact boundary.

### Roadmap PR10 asynchronous push tripwire

Ordinary opaque smart-HTTP pushes now retain their existing GitHub App identity
and pack forwarding behavior while receiving a bounded ref-state preflight:
deletions and stale advertised `before` SHAs are rejected before forwarding,
and GitHub remains the enforcement point for protected-branch and non-fast-
forward rejection. Stable receive-pack `ng` status is audited without parsing
provider prose. Upload-pack streaming is unchanged.

An inert, configuration-reviewed scanner surface returns exact bounded commit
messages and both changed blob sides for admitted repository/ref/before/after
events. New branches resolve a reviewed base ref; incomplete ancestry, tree,
blob, pagination, or bound results are typed `complete:false`, never clean. A
durable idempotent response surface records exact-generation issuance halts and
requests a fully attributed worker/session fence through a strict adapter seam.
Only `fenced` means the adapter confirmed fencing; otherwise the durable state
is `fence_requested` and exact replay retries it. Production enablement and a
live sandbox fence adapter remain later `vps-ops` work. See
`docs/pr10-async-push-tripwire.md` and the shared wire fixture under
`testdata/push-tripwire/`.

The halt is now cross-process enforceable: main broker and sandbox broker share
the sandbox authority SQLite file, sandbox startup registers exact profile
generations, and every authority issuance/admission path checks the durable halt
inside its own `BEGIN IMMEDIATE` transaction before mutation. The shared writer
lock is the linearization point: `/respond` cannot return `halted` ahead of an
issuance transaction that already owns the lock, while issuance that starts
after the halt commit fails closed. Exact committed lease, replacement, and
reassignment replays remain available without creating a new effect. `halted`
is unavailable until enforcement registration exists. The
deployment contract therefore needs a shared read-write state-directory mount,
matching state-file paths, and matching main response-profile/sandbox authority
profile generations. The intentionally absent live fence adapter is unchanged.

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
