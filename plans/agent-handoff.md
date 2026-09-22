> **STATUS: CURRENT HANDOFF.** This is the living handoff context that
> `AGENTS.md` requires be kept current before handing off; treat it as the most
> recent state-of-the-work note, not as a forward plan.

`internal/capability` is an INERT Stage-4 per-run capability policy foundation,
wired into NO live path. It ships the immutable typed claims the coupling design
commits to — `agent_type, mode, run_id, allowed_models, call_budget,
token_budget, expiry` — plus `work_item_id` (the merged inert correlation outbox
binds a correlation to its originating WorkItem). `Claims` is immutable (unexported
fields, allowed-model set copied in and out), and `PolicyEvaluator` implements the
mechanism-independent `Validator`/`Authorizer` seams consumers use instead of
caller headers/body. Model access has exactly two coherent states: model-disabled
(empty allowed_models, both budgets zero — the deployed youknowme-curator reconcile
shape, model.access=false) and model-enabled (non-empty models, both budgets
positive); mixed states are rejected. Authorize checks expiry, exact identity match
on agent_type/mode/run_id/work_item_id, and — model-enabled only — model membership
and call/token budget headroom; against a model-disabled capability it allows an
identity-only op with zero reservation and denies any model/call/token request.
`cmd/capability-validate` is the offline claims-semantics validator.

The design does NOT decide how a minted capability is serialized, signed, and its
keys managed for transport, so this package does not choose one: the broker-issuer
and consumer-verifier roles are explicit UNIMPLEMENTED seams (`Issuer.Issue`,
`Verifier.Verify`, opaque `[]byte` token). The remaining Stage-4 decision — token
format, key hierarchy, rotation/escrow — is documented in
`docs/agent-platform/run-capability-foundation.md`; the claims/validation/evaluator
do not depend on it and land now. No production config, launch wiring, model-proxy
change, static-principal migration, or deploy. `make check` is the gate.

`.github/workflows/deploy-production.yml` now exports
`VPS_OPS_GH_BROKER_RELEASE_PUBLISHER_OPERATOR_TOKEN` and
`VPS_OPS_GH_BROKER_RELEASE_PROMOTER_OPERATOR_TOKEN` from same-named production
environment secrets in BOTH the "Verify deployment secret prerequisites"
preflight step and the "Deploy gh-agent-broker" step, alongside the other
gh-agent-broker role secrets. This is the consumer-first side of the release
publisher/promoter operator identities (the CLI added in #177): the workflow
declares the exports so the vps-ops Doppler env-source wrapper can consume them
once the values exist. The required-secret comment block and the deterministic
deploy-contract tests (`internal/deploycontract/deploy_production_test.go`) were
updated — a new test asserts each token is exported to exactly the two steps.
No vps-ops edit, no secret creation, no deploy: the secret VALUES are provisioned
separately. `make check` is the gate.

The broker ships an INERT run-to-PR correlation outbox foundation
(`internal/correlation`) — durable machinery only, wired into NO live path.
Semantic review established the reason: today's authenticated `pull.create`
carries no run capability. `principal.ID` + a broker operation id +
caller-supplied metadata cannot establish the design's originating
WorkItem/AgentType correlation, and caller metadata is not authority, so wiring
the store to that handler would invent authority the broker does not hold. There
is therefore no `RunCorrelationConfig`, no Server field, and no pull.create
recording — those were removed.

What remains is the store: schema, an atomic correlation+outbox transaction,
idempotency on the broker operation id, a bounded versioned payload
(`run-pr-correlation/v2`), and a claim/ack/expiry-reclaim reader API, plus the
offline `cmd/correlation-validate`. `Identity` now REQUIRES the broker-
authenticated capability fields a future Stage 4 will supply: `agent_type`,
`mode`, `run_id`, `work_item_id`, and the broker `operation_id`, plus the
repo + PR number GitHub returns. `Record` fails closed if any capability field
is empty — there is no caller-metadata path and nothing emits events until Stage
4 supplies a verified capability. This foundation is NOT the design complete; it
is scaffolding awaiting Stage 4 capability wiring. `make check` is the gate.

The AgentRelease publish boundary gives external callers `release.publish` only:
the former public verify/acquire routes and actions are gone. Trusted protected-main
CI submits a bounded `docker-archive/v1` artifact and provenance. Broker code derives
Docker's immutable image ID from the archive, checks deployment-owned platform and
provenance requirements, loads it through the Docker Engine, and observes the exact
local ID and platform before internal verifier/acquirer actors record availability.
A missing, mismatched, or load-failed image stays non-promotable. No registry pull
credential or third-party import helper is required.

PR #176 exposes publish, promote, and separately authorized rollback. The
authentication seam yields a credential-free verified principal before authorization,
so a future OIDC verifier replaces only authentication. `release.publish` and
`release.promote` principals each hold exactly one action; rollback remains independent.
The branch also JSON-encodes the request-tainted fallback finalization log record,
fixing CI's real G706 log-injection finding rather than suppressing it. `make check` is
the delivery gate.

`gh-agent-broker-cli` now exposes the merged release API deterministically for
protected-main CI: `release-publish` uploads a single-image Docker archive plus
`{agent_type, provenance}` over the `docker-archive/v1` multipart protocol and
prints the broker-assigned `generation`/`ready`/`state` (also to `$GITHUB_OUTPUT`),
and `release-promote` promotes a positive generation only. Publisher and promoter
use distinct token flags/env (`BROKER_PUBLISHER_TOKEN` / `BROKER_PROMOTER_TOKEN`)
sent as bearer tokens, never logged. Rollback stays a separate operation and is
deliberately absent from the promoter command. HTTP contract tests live in
`cmd/gh-agent-broker/release_test.go`.

# Agent handoff

The durable architectural invariant is: **“The broker owns durable side
effects. The agent owns reasoning.”** This is a mechanical trust boundary, not
prompt guidance. Codex interprets, edits, validates without broker authority,
and emits bounded output; broker-controlled deterministic code alone advances
durable state, pushes branches, creates or updates PRs, and posts comments.

The first secure Codex issue-to-ready-PR slice is implemented behind the
`codex_issue_workflow` launch-profile contract. It uses distinct durable
preparation, execution, and delivery container identities under one broker run.
Preparation has no Codex
credential and fails stale unless checkout dependency/submodule identity
exactly matches the baked manifest. The sandbox-broker-owned holder performs a
bounded refresh before startup completes, then maintains the full credential
master on a fixed 30-minute interval; periodic failures are bounded and logged
with static redacted text. Run admission never refreshes. It only projects the
current persisted access token and account ID into an access-only `auth.json`
in memory with an explicitly empty refresh token. Token-free issuance state
records only run/idempotency identity and issued/consumed times, independent of
OAuth host, token lineage, and Codex version. After the fresh execution
container starts, sandbox-broker streams it only on Docker exec stdin to a
fixed command that writes into bounded `/dev/shm`; no host
capability file or issuance mount exists. The wrapper atomically accepts it
into a mode-0600 tmpfs `CODEX_HOME`, removes the injection source, and records
a token-free acceptance marker. Execution has no general proxy; its explicit
Responses provider reaches only the broker-owned exact-path subscription
relay, which alone forwards to fixed `https://chatgpt.com` through a separate
origin-only edge.

The only initial profile interface is `terra-medium-v1`, resolved through an
exact reviewed five-entry `codex-model-policy/v1` table to
`gpt-5.6-terra + medium`; unsupported combinations have no fallback. Codex
events and credentials remain on tmpfs and are cleaned, and logs/arbitrary
artifacts are unavailable for this workflow. The terminal projection includes
bounded broker-owned provenance and preserves complete bounded final output.
The vps-ops and Signal Plane schema/network handoff is
`docs/codex-issue-ready-pr-contract.md`. No production or vps-ops change is
included.

The failed-CI repair extension is specified by
`docs/repository-agent-ci-repair-contract.md`. It adds broker-owned complete,
bounded/fail-closed CI observation (active branch rules/rulesets, statuses,
checks, Actions and log metadata), checks out an existing PR at an admitted
SHA, seals final validation to the candidate tree, and uses an exact-SHA
force-with-lease for delivery. A credentialed delivery process now emits a
bounded stale-lease handoff only for Git's positive `stale info` diagnostic;
it does not execute repository validation after broker authority is present.
Sandbox-broker now owns same-run stale-lease recovery: it persists a bounded
credential-free recovery-validation phase, starts a separate recovery template
with the shared prepared workspace, seals winner/candidate/tree/verify
provenance, then creates one fresh delivery container for the single leased
retry. Signal Plane consumes the final terminal result only; it does not
orchestrate a second worker phase or attempt identity.
Ready terminal results carry exact PR, branch, expected-old-head, candidate,
delivered-head, validated-tree, and delivered-tree identities.
Signal Plane owns durable event correlation, attempt/deadline accounting, and
idempotent issue escalation; issue comment keys are durable exact-request keys
namespaced by principal, operation, repository, and issue.

Final validation hardens Actions log redirects to the exact GitHub Actions
delivery hosts and rejects arbitrary GitHub subdomains. SHA-pinned required
workflows now require a matching definition SHA from `referenced_workflows`;
the direct workflow-run path alone cannot satisfy them. The restart-adoption
test explicitly drains its delivery watcher to avoid TempDir cleanup races.

Sandbox-broker now seals a durable `repository-task-terminal-result/v1` at
terminal finalization. `GET /v1/runs/{run_id}/terminal-result` requires the
new explicit `terminal_result` operator action and retains existing
profile/owned-run scoping. The projection contains only bounded,
redacted `/output/result.json` and `/output/final-summary.md`, plus stable
run/profile/idempotency/config correlation fields; it never exposes logs or
arbitrary artifacts. Missing, malformed, unreadable, or oversized worker
output produces a safe structured fallback (`failed`, `timed_out`, `stopped`,
or `cancelled` as appropriate) rather than truncation. The worker still does
not publish or call GitHub. Signal Plane owns comment/outbox delivery in its
follow-on slice.

The generic repository worker and the new deterministic Codex delivery worker
produce the shared bounded
`repository-task-worker-result/v1` contract. It preserves the generic
worker's `task` field and the delivery worker's `worker: "codex"` field, always
includes a structured `verification.status` (`passed`, `failed`, or `not_run`), and a
`ready_for_review` outcome includes only the broker-created pull request's
validated `number`, `html_url`, and `url`. The worker validates that identity
before publishing readiness; malformed or absent broker output fails closed
with the same bounded, log-free failure result. Workers never publish final
issue comments; Signal Plane remains the terminal-comment owner.

The result writer creates a complete JSON document in a same-directory
temporary file and atomically renames it only when it is at most 32,768 bytes;
oversized results are rejected without truncation. Per-repository agent image
builders must copy both worker binaries and
`/usr/local/lib/agent-worker-result.sh` from the pinned broker image. The
required downstream `agent-workflows/.github/workflows/publish-agent-image.yml`
update is to change its v1 agent-image workflow from the old `c176...` broker
digest and copy the shared library as well as `/usr/local/bin` worker scripts;
otherwise newly built agent images fail at startup with an explicit packaging
error.

`gh-agent-broker-cli reload` calls the broker admin reload endpoint with
`BROKER_ADMIN_SECRET` (or `-admin-secret`) and prints the server response. A
restart is still required when changing `server.listen`, `audit.path`,
`push_tripwire.enabled`, or `push_tripwire.state_path`.

The repository-agent lifecycle experiment has been removed. The production
surface remains the broker-agent authenticated smart-HTTP proxy at `/git/*`
and the GitHub REST proxy at `/v1/repos/*`.

Development, CI, and Go-based container builds use Go 1.26.6. The `go 1.25.0`
directive is intentionally retained as the module compatibility floor; the
`toolchain go1.26.6` directive pins the build toolchain.

For a curator push, `handleGit` authenticates the configured broker agent,
checks Git policy and branch/ref preflight, resolves the configured GitHub App
installation, mints its installation token, and forwards smart-HTTP to GitHub
with `x-access-token` Basic authentication. Pull requests are opened through
the existing `/v1/repos/{owner}/{repo}/pulls` API path.

`/usr/local/bin/agent-repo-task-worker` is a generic, model-free worker copied
from the published broker image into per-repository images. It uses only the
broker-mediated Git remote and `gh-agent-broker-cli` for GitHub access. The
shared `publish-agent-image.yml` initializes submodules during image build and
copies their content to `/workspace`. The worker compares the checkout's
gitlink SHA entries against the baked dependency manifest before copying that
content into the fresh checkout. A mismatch fails loudly as a stale image;
the worker never initializes a submodule through a direct GitHub remote.

`/usr/local/bin/agent-codex-repo-task-worker` is the Codex counterpart for a
repository image that supplies Codex CLI. It begins in a bounded credential
wait, accepts only the broker's mode-0600 `/dev/shm` injection after
credential-free preparation, configures the fixed internal subscription relay,
and removes credential material on exit. It uses the broker-mediated checkout,
commit, push, and pull-request flow; Codex never receives a direct GitHub or
general-internet route.

Codex delivery is now a third deterministic phase, not wrapper-owned state in
the same UID boundary. Preparation has private broker credentials and no OpenAI
auth. Execution has the current ID/access/account Codex fields streamed into
tmpfs with an explicitly empty refresh token, the exact-path relay, no broker
agent ID/secret/bundle, no private-broker route, and exactly
one `codex exec`. It rejects created commits/refs, runs the required validation,
and seals bounded `codex-execution-result/v1`, binary
diff, validation output, final output, and usage projection artifacts only
after exact token scanning across every host-backed work,
output, lessons, symlink, filename, and Git object. Codex and validation
statuses are captured so their scans run even after nonzero exits. Once the
task-credential FD exists, the EXIT trap scans before closing it; contamination or an
incomplete scan purges all disposable host paths, exits nonzero, and prevents
delivery. Purge first restores owner `rwX` without following symlinks, deletes,
and verifies `/work`, `/output`, and `/lessons` before claiming removal. Any
cleanup or verification failure emits `purge_failed`, keeps host artifacts
quarantined, and leaves delivery blocked. Clean complete bounded valid-UTF-8
final output remains verbatim in
terminal projections for Codex, validation, and delivery failures; unusable
output is reported explicitly and never truncated.

Codex 0.146.0 requires `tokens.id_token` when loading ChatGPT `auth.json`.
The holder therefore projects that current master field with the access token
and account ID while continuing to omit all refresh capability. A nonzero
Codex exit is credential-scanned before the worker atomically persists one
bounded `codex-execution-failure/v1` operational projection. Raw JSON events,
stderr, prompts, credentials, and hidden reasoning remain tmpfs-only and are
removed at termination; the broker validates the projection identity and
bounds before using it in the durable terminal failure.

The fresh `/usr/local/bin/agent-codex-delivery-worker` has private broker
credentials and no Codex auth, holder, relay, or proxy. It verifies preparation
and execution identity/digests, HEAD/ref invariants, and the sealed successful
validation digest, removes and recreates a fixed minimal local Git config
before Git use, reconstructs a trusted hook/filter/fsmonitor-free index and
broker remote under a scrubbed no-pager/no-editor environment, then commits and
pushes without running repository-controlled subprocesses, and
reconciles exactly one ready PR by repository, base, head, and the durable run
body marker before create. Ambiguous create performs the same exact
reconciliation. The durable launch intent uses `-prep`, `-exec`, and
`-deliver` identities and adopts phase containers across restart; it never
launches a second execution or delivery container.

Execution restart reconciliation preserves the durable phase observed before
container inspection. A running `execution_running` container is watch-only.
`bundle_accept_pending` waits for the in-container acceptance marker and
idempotently consumes issuance before adoption. `bundle_inject_pending` first
probes that marker, so a crash after injection or consumption cannot re-issue
or re-inject an accepted bundle; only a still-unaccepted, unconsumed issuance
may be projected again. Preparation and delivery adoption likewise inspect
without overwriting their durable phase with a transient reconcile phase.

Codex workflow failures stop and verify the current durable phase container
before persisting terminal failure. Container selection comes from the
phase-specific preparation, execution, or delivery identity rather than the
generic last-container field, so cleanup cannot target a prior phase or launch
work. Stop uses the configured grace under a bounded context, reconciles a
verified already-exited/not-modified race, and preserves stop or verification
failure in both the terminal failure reason and audit. Stopping execution also
destroys its access-only credential and injection paths with the container
tmpfs before the one durable terminal result is published.

The staged `repository_transport_stage` audit events remain on the real Git
path. No local repository backend, registered green-PR endpoint, agentd
authority lifecycle, or agentd-issued Git credential path remains.

Durable idempotent launch intents now terminalize container-create and
container-start failures instead of returning an indefinitely replayable
`create_pending` or `start_pending` intent. The broker persists a bounded,
redacted `sandbox_startup` fallback result and returns the stable run identity
with terminal `failed` status. Replaying the launch key returns that same
terminal run without another runtime create or start.

Receive-pack command-prefix parse rejections now emit a dedicated transport
stage with a named failure reason, bytes consumed, request content framing,
and at most the first 128 bytes hex-encoded. Successful upstream Git requests
also emit an `upstream_completed` transport stage.

Receive-pack parsing accepts leading `shallow <40-hex-oid>` pkt-lines before
the command list and preserves them byte-for-byte when replaying the request
upstream. Malformed shallow lines are rejected with the named
`malformed_shallow` reason. Push certificates remain unsupported because their
embedded commands require separate parsing to preserve ref policy enforcement.

The secure Codex production activation also requires an encrypted broker-state
backup. The deployment workflow projects only the three scoped Restic/R2
inputs named `VPS_OPS_GH_BROKER_STATE_BACKUP_*` into the existing vps-ops
env-source boundary. The master Codex `auth.json` is not a GitHub or Doppler
secret and is never projected by this workflow; it remains exclusively in the
managed broker-side holder installed through the separate one-shot bootstrap.

Manual managed deployments may pair `image_sha` with an exact `image_digest`.
The workflow validates the digest shape and passes
`ghcr.io/grubbyhacker/gh-agent-broker:sha-<revision>@sha256:<digest>` to
vps-ops. This is required for reviewed activation pins; omitting the digest
retains the ordinary tag-only behavior for deployment paths whose Ansible
contract does not require an immutable application image.

PR #167 follow-up: CI observation now requires `head_sha` and returns both
requested and authoritative heads; active rules include required workflow DTOs;
and public comments no longer render broker metadata. Repair authority is
persisted in RunMetadata and projected read-only under `/input`; delivery
compares untrusted preparation artifacts to it. Delivery container identities
are retained for cleanup, and terminal results expose bounded model-start and
failure-class fields. Local test/lint/race checks pass. Go 1.26.6 is pinned so
the standard-library vulnerability scan passes as well.

PR #167 recovery hardening now persists a delivery-attempt identity before
container creation; the initial and recovered deliveries therefore use distinct
runtime specs and Docker cannot adopt the exited stale delivery. A single
stale-lease handoff is sealed with a SHA-256 over canonical run/repository/
branch/expected/winner/candidate/tree fields, persisted in run metadata, and
rechecked by the credential-free recovery worker and the broker. Recovery uses
`git merge-tree --write-tree` plus `commit-tree` to apply the candidate onto
the winning head and fails closed on conflicts. Recovery templates accept no
extra mounts and reject `BROKER_*`, Codex, OpenAI, and proxy environment keys.
Issue-comment idempotency atomically reserves an exact request, retains its
first rendered semantic body for reconciliation/retry, and scans an explicit
ten pages of comments; raw idempotency keys remain absent from durable state.

PR #167 acceptance follow-up: terminal failure classification is now durable
phase/execution-start based and limited to `infrastructure`, `model_or_code`,
and `delivery_or_lease`; worker-emitted failed output cannot omit it. Repair
delivery re-reads the authority PR before and after its lease push and projects
the terminal PR from that post-push response. Required workflow matching strips
GitHub's `@ref` path suffix and accepts official referenced-workflow shapes
without repository IDs. Pending comment reconciliation ignores old exact prose
outside a two-minute skew allowance and fails closed on ambiguous candidates.
Repair authority input is mode 0444.

Post-merge contract correction: `terra-medium-v1` remains the single reviewed
initial-and-repair profile. `repair_pr_number` and `expected_head_sha` are
optional declarations but must be supplied together for repair, with partial
pairs rejected before run creation. Parameterized requests may also carry the
sole reviewed top-level `max_runtime_seconds` override when the profile
allowlists it; applying the seconds override replaces the profile's minute
default so Signal Plane can bound the active broker/model phase.

External GitHub availability follow-up: credential-free preparation and
credentialed delivery now emit one bounded structured diagnostic only for
broker-classified GitHub timeout, rate-limit, or upstream errors. Such runs
persist nonterminal `waiting_external` state and expose a phase/operation/
reason/generation DTO. `POST /v1/runs/{run_id}/resume` requires the original
launch authority, a new durable idempotency key for that wait generation, and
an exact bounded `max_runtime_seconds` body. Preparation restarts without model
issuance; delivery restarts from the sealed validated candidate without Codex,
and reconciles an already-delivered candidate before retrying its exact lease.

AgentRelease publication and activation are exposed at `/v1/releases` with the
action-scoped operator vocabulary `release.publish`, `release.promote`, and
`release.rollback`. Verification and acquisition are internal broker transitions.
A `PromoterAuthenticator` verifies the request into a credential-free
`VerifiedPromoter` before the handler checks the action and calls the registry, so a
future OIDC verifier replaces only that authentication implementation. The
configured-token implementation records the principal name as every caller audit
actor. Configuration requires publish and promote principals to hold no other action;
rollback remains separate. `make check` passed locally.
