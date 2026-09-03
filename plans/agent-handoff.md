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
`docs/repository-agent-ci-repair-contract.md`. It adds broker-owned
authoritative observation and bounded Actions-log input, checks out an existing
PR at an admitted SHA, seals final validation to the candidate tree, and uses
an exact-SHA force-with-lease for delivery. Signal Plane owns durable event
correlation, attempt/deadline accounting, and idempotent issue escalation.

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

Development, CI, and Go-based container builds use Go 1.26.5. The `go 1.25.0`
directive is intentionally retained as the module compatibility floor; the
`toolchain go1.26.5` directive pins the build toolchain.

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
