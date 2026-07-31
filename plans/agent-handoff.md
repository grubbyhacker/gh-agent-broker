# Agent handoff

The first secure Codex issue-to-ready-PR slice is implemented behind the
`codex_issue_workflow` launch-profile contract. It uses distinct durable
preparation and execution container identities. Preparation has no Codex
credential and fails stale unless checkout dependency/submodule identity
exactly matches the baked manifest. The sandbox-broker-owned holder performs a
bounded refresh before startup completes, then maintains the full credential
master on a fixed 30-minute interval; periodic failures are bounded and logged
with static redacted text. Run admission never refreshes. It only projects the
current persisted access token and account ID into an access-only `auth.json`
in memory with an explicitly empty refresh token. Token-free issuance state
records only run/idempotency identity and issued/consumed times, independent of
OAuth host, token lineage, and Codex version. After the fresh execution
container starts, sandbox-broker
streams it through Docker's archive API into bounded `/dev/shm`; no host
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

Both deterministic repository workers now produce the shared bounded
`repository-task-worker-result/v1` contract. It preserves the generic
worker's `task` field and the Codex worker's `worker: "codex"` field, always
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
