# Agent handoff

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
repository image that supplies Codex CLI. It copies only
`/credentials/codex/auth.json` into a mode-0600 `CODEX_HOME` below `/dev/shm`,
after broker checkout, dependency-manifest verification, baked-submodule
hydration, and any dependency installation. This ordering is defense in depth
only: the raw credential bundle remains readable at `/credentials/codex` during
preparation, which violates design section 4.3 and is a known defect. Required
follow-up work is a credential-free preparation container that produces a
workspace and provenance record, followed by a fresh coding container that
receives that workspace and the credential. It uses the same broker-mediated checkout,
commit, push, and pull-request flow as the model-free worker. Its task prompt
is supplied by `AGENT_CODEX_PROMPT` or `AGENT_CODEX_PROMPT_FILE`; the wrapper
instructs Codex not to read credentials or perform GitHub delivery actions.
Its JWT expiry check decodes the base64url payload (including restored padding)
with `jq`; a shell regression test uses a synthetic, unpadded payload that
contains a base64url underscore and verifies accepted future tokens plus
rejected expired and safety-margin tokens.

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
