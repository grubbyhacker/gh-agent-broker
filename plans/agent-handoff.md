# Agent handoff

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

Receive-pack command-prefix parse rejections now emit a dedicated transport
stage with a named failure reason, bytes consumed, request content framing,
and at most the first 128 bytes hex-encoded. Successful upstream Git requests
also emit an `upstream_completed` transport stage.

Receive-pack parsing accepts leading `shallow <40-hex-oid>` pkt-lines before
the command list and preserves them byte-for-byte when replaying the request
upstream. Malformed shallow lines are rejected with the named
`malformed_shallow` reason. Push certificates remain unsupported because their
embedded commands require separate parsing to preserve ref policy enforcement.
