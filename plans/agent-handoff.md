# Agent handoff

The repository-agent lifecycle experiment has been removed. The production
surface remains the broker-agent authenticated smart-HTTP proxy at `/git/*`
and the GitHub REST proxy at `/v1/repos/*`.

For a curator push, `handleGit` authenticates the configured broker agent,
checks Git policy and branch/ref preflight, resolves the configured GitHub App
installation, mints its installation token, and forwards smart-HTTP to GitHub
with `x-access-token` Basic authentication. Pull requests are opened through
the existing `/v1/repos/{owner}/{repo}/pulls` API path.

The staged `repository_transport_stage` audit events remain on the real Git
path. No local repository backend, registered green-PR endpoint, agentd
authority lifecycle, or agentd-issued Git credential path remains.

Receive-pack command-prefix parse rejections now emit a dedicated transport
stage with a named failure reason, bytes consumed, request content framing,
and at most the first 128 bytes hex-encoded. Successful upstream Git requests
also emit an `upstream_completed` transport stage.
