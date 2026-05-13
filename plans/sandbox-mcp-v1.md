# Sandbox MCP V1 Design

## Summary

Implement the sandbox broker as a separate Go service in this repository. It
ships from the same OCI image as the GitHub broker, but runs as its own
process/container. The GitHub broker remains GitHub-only: it owns GitHub App
credentials, Git policy, Git proxying, GitHub REST operations, and audit for
those operations. The sandbox broker owns task container lifecycle, run
bookkeeping, curated input snapshots, credential bundle mounting, and
artifact/lesson collection.

V1 decisions:

- Runtime: Docker Engine behind a `RuntimeBackend` interface.
- GitHub credentials: static template-scoped broker identities.
- Model credentials: template-scoped read-only credential bundles, managed by
  the operator.
- Knowledge: explicit snapshots copied into each run's `/input`; never mount
  parent Hermes data.
- MCP auth: private network plus shared token/header secret.
- Artifacts: manifest, hashes, and small inline text snippets only.
- Network: operator-created Docker networks; no v1 domain-level egress
  filtering.

## Key Changes

- Add `cmd/sandbox-broker` and `internal/sandbox` for config, MCP handlers, run
  state, audit, redaction, credential bundle policy, and Docker backend.
- Extend the Dockerfile to include `sandbox-broker`; extend example Compose
  with a separate `sandbox-broker` service. Only this service may access Docker
  Engine. Hermes gets only the MCP URL/token.
- Add `configs/sandbox.example.yaml` with service settings, broker URL, allowed
  repositories, named Docker network policies, credential bundles, and
  templates.
- Document that Hermes must never receive the Docker socket, host root,
  arbitrary host mounts, `/opt/data`, parent memory DB, or parent session files.

The sandbox config should include:

- `listen`, `mcp_path`, `auth_token_env`, `runs_dir`, and `audit.path`.
- `broker_url` and explicit repository allowlists.
- Named network policies mapping to operator-created Docker networks or `none`.
- `credential_bundles` with source path, container mount path, readonly flag,
  allowed templates, and `secret_files` or `redact_files` listing text files to
  read/hash for redaction fingerprints.
- Templates with fixed image, command, user, resources, network policy, max
  runtime, broker identity, branch policy, credential bundle, deliverables
  defaults, and allowed knowledge snapshot paths.

## MCP Contract

Expose these tools:

- `launch_agent`
- `dry_run_launch`
- `validate_template`
- `list_agents`
- `get_agent_status`
- `get_agent_logs`
- `stop_agent`
- `collect_artifacts`
- `collect_lessons`
- `cleanup_run`

`launch_agent` accepts intent only:

- `template`
- `task`
- `repo`
- `base_branch`
- optional `branch`
- optional `max_runtime_minutes`
- optional `deliverables`
- optional `focus`

It must reject unknown templates, invalid repo strings, repos outside allowlist,
runtime above template max, oversized task payloads, arbitrary image, command,
env, mounts, privileged flags, capabilities, host paths, and network overrides.

Run IDs must be unguessable, using a timestamp plus random suffix or a UUID.
Branches must match template policy. If the caller omits `branch`, generate a
safe branch such as `agent/<worker_agent_id>/<run_id>`.

## Runtime And Isolation

Each launch creates this host directory structure:

```text
/srv/hermes-sandbox-broker/runs/<run_id>/
  input/
  work/
  output/
  lessons/
  logs/
  metadata.json
```

The broker always writes task context into `/input` before starting the worker:

- `task.json` contains run ID, task, focus, repo, base branch, generated
  branch, worker agent ID, broker remote URL, and effective deliverables.
- `task.md` contains the user task text.
- `sandbox-rules.md` contains broker-supplied wrapper constraints and required
  output paths.

Container mounts:

- `/input` read-only.
- `/work`, `/output`, and `/lessons` read-write.
- Credential bundle read-only at its configured mount path.
- No Docker socket, arbitrary binds, host namespace, host network, or parent
  Hermes data.

Docker config must enforce:

- Non-root user.
- `no-new-privileges`.
- `cap_drop: ALL`.
- CPU, memory, and PID limits.
- Fixed labels/env from sanitized server-side values only.
- Configured Docker network or no network.
- Image digest required in production mode.
- Resolved image digest always recorded in audit, even if config used a tag.

Startup must reconcile orphaned state:

- Running container with missing metadata.
- Metadata with missing container.
- Timed-out run still running.

Timeout handling stops the container, kills it after grace period, marks the run
failed/timed out, and preserves output, lessons, logs, and metadata. Cleanup is
explicit and must never delete outside the run directory.

## Credentials, Outputs, And Audit

GitHub broker identities are template-scoped, not caller-scoped. Future work can
add short-lived per-run broker credentials.

Provider credential bundles:

- Are secrets.
- Are mounted read-only.
- Are selected by server-side template policy, not caller input.
- Must live under configured bundle source allowlists.
- May contain refresh tokens and can be exfiltrated by a malicious worker.
- Are a pragmatic v1 compromise; a v2 model broker/proxy is the safer long-term
  design.

Worker `$HOME` and `$HERMES_HOME` are task-local and must not inherit image
defaults if those defaults point at shared or persistent state. A startup shim
may copy or symlink minimal auth files from the read-only credential bundle into
expected task-local paths.

Required worker outputs:

- `/output/final-summary.md`
- `/lessons/run-summary.md`

Required deliverables are template policy plus launch-request deliverables.
General task workers should fail nonzero when required sandbox filesystem
deliverables under `/output` or `/lessons` are missing. Repo-relative
deliverables are task requirements for the agent and repository checks, not
wrapper-validated sandbox files. Auth probes and other fixed-purpose templates
should be named explicitly so they are not confused with task-consuming workers.

Strongly recommended worker outputs:

- `/lessons/tool-friction.md`
- `/lessons/security-observations.md`

Audit events include run ID, template, parent agent ID, worker agent ID, repo,
branch, image digest, credential bundle name, start/end time, status, exit
code, policy decision, and error. Logs and artifacts must redact generic
token/authorization patterns and known secret values from configured bundle
files. Do not claim reliable redaction of unknown binary or provider-specific
token formats. Returned logs must be byte-capped.

## Test Plan

- Config validation: unknown template/network/bundle, bundle path outside
  allowlist, missing broker identity secret, missing image digest in production
  mode, runtime above max.
- Launch validation: rejects arbitrary mount, Docker socket mount, privileged
  mode, host network, caller image/command/env, invalid repo/path injection,
  oversized task payload, unsafe branch.
- Filesystem safety: rejects symlink/path traversal in knowledge snapshots and
  artifacts; cleanup cannot delete outside run dir; artifact collection never
  follows symlinks outside run dir.
- Task contract: launches write `/input/task.json`, `/input/task.md`, and
  `/input/sandbox-rules.md`; marker E2Es assert unique task markers appear in
  both required output and lesson artifacts, including two-run regression
  coverage against fixed-prompt workers.
- Docker config: non-root, `cap_drop: ALL`, `no-new-privileges`, resource
  limits, fixed mounts, sanitized labels/env, selected network only.
- Lifecycle with fake backend: launch, status, logs, stop, timeout, cleanup,
  and startup orphan reconciliation.
- Collections: artifact/lesson manifests, small inline text, large file
  manifest-only, log byte cap, redaction.
- Credential bundle isolation: bundle files are never returned by
  `collect_artifacts`, `collect_lessons`, or `get_agent_logs`.
- Audit: launch/deny/stop/timeout/cleanup include sandbox metadata, image
  digest, credential bundle, and policy decision.
- MCP: token required with constant-time comparison; token is never logged; all
  tools map to service behavior.

## Documentation

- Add operator docs for one-time credential bundle bootstrap using a helper
  container with the same image, UID, `$HOME`, CLI versions, and target
  credential path as workers. The helper writes only into the named bundle
  directory, never into `runs_dir` or parent Hermes `/opt/data`.
- Recommend creating fresh sandbox-specific provider logins rather than copying
  live parent auth files.
- Document revocation: delete the bundle directory and revoke the upstream
  provider session.
- Explicitly state v1 credential bundles reduce operational blast radius but do
  not make untrusted workers safe against credential exfiltration; v2 should use
  a model broker/proxy.
