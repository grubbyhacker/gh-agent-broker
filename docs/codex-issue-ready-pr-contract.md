# Secure Codex issue-to-ready-PR contract

This document is the configuration handoff for the first secure Codex
issue-to-ready-PR milestone. It does not authorize production deployment.

## Mechanical trust boundary

> **The broker owns durable side effects. The agent owns reasoning.**

This is an enforced architecture invariant, not prompt guidance. Codex may
interpret the task, edit the prepared workspace, run validation without broker
authority, and emit only bounded execution outputs. Broker-controlled
deterministic code alone may advance durable workflow state, push branches,
create or update pull requests, and post comments. A route that lets agent
reasoning directly perform any of those durable side effects violates this
contract even if a prompt tells the agent not to do so.

## Signal Plane launch contract

Signal Plane launches only the reviewed `terra-medium-v1` launch profile via
`POST /v1/launch-profiles/terra-medium-v1/launch`. It must send a stable
`Idempotency-Key` and these typed parameters. Signal Plane may also set the
single reviewed top-level `max_runtime_seconds` override to the remaining
durable deadline budget:

```json
{
  "parameters": {
    "issue_number": 123,
    "source_delivery_id": "stable-source-delivery-id"
  },
  "max_runtime_seconds": 1800
}
```

`issue_number` is a positive integer. `source_delivery_id` matches
`^[A-Za-z0-9-]{1,128}$`. Existing canonical request fingerprinting and
principal/profile/idempotency namespaces remain authoritative.
Initial issue-to-PR launches omit both conditional repair parameters.

Terminal delivery reads
`GET /v1/runs/{run_id}/terminal-result`. Successful outcomes are
`no_change_required` or `ready_for_review`. Signal Plane must treat missing or
oversized final output as an explicit failure and must not fall back to logs or
arbitrary artifacts.

## sandbox-broker configuration

The profile is a durable four-phase container workflow under one broker run:

```yaml
codex_holder:
  master_auth_path: /srv/hermes-sandbox-broker/codex-holder/master/auth.json
  issuance_root: /srv/hermes-sandbox-broker/codex-holder/issuance

model_policies:
  reviewed-codex-v1:
    version: codex-model-policy/v1
    mappings:
      luna-medium-v1:  {model: gpt-5.6-luna,  effort: medium}
      luna-high-v1:    {model: gpt-5.6-luna,  effort: high}
      terra-medium-v1: {model: gpt-5.6-terra, effort: medium}
      terra-high-v1:   {model: gpt-5.6-terra, effort: high}
      sol-high-v1:     {model: gpt-5.6-sol,   effort: high}

network_policies:
  codex-preparation:
    network: codex-preparation-internal
    private_broker: true
  codex-execution:
    network: codex-execution-internal
    codex_subscription_relay: true
  codex-delivery:
    network: codex-delivery-internal
    private_broker: true

launch_profiles:
  terra-medium-v1:
    template: codex-execution
    repo: OWNER/REPOSITORY
    base_branch: main
    task: Implement the authoritative issue supplied by the typed task contract.
    verification_task: verify
    max_runtime_minutes: 60
    max_concurrent_runs: 1
    require_idempotency_key: true
    allow_overrides: [max_runtime_seconds]
    parameters:
      issue_number: {type: integer, required: true, min: 1}
      source_delivery_id:
        {type: string, required: true, max_length: 128, pattern: "^[A-Za-z0-9-]+$"}
      repair_pr_number: {type: integer, required: false, min: 1}
      expected_head_sha:
        {type: string, required: false, max_length: 40, pattern: "^[a-f0-9]{40}$"}
    codex_issue_workflow:
      preparation_template: codex-preparation
      execution_template: codex-execution
      recovery_template: codex-recovery-validation
      delivery_template: codex-delivery
      model_policy: reviewed-codex-v1
      model_profile: terra-medium-v1
      prompt_revision: issue-ready-pr/v1
```

All four templates use digest-pinned versions of the same reviewed repository
worker image. `codex-preparation` runs
`/usr/local/bin/agent-codex-repo-prep-worker`, has no credential bundle, uses
the private-broker-only preparation network, and has bounded resources and
storage. `codex-execution` runs
`/usr/local/bin/agent-codex-repo-task-worker`, has no broker agent ID, secret,
credential bundle, private-broker route, proxy, or GitHub route, and uses only
the exact-path relay network. `codex-delivery` runs the new
`/usr/local/bin/agent-codex-delivery-worker`, has private broker credentials,
and has no Codex holder mount, access auth, relay, proxy, or public route.
Execution includes:

```yaml
storage_limit_mb: 8192
tmpfs:
  /dev/shm: 64
```

The broker never creates or mounts a run-scoped credential file. After
successful preparation it creates and starts the deterministic execution
container in a bounded credential-wait bootstrap, asks the holder to project
the current access fields in memory, and streams them only on Docker exec stdin
to a fixed command that creates a mode-`0600` file in the container's bounded
`/dev/shm` tmpfs. The worker
atomically accepts the file into its run-local tmpfs `CODEX_HOME`, removes the
injection source, and creates a token-free acceptance marker. Operator mounts
and credential bundles are rejected if they overlap holder paths or `/dev/shm`.

Before `codex exec`, the execution worker proves that broker/GitHub authority
is absent and replaces the local remote with an unreachable credential-free
URL. It invokes Codex exactly once. After Codex exits, HEAD, refs, and commit
objects must be unchanged. With no broker authority present, the worker runs
the required reviewed validation task, then creates a bounded binary diff,
bounded validation output, bounded final output, and a bounded execution result
containing their digests and the prepared HEAD. It performs exact task-credential
contamination scanning before publishing those artifacts. Codex and validation
exit statuses are captured explicitly: their scans always complete before a
nonzero status is acted upon.

The execution worker keeps exact ID- and access-token match patterns only in
`/dev/shm`. It scans Codex-controlled paths, file and symlink contents, Git
objects, final output, events, stderr, and the bounded diff without emitting
matched content. Once the token descriptor exists, the EXIT trap attempts the
complete scan before closing it on every unexpected failure. An exact match or
incomplete scan terminally fails the run. Cleanup first restores owner `rwX`
recursively without following symlinks, deletes the disposable `/work`,
`/output`, and `/lessons` contents, and verifies that only the static
scan-failure marker remains. Only a verified cleanup may report that artifacts
were purged. Any permission-restoration, deletion, marker, or verification
failure emits the distinct `purge_failed` result: removal is not claimed,
host-backed artifacts remain quarantined, and delivery stays blocked.
Contaminated artifacts are never redacted or delivered. Clean, complete,
bounded valid-UTF-8 Codex final
output remains available verbatim when Codex, validation, or delivery fails
after execution starts. Missing, empty, invalid, mismatched, or oversized
execution artifacts are explicit terminal failures, are never truncated, and
prevent delivery launch.

The fresh deterministic delivery container revalidates the preparation and
execution results, HEAD/branch identity, exact diff digest, final-output
digest, and the sealed successful validation result/digest. It runs no
repository-controlled subprocess with broker authority. It removes and
recreates a fixed minimal local Git config before any Git command, and uses a
scrubbed environment with hooks, filters, fsmonitor, pagers, and editors
disabled. It rebuilds the index from the prepared HEAD and reconstructs the
broker remote using its own private credential. It then commits and pushes.
Before creating a non-draft PR it reconciles the broker `pulls` API by the exact
repository endpoint, base branch, head branch, and
`<!-- gh-agent-broker-codex-run:RUN_ID -->` marker. A failed or ambiguous
create performs the same exact reconciliation; multiple matches fail closed.

The holder master file and its parent directory must be mode `0600` and `0700`
respectively. The master file is a Codex `auth.json` containing non-empty
`tokens.access_token` and `tokens.refresh_token`. It is readable only by
sandbox-broker. It is never a Docker mount. Before accepting work,
sandbox-broker performs one refresh bounded to 30 seconds and fails startup if
that refresh fails. It then refreshes the full master every fixed 30 minutes,
well below the normal access-token lifetime, with each attempt bounded to 30
seconds. Periodic failure logs are static and redacted. Refresh preserves
unknown master fields and atomically replaces the mode-`0600` file. The holder
posts refresh requests only to `https://auth.openai.com/oauth/token`, with the
reviewed Codex 0.146.0 client ID compiled into the broker.

Run admission never refreshes credentials. `Holder.Issue` only projects the
current persisted `id_token`, `access_token`, and `account_id` into an
access-only in-memory bundle with an explicitly empty refresh token. Codex
0.146.0 requires the identity token field when loading ChatGPT auth, but the
task bundle still contains no refresh capability. Distinct runs admitted
between maintenance refreshes therefore receive the same current access
fields. Token-free durable
issuance state contains only run ID, idempotency key digest, issued time, and
consumed time; it has no OAuth host, token lineage, or Codex-version credential
semantics. Codex version remains ordinary execution provenance.

## Network/deployment requirements for vps-ops

The named Docker networks are separate internal networks. Preparation and
delivery reach only the broker service. Execution reaches only
`http://codex-subscription-relay:8093`; it has no private broker, credential
helper-capable route, outbound proxy, public route, general DNS, GitHub,
`auth.openai.com`, or direct ChatGPT path. Its pinned
custom provider base is
`http://codex-subscription-relay:8093/backend-api/codex`, with
`requires_openai_auth=true` and the Responses wire API.

The broker-owned relay accepts exactly:

- `GET /backend-api/codex/models?client_version=0.146.0`
- `POST /backend-api/codex/responses` with no query
- `POST /backend-api/codex/responses/compact` with no query

It constructs the fixed `https://chatgpt.com` upstream itself, rejects
redirects, forwards only bounded reviewed headers and bodies, preserves
streaming, and emits no application logs containing Authorization, prompts,
responses, or hidden reasoning. Every other method, path, query, encoded path,
or caller-selected host fails closed.

vps-ops must attach the relay to both `codex-execution-internal` and a distinct
`codex-relay-egress-internal` network. Only the separate
`codex-subscription-edge` Squid service joins that egress network and an
outbound network. The relay has
`HTTPS_PROXY=http://codex-subscription-edge:3128`; Squid allows only
`CONNECT chatgpt.com:443` and denies all other destinations. The execution
container is not joined to either the relay-egress or outbound network.

The sandbox-broker/holder process may reach `auth.openai.com:443`. No worker
network may reach that host. Worker images must not include a runtime
dependency download fallback; a missing or mismatched baked
dependency/submodule manifest is a stale-image failure.

The execution image must contain exactly `@openai/codex@0.146.0`. Web search,
MCP/apps/plugins, update checks, and analytics are disabled in the run-local
configuration. The wrapper passes `--model gpt-5.6-terra` and
`model_reasoning_effort="medium"` explicitly. Unsupported policy mappings fail
without fallback.

## Durable and retained data

Preparation, execution, and delivery have distinct deterministic `-prep`,
`-exec`, and `-deliver` container identities under the same durable broker run.
The launch intent persists explicit create-pending, start-pending, running,
terminal, and reconcile boundaries for every phase, so replay adopts the exact
matching container. Once execution has started or exited, recovery never
launches another execution container; delivery similarly has one deterministic
identity. An ambiguous injection replay may project the
current persisted access fields again using the token-free issuance state. No
credential is recoverable from the issuance tree, run
directory, launch intent, metadata, checkpoint, environment, labels, mounts,
or container configuration.

The broker-owned terminal provenance contains only bounded operational facts:
policy/version, resolved model/effort, Codex version, prompt revision, observed
image digest/platform, workspace HEAD/manifest identity, issue/source IDs,
phase timings, run/profile, verification task/result, bounded token counts,
branch, and validated PR identity. It never contains prompts, event streams,
credentials, or hidden reasoning. Codex JSON events and stderr exist only
temporarily on execution tmpfs. On a nonzero Codex exit, the worker first scans
all host-backed artifacts and both raw streams for the task-local ID and access
tokens, then persists only one bounded operational error projection with its
source, byte counts, and SHA-256 digests. The raw streams are removed on
termination. Logs and arbitrary artifact endpoints are disabled for these
runs.

For failed, timed-out, or stopped Codex runs, terminal `failure_class` always
uses exactly one of: `infrastructure` (preparation, create, start, credential,
or other pre-execution failure), `model_or_code` (a failure after model
execution started), or `delivery_or_lease` (delivery, stale lease, or recovery
validation failure). The class is derived from durable phase and execution
start facts; worker-provided terminal JSON cannot select or omit it.
