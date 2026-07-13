# Webhook-Derived Codex Worker Milestone

## Decision

Build the first implementation-agent path from the existing foundations rather
than introducing Codex Fleet or a new launcher:

```text
GitHub issue labeled agent:implement
  -> Signal Plane GitHub envelope
  -> downstream GitHub task dispatcher
  -> fixed sandbox-broker launch profile
  -> Codex CLI worker container
  -> gh-agent-broker Git and REST access
  -> ready-for-review pull request
```

The first end-to-end proof targets `grubbyhacker/apple-jobs-matcher`. The
existing `hermes-agent-infra` GitHub App and broker agent already have access to
that repository. In this design, `hermes-agent-infra` names the execution
identity; it is not the repository being modified.

Milestone one reuses that GitHub identity to avoid adding an App/bootstrap
project before the launch path is proven. It adds separate sandbox launch and
operator identities so the new worker cannot invoke or alter Curator profiles.
A future multi-engineer milestone may give each worker or worker pool a distinct
GitHub App and broker identity.

The worker uses a dedicated OpenAI Codex OAuth session associated with the
operator's existing ChatGPT/Codex subscription. It does not use the metered
LiteLLM/model-proxy path for milestone one.

## Boundaries

### Signal Plane

Signal Plane remains transport, not job control.

- `signal-gateway` verifies GitHub signatures, repository, event family, and
  action admission.
- The gateway publishes the thin provider envelope and raw payload to
  JetStream.
- The gateway does not know sandbox templates, worker identities, model
  credentials, branch policy, or job lifecycle.
- A separate downstream dispatcher owns GitHub-to-launch interpretation.

The first stimulus is the transition that applies label `agent:implement` to an
issue. Issue creation, edits, comments, assignment changes, and unrelated labels
must not launch work.

### Dispatcher

The dispatcher is the narrow semantic bridge. It may select one fixed launch
profile and submit bounded parameters; it may not choose a worker image,
command, mount, credential bundle, network, arbitrary repository, or broker
identity.

Implement it as a separate `github-task-dispatcher` process in the Signal Plane
repository. It may reuse Signal Plane envelope/eventbus packages, but the
gateway and observer must not import dispatcher or sandbox-launch semantics.
`vps-ops` owns its production configuration, persistent state path, and compose
deployment.

Milestone-one accepted input:

- source is GitHub;
- repository is exactly `grubbyhacker/apple-jobs-matcher`;
- event is `issues`;
- action is `labeled`;
- applied label is exactly `agent:implement`;
- issue is open and is not a pull request;
- sender and delivery metadata are present.

The launch request contains references, not an unbounded prompt copy:

- repository full name;
- issue number;
- GitHub delivery ID;
- label actor login;
- source event and action;
- requested profile name.

The worker reads the authoritative issue body and comments through
`gh-agent-broker`. This keeps the sandbox task document under the broker's
existing size cap and makes GitHub access policy observable and auditable.

### Sandbox Broker

The existing sandbox broker remains the only Docker launcher. Add configuration
for, at minimum:

- operator principal: `github-task-dispatcher`;
- launch profile: `codex-issue-implement`;
- template: `codex-implementation-worker`;
- credential bundle: `codex-worker-openai`;
- repository: `grubbyhacker/apple-jobs-matcher`;
- broker agent identity: `hermes-agent-infra`;
- base branch: `main`;
- generated branch prefix: `agent/hermes-agent-infra`;
- initial maximum runtime: 60 minutes;
- initial maximum concurrency for the credential slot: one.

Profile-level concurrency is not enforced by the current sandbox broker. Slice
1 must add an atomic credential-slot lease or equivalent template/profile
concurrency guard before the profile can be enabled. A second launch must fail
closed with a structured busy response; process-local checking without durable
state is insufficient.

The dispatcher principal receives only profile listing, dry-run, launch, and
status permissions for `codex-issue-implement`. It does not receive Curator
profile access, arbitrary MCP launch access, logs from unrelated runs, stop,
cleanup, or template overrides.

Caller overrides are deny-by-default. The profile accepts only validated issue
number and source delivery metadata parameters. Repository, base branch,
template, command, credentials, resource limits, and deliverables remain fixed
in operator configuration.

### GitHub Broker

The worker receives no GitHub token, App private key, App JWT, or installation
token. It receives the existing broker identity and secret through the sandbox
template and uses:

- brokered clone, fetch, and push;
- broker reads for the issue, comments, checks, and pull requests;
- broker PR creation;
- the existing `agent/hermes-agent-infra/...` branch namespace;
- the existing repository, operation, permission, and metadata policy.

The first proof does not expand the `hermes-agent-infra` repository allowlist.
The existing three-gate contract remains authoritative: GitHub App installation
access, broker repository authorization, and broker branch policy.

## Codex Worker Contract

The immutable worker image contains:

- a pinned Codex CLI version;
- `gh-agent-broker-cli`;
- Git, CA certificates, `rg`, and common shell utilities;
- Python 3.12 and `uv` for the initial `apple-jobs-matcher` proof;
- `mise` when used as the stable task interface by future repositories, with
  additional toolchains added through deliberate worker profiles rather than
  ambient host assumptions;
- a checked-in worker entrypoint rather than generated shell source.

The entrypoint:

1. Copies the read-only credential bundle into a task-local `CODEX_HOME` with
   mode `0600`.
2. Configures the broker Git remote without storing the broker secret in Git
   config.
3. Reads the issue and relevant comments through the broker.
4. Creates a fresh policy-compliant branch.
5. Verifies the dedicated Codex session before making repository changes and
   fails with an auth-specific terminal reason when it needs reprovisioning.
6. Runs `codex exec --ephemeral` noninteractively in the checked-out repository.
7. Requires `uv run pytest -q` for the initial repository before PR creation.
   The proof issue must be deterministic code work and must not require a live
   Apple crawl, private resume/preferences, generated reports, or scheduling.
8. Pushes and opens a ready-for-review PR through the broker.
9. Writes bounded final status and summary artifacts.

Required deliverables:

- `/output/final-summary.md`;
- `/output/result.json` with issue, branch, commit, PR, validation, and outcome;
- `/output/codex-final.txt`;
- bounded Codex event output suitable for redacted diagnostics.

The worker must never merge its PR. Human review remains the completion gate.

## OpenAI Codex Authentication Contract

### Recovered Evidence

The repository already contains a working proof in
`scripts/sandbox-codex-auth-e2e.sh` and
`testdata/sandbox-codex-auth/worker.sh`, originally added with the sandbox MCP
worker foundation. That proof:

- copies `~/.codex/auth.json` and `config.toml` into a temporary credential
  bundle;
- mounts only that bundle read-only;
- copies it into a per-run `CODEX_HOME`;
- verifies parent Hermes credentials are not visible;
- runs real noninteractive `codex exec --ephemeral`;
- verifies a sentinel final response;
- redacts strings extracted from the credential JSON;
- removes the run and temporary credential material.

The same history records a Hermes-native sandbox proof. Current Hermes source
keeps `openai-codex` OAuth state in the Hermes-owned auth store and deliberately
separates it from Codex CLI state to avoid refresh-token reuse races. Relevant
upstream source and discussion:

- <https://github.com/NousResearch/hermes-agent/blob/main/hermes_cli/auth.py>
- <https://github.com/NousResearch/hermes-agent/issues/9283>

### Milestone-One Provisioning

Do not mount the live Hermes auth store or the operator's active Codex home into
workers. Provision a dedicated sandbox Codex session in a root/operator-managed
directory, separate from both:

- the Hermes `HERMES_HOME` auth store;
- the operator's normal `~/.codex` session.

The production credential bundle contains only the minimal Codex `auth.json`
and `config.toml`, is restricted to the coding-worker template, is mounted
read-only, and is copied into the run-local `CODEX_HOME`. Secret-file values are
registered with sandbox redaction before logs or artifacts are collected.

Milestone one permits only one active run using this credential slot. A copied
OAuth bundle is sufficient to prove the launch path, but it is not a complete
multi-worker refresh architecture: rotating refresh tokens from concurrent or
independent copies can invalidate each other, and refreshed state in an
ephemeral copy is not automatically persisted to the source bundle.

Before concurrency exceeds one, choose and prove one of:

- one separately authenticated Codex session per worker slot;
- a trusted host-side credential lease/refresh service with serialized refresh;
- another OpenAI-supported subscription-auth mechanism that does not share a
  rotating refresh token across workers.

The metered model proxy remains a fallback, not the default for this milestone.

## Idempotency And Lifecycle

GitHub may redeliver webhooks, and sandbox launch profiles currently do not
deduplicate repeated launches. The dispatcher therefore owns launch
idempotency before automatic launch is enabled.

Milestone-one idempotency key:

```text
github:grubbyhacker/apple-jobs-matcher:issue:<number>:agent-implement
```

The GitHub delivery ID is recorded as stimulus evidence but is not the sole key,
because a label can be removed and reapplied with a different delivery ID.
Initial policy is one active or successfully completed implementation job per
issue. Retrying requires an explicit operator action defined in a later slice;
ordinary webhook redelivery never launches a second worker.

Minimum durable job record:

- idempotency key;
- source delivery ID and event timestamp;
- repository and issue number;
- selected profile;
- sandbox run ID;
- state: `launching`, `running`, `succeeded`, `failed`, or `cancelled`;
- branch and PR number when available;
- terminal reason and timestamps.

JetStream remains the durable event transport, not this semantic job store.
Use a dispatcher-owned SQLite database with a unique idempotency-key constraint
and transactional state transitions for milestone one. Do not infer job state
from JetStream consumer acknowledgement, sandbox logs, branches, or PRs. The
database lives on a dedicated managed volume; `vps-ops` must declare its
retention and backup/restore policy before production enablement.

## Curator Non-Regression Guardrail

The coding-worker addition must not change existing Curator behavior.

Configuration isolation requirements:

- Do not rename or modify existing `ykm-curator-*` profiles or templates.
- Do not change `ykm-curator-timer` or `ykm-curator-operator` permissions.
- Do not reuse Curator broker identities, model-proxy bundles, intake mounts,
  log mounts, branch prefixes, deliverables, or completion-status paths.
- Keep the coding-worker image, profile, template, principal, credential bundle,
  and state paths separate.
- Rendered-config validation must compare the Curator subtrees before and after
  the addition and fail on unintended changes.

Required validation before any broker production deploy:

1. `gh-agent-broker`: `make check` and sandbox E2E coverage for the new fixed
   profile, auth scope, mounts, redaction, branch policy, and cleanup.
2. `vps-ops`: `mise run required` including rendered broker/App/access policy
   validation.
3. Guarded local Curator staging validation:

   ```sh
   mise run curator:staging:validate-upload-agent -- \
     --source <fixture-path> --upload-id <fixture-id> --mode dry-run
   ```

4. Confirm existing Curator timer/profile names and rendered task JSON are
   unchanged.
5. After an approved broker production deploy, verify broker readiness and run
   one non-mutating Curator state-only launch before declaring the integration
   healthy.

The production Curator validation must not create or repair PRs, consume queued
feedback, or alter corpus state.

## Implementation Slices

### Slice 1: Manual Broker Launch Proof

Prove the execution foundation before connecting webhooks:

- add the pinned coding-worker image and checked-in entrypoint;
- add the dedicated Codex credential bundle contract;
- add the fixed sandbox template, launch profile, and operator principal;
- add the durable concurrency-one credential-slot lease;
- reuse `hermes-agent-infra` for brokered GitHub access to
  `apple-jobs-matcher`;
- launch manually with an issue-number parameter;
- produce a validated ready PR;
- run the Curator non-regression validation.

Done means a human operator can launch exactly one scoped Codex implementation
worker without Signal Plane or dispatcher code.

### Slice 2: Webhook-Derived Launch

Only after slice 1 is proven:

- subscribe and admit GitHub `issues.labeled` for the selected repository;
- add the downstream dispatcher without making `signal-gateway` agent-aware;
- enforce the exact `agent:implement` label transition;
- add durable idempotency and run correlation;
- invoke only the fixed `codex-issue-implement` profile;
- prove real GitHub label -> worker -> ready PR;
- prove redelivery and unrelated labels do not launch duplicates.

Stop after this slice. Review updates, pushback, wake-up behavior, multiple
workers, additional repositories, and issue reassignment are later milestones.

## Explicit Non-Goals

- Codex Fleet in the runtime architecture.
- A general scheduler or semantic workflow engine.
- Multiple concurrent Codex OAuth workers.
- Arbitrary task prompts, repositories, images, commands, mounts, or networks.
- Direct GitHub credentials in the worker.
- Automatic merge.
- PR-review conversation handling or agent wake-up in this milestone.
- Changes to Curator's current execution or model path.
