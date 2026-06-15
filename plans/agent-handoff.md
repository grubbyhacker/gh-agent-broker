# Agent Handoff

## Current State

The repository is a greenfield Go implementation of a GitHub Agent Access Broker.

Current main CI repair:

- Current branch `fix/sandbox-terminal-audit-race` repairs failed main CI run
  `27578004362`, job `81531181595`. The failed workflow was `CI`, job `check`,
  step `Run hygiene gate` (`make ci`), not the production deploy workflow.
- Root cause was not PR `#57` actionlint/workflow validation. `go test ./...`
  failed in `internal/sandbox` because
  `TestExitWatcherFinalizesRunAndWritesTerminalAudit` observed stopped
  metadata before the async exit watcher had written the terminal audit row.
- The test now waits explicitly for the expected terminal audit event instead
  of assuming metadata visibility implies the audit write is already visible.
  Latest verification passed: focused test with `-count=100` and full
  `make ci`.

Current deploy outcome telemetry refactor:

- Current branch `refactor/use-vps-ops-deploy-telemetry` removes the local
  `scripts/log-deploy-event.py` copy and uses the reusable composite action
  from checked-out `vps-ops` at `.github/actions/deploy-telemetry`.
- `.github/workflows/deploy-production.yml` calls the action twice after the
  Ansible deploy step: `if: success()` with `outcome: success`, and
  `if: failure()` with `outcome: failure` plus the production SSH endpoint and
  `/tmp/hermes-deploy` key path. Both calls pass
  `service_label: gh-agent-broker` and `${{ github.token }}`.
- The action defaults keep using label `ssh-deploy-flakiness`, so telemetry
  history remains continuous in issue `#54`.

Current production SSH diagnostics hardening:

- Failed production run `27569598853`, job `81502348587`, was the expected
  intermittent VPS SSH connectivity failure, not a deploy workflow regression:
  Ansible failed during `Gathering Facts` with
  `ssh: connect to host srv1656293.hstgr.cloud port 22: Connection timed out`.
- The PR `#53` diagnostics step did run, classified the failure as
  `timed_out`, printed JSON, and posted a durable comment to issue `#54`
  (`ssh-deploy-flakiness`). Captured runner IP was `172.200.23.68`,
  `time_to_fail_s` was `10`, and `mtr` returned only its report header with no
  responding hop rows.
- Current branch `fix/robust-ssh-diagnostics` hardens the diagnostics step so
  optional package installs and GitHub issue/label/comment operations emit
  explicit `::warning::` messages instead of failing silently. JSON rendering now
  uses Python already required by the workflow, avoiding dependence on `jq`.

Current sandbox curator lifecycle/status fix:

- Current post-merge CI repair branch `fix/postmerge-sandbox-status` fixes a
  race introduced by PR #51 where `GetAgentStatus` could return stale
  `running` while `watchExit` was already finalizing a stopped worker. The
  finalization guard now uses a per-run completion channel so contending status
  polls wait for terminal metadata before returning.
- Failure from main run `27526543315`: `make ci` failed in the `check` job
  during `go test -race ./...`; `TestGetAgentStatusReturnsWorkerDiagnostics`
  observed `Status:running ... ExitCode:<nil> ... Diagnostics:<nil>` instead
  of failed exit 30.
- Latest local verification for the repair passed:
  `go test -race ./internal/sandbox -run TestGetAgentStatusReturnsWorkerDiagnostics -count=50`,
  `.tools/bin/golangci-lint cache clean && make ci`, `make smoke-container`,
  and `make sandbox-e2e`.
- Current branch `feature/sandbox-curator-status-lifecycle` fixes sandbox-broker
  terminal run finalization so a container that has already exited nonzero is
  recorded as `failed` with its exit code and captured output/error text, rather
  than being overwritten as `timed_out` by the timeout watcher.
- `internal/sandbox` now centralizes exited-run finalization across
  reconciliation and status polling; `markTimedOut` re-inspects before stopping
  so races with already-exited containers preserve the real status.
- Templates can set `completion_status_path`, which must resolve under a
  writable `extra_mounts` target. On terminal success/failure/timeout,
  sandbox-broker writes JSON status containing UTC timestamp, status, exit code,
  and a brief redacted message. Docker-backed writes use a helper container and
  the worker bind mounts, so the broker container does not need the host intake
  path mounted directly.
- Sandbox creation now emits a structured JSON log line with `job_id`,
  `profile`, `template`, `success`, and `duration_ms` after Docker container
  creation succeeds or fails.
- The public sandbox example documents
  `completion_status_path: "/data/intake/curator-status.json"` for YKM curator
  templates.
- Companion config branch in `vps-ops`: `feature/curator-status-file`, adding
  `completion_status_path: "/data/intake/curator-status.json"` to the three
  production curator templates. The existing production curator intake mounts
  are already writable (`readonly: false`), so no mount change was required.
- Verification passed: `go test ./internal/sandbox ./cmd/sandbox-broker`,
  `make check`, `git diff --check`, and in `vps-ops`
  `ansible-playbook -i inventory/production.yml playbooks/site.yml --syntax-check`
  plus `git diff --check`.

Current agent development and deployment documentation update:

- Current branch `docs/agent-development-deployment` updates `AGENTS.md` with
  the current production deployment path, local staging command and endpoints,
  compose service inventory, Ansible-managed config ownership, and PR workflow.
- Key operational guardrail now documented: agents must not SSH directly to
  `hermes-vps` for production changes; production changes go through the
  GitHub Actions deployment pipeline, with read-only diagnostics allowed only
  when explicitly authorized.
- Latest local verification passed: documentation diff review,
  `git diff --check`, and `make check`.

Current deploy SSH preflight update:

- Current branch `codex/deploy-ssh-preflight` adds a `Wait for VPS SSH` step to
  `.github/workflows/deploy-production.yml` before the Ansible deploy step. The
  step derives hosts from `vps-ops` inventory via the deploy playbook,
  resolves Ansible SSH host/user/port variables, and retries SSH with linear
  backoff before failing the workflow.
- `docs/deploy.md` now documents that the deploy workflow waits for SSH
  connectivity while still sourcing VPS target details from
  `vps-ops/inventory/production.yml`, not from hardcoded host values in this
  repository.
- Intended verification: workflow YAML parse/static check, `git diff --check`,
  and a PR/main GitHub Actions run that reaches the production approval gate
  and then runs the preflight before Ansible after approval.

Current agent workflow guidance update:

- `AGENTS.md` now explicitly says coding agents must never merge their own pull
  requests unless the human-in-the-loop explicitly instructs them to merge.

Current reporter installation coverage fix:

- Issue `#41` was confirmed as a mismatch between reporter-advertised repos and
  broker GitHub App installation mappings. The reporter service and
  `broker-reporter-01` allowed `grubbyhacker/gh-agent-broker`,
  `grubbyhacker/youknowme`, and `grubbyhacker/ykmcorpus`, but
  `github.apps.reporter.installations` only mapped
  `grubbyhacker/gh-agent-broker`.
- Immediate VPS mitigation was applied on 2026-06-11 by adding exact reporter
  installation mappings for `grubbyhacker/youknowme` and
  `grubbyhacker/ykmcorpus`, both using installation ID `131601703`. Backup:
  `configs/production.yaml.bak-reporter-installations-20260611-080958`.
- Post-mitigation checks passed: broker config-check, broker restart, broker
  health, and authenticated `broker-reporter-01` `repo.probe` returned `200`
  for both YKM repos.
- Current branch `feature/github-app-installation-wildcards` implements the
  durable code fix: owner wildcard installation mappings such as
  `grubbyhacker/*`, and config validation that rejects enabled agents whose
  repo allowlist is not covered by their selected GitHub App installation map.
  Latest verification passed: `go test ./internal/config`, focused
  server/CLI/config tests, example `config-check`, `git diff --check`, and
  `make check`.

Current parameterized sandbox launch profile implementation:

- PR `#39` is merged and deployed to the VPS as
  `ghcr.io/grubbyhacker/gh-agent-broker:sha-79bbb1e41faea1211da10effedf08fe0d6d5689e`.
  Backup before image pin change:
  `.env.bak-image-parameterized-profiles-20260611-045128`.
  Post-deploy checks passed: Compose config render, image pull/recreate,
  Compose service status, broker/sandbox/proxy health endpoints, broker CLI
  health from the broker container, image pin inspection for broker,
  issue-reporter, sandbox-broker, and gh-agent-proxy, short service log tails,
  and Hermes gateway/dashboard `gh-agent-broker-cli health`.
- Current branch `feature/parameterized-launch-profiles` adds parameterized
  REST launch profiles to `sandbox-broker` without letting callers alter
  profile-owned authority such as repo, template/image, mounts, credentials,
  runtime budgets, or enabled actions.
- Sandbox launch profiles now support `parameters` declarations with primitive
  types `string`, `string_list`, `boolean`, and `integer`, plus required/default
  values, integer min/max, string/list length limits, max list items, and an
  optional generic regex pattern. Broker validation is shape-only; values remain
  opaque to domain code such as YKM Curator.
- Profile action request bodies can use `{"parameters": {...}}`. Parameterized
  profiles reject legacy override fields, while non-parameterized profiles keep
  the existing override behavior.
- `/input/task.json` now includes a `parameters` object when resolved
  parameters are present. Preview, dry-run, and launch all validate the resolved
  task contract size before container creation.
- New `POST /v1/launch-profiles/{name}/preview` authenticates like dry-run,
  creates no run directory/container, and returns profile/principal, config
  loaded timestamp/version, resolved launch request, resolved task contract,
  template image/command/user/network/credential-bundle name/broker-agent ID,
  runtime/resource budgets, and caller allowed actions.
- Sandbox audit events now record sanitized parameter values alongside
  profile/principal/run metadata; secrets, auth headers, broker credentials, and
  credential bundle contents are still excluded/redacted.
- Sandbox config now records a sanitized `config_version` digest and
  `config_loaded_at` timestamp. `/healthz` reports both. Runtime reload is not
  part of this change.
- `configs/sandbox.example.yaml` documents `max_parameter_bytes` and a commented
  YKM-style `upload_ids` `string_list` profile example.
- Latest verification passed: `go test ./internal/sandbox ./cmd/sandbox-broker`,
  `make fmt`, `git diff --check`, and `make check`.

Current CI sandbox E2E speed follow-up for issue #35:

- Current branch `fix/sandbox-e2e-minimal-image` keeps the seconds-level timeout
  probe from PR `#37`, but removes the Buildx/GHA cache path that offset the
  runtime savings in GitHub Actions.
- Recent CI timing review showed the actual sandbox E2E script fell from about
  1:42-1:48 to 0:12-0:16, but the added Buildx/cache image-build step cost
  54s on the PR run and 98s on the post-merge `main` run, making the main
  `sandbox-e2e` job slower overall.
- Sandbox launch input now supports `max_runtime_seconds` as a shorter runtime
  cap, mutually exclusive with `max_runtime_minutes` and still bounded by the
  template `max_runtime_minutes`. Existing minute-based behavior remains
  unchanged.
- `cmd/sandbox-e2e` uses a 5-second timeout probe instead of waiting for a
  one-minute timeout, removing the hard minute-long floor from the E2E.
- `scripts/sandbox-e2e.sh` supports `SANDBOX_E2E_SKIP_IMAGE_BUILD=1` and
  `SANDBOX_E2E_IMAGE` for manual experiments, but CI now just runs
  `make sandbox-e2e` and lets the script build the image directly.
- Added `Dockerfile.sandbox-e2e`, a minimal image that builds and packages only
  `sandbox-broker`, which is the only broker binary the sandbox MCP E2E needs.
- Restored the production `Dockerfile` to the plain pre-cache-mount form.
- Latest verification passed: `go test ./internal/sandbox ./cmd/sandbox-e2e`,
  `bash -n scripts/sandbox-e2e.sh`, `git diff --check`,
  `./scripts/sandbox-e2e.sh` (about 18s locally including image build),
  `docker build --no-cache -f Dockerfile.sandbox-e2e ...` (about 7s locally),
  `make check`, and `make smoke-container`.

Current PR review repair-completion implementation:

- Current branch `feature/pr-review-resolution` implements the YKM Curator
  repair-completion broker surface without exposing GitHub credentials to
  agents.
- Deny-by-default write operations now include `issue.comment`,
  `pull.review.dismiss`, `pull.review_thread.resolve`, `issue.label.add`, and
  `issue.label.remove`. The Curator example agent in
  `configs/production.example.yaml` grants the needed operations because it has
  GitHub App `issues:write` and `pull_requests:write`; other agents remain
  unchanged.
- Broker routes now cover the requested sequence:
  `POST /v1/repos/{owner}/{repo}/issues/{number}/comments`,
  `PUT /v1/repos/{owner}/{repo}/pulls/{number}/reviews/{review_id}/dismissal`,
  `PUT /v1/repos/{owner}/{repo}/pulls/{number}/review-threads/{thread_id}/resolve`,
  `POST /v1/repos/{owner}/{repo}/issues/{number}/labels`, and
  `DELETE /v1/repos/{owner}/{repo}/issues/{number}/labels/{label}`.
- Review dismissal accepts either REST numeric review IDs or GraphQL review node
  IDs. Numeric IDs use REST dismissal; node IDs use GraphQL
  `dismissPullRequestReview`. Already dismissed reviews are successful no-ops.
- Thread resolution uses GraphQL review-thread node IDs. If a message is
  supplied and the thread is not already resolved, the broker first posts a
  GitHub-visible thread reply, then resolves the thread. Already resolved
  threads are successful no-ops.
- PR review and review-thread read models now expose GraphQL node IDs,
  database IDs where available, authors, review states including
  `CHANGES_REQUESTED`/`DISMISSED`, thread `is_resolved`, path/line context, and
  comment path/line/body context for exact repair decisions.
- Write routes support `Idempotency-Key`. Successful responses are persisted in
  the configured `idempotency.state_path`, replayed on duplicate keys, and
  audit events include operation, repo, issue/PR number, target ID/label, the
  idempotency key, result URL/ID where available, and bounded error text.
- New CLI support includes `dismiss-review --idempotency-key`,
  `resolve-review-thread --idempotency-key`, `add-label`, and `remove-label`.
- Latest verification passed: `go test ./internal/server ./cmd/gh-agent-broker
  ./internal/githubapp ./internal/idempotency`, `mise exec -- make fmt`,
  `git diff --check`, and `mise exec -- make check`.

Current Codex-compatible proxy surface implementation:

- Current hotfix branch `hotfix/codex-budget-double-count` fixes proxy budget
  double counting for Responses calls with missing or zero usage tokens. Call
  reservation and token reservation are now separate, so completion-time
  accounting no longer increments the per-run call counter a second time.
  Regression tests cover non-streaming and streaming `/v1/responses` calls
  without usage. Latest verification passed: `go test ./internal/proxy`,
  `mise exec -- make fmt`, `git diff --check`, and `mise exec -- make check`.
- Current branch now implements `plans/codex-compatible-proxy-surface.md` in
  `internal/proxy` with a restricted OpenAI-compatible Codex surface on
  `gh-agent-proxy`.
- New config fields are `codex_auth_token[_env]`,
  `codex_upstream_key[_env]`, and `codex_allowed_models`. Model exposure is
  alias-based and not hard-coded to Haiku; example config includes
  `ykm-codex-haiku` and `ykm-codex-sonnet` aliases mapped to upstream
  LiteLLM/OpenRouter model IDs.
- Added authenticated `GET /v1/models` and `POST /v1/responses`. Responses
  calls require `X-GH-Agent-Run-ID`, enforce model allowlist, byte limits, call
  budgets, token budgets when upstream usage is available, and audit
  endpoint/run/model/decision/tokens/error without prompt bodies or auth
  headers. Streaming SSE responses are passed through while parsing usage
  opportunistically.
- Existing `/v1/model/call` behavior is preserved.
- Added `make proxy-codex-e2e`, which starts a fake Responses-compatible
  LiteLLM upstream, launches a real `gh-agent-proxy` process with generated
  config, verifies raw `/v1/models` and `/v1/responses` behavior, then runs a
  real local `codex exec` process through the proxy using `env_key`,
  `wire_api = "responses"`, and `env_http_headers` for `X-GH-Agent-Run-ID`.
- Latest focused verification: `go test ./internal/proxy` and
  `mise exec -- make proxy-codex-e2e` passed.

Latest sandbox-broker operator REST launch profile implementation:

- PR `#32` is merged and deployed to the VPS as
  `ghcr.io/grubbyhacker/gh-agent-broker:sha-89590202fcba9d51e5095b1bf7790b36bbbfd755`.
  The live stack is healthy for `broker`, `issue-reporter`, `sandbox-broker`,
  `gh-agent-proxy`, and `litellm`.
- VPS sandbox config now has a reusable host-local REST E2E profile
  `beta-sleeper-rest-e2e`, timer principal `rest-e2e-timer`, and operator
  principal `rest-e2e-operator`. Backups were written before changes:
  `.env.bak-rest-profiles-20260609-212038` and
  `configs/sandbox-beta.yaml.bak-rest-profiles-20260609-212038`.
- Live REST E2E passed on 2026-06-09:
  profile discovery, dry-run, disallowed repo override denial, timer-token log
  denial, launch, status, logs, artifacts, lessons, stop, cleanup, run
  directory removal, worker container removal, and audit inspection. Successful
  run ID: `20260609T212430Z-b226c9da47ca08f5`.
- Current branch `agent/operator-rest-launch-plan` implements
  `plans/operator-rest-launch-profiles.md`: host-local,
  operator-authenticated REST launch profiles for `sandbox-broker`, without
  adding Docker-launch functionality to the main GitHub broker.
- Sandbox config now supports `launch_profiles` and separate
  `operator_principals`. Profiles define fixed `LaunchAgentInput` defaults plus
  explicit `allow_overrides`; operator principals resolve `token_env`, scope
  allowed profiles, and scope allowed actions (`launch`, `dry_run`, `status`,
  `logs`, `artifacts`, `stop`, `cleanup`).
- `sandbox-broker` now serves `/v1/launch-profiles`, profile dry-run/launch
  endpoints, and `/v1/runs` status/log/artifact/lesson/stop/cleanup endpoints
  on the existing listener. Handlers authenticate operator bearer tokens,
  authorize profile/action scope, merge only allowlisted overrides, and call the
  existing `sandbox.Service` methods for launch, logs, collections, stop, and
  cleanup.
- Sandbox audit events now include operator principal and profile fields for
  REST operations, plus run/template/repo/branch when available. REST auth never
  logs tokens or authorization headers.
- `configs/sandbox.example.yaml` documents a timer token scoped to
  launch/dry-run and a human operator token scoped to read/stop/cleanup actions,
  both using `token_env`.
- Added focused tests for config validation, token env resolution, REST
  auth/authz, launch/dry-run behavior, override rejection, log redaction, and
  artifact collection preserving existing symlink/traversal protections.
- Latest verification for this branch passed:
  `go test ./internal/sandbox ./cmd/sandbox-broker`, `mise exec -- make fmt`,
  `mise exec -- make check`, and `git diff --check`.

Latest YKM Curator prerequisite implementation:
- PR `#31` is merged and deployed to production. It added opt-in per-agent
  `branch_lifecycle_guard` checks for same-repository PR history before
  brokered `git.receive-pack` and `pull.create`; production enables
  `mode: enforce` for `hermes-coder-01` and `ykm-curator`.
- Current branch `feature/ykm-curator-prereqs` implements the prerequisite
  broker work for the YKM Curator sandbox, without applying live production
  configuration changes.
- Broker REST and CLI now expose deny-by-default GitHub read operations needed
  by curator/reporter flows: PR list/detail/files/comments/reviews/review
  comments/review threads, issue list/detail/comments, commit combined status,
  and check runs.
- The `broker-issue-reporter` MCP service now has issue read tools in addition
  to issue reporting: `broker_get_issue`, `broker_search_issues`, and
  `broker_list_issue_comments`.
- `mutation_limits` config adds durable per-run mutation budgets for creation
  operations. Current server enforcement covers `pull.create` and
  `issue.create` before the GitHub API call, returning structured
  `capacity_deferred` denials.
- Sandbox templates now support operator-configured `extra_mounts`; callers
  still cannot supply arbitrary mounts, and validation rejects unsafe source or
  target paths.
- New `gh-agent-proxy` binary and `internal/proxy` package provide a small
  authenticated LLM gateway in front of a LiteLLM-compatible upstream. It
  enforces model allowlists, per-run call/token budgets, request/response size
  caps, timeout, JSONL audit logging, and prompt-body logging is disabled by
  default.
- New example files: `configs/proxy.example.yaml` and
  `configs/litellm.example.yaml`. Compose examples include optional
  `--profile proxy` services for LiteLLM and `gh-agent-proxy`.
- Production and sandbox examples include public-safe YKM Curator placeholders
  for the `YKM Curator` GitHub App context, `ykm-curator` broker principal,
  curator branch patterns, metadata assertions, mutation limits, proxy env
  vars, and sandbox mount guidance.
- Release/build plumbing now includes `gh-agent-proxy`; semver release artifacts
  include `gh-agent-proxy-linux-amd64`.
- Go toolchain is now pinned to Go 1.26.4 in `.mise.toml` and `go.mod` because
  `govulncheck` flagged standard-library vulnerabilities fixed by 1.26.4.
- Local private runbook `runbooks/private/hermes-vps.md` exists and
  `runbooks/private/` is excluded via `.git/info/exclude`; it is intentionally
  untracked because this repo is public.
- Latest verification for this branch passed:
  `mise exec -- make check`, `mise exec -- make smoke-container`,
  `mise exec -- make sandbox-e2e`, `docker compose -f docker-compose.example.yml config`,
  `docker compose --profile proxy -f docker-compose.example.yml config`,
  production Compose config rendering with a dummy pinned image/temp env both
  with and without `--profile proxy`, `bash -n scripts/sandbox-*.sh`, and
  `git diff --check`.
- VPS YKM Curator config was applied on 2026-06-08:
  `/docker/gh-agent-broker/configs/production.yaml` now has GitHub App context
  `ykm-curator` with app ID `3991340`, installation ID `138708452` for
  `grubbyhacker/ykmcorpus`, and broker principal `ykm-curator`.
  `/docker/gh-agent-broker/.env` has generated
  `YKM_CURATOR_BROKER_SECRET`, and the PEM is mounted from
  `/docker/gh-agent-broker/secrets/github-ykm-curator-app.pem`.
  `config-check`, broker restart, authenticated `whoami`, repo probe,
  broker-mediated `git ls-remote`, and a `pull.create` dry-run passed.
- VPS read-surface E2E was applied/tested on 2026-06-08:
  current branch source was synced to
  `/docker/gh-agent-broker/src-ykm-prereqs` and built as local image
  `gh-agent-broker:ykm-prereqs-20260608`. `.env` now pins
  `BROKER_IMAGE=gh-agent-broker:ykm-prereqs-20260608` with backup
  `.env.bak-image-ykm-prereqs-20260608-023812`; previous image pin was
  `ghcr.io/grubbyhacker/gh-agent-broker:sha-e24479b95ddfe55cc7237fc2873815baa8353618`.
  `broker` and `issue-reporter` were recreated on the local image.
  `broker-reporter-01` was granted `issue.read`, `issue.comments.read`, and
  `issues:read` in private production config with backup
  `configs/production.yaml.bak-read-e2e-20260608-023803`.
  E2E passed through direct broker REST, the new CLI `issues` wrapper, and
  Hermes MCP `broker-reporter` calling `broker_search_issues`, all returning
  open issues `#27`, `#24`, and `#23` from `grubbyhacker/gh-agent-broker`.
- VPS model proxy E2E was applied/tested on 2026-06-08:
  private `.env` now has generated `GH_AGENT_PROXY_TOKEN`, generated
  `LITELLM_MASTER_KEY`, and operator-supplied `OPENROUTER_API_KEY`, with
  backup `.env.bak-proxy-20260608-025610`. Private configs
  `/docker/gh-agent-broker/configs/proxy.yaml` and
  `/docker/gh-agent-broker/configs/litellm.yaml` were added for OpenRouter
  models `google/gemma-4-26b-a4b-it` and
  `google/gemma-4-26b-a4b-it:free`. Live Compose now runs `litellm` and
  `gh-agent-proxy`; `gh-agent-proxy` is published on host-local
  `127.0.0.1:8092` and aliased on the Hermes network as `gh-agent-proxy`.
  E2E passed for proxy health, denied model policy, paid model call via
  LiteLLM/OpenRouter, one-call budget exhaustion, and audit/state checks.
  The free model is allowed by policy but was upstream rate-limited by
  OpenRouter/Google and currently surfaces as proxy `upstream_error` with HTTP
  502 because the proxy normalizes non-2xx upstream responses as bad gateway.

Latest Hermes retest result:

- Current branch `agent/cli-whoami-wrapper` adds
  `gh-agent-broker-cli whoami` as an authenticated wrapper for `GET /whoami`,
  documents that `/whoami` requires broker agent auth, and updates `AGENTS.md`
  to require coding agents to use feature branches rather than editing `main`
  directly.
- Current branch work for issue `#12` adds reporter capability discovery via
  `broker_reporter_capabilities`, updates the bundled `gh-agent-broker` skill
  guidance to call it before `broker_report_issue`, and rolls in the pending
  Dependabot Docker action bumps for setup-buildx v4, login v4, metadata v6,
  and build-push v7.
- GO for the first controlled research-agent project using `BROKER_AGENT_ID=hermes-coder-01` and `grubbyhacker/research`.
- Issue `#13` is fixed and deployed: `gh-agent-broker-cli configure` now
  writes a repo-local URL-scoped Git credential helper so non-interactive
  `git fetch`/`git push` can read `BROKER_AGENT_ID` and `BROKER_AGENT_SECRET`
  from the environment without storing broker secrets in Git config.
- PR `#15` also took the pending Dependabot updates for
  `actions/checkout@v6`, `actions/setup-go@v6`, and
  `github.com/golang-jwt/jwt/v4@v4.5.2`. Issues `#13` and `#14` are closed.
- Hermes focused v1 REST/readiness suite passed: 24 pass, 0 fail.
- Dry-run shape tests passed for `repo`, `repository`, and `owner`+`repo` forms.
- Git `GIT_ASKPASS` works after the `WWW-Authenticate` fix.
- Git clone/fetch, allowed branch push, unauthorized branch denial, repo probe, PR creation, and issue comment creation all pass through the broker.
- Latest Hermes readiness side effects:
  - Branch: `agent/hermes-coder-01/research-agent-readiness-20260512-014725`
  - Pull request: `#5`
  - Comment: created on PR `#5` through broker `issue.comment`.

Remaining after this attempt:

- Decide whether to enforce `Hermes-Run-Id` on Git `receive-pack` for stronger audit metadata.
- Move `issue.comment` metadata assertions from warn mode to enforce mode before broader autonomous usage.
- Sandbox MCP v1 has an initial implementation in this repo. Remaining work is
  operator hardening and live Docker/Hermes validation before exposing it to
  real workers.
- Production Compose is pinned to the latest published broker image from PR `#15`.
- Confirm the GHCR package is public after first publish if deployment hosts should pull without registry credentials.
- Confirm the first semver release uploads standalone Linux binaries and `SHA256SUMS`.

Tonight's recommended research-agent pattern:

- Broker URL: `http://gh-agent-broker:8080`
- Git remote: `http://gh-agent-broker:8080/git/grubbyhacker/research.git`
- Branches: `agent/hermes-coder-01/<task-slug>`
- Base branch: `main`
- Start each run with `GET /readyz` and authenticated `GET /whoami`.
- Before PR creation, run `POST /v1/policy/dry-run` with `operation: pull.create`, `owner: grubbyhacker`, `repo: research`, `branch`, `base_branch: main`, and metadata fields `Agent-Id` and `Hermes-Run-Id`.
- Use one broker identity only for same-permission subagents; distinguish them with `Hermes-Run-Id` suffixes such as `research-run-001:planner`.
- Use separate broker identities, and preferably separate sandbox containers, for subagents with different permission sets.

Public repo:

- `https://github.com/grubbyhacker/gh-agent-broker.git`
- Initial commit pushed on `main`: `048eae0 Initial GitHub agent broker`

Implemented plan target:

- Broker service and CLI in Go.
- YAML config.
- Per-agent static broker authentication.
- Deny-by-default policy.
- Generic metadata assertions with `off`, `warn`, and `enforce` modes.
- Structured self-correction responses for denials.
- JSONL audit logs with secret redaction.
- GitHub App installation token minting inside the broker.
- HTTP Git smart proxy for clone/fetch/push.
- REST endpoints for repo probe, PR creation, comments, policy dry-run, health, readiness, and config reload.
- Sanitized Compose production deployment runbook, production config example, container smoke target, and fake GitHub REST/Git smart-HTTP integration tests.

Real GitHub e2e status:

- E2E was validated against `grubbyhacker/research` using local ignored config and key material.
- Broker-mediated health, repo probe, policy dry-run, clone/fetch, allowed branch push, PR creation, comment creation, and disallowed branch rejection all worked.
- Latest E2E artifacts created before the initial public push:
  - Branch: `agent/hermes-coder-01/e2e-precommit-20260511-171026`
  - PR: `https://github.com/grubbyhacker/research/pull/2`
  - Comment: `https://github.com/grubbyhacker/research/pull/2#issuecomment-4426177733`
- Local runtime artifacts are intentionally ignored: `/audit/`, `configs/e2e.local.yaml`, `secrets/`, and `.tools/`.

Code hygiene baseline:

- Target Go toolchain is Go 1.26.4.
- `.mise.toml` pins local tools and `.devcontainer/devcontainer.json` defines a containerized dev environment.
- `make check` is the local/CI gate.
- Gate includes format check, `go mod tidy` drift check, `golangci-lint`, unit tests, race tests, `govulncheck`, and builds.
- CI runs `make ci` on pushes to `main` and pull requests.
- Dependabot tracks Go modules and GitHub Actions.
- CI now runs the Go hygiene gate, a Docker container smoke test, and publishes the primary deploy artifact to GHCR after successful `main` or semver tag pushes.
- Published image tags are immutable `sha-<commit>`, the `main` convenience tag, and semver release tags; production deployments should pin SHA or semver tags, not `main` or `latest`.
- Semver tag builds also publish `gh-agent-broker-linux-amd64`, `gh-agent-broker-cli-linux-amd64`, and `SHA256SUMS` as GitHub Release artifacts.

## Important Design Choices

- V1 uses HTTP Git, not SSH Git.
- V1 proxies Git to GitHub and injects GitHub App installation tokens upstream only.
- V1 does not expose a general token minting API.
- V1 enforces metadata assertions on broker REST operations and dry-runs.
- Server-side rejection of pushed commits based on commit trailers is deferred because it requires broker-terminated Git receive for strong enforcement.
- Hermes-specific metadata is represented in example config only.
- The first Hermes integration is documented as a separate Docker Compose broker project, not a Hermes sidecar or systemd-managed container.
- Git policy denials default to a Git-friendly plain-text response with operation ID and safe self-correction details; explicit `Accept: application/json` still returns structured JSON.
- Hermes agreed that same-permission subagents can share a broker identity with distinct `Hermes-Run-Id` values, while different permission sets should become separate broker principals and preferably separate containers.
- Hermes discovered that raw REST routes were not self-describing; discovery endpoints now document the `/v1` routes at `/`, `/docs`, `/operations`, `/api/operations`, `/openapi.json`, `/whoami`, and `/api/whoami`.

## Next Agent Checklist

- Read `plans/phase1.md` first.
- Use `mise trust && mise install`, then run `mise run check`.
- If sandboxed caches are read-only, run with writable temp caches: `GOCACHE=/tmp/gh-agent-broker-gocache GOLANGCI_LINT_CACHE=/tmp/gh-agent-broker-golangci-cache mise run check`.
- Before live Hermes integration, copy `configs/production.example.yaml` to a private config path and fill in real GitHub App IDs, installation IDs, repo names, agent IDs, and secrets.
- Run `make smoke-container` when Docker is available; the broker image runs as UID 65532, so mounted audit directories must be writable by that UID.
- Update this handoff before ending work.

## Compose Deployment Prep

- `plans/compose-production-deploy.md` now documents topology, ports, volumes, secrets, first install, and rollback with public-safe placeholders.
- Production Compose deployment should use `docker-compose.production.example.yml` with `BROKER_IMAGE=ghcr.io/grubbyhacker/gh-agent-broker:sha-COMMIT`; local development can keep using the source-build `docker-compose.example.yml`.
- The production Compose template reads host-owned secrets from `.env` by default and keeps private config/key mounts outside git; `.env` is ignored by git and excluded from the Docker build context.
- Agent runtimes should install or bind-mount `gh-agent-broker-cli`; compatible agents can use the generic `skills/gh-agent-broker` skill to prefer CLI commands over raw REST calls.
- `configs/production.example.yaml` documents required GitHub App permissions and keeps Hermes metadata names as config examples only.
- Current implementation work is adding broker-internal `issue.create`, named
  GitHub App contexts, and a host-side `broker-issue-reporter` MCP service so
  issue creation can use an issues-only GitHub App without injecting reporter
  credentials into Hermes.
- README now includes Hermes CLI usage for remotes, broker env vars, PRs, comments, and metadata.
- Dockerfile now creates `/var/log/gh-agent-broker` owned by UID 65532, and the Compose example uses a named audit volume by default.
- `internal/server/integration_test.go` covers fake GitHub REST operations, fake Git smart-HTTP proxying, auth-header filtering, and Git denial UX.
- `make smoke-container` builds the image, validates config-check failure behavior, starts the broker with generated test key/config, and checks health.
- Latest verification in this handoff: `mise exec -- make check`,
  `scripts/sandbox-e2e.sh`, `scripts/sandbox-codex-auth-e2e.sh`,
  VPS `scripts/sandbox-hermes-auth-e2e.sh`, `scripts/container-smoke.sh`,
  `git diff --check`, `bash -n scripts/sandbox-e2e.sh`,
  `docker compose -f docker-compose.example.yml config`, and production Compose
  config rendering with a dummy pinned image and temporary empty env file passed.
  Plain system `go` is too old in this shell and fails before tests because the
  repo requires the `.mise.toml` Go toolchain.

## Sandbox MCP V1 Implementation

- New binary: `cmd/sandbox-broker`, shipped in the existing OCI image and built
  by `make build` and semver release artifact workflow as
  `sandbox-broker-linux-amd64`.
- New package: `internal/sandbox`.
  - Loads and validates sandbox config, including token auth, repo allowlists,
    named network policies, read-only credential bundles, templates, digest
    requirement in production mode, non-root users, branch policies, runtime
    caps, and unsafe Docker socket/host network rejection.
  - Exposes a testable `RuntimeBackend`; `DockerBackend` talks to Docker Engine
    over the Unix socket API and creates containers with `no-new-privileges`,
    `cap_drop: ALL`, no privileged mode, fixed mounts, configured network only,
    resource limits, task-local `HOME`/`HERMES_HOME`, and server-side env/labels.
  - Implements MCP service behavior for `launch_agent`, `dry_run_launch`,
    `validate_template`, `list_agents`, `get_agent_status`, `get_agent_logs`,
    `stop_agent`, `collect_artifacts`, `collect_lessons`, and `cleanup_run`.
  - Launch input uses a custom JSON decoder so arbitrary fields such as image,
    command, env, mounts, privileged flags, and network overrides are rejected
    instead of ignored.
  - Runs create `input`, `work`, `output`, `lessons`, `logs`, and
    `metadata.json`; configured knowledge snapshots are copied into `/input`.
  - Logs/artifact snippets are byte-capped and redacted using generic token
    patterns plus values read from configured bundle `secret_files` and
    `redact_files`. Artifact/lesson collection skips symlinks and returns
    manifests, hashes, and small inline text only.
  - Cleanup requires a safe run ID and deletes only under `runs_dir`.
- New config and deployment examples:
  - `configs/sandbox.example.yaml`
  - `sandbox-broker` services in both Compose templates; only this service gets
    `/var/run/docker.sock`, `runs_dir`, and credential bundle mounts.
  - Compose examples declare an external `hermes-sandbox-workers` Docker
    network and attach the GitHub broker to it so worker containers can reach
    `broker_url: http://broker:8080`.
  - Compose examples use `group_add: ${DOCKER_SOCK_GID:-1001}` for the sandbox
    broker; on Docker Desktop here the socket is `root:1001`, and the image
    runs as UID/GID 65532, so socket group access is required.
  - README now documents the sandbox broker, MCP auth token, host-path
    requirements for sibling Docker containers, and the v1 credential-bundle
    limitation.
- Tests added under `internal/sandbox` cover config validation, example config
  loading, launch denial cases, generated branch/runtime spec shape, unknown
  launch JSON field rejection, log/artifact redaction, symlink-safe artifact
  collection, and cleanup path traversal rejection.
- Local Docker Desktop E2E script: `scripts/sandbox-e2e.sh`, with the MCP
  client implemented as checked-in Go code in `cmd/sandbox-e2e` rather than
  generated source in the shell harness.
  - Builds the packaged OCI image.
  - Starts a private Docker network and fake broker container.
  - Runs packaged `sandbox-broker` with Docker socket group access.
  - Verifies unauthenticated/bad-token MCP requests return 401.
  - Uses a real MCP client to list tools, validate templates, reject bad launch
    inputs, launch a worker, inspect Docker security settings, verify log and
    artifact redaction, collect artifacts/lessons, stop a running worker, and
    cleanup runs.
- `AGENTS.md` now explicitly bans hiding Go or other source code in shell
  heredocs, generated temp files, or compiler stdin to bypass formatting,
  tests, review, or linting.
- VPS sandbox beta status as of 2026-05-13:
  - Synced the uncommitted beta tree to
    `/docker/gh-agent-broker/src-sandbox-beta` and built local image
    `gh-agent-broker:sandbox-beta` on `hermes-vps`; this image was not pushed
    to GHCR.
  - Added `sandbox-broker` to `/docker/gh-agent-broker/docker-compose.yml`
    using the local beta image. Existing `broker` and `issue-reporter` services
    remain pinned to
    `ghcr.io/grubbyhacker/gh-agent-broker:sha-221e3add7696ba66a69301f43fb5fa4d09b1add6`.
    Compose briefly recreated `broker` while adding the dependency; it returned
    healthy.
  - Added private `/docker/gh-agent-broker/configs/sandbox-beta.yaml`, host
    directories under `/srv/hermes-sandbox-broker`, and a fake beta credential
    bundle at `/srv/hermes-sandbox-credentials/beta-codex`.
  - Added `SANDBOX_MCP_TOKEN` and `DOCKER_SOCK_GID` to the broker private
    `.env`; Docker socket on the VPS is `root:docker` with GID 988.
  - Sandbox worker network policy uses `gh-agent-broker_default`, where workers
    resolve the GitHub broker as `http://broker:8080`.
  - Added Hermes MCP config entry `sandbox-broker` in
    `/docker/hermes-agent-6aso/data/config.yaml` with an Authorization bearer
    header; backed up the config before editing.
  - Recreated `hermes-gateway` and `hermes-dashboard` so they pick up the MCP
    config. Both returned healthy.
  - Direct VPS sandbox E2E passed with `/tmp/sandbox-e2e` against
    `http://127.0.0.1:8091/mcp`, repo `grubbyhacker/research`, templates
    `beta-worker` and `beta-sleeper`. First attempt failed because
    `busybox:latest` was absent; after `docker pull busybox:latest`, the E2E
    passed. The stale failed run directory was removed.
  - Hermes CLI tests passed from `hermes-gateway`:
    `hermes mcp list`, `hermes mcp test sandbox-broker`, and
    `hermes mcp test broker-reporter`.
  - Broker health and sandbox health both returned `{"status":"ok"}` on the VPS.
  - No leftover sandbox worker containers or run directories remained after the
    beta E2E cleanup.
- Codex credential bundle testing passed locally on Docker Desktop as of
  2026-05-13 using `scripts/sandbox-codex-auth-e2e.sh`. The test copies local
  Codex `auth.json` and `config.toml` into a temporary read-only bundle, mounts
  only that bundle into a non-root sandbox worker, verifies parent Hermes auth
  is not visible at `/opt/data` or `/input`, runs `codex exec`
  noninteractively, collects the exact `SANDBOX_CODEX_AUTH_OK` final output,
  redacts strings extracted from the Codex-shaped JSON secret file, and cleans
  up the run. Do not copy live parent Hermes auth into production sandboxes by
  default; provision a sandbox-specific Codex credential bundle for real use.
  This local code has not been rebuilt/redeployed to the VPS beta image yet.
- A local Codex auth E2E failure exposed two sandbox portability issues that
  are now fixed in the repo: broker-created `work`, `output`, and `lessons`
  mount sources are writable by non-root worker UIDs, copied knowledge
  snapshots are readable through the read-only `/input` mount, and the Codex
  probe image installs CA certificates. The probe sets a permissive umask so
  cleanup succeeds when the broker runs as UID 65532 and the worker runs as UID
  1000. For arbitrary third-party worker images, production cleanup still needs
  either a documented worker umask contract or a broker-owned cleanup helper.
- Local Codex auth mechanics checked on 2026-05-13:
  - Host `codex exec --ephemeral --json --sandbox read-only --skip-git-repo-check`
    returned the expected sentinel output.
  - A minimal temporary `CODEX_HOME` containing only copied `auth.json` and
    `config.toml` also returned the expected sentinel output.
  - Added checked-in Codex auth sandbox probe files:
    `testdata/sandbox-codex-auth/Dockerfile`,
    `testdata/sandbox-codex-auth/worker.sh`, and
    `scripts/sandbox-codex-auth-e2e.sh`. The worker copies the read-only
    credential bundle into task-local `/work/home/.codex`, sets
    `CODEX_HOME`, verifies parent Hermes auth is not visible, and runs
    `codex exec` noninteractively.
  - Docker Desktop local sandbox Codex auth E2E passed after Docker Desktop WSL
    integration was restored: `scripts/sandbox-codex-auth-e2e.sh`.
- Codex CLI in sandbox is intentionally punted for now. Upstream Hermes code
  confirms Hermes owns a separate OpenAI Codex OAuth session in
  `HERMES_HOME/auth.json` and avoids sharing refresh tokens with Codex CLI /
  VS Code because refresh tokens are single-use and can trigger
  `refresh_token_reused` races.
- Hermes-native sandbox worker path added and proven on `hermes-vps`:
  - Added `testdata/sandbox-hermes-auth/Dockerfile`,
    `testdata/sandbox-hermes-auth/worker.sh`, and
    `scripts/sandbox-hermes-auth-e2e.sh`.
  - The worker image is based on
    `ghcr.io/hostinger/hvps-hermes-agent:latest`, includes
    `gh-agent-broker-cli`, and copies the checked-in `skills/gh-agent-broker`
    skill into task-local `HERMES_HOME`.
  - The E2E script copies `/docker/hermes-agent-6aso/data/auth.json` into a
    temporary read-only Hermes credential bundle, generates a minimal sandbox
    `config.yaml` for `openai-codex`, launches a non-root Hermes worker,
    verifies parent `/opt/data/auth.json` is not visible, runs
    `hermes -z 'Reply with exactly: HERMES_AUTH_OK'`, verifies
    `hermes auth status openai-codex`, checks broker CLI reachability, redacts
    auth-store string values, and cleans up.
  - Latest VPS verification passed:
    `SANDBOX_HERMES_AUTH_SOURCE_DIR=/docker/hermes-agent-6aso/data ./scripts/sandbox-hermes-auth-e2e.sh`.
  - No leftover E2E sandbox worker containers or networks remained afterward.
  - Rebuilt persistent VPS image tag `gh-agent-broker:sandbox-beta` from
    `/docker/gh-agent-broker/src-sandbox-beta` and recreated only the
    `sandbox-broker` Compose service; `http://127.0.0.1:8091/healthz` returned
    `{"status":"ok"}` afterward.
  - Created and pushed feature branch
    `feature/sandbox-mcp-v1-hermes` at commit `7f213f2`.
  - Updated persistent VPS `/docker/gh-agent-broker/configs/sandbox-beta.yaml`
    to add template `hermes-worker` and bundle
    `/srv/hermes-sandbox-credentials/hermes-worker`, sourced from
    `/docker/hermes-agent-6aso/data/auth.json` plus a minimal sandbox
    `config.yaml`; restarted `sandbox-broker` so it loaded the new template.
  - Hermes-originated E2E passed from `hermes-gateway` using the configured
    `sandbox-broker` MCP server, not direct shell calls to the broker:
    Hermes launched `hermes-worker`, polled status to `stopped`, observed
    `exit_code=0`, collected artifacts, verified trimmed `hermes-final.txt`
    matched `HERMES_AUTH_OK`, verified `final-summary.md`, and called
    `cleanup_run`. Latest run:
    `20260513T182210Z-de2ddbd58238fad5`.
  - A first Hermes-originated run also launched and cleaned successfully
    (`20260513T182122Z-68683c4cece7900d`) but Hermes reported the artifact
    comparison as false despite worker exit `0`; rerun with explicit trimmed
    comparison reported `hermes-final matched after trim: true`.
- General Hermes task-worker path now exists in the repo but still needs the
  live VPS marker run after redeploying the beta image/config:
  - The sandbox broker now writes `/input/task.json`, `/input/task.md`, and
    `/input/sandbox-rules.md` for every launch. `task.json` includes repo,
    base branch, generated branch, broker remote URL, worker agent ID, focus,
    task, and the effective deliverable list.
  - Effective deliverables are now template defaults plus launch-request
    deliverables, de-duplicated in order. `hermes-task-worker` defaults should
    include `/output/final-summary.md` and `/lessons/run-summary.md`.
  - The example sandbox config now distinguishes `hermes-auth-probe` from
    `hermes-task-worker`; do not reuse ambiguous `hermes-worker` in new beta
    config.
  - Added `testdata/sandbox-hermes-task/Dockerfile`,
    `testdata/sandbox-hermes-task/worker.sh`, and
    `scripts/sandbox-hermes-task-e2e.sh`. The task worker copies the read-only
    Hermes auth bundle into task-local `/work/hermes`, runs
    `hermes chat --query ... --quiet --skills gh-agent-broker --max-turns ...`
    from `/work`, captures stdout/stderr under `/output`, and exits nonzero if
    Hermes fails or required deliverables are missing.
  - `cmd/sandbox-e2e` has a `--task-marker-only` mode that launches two runs
    with distinct markers and requires each marker in both
    `final-summary.md` and `run-summary.md`, catching fixed-prompt/task-ignored
    regressions.
  - VPS beta was updated from this branch on 2026-05-13: synced to
    `/docker/gh-agent-broker/src-sandbox-beta`, rebuilt
    `gh-agent-broker:sandbox-beta`, refreshed `gh-agent-broker:sandbox-e2e`,
    rebuilt `gh-agent-broker/sandbox-hermes-auth:local` and
    `gh-agent-broker/sandbox-hermes-task:local`, refreshed
    `/srv/hermes-sandbox-credentials/hermes-worker` from the parent Hermes auth
    store, and replaced the persistent sandbox config with explicit
    `hermes-auth-probe` and `hermes-task-worker` templates.
  - Persistent VPS broker-level task marker E2E passed against
    `http://127.0.0.1:8091/mcp` using template `hermes-task-worker` and repo
    `grubbyhacker/research`; it launched two real Hermes task workers and
    verified distinct markers in both required artifacts before cleanup.
  - Hermes-originated task marker E2E passed from
    `hermes-agent-6aso-hermes-gateway-1` through the configured
    `sandbox-broker` MCP server. Hermes launched `hermes-task-worker`, verified
    marker `HERMES-MCP-20260513-192416` in both `/output/final-summary.md` and
    `/lessons/run-summary.md`, and called `cleanup_run`. Run ID:
    `20260513T192424Z-7de7e29b6a336b9e`; follow-up checks confirmed the run
    directory and Docker container were gone, and audit logged launch plus
    cleanup with exit code 0.
  - A final research beta run produced PR #9 and proved repo clone/fetch,
    branch push, PR creation, marker artifacts, and cleanup, but exited 30
    because repo-relative deliverables passed in `launch_agent.deliverables`
    were interpreted by the worker as sandbox filesystem deliverables. The
    worker contract has been corrected locally so only `/output` and `/lessons`
    deliverables are wrapper-enforced; repo-relative deliverables remain task
    requirements for Hermes and repository verification.
  - The repo-relative deliverable fix was synced to the VPS beta source and
    `gh-agent-broker/sandbox-hermes-task:local` was rebuilt. The updated
    `cmd/sandbox-e2e --task-marker-only` now passes a repo-relative deliverable
    in the launch request and still requires markers in `/output` and
    `/lessons`; it passed against the persistent VPS sandbox broker and
    `hermes-task-worker`.
  - Hermes Telegram MCP live validation passed after the repo-relative
    deliverable fix:
    - `run_hermes_test` requested
      `sandbox-task-marker-repo-relative-no-pr`; Hermes reported PASS for run
      `20260513T203941Z-705e817009423a5c`, marker
      `SANDBOX_TASK_MARKER_REPO_RELATIVE_NO_PR_20260513_2040Z`, status
      `stopped`, exit code 0, cleanup `cleaned`, marker present in
      `/output/final-summary.md` and `/lessons/run-summary.md`, and
      repo-relative deliverable did not trip wrapper enforcement.
    - Hermes also completed a broader push/delete-cleanup E2E:
      run `20260513T203802Z-fd22b27682504de0`, marker
      `HERMES_SANDBOX_BETA_E2E_20260513_2038Z`, exit code 0, cleanup
      `cleaned`, broker probe/fetch succeeded, branch push was verified by
      `git ls-remote`, remote branch deletion was verified, and no PR was
      created.
    - Codex independently verified both reported run directories were gone,
      containers were gone, no active sandbox worker containers remained, and
      audit had launch/cleanup entries with exit code 0.
    - Hermes replied `SATISFIED`: no more E2E required for merge readiness.
      Optional future tests only: failure diagnostics, timeout handling, policy
      denial, and one extra disposable PR creation test.
  - Latest local verification after this change: `mise exec -- make check`,
    `scripts/sandbox-e2e.sh`, `bash -n scripts/sandbox-e2e.sh
    scripts/sandbox-hermes-auth-e2e.sh scripts/sandbox-hermes-task-e2e.sh
    testdata/sandbox-hermes-task/worker.sh`, and focused
    `mise exec -- go test ./internal/sandbox ./cmd/sandbox-e2e` all passed.
- Cleanup hardening added: if `cleanup_run` cannot remove worker-owned files
  because a worker tightened permissions inside `/work`, DockerBackend runs a
  short root cleanup helper from the worker image with the run dir mounted at
  `/cleanup`, network disabled, and retries removal. This was required by
  Hermes workers because Hermes tightens files under task-local `HERMES_HOME`.
- PR #20 merged to `main` as
  `e24479b95ddfe55cc7237fc2873815baa8353618`; CI passed and published the
  official GHCR image. The VPS broker, issue-reporter, and sandbox-broker
  services were switched from the local beta image to
  `ghcr.io/grubbyhacker/gh-agent-broker:sha-e24479b95ddfe55cc7237fc2873815baa8353618`.
  Health checks passed and `hermes mcp test sandbox-broker` discovered all 10
  tools. A post-switch `hermes-task-worker` marker E2E also passed against the
  official sandbox-broker image. The Hermes worker images remain local beta
  images because CI does not publish those worker artifacts yet.
- Current feature branch for final sandbox hardening:
  `feature/finalize-sandbox-e2e`.
  - Added structured sandbox failure diagnostics to `get_agent_status`.
    Failed and timed-out runs now include a `diagnostics` object, and the
    broker writes `/output/wrapper-diagnostics.json` for broker-detected
    timeout/nonzero-exit failures when the worker did not already provide one.
  - Timeout enforcement now also happens during `get_agent_status`, so a
    missed background watcher or post-restart poll still transitions overdue
    running containers to `timed_out`.
  - Sandbox launch policy denials now include explicit `policy denial`
    self-correction text without exposing secrets or unrelated policy.
  - Added `make sandbox-e2e` and a CI `sandbox-e2e` job. Publish/release jobs
    now require the true Docker MCP E2E job as well as hygiene and container
    smoke.
  - `cmd/sandbox-e2e` now verifies policy-denial text, failure diagnostics,
    timeout diagnostics, and has `--finalization-live` for persistent
    sandbox-broker validation including a real Hermes task-worker PR creation.
  - Latest local verification on 2026-05-13:
    `mise exec -- make check`, `./scripts/sandbox-e2e.sh`,
    `./scripts/container-smoke.sh`, `git diff --check`, `bash -n
    scripts/sandbox-e2e.sh scripts/sandbox-hermes-auth-e2e.sh
    scripts/sandbox-hermes-task-e2e.sh testdata/sandbox-hermes-task/worker.sh`,
    and focused `mise exec -- go test ./internal/sandbox ./cmd/sandbox-e2e`
    all passed.
  - PR `#21` (`https://github.com/grubbyhacker/gh-agent-broker/pull/21`)
    is open from this branch. GitHub Actions passed on the PR:
    `check`, `container-smoke`, and the new `sandbox-e2e` job.
  - Live VPS validation on 2026-05-13 used a temporary local beta image
    `gh-agent-broker:sandbox-beta` for `sandbox-broker`, then restored
    `/docker/gh-agent-broker/.env` to the official pinned image
    `ghcr.io/grubbyhacker/gh-agent-broker:sha-e24479b95ddfe55cc7237fc2873815baa8353618`
    and recreated only `sandbox-broker`. Health returned `{"status":"ok"}`
    after both redeploy and restore.
  - Live finalization E2E passed via
    `cmd/sandbox-e2e --finalization-live` against
    `http://127.0.0.1:8091/mcp` on `hermes-vps`:
    policy denial contained `policy denial`; failure diagnostics run
    `20260513T215644Z-cf4a29f31c3cd6a2` ended `failed` with exit code 30 and
    diagnostics for `/output/required-never-created.txt`; timeout run
    `20260513T215717Z-f03a8c9efedd059f` ended `timed_out` with
    `run exceeded deadline`; PR run
    `20260513T215817Z-edb0ba96995078b1` ended `stopped` with exit code 0 and
    created disposable PR `https://github.com/grubbyhacker/research/pull/10`.
    PR #10 was closed and branch
    `agent/hermes-coder-01/disposable-pr-20260513-final-sandbox-20260513-215817`
    was deleted after verification.
  - Two stale runs from an earlier interrupted Telegram-driven attempt,
    `20260513T215215Z-19f028d84d6afd46` and
    `20260513T215219Z-e8f796fda300d6b6`, were manually removed from the VPS
    after the repeatable live-finalization E2E passed. Final host check showed
    no sandbox worker containers and no run directories left under
    `/srv/hermes-sandbox-broker/runs`.

## VPS Deployment Status

- `hermes-vps` has a running broker Compose project at `/docker/gh-agent-broker`.
- Broker Compose now consumes `BROKER_IMAGE` from `/docker/gh-agent-broker/.env`
  and is pinned to
  `ghcr.io/grubbyhacker/gh-agent-broker:sha-e24479b95ddfe55cc7237fc2873815baa8353618`.
- Broker, issue-reporter, and sandbox-broker containers were recreated from
  that image on 2026-05-13 and are healthy/running.
- Broker health is reachable from the host at `http://127.0.0.1:8080/healthz` and from the Hermes Docker network at `http://gh-agent-broker:8080/healthz`.
- Hermes container env now includes `BROKER_URL`, `BROKER_AGENT_ID`, and `BROKER_AGENT_SECRET`.
- Hermes Compose project at `/docker/hermes-agent-6aso` now has only
  `hermes-gateway` and `hermes-dashboard` services; the old `hermes-agent`
  service was removed with `docker compose up -d --remove-orphans`.
  `hermes-gateway` runs `gateway run` through
  `/opt/hermes/docker/entrypoint.sh` with no published port.
  `hermes-dashboard` runs `dashboard --host 0.0.0.0 --port 9119 --no-open
  --insecure` and publishes only `127.0.0.1:9119:9119` on the VPS.
  Both services have Compose healthchecks and were healthy after restart on
  2026-05-12.
- `gh-agent-broker-cli` was extracted from the pinned broker image to
  `/docker/gh-agent-broker/bin/gh-agent-broker-cli` and bind-mounted read-only
  into both Hermes services at `/usr/local/bin/gh-agent-broker-cli`.
- Hermes services were force-recreated on 2026-05-12 so the file bind mount
  sees the updated CLI. `stat` from the host, `hermes-gateway`, and
  `hermes-dashboard` all reported the same updated CLI size and timestamp.
- The generic `gh-agent-broker` skill is installed at
  `/docker/hermes-agent-6aso/data/skills/gh-agent-broker` and `hermes skills
  list` reports it as a local enabled skill.
- Verified from both `hermes-gateway` and `hermes-dashboard`:
  `gh-agent-broker-cli health` returns `ok`,
  `gh-agent-broker-cli probe -repo grubbyhacker/research` succeeds through the
  broker, and the new `credential-helper get` subcommand returns test
  credentials when supplied fake `BROKER_AGENT_ID`/`BROKER_AGENT_SECRET` values.
- Repaired `/docker/hermes-agent-6aso/data` ownership to `10000:10000` after
  root-owned memory files blocked Hermes from writing
  `/opt/data/memories/USER.md.lock`. Verified write access as the `hermes`
  user in the Hermes services.
- Secrets were not committed; VPS private config/key/env live outside git under `/docker/gh-agent-broker`.
- Hermes session `20260512_005558_19ac2d` discussed broker usage and recommended a Hermes skill/runbook for broker remotes, metadata, branch rules, subagent identity, and secret safety.
