# Repository-agent failed-CI repair contract

This is the exact broker/worker interface consumed by Signal Plane for the
first failed-CI repair milestone. It does not authorize deployment.

Signal Plane launches the same reviewed `terra-medium-v1` profile used for the
initial issue-to-PR execution with a stable task-attempt idempotency key. The
profile always requires `issue_number` and `source_delivery_id`; it declares
`repair_pr_number` and `expected_head_sha` as optional individually but the
broker requires them all-or-neither before run creation. A repair supplies both
and may set the sole reviewed deadline override:

```json
{
  "parameters": {
    "issue_number": 123,
    "source_delivery_id": "github-delivery-id",
    "repair_pr_number": 456,
    "expected_head_sha": "40-lowercase-hex-characters"
  },
  "max_runtime_seconds": 1800
}
```

`source_delivery_id` identifies the admitted delivery, not a GitHub mutable
object. `max_runtime_seconds`, when present, is a positive active-run budget no
greater than the reviewed template cap; every other top-level override is
denied. Waiting for GitHub or CI never ends the repair:
`repair_reconciliation_wake` only schedules another check, while
`repair_active_timeout` limits one active broker phase. The Signal Plane durable
attempt identity must include repository, pull number, admitted head SHA,
model/profile, and attempt number, and at most two model-started repair
attempts may be charged. The broker runtime cap enforces that active phase; it
is not a polling mechanism.

Before launching, and on each relevant admitted check/status/pull-request
event, Signal Plane calls:

```
GET /v1/repos/{owner}/{repo}/pulls/{number}/ci-observation?head_sha={40-lower-hex}
```

The response has `version:"broker-ci-observation/v1"` and is a point-in-time
authoritative GitHub observation containing
the pull, complete bounded/paginated commit statuses and latest check runs,
failed check annotations, Actions workflow runs and jobs for the head, plus
the active branch rules (rulesets first through GitHub's branch-rules endpoint)
and legacy branch protection when exposed. `required_ci` is extracted only
from those active GitHub rules and `aggregate_state` is one of `pending`,
`success`, `code_failure`, or `infrastructure_failure`; there is no second
broker check-name configuration. Pagination or an explicit observation bound
fails closed. Signal Plane must correlate the
response to both `requested_head_sha` and authoritative `pull.head_sha`;
the broker rejects a changed head with stable `409 stale_pull_head` rather
than returning mixed-head evidence. A changed head is a new
semantic lifecycle state, not a retry of the old repair.

The preparation worker selects every completed unsuccessful Actions job from
that observation, subject to explicit safety bounds of 32 items and 64 MiB in
aggregate (excess fails visibly), and calls for each:

```
GET /v1/repos/{owner}/{repo}/actions/jobs/{job_id}/log
```

The broker follows only an approved HTTPS GitHub Actions signed-log redirect,
does not return the URL, and returns the whole log only when it is valid UTF-8
and at most 16 MiB. Responses include `size_bytes`, `sha256`, and `byte_limit`.
Oversize or invalid logs fail closed rather than truncate.
Logs are untrusted repository input and must not be copied wholesale into
GitHub comments.

The repair preparation worker re-reads the pull and observation, verifies the
open PR head equals `expected_head_sha`, and checks out that exact existing
head. The model execution has no GitHub or broker authority and produces only
working-tree edits. Its deterministic wrapper records the validated candidate
tree SHA with the sealed final validation result. Delivery commits once,
requires the committed tree to equal that validated tree, and updates the
existing PR head only with:

```
git push --force-with-lease=refs/heads/<head-ref>:<expected_head_sha> \
  origin HEAD:refs/heads/<head-ref>
```

The broker smart-HTTP preflight independently checks that advertised expected
old SHA. Deletion and unconditional overwrite remain denied. A credentialed
delivery process never runs repository-controlled validation. On the sole
positive stale-lease diagnostic (`stale info`), it records a bounded,
broker-sealed `codex-stale-lease/v3` handoff. The broker keeps the admitted
attempt running, starts its distinct credential-free recovery template, and,
after successful integration and validation, starts a fresh delivery process
with the winner SHA as its exact lease. Signal Plane observes only the eventual
terminal result; it does not launch or model stale-lease recovery as a separate
state. Transport, authentication, hook, and upstream-policy failures are
terminal delivery failures and must not create a recovery handoff. Recovery is
bounded to one attempt and never launches or charges a second model attempt.

## Structured GitHub wait and resume

Preparation and delivery may exit with a bounded
`github-external-wait/v1` report only when the broker API itself classified a
GitHub response as `github_timeout`/504, `github_rate_limited`/429, or
`github_error`/502. The worker must also exit with reserved status 75; those
exact combinations become the nonterminal durable run status
`waiting_external`. Authentication and authorization failures,
invalid worker or GitHub DTOs, policy denial, and stale/nonmatching leases do
not qualify and retain their existing terminal failure behavior.

`GET /v1/runs/{run_id}` projects `version:"broker-run-status/v1"` and this
stable wait DTO:

```json
{
  "version": "broker-run-status/v1",
  "run_id": "20260903T000000Z-0123456789abcdef",
  "status": "waiting_external",
  "external_wait": {
    "version": "broker-external-wait/v1",
    "service": "github",
    "phase": "preparation",
    "operation": "ci.observe",
    "reason": "unavailable",
    "generation": 1,
    "since": "2026-09-03T18:00:00Z"
  }
}
```

The stable `phase` vocabulary is `preparation|delivery`; `reason` is
`unavailable|rate_limited`. Preparation operations are `issue.read`,
`issue_comments.read`, `pull.read`, `ci.observe`, and
`actions_job_log.read`. Delivery operations are `pull.read`,
`pull.reconcile`, `pull.create`, and `git.push`. The existing `deadline` field
records the most recent active-phase deadline and is inactive while status is
`waiting_external`; a waiting run has no terminal result.

After Signal Plane has independently observed that GitHub is available, it may
continue the same authorized attempt with:

```http
POST /v1/runs/{run_id}/resume
Authorization: Bearer <same launch principal>
Idempotency-Key: <stable key for run and external_wait.generation>
Content-Type: application/json

{"max_runtime_seconds": 900}
```

The request accepts exactly one positive integer field,
`max_runtime_seconds`, bounded by the reviewed template maximum. Resume uses
the existing `launch` action permission, allowed profile, and owned-run scope;
the original launch principal must match. A successful response is the normal
`version:"broker-run-launch/v1"` launch status DTO for the same `run_id`, with
`replay:false` and a fresh active
`deadline`. Replaying the same key and canonical body returns the same run with
`replay:true`; reusing the key with another body returns `409
idempotency_conflict`. A missing key returns `428
idempotency_key_required`, an invalid body returns `400 validation_error`, and
a nonwaiting run returns `409 run_not_waiting_external`.

Preparation resume creates a fresh credential-free preparation container and
does not issue or charge a model capability. Delivery resume creates a fresh
delivery container, preserves the sealed execution/recovery artifacts, and
never invokes Codex. Repair delivery reconciles the authoritative PR head
before a leased push: an already-delivered exact candidate completes without
another push; the admitted old head permits the existing exact lease; any
other head remains a nonretryable lease failure. A dropped push response is
also reconciled before it can be classified as failure.

Both an initial and repair `ready_for_review` terminal result include the
exact `pull_request.number`, `branch`, `delivered_head_sha`, and
`validated_tree_sha` fields. The terminal projection rejects a Codex result
without these bounded values, so replay/reconciliation carries the same PR,
head, and validated-tree identity.

Every Codex terminal projection includes `model_execution_started`. Failed
results also use the bounded `failure_class` vocabulary: `infrastructure`
(zero-charge pre-model/start failures), `model_or_code`, or
`delivery_or_lease`. `finalize_reason` and `terminal_source` remain
diagnostic-only details.

GitHub reporting uses the existing idempotent mutation endpoints. `POST
/v1/repos/{owner}/{repo}/issues/{number}/comments` requires one visible-ASCII
`Idempotency-Key` header. It is durable and namespaced by principal, operation,
repository, and issue; the broker records a request digest, replays only an
identical request, and returns `409 idempotency_key_conflict` for reuse with
different content or target. Signal Plane owns issue escalation/comment outbox
delivery and supplies that stable key.
Public comments must be terse, specific, and free of raw logs, credentials,
internal IDs, or hidden reasoning.

Required broker policy operations for the repair identity are `pull.read`,
`ci.read`, `actions.logs.read`, `status.read`, `checks.read`, Git receive-pack
for the reviewed PR-head namespace, and the existing selected reporting
operation. vps-ops must grant the GitHub App narrowly sufficient read access
for Actions logs and branch/ruleset requirement observation. Confirmed official
GitHub App endpoints are `GET /repos/{owner}/{repo}/rules/branches/{branch}`
(active rules; Metadata:read), commit statuses (Commit statuses:read), check
runs and annotations (Checks:read), and Actions runs/jobs/logs (Actions:read),
plus Issues/Pull requests write for reporting. The broker intentionally avoids
the legacy protection fallback because it requires Administration:read.
Check annotations are fetched from their separate paginated endpoint only for
failed checks, bounded to 100 items and 256 KiB per run; exceeding either bound
fails the observation closed.
