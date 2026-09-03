# Repository-agent failed-CI repair contract

This is the exact broker/worker interface consumed by Signal Plane for the
first failed-CI repair milestone. It does not authorize deployment.

Signal Plane launches a reviewed Codex repair profile with a stable,
task-attempt idempotency key. The launch profile must require these typed
parameters in addition to the existing `issue_number` and
`source_delivery_id`:

```json
{
  "parameters": {
    "issue_number": 123,
    "source_delivery_id": "github-delivery-id",
    "repair_pr_number": 456,
    "expected_head_sha": "40-lowercase-hex-characters"
  }
}
```

`source_delivery_id` identifies the admitted delivery, not a GitHub mutable
object. The Signal Plane durable attempt identity must include repository,
pull number, admitted head SHA, model/profile, and attempt number. It may
launch no more than two coding attempts for that model/profile before its own
deadline; broker runtime deadlines remain independent and are not a polling
mechanism.

Before launching, and on each relevant admitted check/status/pull-request
event, Signal Plane calls:

```
GET /v1/repos/{owner}/{repo}/pulls/{number}/ci-observation
```

The response is a point-in-time authoritative GitHub observation containing
the pull, commit status, latest check runs, Actions workflow runs and jobs for
the head, and branch protection when GitHub exposes it. It intentionally contains no
broker-computed required-check verdict. Signal Plane must correlate the
response to `pull.head_sha == expected_head_sha`; a changed head is a new
semantic lifecycle state, not a retry of the old repair.

The preparation worker selects completed unsuccessful jobs from that observation
(at most four; more fails closed) and calls for each:

```
GET /v1/repos/{owner}/{repo}/actions/jobs/{job_id}/log
```

The broker follows only an approved HTTPS GitHub Actions signed-log redirect,
does not return the URL, and returns the whole log only when it is valid UTF-8
and at most 16 MiB. Oversize or invalid logs fail closed rather than truncate.
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
old SHA. Deletion and unconditional overwrite remain denied. A lease rejection
is a stale-head outcome: Signal Plane must reconcile GitHub and decide whether
the new head merits a new admitted attempt; it must never reinterpret it as a
successful repair.

GitHub reporting uses the existing idempotent mutation endpoints. Signal Plane
owns issue escalation/comment outbox delivery and supplies a stable
`Idempotency-Key`; the broker replays the recorded result for exact retries.
Public comments must be terse, specific, and free of raw logs, credentials,
internal IDs, or hidden reasoning.

Required broker policy operations for the repair identity are `pull.read`,
`ci.read`, `actions.logs.read`, `status.read`, `checks.read`, Git receive-pack
for the reviewed PR-head namespace, and the existing selected reporting
operation. vps-ops must grant the GitHub App narrowly sufficient read access
for Actions logs and branch/ruleset requirement observation; this repository
does not change App installation permissions.
