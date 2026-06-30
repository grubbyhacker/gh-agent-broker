# Sandbox run retention and prune interface

This document defines the broker-owned retention semantics for sandbox run cleanup.
The design is implemented by `cmd/sandbox-broker prune-runs` and
`internal/sandbox.PruneRuns`.

## Policy inputs

Inputs are provided by the `prune-runs` CLI subcommand and emitted as
`PruneReport.Policy`.

- `max_age` (`time.Duration`, default `24h`)  
  Only terminal runs older than this age are eligible for deletion.
- `keep_newest` (`int`, default `0`)  
  Preserve the newest `N` terminal-eligible runs before any age-based prune.
- `terminal-only` (`bool`, default `true`)  
  If `true`, non-terminal runs are never deleted (including failed metadata states
  and pending/running runs).
- `max_bytes` (`int64`, default `0`)  
  Optional disk budget in bytes. After age filtering and `keep_newest`, prune the
  oldest eligible runs until remaining selected bytes are `<= max_bytes`.
- `dry-run` (`bool`, default `false`)  
  Report what would be deleted, do not delete.
- `max_output` (`int`, default `200`)  
  Bound output list length in JSON report to `report.entries`.

## Safety constraints

The prune behavior must be safe-by-default:

- Never delete:
  - active/running entries
  - entries that fail metadata parsing
  - non-directory/symlink entries
  - malformed run IDs
  - run paths that escape configured `runs_dir`
- Only delete under exact configured `runs_dir` (`cfg.runs_dir`) and enforce
  `escapesBase` checks before deletion.
- Use existing `CleanupRun` semantics for deletion and audit event emission, so all
  run directory/removal invariants are shared with explicit `cleanup` behavior.
- Missing/corrupt metadata is skipped and counted in the report; it does not abort
  the job.
- Keep audit records for each successful/failed deletion attempt with operation
  `prune_run`.

## Machine-readable report shape

`prune-runs` prints newline-separated JSON (`pretty` via `json.MarshalIndent`) to
stdout with:

- `timestamp`
- `runs_dir`
- `policy`
- `scanned`, `considered`, `deleted`, `failed`, `skipped`
- `budget_before_bytes`, `budget_after_bytes`
- `entries` (bounded by `max_output`)
- `errors` (non-fatal and summary error details)

Each entry contains `run_id`, `status`, `template`, `repo`, `branch`,
`last_activity_at`, `age_seconds`, `size_bytes`, `keep`, `delete`, `reason`, and
`error` where applicable.

`reason` examples:
`keep_newest`, `delete_age`, `delete_budget`, `would_delete`,
`delete_failed`, `not_terminal`, `active`, `retained`.

## Execution interface recommendation

Recommended interface for vps-ops integration:

- Use a local CLI subcommand invoked from a systemd timer:
  `sandbox-broker prune-runs ...`
- Reason:
  - no new remote attack surface
  - clear operational operator boundary
  - deterministic machine-readable output can be routed to journald
  - easy environment-driven config paths per host/slot

Alternative `localhost` admin HTTP endpoint is intentionally not used in this phase.

## vps-ops scheduling and config contract

`vps-ops` should treat retention as a timed host task with explicit CLI flags:

```text
sandbox-broker prune-runs \
  -config /srv/hermes-sandbox-broker/configs/sandbox.yaml \
  -max-age 12h \
  -keep-newest 20 \
  -max-bytes 10737418240 \
  -terminal-only=true
```

- Add scheduling cadence in timer/service units (example guidance):
  - service runs as one-shot and exits after print/report.
  - timer every `12h` or aligned with VPS usage windows.
  - keep `--dry-run` in non-production validation first.
- Pass `-docker-socket` explicitly if the run environment differs from default.
- Persist output for observability (unit test artifacts can assert against report JSON,
  and journald can be scraped by future scraper jobs).
