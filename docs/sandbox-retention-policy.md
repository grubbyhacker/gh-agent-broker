# Sandbox run retention and prune/slim interfaces

This document defines retention and post-run space-control semantics in
`internal/sandbox`, exposed via CLI subcommands:

- `prune-runs` (`PruneRuns`)
- `slim-runs` (`SlimRuns`)

`slim-runs` is designed to preserve reviewable outputs while removing bulky
reconstructible state after terminal completion.

## Policy inputs

Inputs are provided by `prune-runs`/`slim-runs` CLI flags and emitted as
`PruneReport.Policy` / `SlimReport.Policy`.

For both commands:

- `max_age` (`time.Duration`, default `24h`)  
  Only terminal runs older than this age are eligible.
- `keep_newest` (`int`, default `0`)  
  Preserve the newest `N` terminal-eligible runs before age/budget-driven action.
- `terminal-only` (`bool`, default `true`)  
  If `true`, non-terminal runs are never affected.
- `max_bytes` (`int64`, default `0`)  
  Optional aggregate disk budget in bytes after candidate selection. Older
  candidates are removed until budget is met.
- `dry-run` (`bool`, default `false`)  
  Report what would change; do not mutate disk.
- `max_output` (`int`, default `200`)  
  Truncates JSON report entries.

## Slim behavior

`slim-runs` follows the same terminal/age/budget candidate selection as
`prune-runs` and then performs run-local reconstruction-aware cleanup.

- Kept inputs:
  - `metadata.json`
  - run `input` tree
  - configured `deliverables` under `/output` and `/lessons`
  - `/output/wrapper-diagnostics.json` when present
  - `/output/slim-artifacts-manifest.json` (always generated after slimming)
  - `/logs` and `logs/slim-run.log` (best-effort snapshot capture)
- Removed by default:
  - `/work` and subtrees (e.g. `/work/home`, checkout caches, `.git`, build caches)
  - non-deliverable `/output` entries, including nested agent workspaces or
    reconstructed artifacts
- No path leaves `cfg.runs_dir`; the traversal logic applies `escapesBase` checks
  for all runtime paths.
- Symlinks are never followed; they are treated as path entries and removed only when
  outside the keep map.

The command emits `SlimReport` entries with:
- `removed_paths` (relative to the run root),
- `removed_entries` and `removed_bytes`,
- `artifact_manifest_path`,
- `log_snapshot_path`,
- `size_after_bytes`.

`reason` examples include:
`keep_newest`, `within_budget`, `slim_budget`, `would_slim`, `slimmed`,
`slim_noop`, `not_terminal`, `active`, `not_slimmed`.

`slim-run` failures are logged via `audit`:
- `operation: slim_run`
- `decision: allow|deny`
- decision-scoped `run_id`, template, status, and redacted errors.

## Safety constraints

`slim-runs` is safe-by-default:

- It does not touch non-terminal runs when `terminal-only=true`.
- It does not process non-directories, symlinks, malformed IDs, or paths that escape
  `runs_dir`.
- It preserves terminal runs that fail metadata reads as skipped/skippable.
- It never uses raw deletes rooted outside the configured run directory.

## Report output contract

`slim-runs` prints JSON via `json.MarshalIndent` with:

- `timestamp`
- `runs_dir`
- `policy`
- `scanned`, `considered`, `slimmed`, `failed`, `skipped`
- `budget_before_bytes`, `budget_after_bytes`
- `entries` (bounded by `max_output`)
- `errors`

## Execution interface recommendation

`slim-runs` is currently CLI-only. Automatic runtime on terminal transition is
explicitly deferred to keep behavior deterministic and observable.

Recommended vps-ops integration:

- Run `sandbox-broker slim-runs` from a one-shot service + timer.
- Keep `--dry-run` in staging and dry-run validation.
- Persist `slim-runs` JSON output to journald or an artifact file for auditability.

Example:

```text
sandbox-broker slim-runs \
  -config /srv/hermes-sandbox-broker/configs/sandbox.yaml \
  -max-age 12h \
  -keep-newest 20 \
  -max-bytes 10737418240 \
  -terminal-only=true
```

If you want true terminal-time automation later, gate it behind a new `RunFinalized`
hook and preserve the same policy/dry-run defaults used by the CLI.
