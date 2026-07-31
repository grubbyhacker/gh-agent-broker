#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
test_root=$(mktemp -d)
trap 'rm -rf -- "$test_root"' EXIT
export CODEX_WORKER_PURGE_WORK_ROOT="$test_root/host/work"
export CODEX_WORKER_PURGE_OUTPUT_ROOT="$test_root/host/output"
export CODEX_WORKER_PURGE_LESSONS_ROOT="$test_root/host/lessons"
source "$repo_root/workers/codex-repo-task/worker.sh"

token='codex-access-token-exact-canary'
printf '%s\n' "$token" > "$test_root/token"
token_pattern_file="$test_root/token"

scan_for_token_contamination() {
  if grep -R -F -q -- "$token" "$test_root/host" 2>/dev/null; then
    return 1
  fi
  return 0
}

run_failure_case() {
  local phase=$1 log="$test_root/$1.log"
  rm -rf -- "$test_root/host"
  install -d -m 0700 "$purge_work_root/repo" "$purge_work_root/execution" \
    "$purge_output_root" "$purge_lessons_root"
  rm -f -- "$test_root/delivery-launched"
  if (
    if [[ "$phase" == codex ]]; then
      invoke_codex() {
        printf '%s\n' "$token" > "$purge_work_root/repo/codex-leak"
        return 41
      }
      run_codex_and_scan
    else
      invoke_validation() {
        printf '%s\n' "$token" > "$purge_work_root/execution/validation-leak"
        return 42
      }
      run_validation_and_scan
    fi
    : > "$test_root/delivery-launched"
  ) >"$log" 2>&1; then
    printf '%s failure unexpectedly succeeded\n' "$phase" >&2
    exit 1
  fi
  grep -F -q 'exact task credential detected' "$log"
  [[ "$(cat "$purge_output_root/codex-token-scan-failure")" == contamination ]]
  [[ ! -e "$test_root/delivery-launched" ]]
  if grep -R -F -q -- "$token" "$test_root/host" 2>/dev/null; then
    printf '%s failure retained the exact token\n' "$phase" >&2
    exit 1
  fi
  [[ -z "$(find "$purge_work_root" "$purge_lessons_root" -mindepth 1 -print -quit)" ]]
  [[ "$(find "$purge_output_root" -mindepth 1 -maxdepth 1 -print)" == "$purge_output_root/codex-token-scan-failure" ]]
}

run_failure_case codex
run_failure_case validation

AGENT_RUN_ID='projection-run'
AGENT_REPO='owner/repo'
AGENT_BRANCH='codex/issue-1'
projection_root="$test_root/projection"
install -d -m 0700 "$projection_root"
: > "$projection_root/events.jsonl"
printf '%s\n' 'missing field `id_token` at line 1 column 67' > "$projection_root/stderr.log"
write_codex_failure_diagnostic 1 "$projection_root/events.jsonl" "$projection_root/stderr.log" \
  "$projection_root/execution-failure.json"
jq -e '
  .version == "codex-execution-failure/v1" and .status == "failed" and
  .run_id == "projection-run" and .repository == "owner/repo" and
  .branch == "codex/issue-1" and .stage == "codex" and .exit_code == 1 and
  .diagnostic_source == "stderr" and
  .diagnostic == "missing field `id_token` at line 1 column 67" and
  (.events_sha256 | test("^[a-f0-9]{64}$")) and
  (.stderr_sha256 | test("^[a-f0-9]{64}$"))
' "$projection_root/execution-failure.json" >/dev/null
[[ ! -e "$projection_root/execution-failure.json.tmp" ]]
