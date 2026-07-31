#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
test_root=$(mktemp -d)
trap 'chmod -R u+rwx "$test_root" 2>/dev/null || true; rm -rf -- "$test_root"' EXIT

export CODEX_WORKER_PURGE_WORK_ROOT="$test_root/work"
export CODEX_WORKER_PURGE_OUTPUT_ROOT="$test_root/output"
export CODEX_WORKER_PURGE_LESSONS_ROOT="$test_root/lessons"
source "$repo_root/workers/codex-repo-task/worker.sh"

token='codex-access-token-unreadable-directory-canary'
install -d -m 0700 "$purge_work_root/repo/unreadable/nested" \
  "$purge_output_root" "$purge_lessons_root"
printf '%s\n' "$token" > "$purge_work_root/repo/unreadable/nested/leak"
chmod 000 "$purge_work_root/repo/unreadable/nested"
chmod 000 "$purge_work_root/repo/unreadable"

record_scan_failure contamination
verify_scan_failure_layout contamination
[[ "$(cat "$purge_output_root/codex-token-scan-failure")" == contamination ]]
if grep -R -F -q -- "$token" "$purge_work_root" "$purge_output_root" "$purge_lessons_root"; then
  printf 'verified contamination purge retained the exact token\n' >&2
  exit 1
fi

external="$test_root/external"
install -d -m 0700 "$external"
printf '%s\n' "$token" > "$external/leak"
printf '%s\n' 'external-marker-sentinel' > "$external/marker"
rm -rf -- "$purge_work_root"
ln -s "$external" "$purge_work_root"
rm -f -- "$purge_output_root/codex-token-scan-failure"
ln -s "$external/marker" "$purge_output_root/codex-token-scan-failure"
if record_scan_failure contamination; then
  printf 'symlinked purge root was incorrectly accepted\n' >&2
  exit 1
fi
[[ "$(cat "$purge_output_root/codex-token-scan-failure")" == purge_failed ]]
[[ -f "$external/leak" ]]
[[ "$(cat "$external/marker")" == external-marker-sentinel ]]
