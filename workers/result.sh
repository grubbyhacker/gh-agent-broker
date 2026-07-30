#!/usr/bin/env bash
# Shared bounded terminal result contract for deterministic repository workers.

readonly worker_result_schema_version='repository-task-worker-result/v1'
readonly worker_result_path="${AGENT_RESULT_OUTPUT_PATH:-/output/result.json}"
readonly worker_pull_request_path="${AGENT_PULL_REQUEST_OUTPUT_PATH:-/output/pull-request.json}"
readonly worker_pull_request_max_bytes=16384
readonly worker_result_max_bytes=32768

read_pull_request() {
  local size
  [[ -f "$worker_pull_request_path" ]] || return 1
  size=$(wc -c < "$worker_pull_request_path") || return 1
  (( size > 0 && size <= worker_pull_request_max_bytes )) || return 1
  mise exec -- jq -ce '
    if type != "object" then error("pull request response must be an object")
    elif (.number | type) != "number" or (.number | floor) != .number or .number < 1 or .number > 2147483647 then error("pull request number is invalid")
    elif (.html_url | type) != "string" or (.html_url | length) == 0 or (.html_url | length) > 2048 or (.html_url | test("^https://[^[:space:]]+$") | not) then error("pull request html_url is invalid")
    elif (.url | type) != "string" or (.url | length) == 0 or (.url | length) > 2048 or (.url | test("^https://[^[:space:]]+$") | not) then error("pull request url is invalid")
    else {number: .number, html_url: .html_url, url: .url}
    end
  ' "$worker_pull_request_path" 2>/dev/null
}

write_result() {
  local outcome="$1" detail="$2" pull_request="${3:-}" verification="$verification_status" result_dir result_tmp size
  if [[ "$outcome" == 'failed' && "$stage" == 'repository verification task' ]]; then
    verification='failed'
  fi
  if [[ "$outcome" == 'ready_for_review' ]]; then
    [[ -n "$pull_request" ]] || return 1
  else
    pull_request='null'
  fi
  result_dir=$(dirname "$worker_result_path") || return 1
  result_tmp=$(mktemp "$result_dir/.result.json.XXXXXX") || return 1
  if ! mise exec -- jq -n --arg version "$worker_result_schema_version" --arg outcome "$outcome" --arg detail "$detail" --arg stage "$stage" \
    --arg run_id "$AGENT_RUN_ID" --arg repository "$AGENT_REPO" --arg base_branch "$AGENT_BASE_BRANCH" \
    --arg branch "$AGENT_BRANCH" --arg verification "$verification" --arg verify_task "${AGENT_VERIFY_TASK:-}" \
    --arg manifest_status "${manifest_status:-not_checked}" --arg task "${worker_result_task:-}" --arg worker "${worker_result_worker:-}" \
    --argjson pull_request "$pull_request" \
    '{version: $version, outcome: $outcome, detail: $detail, stage: $stage, run_id: $run_id, repository: $repository, base_branch: $base_branch, branch: $branch, verification: {status: $verification}, verify_task: $verify_task, dependency_manifest: $manifest_status} + if $task == "" then {} else {task: $task} end + if $worker == "" then {} else {worker: $worker} end + if $outcome == "ready_for_review" then {pull_request: $pull_request} else {} end' \
    > "$result_tmp"; then
    rm -f -- "$result_tmp"
    return 1
  fi
  size=$(wc -c < "$result_tmp") || { rm -f -- "$result_tmp"; return 1; }
  if (( size > worker_result_max_bytes )); then
    rm -f -- "$result_tmp"
    return 1
  fi
  mv -f -- "$result_tmp" "$worker_result_path"
}
