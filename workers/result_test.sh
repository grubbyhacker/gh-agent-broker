#!/usr/bin/env bash
set -euo pipefail

fail_test() { printf 'worker result regression test: %s\n' "$*" >&2; exit 1; }
[[ $# == 1 ]] || fail_test 'expected one worker path'

mise() {
  [[ "$1" == 'exec' && "$2" == '--' ]] || fail_test 'unexpected mise invocation'
  shift 2
  command "$@"
}

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT
export AGENT_RESULT_OUTPUT_PATH="$tmpdir/result.json"
export AGENT_PULL_REQUEST_OUTPUT_PATH="$tmpdir/pull-request.json"
export AGENT_RUN_ID='run-1'
export AGENT_REPO='owner/repository'
export AGENT_BASE_BRANCH='main'
export AGENT_BRANCH='agent/run-1'
export AGENT_TASK='task'

source "$1"

assert_result() {
  local expected="$1"
  diff -u <(printf '%s\n' "$expected" | jq -S .) <(jq -S . "$AGENT_RESULT_OUTPUT_PATH") || fail_test 'unexpected result shape'
}

if [[ "$1" == *'/repo-task/'* ]]; then
  producer_fields=',"task":"task"'
else
  producer_fields=',"worker":"codex"'
fi

result_json() {
  local outcome="$1" detail="$2" current_stage="$3" verification="$4" verify_task="$5" pull_request="${6:-null}"
  printf '{"version":"repository-task-worker-result/v1","outcome":"%s","detail":"%s","stage":"%s","run_id":"run-1","repository":"owner/repository","base_branch":"main","branch":"agent/run-1","verification":{"status":"%s"},"verify_task":"%s","dependency_manifest":"match"%s' "$outcome" "$detail" "$current_stage" "$verification" "$verify_task" "$producer_fields"
  if [[ "$outcome" == 'ready_for_review' ]]; then
    printf ',"pull_request":%s,"expected_old_head_sha":"3333333333333333333333333333333333333333","candidate_head_sha":"4444444444444444444444444444444444444444","delivered_head_sha":"1111111111111111111111111111111111111111","validated_tree_sha":"2222222222222222222222222222222222222222","delivered_tree_sha":"2222222222222222222222222222222222222222"' "$pull_request"
  fi
  printf '}'
}

manifest_status='match'
stage='change detection'
unset AGENT_VERIFY_TASK
verification_status='not_run'
write_result no_change_required 'task completed successfully; repository is unchanged'
assert_result "$(result_json no_change_required 'task completed successfully; repository is unchanged' 'change detection' not_run '')"

export AGENT_VERIFY_TASK='verify'
verification_status='passed'
write_result no_change_required 'task completed successfully; repository is unchanged'
assert_result "$(result_json no_change_required 'task completed successfully; repository is unchanged' 'change detection' passed verify)"

verification_status='not_run'
write_result no_change_required ''
base_result_size=$(wc -c < "$AGENT_RESULT_OUTPUT_PATH")
boundary_detail_length=$((worker_result_max_bytes - base_result_size))
boundary_detail=$(head -c "$boundary_detail_length" /dev/zero | tr '\0' x)
write_result no_change_required "$boundary_detail"
[[ $(wc -c < "$AGENT_RESULT_OUTPUT_PATH") -eq $worker_result_max_bytes ]] || fail_test 'result exactly at the byte limit was not written intact'
if write_result no_change_required "${boundary_detail}x"; then
  fail_test 'oversized result was accepted'
fi
[[ $(wc -c < "$AGENT_RESULT_OUTPUT_PATH") -eq $worker_result_max_bytes ]] || fail_test 'oversized result replaced the prior complete result'

printf '%s\n' '{"number":42,"html_url":"https://github.example/owner/repository/pull/42","url":"https://api.github.example/repos/owner/repository/pulls/42","secret":"canary-secret"}' > "$AGENT_PULL_REQUEST_OUTPUT_PATH"
pull_request=$(read_pull_request) || fail_test 'valid broker pull request response was rejected'
stage='completed'
verification_status='passed'
export delivered_head_sha='1111111111111111111111111111111111111111'
export validated_tree_sha='2222222222222222222222222222222222222222'
export delivered_tree_sha="$validated_tree_sha"
export expected_old_head_sha='3333333333333333333333333333333333333333'
export candidate_head_sha='4444444444444444444444444444444444444444'
write_result ready_for_review 'repository changed and a pull request was created' "$pull_request"
assert_result "$(result_json ready_for_review 'repository changed and a pull request was created' completed passed verify "$pull_request")"
if grep -Fq 'canary-secret' "$AGENT_RESULT_OUTPUT_PATH"; then
  fail_test 'broker response canary leaked into the terminal result'
fi

stage='repository task'
verification_status='not_run'
write_result failed 'worker failed during repository task'
assert_result "$(result_json failed 'worker failed during repository task' 'repository task' not_run verify)"

stage='repository verification task'
verification_status='not_run'
write_result failed 'worker failed during repository verification task'
assert_result "$(result_json failed 'worker failed during repository verification task' 'repository verification task' failed verify)"

printf '%s\n' '{"number":"42","html_url":"https://github.example/owner/repository/pull/42","url":"https://api.github.example/repos/owner/repository/pulls/42","secret":"canary-secret"}' > "$AGENT_PULL_REQUEST_OUTPUT_PATH"
if malformed=$(read_pull_request 2>&1); then
  fail_test 'malformed broker pull request response was accepted'
fi
[[ -z "$malformed" ]] || fail_test 'malformed broker response leaked parser output'
stage='pull request result validation'
verification_status='passed'
write_result failed "worker failed during $stage"
assert_result "$(result_json failed 'worker failed during pull request result validation' 'pull request result validation' passed verify)"
