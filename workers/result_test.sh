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
export AGENT_VERIFY_TASK='verify'
export AGENT_TASK='task'

source "$1"

assert_result() {
  local expected="$1"
  diff -u <(printf '%s\n' "$expected" | jq -S .) <(jq -S . "$AGENT_RESULT_OUTPUT_PATH") || fail_test 'unexpected result shape'
}

manifest_status='match'
stage='change detection'
verification_status='not_run'
write_result no_change_required 'task completed successfully; repository is unchanged'
assert_result '{"version":"repository-task-worker-result/v1","outcome":"no_change_required","detail":"task completed successfully; repository is unchanged","stage":"change detection","run_id":"run-1","repository":"owner/repository","base_branch":"main","branch":"agent/run-1","verification":{"status":"not_run"},"verify_task":"verify","dependency_manifest":"match"}'

printf '%s\n' '{"number":42,"html_url":"https://github.example/owner/repository/pull/42","url":"https://api.github.example/repos/owner/repository/pulls/42","secret":"canary-secret"}' > "$AGENT_PULL_REQUEST_OUTPUT_PATH"
pull_request=$(read_pull_request) || fail_test 'valid broker pull request response was rejected'
stage='completed'
verification_status='passed'
write_result ready_for_review 'repository changed and a pull request was created' "$pull_request"
assert_result '{"version":"repository-task-worker-result/v1","outcome":"ready_for_review","detail":"repository changed and a pull request was created","stage":"completed","run_id":"run-1","repository":"owner/repository","base_branch":"main","branch":"agent/run-1","verification":{"status":"passed"},"verify_task":"verify","dependency_manifest":"match","pull_request":{"number":42,"html_url":"https://github.example/owner/repository/pull/42","url":"https://api.github.example/repos/owner/repository/pulls/42"}}'
if grep -Fq 'canary-secret' "$AGENT_RESULT_OUTPUT_PATH"; then
  fail_test 'broker response canary leaked into the terminal result'
fi

stage='repository task'
verification_status='not_run'
write_result failed 'worker failed during repository task'
assert_result '{"version":"repository-task-worker-result/v1","outcome":"failed","detail":"worker failed during repository task","stage":"repository task","run_id":"run-1","repository":"owner/repository","base_branch":"main","branch":"agent/run-1","verification":{"status":"not_run"},"verify_task":"verify","dependency_manifest":"match"}'

stage='repository verification task'
verification_status='not_run'
write_result failed 'worker failed during repository verification task'
assert_result '{"version":"repository-task-worker-result/v1","outcome":"failed","detail":"worker failed during repository verification task","stage":"repository verification task","run_id":"run-1","repository":"owner/repository","base_branch":"main","branch":"agent/run-1","verification":{"status":"failed"},"verify_task":"verify","dependency_manifest":"match"}'

printf '%s\n' '{"number":"42","html_url":"https://github.example/owner/repository/pull/42","url":"https://api.github.example/repos/owner/repository/pulls/42","secret":"canary-secret"}' > "$AGENT_PULL_REQUEST_OUTPUT_PATH"
if malformed=$(read_pull_request 2>&1); then
  fail_test 'malformed broker pull request response was accepted'
fi
[[ -z "$malformed" ]] || fail_test 'malformed broker response leaked parser output'
if write_result ready_for_review 'repository changed and a pull request was created'; then
  fail_test 'ready-for-review result was written without a valid pull request identity'
fi
[[ "$(jq -r '.outcome' "$AGENT_RESULT_OUTPUT_PATH")" == 'failed' ]] || fail_test 'malformed response replaced the bounded failure result'
