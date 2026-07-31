#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
test_root=$(mktemp -d)
trap 'rm -rf -- "$test_root"' EXIT
export CODEX_DELIVERY_OUTPUT_PATH="$test_root"
export AGENT_PULL_REQUEST_OUTPUT_PATH="$test_root/pull-request.json"
export AGENT_RESULT_OUTPUT_PATH="$test_root/result.json"
export AGENT_RUN_ID='run-154'
export AGENT_REPO='owner/repo'
export AGENT_BASE_BRANCH='main'
export AGENT_BRANCH='agent/delivery/run-154'
export BROKER_URL='http://broker.invalid'

mise() {
  shift 2
  command "$@"
}

source "$repo_root/workers/codex-delivery/worker.sh"

gh-agent-broker-cli() {
  [[ "$1" == pulls ]] || return 90
  printf '%s\n' '[
    {"number":153,"head_ref":"agent/delivery/run-154","base_ref":"other","body":"<!-- gh-agent-broker-codex-run:run-154 -->","html_url":"https://example/pull/153","url":"https://api.example/pulls/153"},
    {"number":154,"head_ref":"agent/delivery/run-154","base_ref":"main","body":"<!-- gh-agent-broker-codex-run:run-154 -->","html_url":"https://example/pull/154","url":"https://api.example/pulls/154"},
    {"number":155,"head_ref":"agent/delivery/run-154-extra","base_ref":"main","body":"<!-- gh-agent-broker-codex-run:run-154 -->","html_url":"https://example/pull/155","url":"https://api.example/pulls/155"}
  ]'
}

marker='<!-- gh-agent-broker-codex-run:run-154 -->'
reconcile_pull_request "$marker"
[[ "$(jq -r .number "$AGENT_PULL_REQUEST_OUTPUT_PATH")" == 154 ]]
[[ "$(jq 'length' "$test_root/pull-request-reconcile.json")" == 1 ]]

gh-agent-broker-cli() {
  [[ "$1" == pulls ]] || return 90
  printf '%s\n' '[
    {"number":154,"head_ref":"agent/delivery/run-154","base_ref":"main","body":"<!-- gh-agent-broker-codex-run:run-154 -->","html_url":"https://example/pull/154","url":"https://api.example/pulls/154"},
    {"number":156,"head_ref":"agent/delivery/run-154","base_ref":"main","body":"<!-- gh-agent-broker-codex-run:run-154 -->","html_url":"https://example/pull/156","url":"https://api.example/pulls/156"}
  ]'
}
if (reconcile_pull_request "$marker") >/dev/null 2>&1; then
  printf 'duplicate exact PR reconciliation was accepted\n' >&2
  exit 1
fi
