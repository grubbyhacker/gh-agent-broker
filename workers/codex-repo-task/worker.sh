#!/usr/bin/env bash
set -euo pipefail

readonly worker_name='agent-codex-repo-task-worker'
readonly injection_dir='/dev/shm/codex-credential-injection'
readonly capability_path="${injection_dir}/auth.json"
readonly acceptance_marker='/dev/shm/codex-credential-accepted'
readonly codex_home_base='/dev/shm/codex-home'
readonly credential_wait_seconds=45
readonly codex_events_limit=$((8 * 1024 * 1024))
readonly final_output_limit="${AGENT_FINAL_OUTPUT_LIMIT:-32768}"
readonly worker_result_lib_path="${WORKER_RESULT_LIB_PATH:-/usr/local/lib/agent-worker-result.sh}"
readonly worker_result_worker='codex'
stage='initializing'
verification_status='not_run'
CODEX_HOME=''

if [[ -r "$worker_result_lib_path" ]]; then
  source "$worker_result_lib_path"
elif [[ -r "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/result.sh" ]]; then
  source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/result.sh"
else
  printf '%s: missing shared result library %s\n' "$worker_name" "$worker_result_lib_path" >&2
  exit 1
fi

fail() { printf '%s: %s\n' "$worker_name" "$*" >&2; exit 1; }
require_env() { [[ -n "${!1:-}" ]] || fail "missing required environment variable: $1"; }

cleanup_credentials() {
  rm -f -- "$capability_path" 2>/dev/null || true
  rm -f -- "$acceptance_marker" 2>/dev/null || true
  rmdir -- "$injection_dir" 2>/dev/null || true
  rm -f -- /dev/shm/codex-events.jsonl /dev/shm/codex-stderr.log /dev/shm/codex-prompt.md 2>/dev/null || true
  [[ -z "$CODEX_HOME" ]] || rm -rf -- "$CODEX_HOME" 2>/dev/null || true
}

on_exit() {
  local status=$?
  trap - EXIT
  cleanup_credentials
  if (( status != 0 )); then
    write_result failed "worker failed during $stage" || true
    printf 'Codex repository task worker failed during %s. See /output/result.json.\n' "$stage" > /output/final-summary.md
  fi
  exit "$status"
}

validate_inputs() {
  [[ "$AGENT_REPO" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || fail 'AGENT_REPO must be owner/name'
  [[ "$AGENT_RUN_ID" =~ ^[A-Za-z0-9_.:-]+$ ]] || fail 'AGENT_RUN_ID is invalid'
  [[ "$AGENT_CODEX_VERSION" == '0.146.0' ]] || fail 'worker requires pinned Codex 0.146.0'
  [[ "$AGENT_MODEL" == 'gpt-5.6-terra' && "$AGENT_REASONING_EFFORT" == 'medium' ]] ||
    fail 'unsupported model policy resolution; no fallback is permitted'
  [[ "$AGENT_MODEL_POLICY_VERSION" == 'codex-model-policy/v1' ]] || fail 'unreviewed model policy version'
  [[ "$CODEX_SUBSCRIPTION_RELAY_BASE_URL" == 'http://codex-subscription-relay:8093/backend-api/codex' ]] ||
    fail 'Codex subscription relay base URL is not the pinned internal endpoint'
  [[ "$final_output_limit" =~ ^[1-9][0-9]*$ ]] && (( final_output_limit <= 1048576 )) ||
    fail 'AGENT_FINAL_OUTPUT_LIMIT must be a positive bounded integer'
  [[ -z "${AGENT_VERIFY_TASK:-}" || "$AGENT_VERIFY_TASK" =~ ^[A-Za-z0-9_.:-]+$ ]] ||
    fail 'AGENT_VERIFY_TASK must be a single mise task name'
}

validate_preparation() {
  jq -e --arg run "$AGENT_RUN_ID" --arg repo "$AGENT_REPO" --arg branch "$AGENT_BRANCH" '
    .version == "codex-preparation-result/v1" and .status == "prepared" and
    .run_id == $run and .repository == $repo and .branch == $branch and
    (.workspace_head | test("^[a-f0-9]{40}$")) and (.manifest_sha256 | test("^[a-f0-9]{64}$")) and
    (.issue_number | type == "number" and . > 0) and
    (.source_delivery_id | type == "string" and test("^[A-Za-z0-9-]{1,128}$"))
  ' /work/prepared/preparation.json >/dev/null || fail 'broker-prepared workspace identity is missing or invalid'
  [[ "$(git -C /work/repo rev-parse HEAD)" == "$(jq -r .workspace_head /work/prepared/preparation.json)" ]] ||
    fail 'prepared workspace changed before execution'
}

consume_capability() {
  local deadline fs mode temp_auth
  fs=$(stat -f -c %T /dev/shm) || fail '/dev/shm is required'
  [[ "$fs" == 'tmpfs' ]] || fail "/dev/shm must be tmpfs, found $fs"
  install -d -m 0700 "$injection_dir"
  deadline=$((SECONDS + credential_wait_seconds))
  while [[ ! -f "$capability_path" ]]; do
    (( SECONDS < deadline )) || fail 'timed out waiting for in-memory Codex credential injection'
    sleep 0.1
  done
  [[ ! -L "$capability_path" && "$(stat -c %a "$capability_path")" == 600 ]] ||
    fail 'injected Codex auth.json must be a mode-0600 regular file'
  CODEX_HOME="${codex_home_base}-${AGENT_RUN_ID}"
  export CODEX_HOME
  install -d -m 0700 "$CODEX_HOME"
  temp_auth="$CODEX_HOME/.auth.json.accepting"
  install -m 0600 "$capability_path" "$temp_auth"
  mv -f -- "$temp_auth" "$CODEX_HOME/auth.json"
  rm -f -- "$capability_path"
  : > "$acceptance_marker"
  chmod 0600 "$acceptance_marker"
  mode=$(stat -c %a "$CODEX_HOME/auth.json")
  [[ "$mode" == 600 ]] || fail 'Codex auth.json must be mode 0600'
  jq -e '.tokens.access_token | type == "string" and length > 0' "$CODEX_HOME/auth.json" >/dev/null ||
    fail 'access token is missing'
  jq -e '.tokens.refresh_token | type == "string" and . == ""' "$CODEX_HOME/auth.json" >/dev/null ||
    fail 'refresh_token must be explicitly empty'
  export HOME="$CODEX_HOME/home"
  install -d -m 0700 "$HOME"
  cat > "$CODEX_HOME/config.toml" <<EOF
model = "$AGENT_MODEL"
model_provider = "codex-subscription-relay"
model_reasoning_effort = "$AGENT_REASONING_EFFORT"
check_for_update_on_startup = false
web_search = "disabled"

[model_providers.codex-subscription-relay]
name = "Broker-owned Codex subscription relay"
base_url = "$CODEX_SUBSCRIPTION_RELAY_BASE_URL"
wire_api = "responses"
requires_openai_auth = true

[features]
web_search_request = false
web_search_cached = false
standalone_web_search = false
enable_mcp_apps = false
remote_plugin = false
plugin_sharing = false
runtime_metrics = false
EOF
  chmod 0600 "$CODEX_HOME/config.toml"
}

build_prompt() {
  {
    printf '# Implementation Task\n\n'
    cat /input/task.md
    printf '\n# Authoritative Issue Context\n\n'
    cat /work/prepared/issue-context.md
    printf '\n# Execution Contract\n\n'
    printf '%s\n' '- Work only in this prepared repository checkout.'
    printf '%s\n' '- Keep the diff focused on the requested issue.'
    printf '%s\n' '- Do not read, print, or store credentials or authorization headers.'
    printf '%s\n' '- Do not push, create a pull request, or contact GitHub directly; the wrapper owns delivery.'
    printf '%s\n' '- Web search, plugins, MCP, updates, analytics, and general internet are disabled.'
  } > /dev/shm/codex-prompt.md
}

extract_usage() {
  local events=$1 size
  size=$(stat -c %s "$events")
  (( size <= codex_events_limit )) || fail 'Codex event stream exceeded bounded usage-processing limit'
  jq -s '
    [.. | objects | select(has("usage")) | .usage] | last //
    {input_tokens:0,cached_input_tokens:0,output_tokens:0,status:"not_reported"} |
    with_entries(select(.key == "input_tokens" or .key == "cached_input_tokens" or
      .key == "output_tokens" or .key == "status"))
  ' "$events" > /output/codex-usage.json
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  for name in BROKER_URL AGENT_REPO AGENT_BASE_BRANCH AGENT_BRANCH AGENT_RUN_ID \
    AGENT_MODEL AGENT_REASONING_EFFORT AGENT_MODEL_POLICY_VERSION AGENT_CODEX_VERSION; do require_env "$name"; done
  trap on_exit EXIT
  validate_inputs
  validate_preparation
  consume_capability
  build_prompt
  export CODEX_DISABLE_ANALYTICS=1 DO_NOT_TRACK=1
  unset HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY http_proxy https_proxy all_proxy no_proxy

  stage='Codex repository task'
  codex exec \
    --ephemeral \
    --json \
    --model "$AGENT_MODEL" \
    -c "model_reasoning_effort=\"$AGENT_REASONING_EFFORT\"" \
    --dangerously-bypass-approvals-and-sandbox \
    --skip-git-repo-check \
    -C /work/repo \
    -o /output/codex-final.txt \
    "$(cat /dev/shm/codex-prompt.md)" \
    > /dev/shm/codex-events.jsonl \
    2> /dev/shm/codex-stderr.log
  stage='Codex final output validation'
  if [[ ! -f /output/codex-final.txt ]]; then
    stage='Codex final output missing'
    fail 'Codex final output is missing'
  fi
  final_size=$(stat -c %s /output/codex-final.txt)
  if (( final_size == 0 )); then
    stage='Codex final output missing'
    fail 'Codex final output is empty'
  fi
  (( final_size <= final_output_limit )) || {
    stage='Codex final output oversized'
    rm -f /output/codex-final.txt
    fail "Codex final output exceeds ${final_output_limit}-byte complete-output limit"
  }
  stage='bounded usage extraction'
  extract_usage /dev/shm/codex-events.jsonl
  rm -f /dev/shm/codex-events.jsonl /dev/shm/codex-stderr.log /dev/shm/codex-prompt.md

  if [[ -n "${AGENT_VERIFY_TASK:-}" ]]; then
    stage='repository verification task'
    mise run "$AGENT_VERIFY_TASK" > /output/verify.txt 2>&1
    verification_status='passed'
  fi

  cd /work/repo
  stage='change detection'
  if git diff --quiet && git diff --cached --quiet && [[ -z "$(git status --porcelain)" ]]; then
    stage='completed without changes'
    write_result no_change_required 'Codex determined that the issue requires no repository change'
    cp /output/codex-final.txt /output/final-summary.md
    exit 0
  fi

  stage='commit and push'
  git add --all
  git commit --quiet -m "Implement Codex issue task ${AGENT_RUN_ID}"
  git push --quiet origin "HEAD:${AGENT_BRANCH}"

  stage='pull request creation'
  pr_title="${AGENT_PR_TITLE:-Codex issue implementation}"
  pr_body="${AGENT_PR_BODY:-Codex issue task completed for run ${AGENT_RUN_ID}.}"
  gh-agent-broker-cli pr -broker "$BROKER_URL" -repo "$AGENT_REPO" -title "$pr_title" \
    -head "$AGENT_BRANCH" -base "$AGENT_BASE_BRANCH" -body "$pr_body" \
    -metadata "Agent-Id=${BROKER_AGENT_ID:?BROKER_AGENT_ID is required}" \
    -metadata "Run-Id=${AGENT_RUN_ID}" > /output/pull-request.json
  pull_request=$(read_pull_request) || fail 'broker pull request response is invalid'
  stage='completed'
  write_result ready_for_review 'Codex changed the repository and opened a ready-for-review pull request' "$pull_request"
  cp /output/codex-final.txt /output/final-summary.md
fi
