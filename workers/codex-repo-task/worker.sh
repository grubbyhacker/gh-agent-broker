#!/usr/bin/env bash
set -euo pipefail

readonly worker_name='agent-codex-repo-task-worker'
readonly injection_dir='/dev/shm/codex-credential-injection'
readonly capability_path="${injection_dir}/auth.json"
readonly acceptance_marker='/dev/shm/codex-credential-accepted'
readonly codex_home_base='/dev/shm/codex-home'
readonly scan_base='/dev/shm/codex-scan'
readonly credential_wait_seconds=45
readonly codex_events_limit=$((8 * 1024 * 1024))
readonly execution_diff_limit=$((8 * 1024 * 1024))
readonly verification_output_limit=$((1024 * 1024))
readonly final_output_limit="${AGENT_FINAL_OUTPUT_LIMIT:-32768}"
readonly repo_path='/work/repo'
readonly execution_path='/work/execution'
readonly output_path='/output'
readonly lessons_path='/lessons'
readonly events_path='/dev/shm/codex-events.jsonl'
readonly stderr_path='/dev/shm/codex-stderr.log'
readonly prompt_path='/dev/shm/codex-prompt.md'
stage='initializing'
CODEX_HOME=''
scan_dir=''
token_pattern_file=''
contamination_detected=0

fail() { printf '%s: %s\n' "$worker_name" "$*" >&2; exit 1; }
security_fail() { contamination_detected=1; fail "$@"; }
require_env() { [[ -n "${!1:-}" ]] || fail "missing required environment variable: $1"; }

cleanup_credentials() {
  rm -f -- "$capability_path" "$acceptance_marker" "$events_path" "$stderr_path" "$prompt_path" 2>/dev/null || true
  rmdir -- "$injection_dir" 2>/dev/null || true
  [[ -z "$CODEX_HOME" ]] || rm -rf -- "$CODEX_HOME" 2>/dev/null || true
  [[ -z "$scan_dir" ]] || rm -rf -- "$scan_dir" 2>/dev/null || true
  exec 9<&- 2>/dev/null || true
}

purge_contaminated_artifacts() {
  find /work "$output_path" "$lessons_path" -mindepth 1 -delete 2>/dev/null || true
}

on_exit() {
  local status=$?
  trap - EXIT
  cleanup_credentials
  if (( status != 0 && contamination_detected != 0 )); then
    purge_contaminated_artifacts
    printf '%s: exact access-token contamination blocked; host-backed work and output removed\n' "$worker_name" >&2
  fi
  exit "$status"
}

reject_broker_authority() {
  local name _
  while IFS='=' read -r name _; do
    case "$name" in
      BROKER_*|GH_TOKEN|GITHUB_TOKEN|GIT_ASKPASS|SSH_ASKPASS)
        fail "broker or GitHub authority is forbidden during Codex execution: $name" ;;
    esac
  done < <(env)
  for path in /credentials /run/codex-issuance; do
    [[ ! -e "$path" ]] || fail "private broker credential path is visible during execution: $path"
  done
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
  [[ "$AGENT_VERIFY_TASK" =~ ^[A-Za-z0-9_.:-]+$ ]] ||
    fail 'AGENT_VERIFY_TASK must be one reviewed mise task name'
}

validate_preparation() {
  jq -e --arg run "$AGENT_RUN_ID" --arg repo "$AGENT_REPO" --arg branch "$AGENT_BRANCH" '
    .version == "codex-preparation-result/v1" and .status == "prepared" and
    .run_id == $run and .repository == $repo and .branch == $branch and
    (.workspace_head | test("^[a-f0-9]{40}$")) and (.refs_sha256 | test("^[a-f0-9]{64}$")) and
    (.manifest_sha256 | test("^[a-f0-9]{64}$"))
  ' /work/prepared/preparation.json >/dev/null || fail 'broker-prepared workspace identity is missing or invalid'
  [[ "$(git -C "$repo_path" rev-parse HEAD)" == "$(jq -r .workspace_head /work/prepared/preparation.json)" ]] ||
    fail 'prepared workspace changed before execution'
}

consume_capability() {
  local deadline temp_auth
  [[ "$(stat -f -c %T /dev/shm)" == 'tmpfs' ]] || fail '/dev/shm must be tmpfs'
  install -d -m 0700 "$injection_dir"
  deadline=$((SECONDS + credential_wait_seconds))
  while [[ ! -f "$capability_path" ]]; do
    (( SECONDS < deadline )) || fail 'timed out waiting for in-memory Codex credential injection'
    sleep 0.1
  done
  [[ ! -L "$capability_path" && "$(stat -c %a "$capability_path")" == 600 ]] ||
    fail 'injected Codex auth.json must be a mode-0600 regular file'
  CODEX_HOME="${codex_home_base}-${AGENT_RUN_ID}"
  install -d -m 0700 "$CODEX_HOME"
  temp_auth="$CODEX_HOME/.auth.json.accepting"
  install -m 0600 "$capability_path" "$temp_auth"
  mv -f -- "$temp_auth" "$CODEX_HOME/auth.json"
  rm -f -- "$capability_path"
  : > "$acceptance_marker"
  chmod 0600 "$acceptance_marker"
  jq -e '.tokens.access_token | type == "string" and length > 0' "$CODEX_HOME/auth.json" >/dev/null ||
    fail 'access token is missing'
  jq -e '.tokens.refresh_token | type == "string" and . == ""' "$CODEX_HOME/auth.json" >/dev/null ||
    fail 'refresh_token must be explicitly empty'
  scan_dir="${scan_base}-${AGENT_RUN_ID}"
  install -d -m 0700 "$scan_dir"
  jq -er '.tokens.access_token' "$CODEX_HOME/auth.json" > "$scan_dir/access-token.pattern"
  chmod 0400 "$scan_dir/access-token.pattern"
  exec 9< "$scan_dir/access-token.pattern"
  rm -f -- "$scan_dir/access-token.pattern"
  token_pattern_file="/proc/$$/fd/9"
  export CODEX_HOME HOME="$CODEX_HOME/home"
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

snapshot_refs() {
  git -C "$repo_path" for-each-ref --format='%(refname) %(objectname) %(symref)' | LC_ALL=C sort
}

snapshot_git_identity() {
  git -C "$repo_path" rev-parse HEAD > "$scan_dir/head"
  snapshot_refs > "$scan_dir/refs"
  git -C "$repo_path" cat-file --batch-all-objects --batch-check='%(objecttype) %(objectname)' |
    awk '$1 == "commit" { print $2 }' | LC_ALL=C sort > "$scan_dir/commits"
  : > "$repo_path/.git/config"
  git config --file "$repo_path/.git/config" core.repositoryformatversion 0
  git config --file "$repo_path/.git/config" core.filemode true
  git config --file "$repo_path/.git/config" core.bare false
  git config --file "$repo_path/.git/config" core.logallrefupdates true
  git config --file "$repo_path/.git/config" core.hooksPath /dev/null
  git config --file "$repo_path/.git/config" remote.origin.url 'no-broker-access://codex-execution'
}

verify_git_identity() {
  [[ "$(git -C "$repo_path" rev-parse HEAD)" == "$(cat "$scan_dir/head")" ]] ||
    security_fail 'Codex changed workspace HEAD'
  snapshot_refs > "$scan_dir/current-refs"
  cmp -s "$scan_dir/refs" "$scan_dir/current-refs" || security_fail 'Codex changed repository refs'
  git -C "$repo_path" cat-file --batch-all-objects --batch-check='%(objecttype) %(objectname)' |
    awk '$1 == "commit" { print $2 }' | LC_ALL=C sort > "$scan_dir/current-commits"
  cmp -s "$scan_dir/commits" "$scan_dir/current-commits" || security_fail 'Codex created a commit object'
}

scan_for_token_contamination() {
  local path
  stage='exact access-token contamination scan'
  for path in /work "$output_path" "$lessons_path" "$events_path" "$stderr_path"; do
    [[ -e "$path" ]] || continue
    if grep -R -F -q -f "$token_pattern_file" -- "$path" 2>/dev/null; then
      security_fail 'exact access token detected in Codex-controlled work or output'
    fi
  done
  while IFS= read -r -d '' path; do
    if printf '%s' "$path" | grep -F -q -f "$token_pattern_file"; then
      security_fail 'exact access token detected in a Codex-controlled path'
    fi
  done < <(find -P /work "$output_path" "$lessons_path" -print0)
  while IFS= read -r -d '' path; do
    if readlink -- "$path" | grep -F -q -f "$token_pattern_file"; then
      security_fail 'exact access token detected in a Codex-controlled symlink'
    fi
  done < <(find -P /work "$output_path" "$lessons_path" -type l -print0)
  while read -r oid type; do
    case "$type" in
      blob|commit|tag|tree)
        if git -C "$repo_path" cat-file "$type" "$oid" |
          grep -F -q -f "$token_pattern_file"; then
          security_fail 'exact access token detected in a Git object'
        fi
        ;;
    esac
  done < <(git -C "$repo_path" cat-file --batch-all-objects --batch-check='%(objectname) %(objecttype)')
}

build_prompt() {
  {
    printf '# Implementation Task\n\n'; cat /input/task.md
    printf '\n# Authoritative Issue Context\n\n'; cat /work/prepared/issue-context.md
    printf '\n# Execution Contract\n\n'
    printf '%s\n' '- Work only in this prepared repository checkout.'
    printf '%s\n' '- Do not push, create a pull request, or contact GitHub; a separate deterministic container owns delivery.'
    printf '%s\n' '- Do not create commits or refs. Leave only working-tree changes.'
    printf '%s\n' '- Web search, plugins, MCP, updates, analytics, and general internet are disabled.'
  } > "$prompt_path"
}

write_execution_result() {
  local temp_index="$scan_dir/index" diff_temp="$execution_path/diff.patch.tmp"
  local result_temp="$execution_path/execution.json.tmp" final_size
  mkdir -p "$execution_path"
  GIT_INDEX_FILE="$temp_index" git -C "$repo_path" read-tree HEAD
  GIT_INDEX_FILE="$temp_index" git -C "$repo_path" -c core.hooksPath=/dev/null add --all
  GIT_INDEX_FILE="$temp_index" git -C "$repo_path" diff --cached --binary HEAD > "$diff_temp"
  (( $(stat -c %s "$diff_temp") <= execution_diff_limit )) || fail 'Codex diff exceeded bounded execution limit'
  mv -f -- "$diff_temp" "$execution_path/diff.patch"
  final_size=$(stat -c %s "$output_path/codex-final.txt")
  jq -n --arg run "$AGENT_RUN_ID" --arg repo "$AGENT_REPO" --arg branch "$AGENT_BRANCH" \
    --arg head "$(cat "$scan_dir/head")" \
    --arg refs "$(sha256sum "$scan_dir/refs" | cut -d' ' -f1)" \
    --arg diff "$(sha256sum "$execution_path/diff.patch" | cut -d' ' -f1)" \
    --arg final "$(sha256sum "$output_path/codex-final.txt" | cut -d' ' -f1)" \
    --arg verify "$(sha256sum "$execution_path/verify.txt" | cut -d' ' -f1)" \
    --argjson final_size "$final_size" \
    '{version:"codex-execution-result/v1",status:"executed",run_id:$run,repository:$repo,
      branch:$branch,workspace_head:$head,refs_sha256:$refs,diff_sha256:$diff,final_sha256:$final,
      verification:"passed",verify_sha256:$verify,final_size_bytes:$final_size}' > "$result_temp"
  (( $(stat -c %s "$result_temp") <= 4096 )) || fail 'execution result exceeded bound'
  mv -f -- "$result_temp" "$execution_path/execution.json"
  chmod 0444 "$execution_path/execution.json" "$execution_path/diff.patch"
}

extract_usage() {
  jq -s '
    [.. | objects | select(has("usage")) | .usage] | last //
    {input_tokens:0,cached_input_tokens:0,output_tokens:0,status:"not_reported"} |
    with_entries(select(.key == "input_tokens" or .key == "cached_input_tokens" or
      .key == "output_tokens" or .key == "status"))
  ' "$events_path" > "$output_path/codex-usage.json"
  (( $(stat -c %s "$output_path/codex-usage.json") <= 4096 )) ||
    fail 'Codex usage projection exceeded bound'
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  for name in AGENT_REPO AGENT_BASE_BRANCH AGENT_BRANCH AGENT_RUN_ID AGENT_MODEL \
    AGENT_REASONING_EFFORT AGENT_MODEL_POLICY_VERSION AGENT_CODEX_VERSION \
    CODEX_SUBSCRIPTION_RELAY_BASE_URL; do require_env "$name"; done
  trap on_exit EXIT
  reject_broker_authority
  validate_inputs
  validate_preparation
  consume_capability
  snapshot_git_identity
  build_prompt
  export CODEX_DISABLE_ANALYTICS=1 DO_NOT_TRACK=1 GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null
  unset HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY http_proxy https_proxy all_proxy no_proxy
  stage='Codex repository task'
  codex exec --ephemeral --json --model "$AGENT_MODEL" \
    -c "model_reasoning_effort=\"$AGENT_REASONING_EFFORT\"" \
    --dangerously-bypass-approvals-and-sandbox --skip-git-repo-check -C "$repo_path" \
    -o "$output_path/codex-final.txt" "$(cat "$prompt_path")" > "$events_path" 2> "$stderr_path" 9<&-
  verify_git_identity
  [[ -s "$output_path/codex-final.txt" ]] || fail 'Codex final output is missing or empty'
  (( $(stat -c %s "$output_path/codex-final.txt") <= final_output_limit )) ||
    fail "Codex final output exceeds ${final_output_limit}-byte complete-output limit"
  (( $(stat -c %s "$events_path") <= codex_events_limit )) || fail 'Codex event stream exceeded bounded limit'
  extract_usage
  scan_for_token_contamination
  mkdir -p "$execution_path"
  stage='repository validation'
  (cd "$repo_path" && mise run "$AGENT_VERIFY_TASK") > "$execution_path/verify.txt" 2>&1
  (( $(stat -c %s "$execution_path/verify.txt") <= verification_output_limit )) ||
    fail 'repository validation output exceeded bounded limit'
  verify_git_identity
  scan_for_token_contamination
  write_execution_result
  scan_for_token_contamination
  stage='executed'
fi
