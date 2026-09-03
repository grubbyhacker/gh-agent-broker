#!/usr/bin/env bash
set -euo pipefail

readonly worker_name='agent-codex-repo-task-worker'
readonly injection_dir='/dev/shm/codex-credential-injection'
readonly capability_path="${injection_dir}/auth.json"
readonly injection_ready_marker='/dev/shm/codex-credential-injection-ready'
readonly acceptance_marker='/dev/shm/codex-credential-accepted'
readonly codex_home_base='/dev/shm/codex-home'
readonly scan_base='/dev/shm/codex-scan'
readonly credential_wait_seconds=45
readonly codex_events_limit=$((8 * 1024 * 1024))
readonly execution_diff_limit=$((8 * 1024 * 1024))
readonly verification_output_limit=$((1024 * 1024))
readonly final_output_limit="${AGENT_FINAL_OUTPUT_LIMIT:-32768}"
readonly failure_diagnostic_limit=4096
readonly repo_path='/work/repo'
readonly execution_path='/work/execution'
readonly output_path='/output'
readonly lessons_path='/lessons'
readonly purge_work_root="${CODEX_WORKER_PURGE_WORK_ROOT:-/work}"
readonly purge_output_root="${CODEX_WORKER_PURGE_OUTPUT_ROOT:-/output}"
readonly purge_lessons_root="${CODEX_WORKER_PURGE_LESSONS_ROOT:-/lessons}"
readonly events_path='/dev/shm/codex-events.jsonl'
readonly stderr_path='/dev/shm/codex-stderr.log'
readonly prompt_path='/dev/shm/codex-prompt.md'
stage='initializing'
CODEX_HOME=''
scan_dir=''
token_pattern_file=''
contamination_detected=0
scan_incomplete=0
purge_failed=0

fail() { printf '%s: %s\n' "$worker_name" "$*" >&2; exit 1; }
security_fail() { contamination_detected=1; fail "$@"; }
require_env() { [[ -n "${!1:-}" ]] || fail "missing required environment variable: $1"; }
file_size() { stat -c %s "$1" 2>/dev/null || stat -f %z "$1"; }
execution_git() {
  env -i PATH="$PATH" HOME=/nonexistent LANG=C LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
    GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null GIT_OPTIONAL_LOCKS=0 \
    GIT_TERMINAL_PROMPT=0 GIT_ASKPASS=/bin/false SSH_ASKPASS=/bin/false \
    GIT_PAGER=cat PAGER=cat GIT_EDITOR=/bin/false GIT_SEQUENCE_EDITOR=/bin/false \
    git --no-optional-locks -c core.hooksPath=/dev/null -c core.fsmonitor=false "$@"
}

cleanup_credentials() {
  rm -f -- \
    "$capability_path" "$injection_ready_marker" "$acceptance_marker" \
    "$events_path" "$stderr_path" "$prompt_path" 2>/dev/null || true
  rmdir -- "$injection_dir" 2>/dev/null || true
  [[ -z "$CODEX_HOME" ]] || rm -rf -- "$CODEX_HOME" 2>/dev/null || true
  [[ -z "$scan_dir" ]] || rm -rf -- "$scan_dir" 2>/dev/null || true
  exec 9<&- 2>/dev/null || true
}

restore_owner_rwX() {
  local path=$1 child
  [[ ! -L "$path" ]] || return 0
  if [[ -d "$path" ]]; then
    chmod u+rwx "$path" 2>/dev/null || return 1
  else
    chmod u+rw "$path" 2>/dev/null || return 1
    return 0
  fi
  for child in "$path"/* "$path"/.[!.]* "$path"/..?*; do
    [[ -e "$child" || -L "$child" ]] || continue
    restore_owner_rwX "$child" || return 1
  done
}

purge_contaminated_artifacts() {
  local root remaining status=0
  for root in "$purge_work_root" "$purge_output_root" "$purge_lessons_root"; do
    if [[ ! -d "$root" || -L "$root" ]]; then
      status=1
      continue
    fi
    restore_owner_rwX "$root" || status=1
  done
  find -P "$purge_work_root" "$purge_output_root" "$purge_lessons_root" \
    -mindepth 1 -delete 2>/dev/null || status=1
  for root in "$purge_work_root" "$purge_output_root" "$purge_lessons_root"; do
    [[ -d "$root" && ! -L "$root" ]] || status=1
    remaining=''
    if ! remaining=$(find -P "$root" -mindepth 1 -print -quit 2>/dev/null); then
      status=1
    fi
    [[ -z "$remaining" ]] || status=1
  done
  (( status == 0 ))
}

write_scan_failure_marker() {
  local reason=$1 marker="$purge_output_root/codex-token-scan-failure"
  local temp="$purge_output_root/.codex-token-scan-failure.$$"
  [[ -d "$purge_output_root" && ! -L "$purge_output_root" ]] || return 1
  rm -f -- "$marker" "$temp" 2>/dev/null || return 1
  (umask 077; printf '%s\n' "$reason" > "$temp") || return 1
  [[ -f "$temp" && ! -L "$temp" ]] || return 1
  chmod 0444 "$temp" 2>/dev/null || return 1
  mv -f -- "$temp" "$marker" 2>/dev/null || return 1
}

verify_scan_failure_layout() {
  local reason=$1 root entry marker="$purge_output_root/codex-token-scan-failure"
  for root in "$purge_work_root" "$purge_lessons_root"; do
    [[ -d "$root" && ! -L "$root" ]] || return 1
    entry=''
    if ! entry=$(find -P "$root" -mindepth 1 -print -quit 2>/dev/null); then
      return 1
    fi
    [[ -z "$entry" ]] || return 1
  done
  [[ -d "$purge_output_root" && ! -L "$purge_output_root" ]] || return 1
  entry=$(find -P "$purge_output_root" -mindepth 1 -maxdepth 1 -print 2>/dev/null) || return 1
  [[ "$entry" == "$marker" && -f "$marker" && ! -L "$marker" ]] || return 1
  [[ "$(cat "$marker" 2>/dev/null)" == "$reason" ]]
}

record_scan_failure() {
  local reason=$1
  if ! purge_contaminated_artifacts; then
    purge_failed=1
  fi
  if (( purge_failed != 0 )); then
    write_scan_failure_marker purge_failed || true
    return 1
  fi
  if ! write_scan_failure_marker "$reason" || ! verify_scan_failure_layout "$reason"; then
    purge_failed=1
    write_scan_failure_marker purge_failed || true
    return 1
  fi
  return 0
}

on_exit() {
  local status=$? scan_status=0
  trap - EXIT
  if (( status != 0 )) && [[ -n "$token_pattern_file" ]]; then
    scan_for_token_contamination || scan_status=$?
    if (( scan_status == 1 )); then
      contamination_detected=1
    elif (( scan_status != 0 )); then
      scan_incomplete=1
    fi
  fi
  if (( status != 0 && (contamination_detected != 0 || scan_incomplete != 0) )); then
    if (( contamination_detected != 0 )); then
      if record_scan_failure contamination; then
        printf '%s: exact task-credential contamination blocked; disposable host-backed artifacts purged\n' "$worker_name" >&2
      else
        printf '%s: credential contamination cleanup could not be verified; run remains blocked\n' "$worker_name" >&2
      fi
    else
      if record_scan_failure incomplete; then
        printf '%s: task-credential scan incomplete; disposable host-backed artifacts purged\n' "$worker_name" >&2
      else
        printf '%s: credential contamination cleanup could not be verified; run remains blocked\n' "$worker_name" >&2
      fi
    fi
  fi
  cleanup_credentials
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
  [[ "$purge_work_root" == /work && "$purge_output_root" == /output &&
    "$purge_lessons_root" == /lessons ]] ||
    fail 'contamination purge roots are fixed by the reviewed execution contract'
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
  : > "$injection_ready_marker"
  chmod 0600 "$injection_ready_marker"
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
  jq -e '.tokens.id_token | type == "string" and length > 0' "$CODEX_HOME/auth.json" >/dev/null ||
    fail 'ID token is missing'
  jq -e '.tokens.refresh_token | type == "string" and . == ""' "$CODEX_HOME/auth.json" >/dev/null ||
    fail 'refresh_token must be explicitly empty'
  scan_dir="${scan_base}-${AGENT_RUN_ID}"
  install -d -m 0700 "$scan_dir"
  jq -er '.tokens | .access_token, .id_token' "$CODEX_HOME/auth.json" > "$scan_dir/task-credentials.pattern"
  chmod 0400 "$scan_dir/task-credentials.pattern"
  exec 9< "$scan_dir/task-credentials.pattern"
  rm -f -- "$scan_dir/task-credentials.pattern"
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
  local path oid type grep_status
  local found=0 incomplete=0
  local scan_work host_paths git_objects git_object_contents result=0
  stage='exact task-credential contamination scan'
  [[ -r "$token_pattern_file" ]] || return 2
  scan_work=$(mktemp -d "$scan_dir/pass.XXXXXX") || return 2
  host_paths="$scan_work/host-paths"
  git_objects="$scan_work/git-objects"
  git_object_contents="$scan_work/git-object-contents"
  if ! find -P /work "$output_path" "$lessons_path" -print0 > "$host_paths"; then
    incomplete=1
  fi
  while IFS= read -r -d '' path; do
    grep_status=0
    printf '%s' "$path" | grep -F -q -f "$token_pattern_file" || grep_status=$?
    if (( grep_status == 0 )); then
      found=1
    elif (( grep_status != 1 )); then
      incomplete=1
    fi
    if [[ -f "$path" && ! -L "$path" ]]; then
      grep_status=0
      grep -F -q -f "$token_pattern_file" -- "$path" 2>/dev/null || grep_status=$?
      if (( grep_status == 0 )); then
        found=1
      elif (( grep_status != 1 )); then
        incomplete=1
      fi
    elif [[ -L "$path" ]]; then
      grep_status=0
      readlink -- "$path" | grep -F -q -f "$token_pattern_file" || grep_status=$?
      if (( grep_status == 0 )); then
        found=1
      elif (( grep_status != 1 )); then
        incomplete=1
      fi
    elif [[ ! -d "$path" ]]; then
      incomplete=1
    fi
  done < "$host_paths"
  for path in "$events_path" "$stderr_path"; do
    [[ -e "$path" ]] || continue
    if [[ ! -f "$path" || -L "$path" ]]; then
      incomplete=1
      continue
    fi
    grep_status=0
    grep -F -q -f "$token_pattern_file" -- "$path" 2>/dev/null || grep_status=$?
    if (( grep_status == 0 )); then
      found=1
    elif (( grep_status != 1 )); then
      incomplete=1
    fi
  done
  if [[ ! -d "$repo_path/.git" || -L "$repo_path/.git" ]]; then
    incomplete=1
  else
    rm -f -- "$repo_path/.git/config" "$repo_path/.git/config.worktree" || incomplete=1
    if ! printf '%s\n' '[core]' 'repositoryformatversion = 0' 'filemode = true' \
      'bare = false' 'logallrefupdates = true' 'hooksPath = /dev/null' \
      'fsmonitor = false' > "$repo_path/.git/config"; then
      incomplete=1
    elif ! execution_git -C "$repo_path" cat-file --batch-all-objects \
      --batch-check='%(objectname) %(objecttype)' > "$git_objects"; then
      incomplete=1
    else
      while IFS=' ' read -r oid type; do
        case "$type" in
          blob|commit|tag|tree)
            if ! execution_git -C "$repo_path" cat-file "$type" "$oid" > "$git_object_contents" 2>/dev/null; then
              incomplete=1
              continue
            fi
            grep_status=0
            grep -F -q -f "$token_pattern_file" -- "$git_object_contents" || grep_status=$?
            if (( grep_status == 0 )); then
              found=1
            elif (( grep_status != 1 )); then
              incomplete=1
            fi
            ;;
          '') ;;
          *) incomplete=1 ;;
        esac
      done < "$git_objects"
    fi
  fi
  (( found == 0 )) || result=1
  if (( result == 0 && incomplete != 0 )); then
    result=2
  fi
  rm -rf -- "$scan_work" 2>/dev/null || result=2
  return "$result"
}

require_clean_token_scan() {
  local scan_status=0
  scan_for_token_contamination || scan_status=$?
  if (( scan_status == 1 )); then
    contamination_detected=1
    record_scan_failure contamination || true
    fail 'exact task credential detected in Codex-controlled work or output'
  fi
  if (( scan_status != 0 )); then
    scan_incomplete=1
    record_scan_failure incomplete || true
    fail 'task-credential scan was incomplete'
  fi
}

invoke_codex() {
  codex exec --ephemeral --json --model "$AGENT_MODEL" \
    -c "model_reasoning_effort=\"$AGENT_REASONING_EFFORT\"" \
    --dangerously-bypass-approvals-and-sandbox --skip-git-repo-check -C "$repo_path" \
    -o "$output_path/codex-final.txt" "$(cat "$prompt_path")" > "$events_path" 2> "$stderr_path" 9<&-
}

invoke_validation() {
  (cd "$repo_path" && mise run "$AGENT_VERIFY_TASK") > "$execution_path/verify.txt" 2>&1
}

write_codex_failure_diagnostic() {
  local codex_status=$1 failure_events_path=$2 failure_stderr_path=$3 failure_path=$4
  local diagnostic='' diagnostic_size=0 source='none'
  local events_size=0 stderr_size=0 events_sha stderr_sha result_temp
  mkdir -p "$(dirname "$failure_path")"
  result_temp="${failure_path}.tmp"
  [[ ! -e "$failure_events_path" ]] || events_size=$(file_size "$failure_events_path")
  [[ ! -e "$failure_stderr_path" ]] || stderr_size=$(file_size "$failure_stderr_path")
  events_sha=$(sha256sum "$failure_events_path" 2>/dev/null | cut -d' ' -f1 || true)
  stderr_sha=$(sha256sum "$failure_stderr_path" 2>/dev/null | cut -d' ' -f1 || true)
  if (( events_size <= codex_events_limit )) && [[ -s "$failure_events_path" ]]; then
    diagnostic=$(jq -jrs '
      [ .[] |
        if .type == "turn.failed" then .error.message?
        elif .type == "error" then (.message? // .error.message?)
        else empty end |
        select(type == "string" and length > 0)
      ] | last // empty
    ' "$failure_events_path" 2>/dev/null || true)
    if [[ -n "$diagnostic" ]]; then source='event'; fi
  fi
  if [[ -z "$diagnostic" && -s "$failure_stderr_path" ]] &&
    (( stderr_size <= failure_diagnostic_limit )) &&
    iconv -f UTF-8 -t UTF-8 "$failure_stderr_path" >/dev/null 2>&1; then
    diagnostic=$(sed -e 's/[[:space:]]*$//' "$failure_stderr_path")
    if [[ -n "$diagnostic" ]]; then source='stderr'; fi
  fi
  diagnostic_size=$(printf '%s' "$diagnostic" | wc -c)
  if (( diagnostic_size > failure_diagnostic_limit )); then
    diagnostic='Codex emitted an operational failure diagnostic that exceeded the complete-output bound'
    source='oversize'
  elif [[ -z "$diagnostic" ]]; then
    if (( events_size > codex_events_limit || stderr_size > failure_diagnostic_limit )); then
      diagnostic='Codex failure output exceeded its complete-output bound'
      source='oversize'
    else
      diagnostic='Codex exited without a usable operational failure diagnostic'
    fi
  fi
  jq -n --arg run "$AGENT_RUN_ID" --arg repo "$AGENT_REPO" --arg branch "$AGENT_BRANCH" \
    --arg source "$source" --arg diagnostic "$diagnostic" --arg events_sha "$events_sha" \
    --arg stderr_sha "$stderr_sha" --argjson exit_code "$codex_status" \
    --argjson events_size "$events_size" --argjson stderr_size "$stderr_size" \
    '{version:"codex-execution-failure/v1",status:"failed",run_id:$run,repository:$repo,
      branch:$branch,stage:"codex",exit_code:$exit_code,diagnostic_source:$source,
      diagnostic:$diagnostic,events_size_bytes:$events_size,events_sha256:$events_sha,
      stderr_size_bytes:$stderr_size,stderr_sha256:$stderr_sha}' > "$result_temp"
  (( $(file_size "$result_temp") <= 8192 )) || fail 'Codex failure projection exceeded bound'
  mv -f -- "$result_temp" "$failure_path"
  chmod 0444 "$failure_path"
}

run_codex_and_scan() {
  local codex_status=0
  invoke_codex || codex_status=$?
  require_clean_token_scan
  if (( codex_status != 0 )); then
    write_codex_failure_diagnostic "$codex_status" "$events_path" "$stderr_path" \
      "$execution_path/execution-failure.json"
    require_clean_token_scan
    fail "Codex repository task exited with status ${codex_status}"
  fi
}

run_validation_and_scan() {
  local validation_status=0
  invoke_validation || validation_status=$?
  require_clean_token_scan
  (( validation_status == 0 )) || fail "repository validation exited with status ${validation_status}"
}

build_prompt() {
  {
    printf '# Implementation Task\n\n'; cat /input/task.md
    printf '\n# Authoritative Issue Context\n\n'; cat /work/prepared/issue-context.md
    if [[ -f /work/prepared/ci-observation.json ]]; then
      printf '\n# Authoritative CI Observation\n\n'; cat /work/prepared/ci-observation.json
      for log in /work/prepared/actions-logs/*.json; do
        [[ -f "$log" ]] || continue
        printf '\n# Failed Actions Job Log\n\n'; jq -r .text "$log"
      done
    fi
    printf '\n# Execution Contract\n\n'
    printf '%s\n' '- Work only in this prepared repository checkout.'
    printf '%s\n' '- Do not push, create a pull request, or contact GitHub; a separate deterministic container owns delivery.'
    printf '%s\n' '- Do not create commits or refs. Leave only working-tree changes.'
    printf '%s\n' '- Web search, plugins, MCP, updates, analytics, and general internet are disabled.'
  } > "$prompt_path"
}

write_execution_result() {
  local temp_index="$scan_dir/index" diff_temp="$execution_path/diff.patch.tmp" tree
  local result_temp="$execution_path/execution.json.tmp" final_size
  mkdir -p "$execution_path"
  GIT_INDEX_FILE="$temp_index" git -C "$repo_path" read-tree HEAD
  GIT_INDEX_FILE="$temp_index" git -C "$repo_path" -c core.hooksPath=/dev/null add --all
  GIT_INDEX_FILE="$temp_index" git -C "$repo_path" diff --cached --binary HEAD > "$diff_temp"
  (( $(stat -c %s "$diff_temp") <= execution_diff_limit )) || fail 'Codex diff exceeded bounded execution limit'
  mv -f -- "$diff_temp" "$execution_path/diff.patch"
  tree=$(GIT_INDEX_FILE="$temp_index" git -C "$repo_path" write-tree)
  final_size=$(stat -c %s "$output_path/codex-final.txt")
  jq -n --arg run "$AGENT_RUN_ID" --arg repo "$AGENT_REPO" --arg branch "$AGENT_BRANCH" \
    --arg head "$(cat "$scan_dir/head")" \
    --arg refs "$(sha256sum "$scan_dir/refs" | cut -d' ' -f1)" \
    --arg diff "$(sha256sum "$execution_path/diff.patch" | cut -d' ' -f1)" --arg tree "$tree" \
    --arg final "$(sha256sum "$output_path/codex-final.txt" | cut -d' ' -f1)" \
    --arg verify "$(sha256sum "$execution_path/verify.txt" | cut -d' ' -f1)" \
    --argjson final_size "$final_size" \
    '{version:"codex-execution-result/v1",status:"executed",run_id:$run,repository:$repo,
      branch:$branch,workspace_head:$head,refs_sha256:$refs,diff_sha256:$diff,validated_tree_sha:$tree,final_sha256:$final,
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
  run_codex_and_scan
  verify_git_identity
  [[ -s "$output_path/codex-final.txt" ]] || fail 'Codex final output is missing or empty'
  (( $(stat -c %s "$output_path/codex-final.txt") <= final_output_limit )) ||
    fail "Codex final output exceeds ${final_output_limit}-byte complete-output limit"
  iconv -f UTF-8 -t UTF-8 "$output_path/codex-final.txt" >/dev/null ||
    fail 'Codex final output is not valid UTF-8'
  (( $(stat -c %s "$events_path") <= codex_events_limit )) || fail 'Codex event stream exceeded bounded limit'
  extract_usage
  require_clean_token_scan
  mkdir -p "$execution_path"
  stage='repository validation'
  run_validation_and_scan
  (( $(stat -c %s "$execution_path/verify.txt") <= verification_output_limit )) ||
    fail 'repository validation output exceeded bounded limit'
  verify_git_identity
  require_clean_token_scan
  write_execution_result
  require_clean_token_scan
  stage='executed'
fi
