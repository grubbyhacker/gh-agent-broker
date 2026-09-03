#!/usr/bin/env bash
set -euo pipefail

readonly worker_name='agent-codex-delivery-worker'
readonly worker_result_lib_path="${WORKER_RESULT_LIB_PATH:-/usr/local/lib/agent-worker-result.sh}"
readonly worker_result_worker='codex'
readonly delivery_output_path="${CODEX_DELIVERY_OUTPUT_PATH:-/output}"
stage='initializing'
verification_status='not_run'
manifest_status='match'
readonly repair_recovery_limit=1

if [[ -r "$worker_result_lib_path" ]]; then
  source "$worker_result_lib_path"
else
  source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/result.sh"
fi
fail() { printf '%s: %s\n' "$worker_name" "$*" >&2; exit 1; }
require_env() { [[ -n "${!1:-}" ]] || fail "missing required environment variable: $1"; }
trusted_git() {
  local -a git_environment=(
    "PATH=$PATH" HOME=/nonexistent LANG=C LC_ALL=C GIT_CONFIG_NOSYSTEM=1
    GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null GIT_OPTIONAL_LOCKS=0
    GIT_TERMINAL_PROMPT=0 GIT_ASKPASS=/bin/false SSH_ASKPASS=/bin/false
    GIT_PAGER=cat PAGER=cat GIT_EDITOR=/bin/false GIT_SEQUENCE_EDITOR=/bin/false
    "BROKER_AGENT_ID=$BROKER_AGENT_ID" "BROKER_AGENT_SECRET=$BROKER_AGENT_SECRET"
    "BROKER_URL=$BROKER_URL"
  )
  [[ -z "${GIT_INDEX_FILE:-}" ]] || git_environment+=("GIT_INDEX_FILE=$GIT_INDEX_FILE")
  env -i "${git_environment[@]}" git --no-optional-locks \
    -c core.hooksPath=/dev/null -c core.fsmonitor=false -c core.pager=cat "$@"
}
trusted_broker_configure() {
  env -i PATH="$PATH" HOME=/nonexistent LANG=C LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
    GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null GIT_OPTIONAL_LOCKS=0 \
    GIT_TERMINAL_PROMPT=0 GIT_ASKPASS=/bin/false SSH_ASKPASS=/bin/false \
    GIT_PAGER=cat PAGER=cat GIT_EDITOR=/bin/false GIT_SEQUENCE_EDITOR=/bin/false \
    BROKER_AGENT_ID="$BROKER_AGENT_ID" BROKER_AGENT_SECRET="$BROKER_AGENT_SECRET" \
    BROKER_URL="$BROKER_URL" gh-agent-broker-cli configure \
    -broker "$BROKER_URL" -repo "$AGENT_REPO" -remote origin
}

on_exit() {
  local status=$?
  trap - EXIT
  if (( status != 0 )); then
    write_result failed "delivery failed during $stage" || true
    printf 'Deterministic Codex delivery failed during %s.\n' "$stage" > /output/final-summary.md
  fi
  exit "$status"
}

reject_codex_authority() {
  local name _
  while IFS='=' read -r name _; do
    case "$name" in
      OPENAI_*|CODEX_*|AGENT_MODEL|AGENT_REASONING_EFFORT)
        fail "Codex authority is forbidden during delivery: $name" ;;
    esac
  done < <(env)
  for path in /run/codex-issuance /dev/shm/codex-credential-injection; do
    [[ ! -e "$path" ]] || fail "Codex holder or relay artifact is visible during delivery: $path"
  done
}

validate_results() {
  jq -e --arg run "$AGENT_RUN_ID" --arg repo "$AGENT_REPO" --arg branch "$AGENT_BRANCH" '
    .version == "codex-preparation-result/v1" and .status == "prepared" and
    .run_id == $run and .repository == $repo and .branch == $branch and
    (.workspace_head | test("^[a-f0-9]{40}$")) and (.refs_sha256 | test("^[a-f0-9]{64}$"))
  ' /work/prepared/preparation.json >/dev/null || fail 'preparation result is invalid'
  jq -e --arg run "$AGENT_RUN_ID" --arg repo "$AGENT_REPO" --arg branch "$AGENT_BRANCH" \
    --arg head "$(jq -r .workspace_head /work/prepared/preparation.json)" '
    .version == "codex-execution-result/v1" and .status == "executed" and
    .run_id == $run and .repository == $repo and .branch == $branch and .workspace_head == $head and
    (.refs_sha256 | test("^[a-f0-9]{64}$")) and
    (.diff_sha256 | test("^[a-f0-9]{64}$")) and (.final_sha256 | test("^[a-f0-9]{64}$")) and
    (.validated_tree_sha | test("^[a-f0-9]{40}$")) and
    .verification == "passed" and (.verify_sha256 | test("^[a-f0-9]{64}$")) and
    (.final_size_bytes | type == "number" and . > 0 and . <= 1048576)
  ' /work/execution/execution.json >/dev/null || fail 'execution result is invalid'
  [[ "$(sha256sum /work/execution/diff.patch | cut -d' ' -f1)" == "$(jq -r .diff_sha256 /work/execution/execution.json)" ]] ||
    fail 'execution diff digest mismatch'
  [[ "$(sha256sum /output/codex-final.txt | cut -d' ' -f1)" == "$(jq -r .final_sha256 /work/execution/execution.json)" ]] ||
    fail 'execution final-output digest mismatch'
  [[ "$(sha256sum /work/execution/verify.txt | cut -d' ' -f1)" == "$(jq -r .verify_sha256 /work/execution/execution.json)" ]] ||
    fail 'execution validation digest mismatch'
}

seal_repository_git_config() {
  local repository=$1 git_dir="$1/.git"
  [[ -d "$repository" && ! -L "$repository" && -d "$git_dir" && ! -L "$git_dir" &&
    -f "$git_dir/HEAD" && ! -L "$git_dir/HEAD" ]] ||
    fail 'workspace Git directory or HEAD is not an ordinary trusted path'
  rm -f -- "$git_dir/config" "$git_dir/config.worktree"
  rm -rf -- "$git_dir/hooks"
  install -d -m 0700 "$git_dir/hooks"
  trusted_git config --file "$git_dir/config" core.repositoryformatversion 0
  trusted_git config --file "$git_dir/config" core.filemode true
  trusted_git config --file "$git_dir/config" core.bare false
  trusted_git config --file "$git_dir/config" core.logallrefupdates true
  trusted_git config --file "$git_dir/config" core.hooksPath /dev/null
  trusted_git config --file "$git_dir/config" core.fsmonitor false
  trusted_git config --file "$git_dir/config" user.name 'Codex Repository Task Worker'
  trusted_git config --file "$git_dir/config" user.email 'codex-repository-task-worker@invalid'
  chmod 0600 "$git_dir/config"
}

restore_repository_authority() {
  local expected_head git_dir expected_git_dir current_refs
  expected_head=$(jq -r .workspace_head /work/prepared/preparation.json)
  seal_repository_git_config /work/repo
  git_dir=$(trusted_git -C /work/repo rev-parse --absolute-git-dir)
  expected_git_dir="$(cd /work/repo && pwd -P)/.git"
  [[ "$git_dir" == "$expected_git_dir" && -d "$git_dir" && ! -L "$git_dir" &&
    -f "$git_dir/HEAD" && ! -L "$git_dir/HEAD" ]] ||
    fail 'workspace Git directory or HEAD is not an ordinary trusted path'
  [[ "$(trusted_git -C /work/repo rev-parse HEAD)" == "$expected_head" ]] || fail 'workspace HEAD changed after preparation'
  [[ "$(trusted_git -C /work/repo symbolic-ref --short HEAD)" == "$AGENT_BRANCH" ]] || fail 'workspace branch changed after preparation'
  current_refs=$(trusted_git -C /work/repo for-each-ref --format='%(refname) %(objectname) %(symref)' | LC_ALL=C sort | sha256sum | cut -d' ' -f1)
  [[ "$current_refs" == "$(jq -r .refs_sha256 /work/prepared/preparation.json)" &&
    "$current_refs" == "$(jq -r .refs_sha256 /work/execution/execution.json)" ]] ||
    fail 'workspace refs changed after preparation'
  rm -f -- /work/repo/.git/index /work/repo/.git/index.lock
  trusted_git -C /work/repo read-tree "$expected_head"
  trusted_git -C /work/repo remote add origin placeholder
  (cd /work/repo && trusted_broker_configure) > /output/broker-remote.txt
  [[ "$(trusted_git -C /work/repo rev-parse HEAD)" == "$expected_head" ]] || fail 'broker configuration changed workspace HEAD'
  local regenerated=/work/execution/delivery-diff.patch
  local temp_index=/tmp/codex-delivery-index
  GIT_INDEX_FILE="$temp_index" trusted_git -C /work/repo read-tree HEAD
  GIT_INDEX_FILE="$temp_index" trusted_git -C /work/repo add --all
  GIT_INDEX_FILE="$temp_index" trusted_git -C /work/repo diff --no-ext-diff --cached --binary HEAD > "$regenerated"
  cmp -s "$regenerated" /work/execution/diff.patch || fail 'workspace diff no longer matches execution result'
  rm -f -- "$regenerated" "$temp_index"
}

repair_target() {
  [[ -f /work/prepared/repair.json ]] || return 1
  jq -e '
    (.pull_number | type == "number" and . > 0) and
    (.head_ref | type == "string" and length > 0) and
    (.expected_head_sha | type == "string" and test("^[a-f0-9]{40}$"))
  ' /work/prepared/repair.json >/dev/null || fail 'repair target is invalid'
}

verify_validated_candidate_tree() {
  local tree
  tree=$(trusted_git -C /work/repo rev-parse 'HEAD^{tree}')
  [[ "$tree" == "$(jq -r .validated_tree_sha /work/execution/execution.json)" ]] ||
    fail 'delivered candidate tree differs from the tree that passed final validation'
}

# A lease race is recovered inside this already-authorized deterministic
# delivery. The model is never invoked again: we apply its sealed diff to the
# winning head, re-run the reviewed validation, bind a new tree provenance, and
# make exactly one new exact-lease attempt.
recover_stale_repair_lease() {
  local repair_head=$1 winner tree
  stage='stale repair lease recovery'
  trusted_git fetch --quiet origin "refs/heads/${repair_head}"
  winner=$(trusted_git rev-parse FETCH_HEAD)
  [[ "$winner" =~ ^[a-f0-9]{40}$ ]] || fail 'stale repair winner head is invalid'
  trusted_git reset --hard --quiet "$winner"
  trusted_git apply --index --whitespace=nowarn /work/execution/diff.patch ||
    fail 'stale repair candidate cannot be integrated with winning head'
  stage='stale repair final validation'
  (cd /work/repo && env -u BROKER_AGENT_ID -u BROKER_AGENT_SECRET -u BROKER_URL mise run "$AGENT_VERIFY_TASK") > /work/execution/stale-recovery-verify.txt 2>&1 ||
    fail 'integrated stale repair candidate failed reviewed final validation'
  tree=$(trusted_git write-tree)
  [[ "$tree" =~ ^[a-f0-9]{40}$ ]] || fail 'integrated stale repair tree is invalid'
  validated_tree_sha="$tree"
  trusted_git commit --quiet -m "Implement Codex issue task ${AGENT_RUN_ID} (stale-lease recovery)"
  [[ "$(trusted_git rev-parse 'HEAD^{tree}')" == "$validated_tree_sha" ]] ||
    fail 'integrated repair commit tree differs from revalidated tree'
  stage='stale repair leased retry'
  trusted_git push --quiet --force-with-lease="refs/heads/${repair_head}:${winner}" \
    origin "HEAD:refs/heads/${repair_head}" || fail 'stale repair leased retry was rejected'
}

reconcile_pull_request() {
  local marker=$1 list="$delivery_output_path/pull-request-reconcile.json" count
  gh-agent-broker-cli pulls -broker "$BROKER_URL" -repo "$AGENT_REPO" -state all \
    -head-prefix "$AGENT_BRANCH" -body-marker "$marker" > "$list"
  jq --arg head "$AGENT_BRANCH" --arg base "$AGENT_BASE_BRANCH" --arg marker "$marker" \
    '[.[] | select(.head_ref == $head and .base_ref == $base and (.body | contains($marker)))]' \
    "$list" > "$list.exact"
  mv -f -- "$list.exact" "$list"
  count=$(jq 'length' "$list")
  (( count <= 1 )) || fail 'multiple pull requests match the exact run marker and head branch'
  if (( count == 1 )); then
    jq '.[0]' "$list" > "$delivery_output_path/pull-request.json"
    return 0
  fi
  return 1
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  for name in BROKER_URL BROKER_AGENT_ID BROKER_AGENT_SECRET AGENT_REPO AGENT_BASE_BRANCH \
    AGENT_BRANCH AGENT_RUN_ID; do require_env "$name"; done
  trap on_exit EXIT
  [[ "$delivery_output_path" == /output ]] || fail 'delivery output path is fixed by the reviewed template'
  reject_codex_authority
  validate_results
  restore_repository_authority
  verification_status='passed'
  cd /work/repo
  if trusted_git diff --no-ext-diff --quiet &&
    trusted_git diff --no-ext-diff --cached --quiet &&
    [[ -z "$(trusted_git status --porcelain)" ]]; then
    stage='completed without changes'
    write_result no_change_required 'Codex determined that the issue requires no repository change'
    cp /output/codex-final.txt /output/final-summary.md
    exit 0
  fi
  stage='commit and push'
  trusted_git add --all
  trusted_git commit --quiet -m "Implement Codex issue task ${AGENT_RUN_ID}"
  verify_validated_candidate_tree
  validated_tree_sha=$(jq -r .validated_tree_sha /work/execution/execution.json)
  if repair_target; then
    repair_head=$(jq -r .head_ref /work/prepared/repair.json)
    expected_head=$(jq -r .expected_head_sha /work/prepared/repair.json)
    stage='leased repair push'
    if ! trusted_git push --quiet --force-with-lease="refs/heads/${repair_head}:${expected_head}" \
      origin "HEAD:refs/heads/${repair_head}"; then
      (( repair_recovery_limit == 1 )) || fail 'stale repair recovery bound is invalid'
      recover_stale_repair_lease "$repair_head"
    fi
    delivered_head_sha=$(trusted_git rev-parse HEAD)
    delivered_branch="$repair_head"
    pull_request=$(jq '{number,html_url,url}' /work/prepared/pull.json)
    stage='completed repair'
    write_result ready_for_review 'Codex CI repair was delivered to the existing pull request after validation of the exact candidate tree' "$pull_request"
    cp /output/codex-final.txt /output/final-summary.md
    exit 0
  fi
  trusted_git push --quiet origin "HEAD:${AGENT_BRANCH}"
  delivered_head_sha=$(trusted_git rev-parse HEAD)
  delivered_branch="$AGENT_BRANCH"
  marker="<!-- gh-agent-broker-codex-run:${AGENT_RUN_ID} -->"
  stage='pull request reconciliation'
  if ! reconcile_pull_request "$marker"; then
    pr_title="${AGENT_PR_TITLE:-Codex issue implementation}"
    pr_body="${AGENT_PR_BODY:-Codex issue task completed for run ${AGENT_RUN_ID}.}"
    pr_body="${pr_body}"$'\n\n'"${marker}"
    stage='pull request creation'
    if ! gh-agent-broker-cli pr -broker "$BROKER_URL" -repo "$AGENT_REPO" -title "$pr_title" \
      -head "$AGENT_BRANCH" -base "$AGENT_BASE_BRANCH" -body "$pr_body" \
      -metadata "Agent-Id=${BROKER_AGENT_ID}" -metadata "Run-Id=${AGENT_RUN_ID}" \
      > /output/pull-request.json; then
      stage='ambiguous pull request reconciliation'
      reconcile_pull_request "$marker" || fail 'pull request creation failed and exact reconciliation found no match'
    fi
  fi
  pull_request=$(read_pull_request) || fail 'broker pull request response is invalid'
  stage='completed'
  write_result ready_for_review 'Codex changes were deterministically delivered in a ready pull request' "$pull_request"
  cp /output/codex-final.txt /output/final-summary.md
fi
