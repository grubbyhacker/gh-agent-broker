#!/usr/bin/env bash
set -euo pipefail

readonly worker_name='agent-codex-repo-prep-worker'
readonly dependency_manifest_path="${AGENT_IMAGE_DEPENDENCY_MANIFEST_PATH:-/usr/local/share/agent-image/dependency-manifest.sha256}"
readonly baked_workspace_path="${AGENT_IMAGE_WORKSPACE:-/workspace}"
readonly issue_context_byte_limit=24576
readonly issue_comment_limit=30
stage='initializing'

fail() { printf '%s: %s\n' "$worker_name" "$*" >&2; exit 1; }
require_env() { [[ -n "${!1:-}" ]] || fail "missing required environment variable: $1"; }

on_exit() {
  local status=$?
  trap - EXIT
  if (( status != 0 )); then
    printf '{"version":"codex-preparation-result/v1","status":"failed","stage":%q}\n' "$stage" > /output/preparation-failed.txt
  fi
  exit "$status"
}

reject_credentials() {
  local name _
  while IFS='=' read -r name _; do
    case "$name" in
      OPENAI_*|CODEX_HOME) fail "credential-bearing environment is forbidden during preparation: $name" ;;
    esac
  done < <(env)
  for path in /credentials /run/codex-issuance /input/auth.json /opt/data/auth.json; do
    [[ ! -e "$path" ]] || fail "credential path is visible during preparation: $path"
  done
}

validate_contract() {
  jq -e --arg run "$AGENT_RUN_ID" --arg repo "$AGENT_REPO" '
    .run_id == $run and .repo == $repo and
    (.parameters.issue_number | type == "number" and floor == . and . > 0) and
    (.parameters.source_delivery_id | type == "string" and test("^[A-Za-z0-9-]{1,128}$"))
  ' /input/task.json >/dev/null || fail 'typed issue task contract is invalid'
}

collect_submodule_manifest_entries() {
  local entry metadata path mode sha
  while IFS= read -r -d '' entry; do
    metadata="${entry%%$'\t'*}"
    path="${entry#*$'\t'}"
    mode="${metadata%% *}"
    [[ "$mode" == '160000' ]] || continue
    sha="${metadata#* }"; sha="${sha%% *}"
    printf 'submodule %s %s\n' "$sha" "$path"
  done < <(git ls-files --stage -z)
}

collect_dependency_inputs() {
  local path
  for path in mise.toml package.json go.mod pyproject.toml Cargo.toml \
    package-lock.json pnpm-lock.yaml yarn.lock bun.lock bun.lockb uv.lock poetry.lock Pipfile.lock go.sum Cargo.lock Gemfile.lock; do
    git ls-files --error-unmatch -- "$path" >/dev/null 2>&1 && sha256sum "$path"
  done
  while IFS= read -r path; do
    case "$path" in
      requirements*.txt) sha256sum "$path" ;;
      */*lock*|*lock*.json|*lock*.yaml|*lock*.yml|*Lock*|*/requirements*.txt)
        fail "unsupported nested dependency input: $path" ;;
    esac
  done < <(git ls-files)
  collect_submodule_manifest_entries
}

hydrate_baked_submodules() {
  local entry metadata path mode baked_path
  while IFS= read -r -d '' entry; do
    metadata="${entry%%$'\t'*}"
    path="${entry#*$'\t'}"
    mode="${metadata%% *}"
    [[ "$mode" == '160000' ]] || continue
    [[ "$path" != /* && "$path" != *'..'* ]] || fail "unsafe submodule path: $path"
    baked_path="$baked_workspace_path/$path"
    [[ -d "$baked_path" ]] || fail "stale image: baked submodule content is missing for $path"
    rm -rf -- "$path"
    mkdir -p "$path"
    cp -a "$baked_path/." "$path/"
  done < <(git ls-files --stage -z)
}

verify_baked_manifest() {
  local baked current
  git ls-files --error-unmatch -- mise.toml >/dev/null 2>&1 || fail 'stale image: tracked mise.toml is required'
  [[ -f "$dependency_manifest_path" ]] || fail 'stale image: baked dependency manifest is missing'
  IFS= read -r baked < "$dependency_manifest_path"
  [[ "$baked" =~ ^[a-f0-9]{64}$ ]] || fail 'stale image: baked dependency manifest is invalid'
  current=$({ collect_dependency_inputs; } | LC_ALL=C sort | sha256sum | cut -d' ' -f1)
  [[ "$current" == "$baked" ]] || fail "stale image: dependency/submodule manifest mismatch"
  hydrate_baked_submodules
  printf '%s\n' "$current"
}

# Named helpers are kept sourceable for the shared submodule regression test.
compute_dependency_manifest() {
  { collect_dependency_inputs; } | LC_ALL=C sort | sha256sum | cut -d' ' -f1
}

check_dependency_manifest() {
  local baked current
  manifest_status='missing'
  [[ -f "$dependency_manifest_path" ]] || fail 'stale image: baked dependency manifest is missing'
  IFS= read -r baked < "$dependency_manifest_path"
  current=$(compute_dependency_manifest)
  if [[ "$current" != "$baked" ]]; then
    fail 'baked submodule SHA does not match the checkout; rebuild the agent image before running this worker'
  fi
  hydrate_baked_submodules
  manifest_status='match'
}

ingest_issue() {
  local issue_number
  issue_number=$(jq -r '.parameters.issue_number' /input/task.json)
  gh-agent-broker-cli issue -broker "$BROKER_URL" -repo "$AGENT_REPO" -number "$issue_number" > /work/prepared/issue.json
  gh-agent-broker-cli issue-comments -broker "$BROKER_URL" -repo "$AGENT_REPO" -number "$issue_number" > /work/prepared/comments.json
  jq -e '
    type == "object" and .is_pull_request != true and .state == "open" and
    (.number | type == "number" and . > 0) and (.title | type == "string" and length > 0) and
    (.body == null or (.body | type == "string"))
  ' /work/prepared/issue.json >/dev/null || fail 'typed issue resolved to a closed, pull-request, or malformed object'
  jq -e --argjson limit "$issue_comment_limit" '
    type == "array" and length <= $limit and
    all(.[]; type == "object" and (.id | type == "number") and
      (.body == null or (.body | type == "string")) and
      (.author == null or (.author | type == "string")))
  ' /work/prepared/comments.json >/dev/null || fail 'typed issue comments exceed the current bounded DTO contract'
  jq -nr --argfile issue /work/prepared/issue.json --slurpfile comments /work/prepared/comments.json '
    ["# Authoritative GitHub Issue", "",
     ("Issue: #" + ($issue.number|tostring) + " — " + $issue.title), "",
     "## Body", "", ($issue.body // "[no issue body]")] +
    [ $comments[0][] | "", ("## Comment from " + (.author // "unknown")), "", (.body // "") ] |
    join("\n") + "\n"
  ' > /work/prepared/issue-context.md
  local bytes
  bytes=$(stat -c %s /work/prepared/issue-context.md)
  (( bytes <= issue_context_byte_limit )) || fail "issue body/comments exceed ${issue_context_byte_limit}-byte input limit"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  require_env BROKER_URL
  require_env AGENT_REPO
  require_env AGENT_BASE_BRANCH
  require_env AGENT_BRANCH
  require_env AGENT_RUN_ID
  trap on_exit EXIT
  reject_credentials
  validate_contract
  mkdir -p /work/repo /work/prepared /output

  stage='broker-mediated checkout'
  cd /work/repo
  git init --quiet
  git check-ref-format --branch "$AGENT_BASE_BRANCH" >/dev/null || fail 'invalid base branch'
  git remote add origin placeholder
  gh-agent-broker-cli configure -broker "$BROKER_URL" -repo "$AGENT_REPO" -remote origin > /output/broker-remote.txt
  git fetch --quiet origin "$AGENT_BASE_BRANCH"
  git checkout --quiet -B "$AGENT_BRANCH" FETCH_HEAD
  git config user.name "${GIT_AUTHOR_NAME:-Codex Repository Task Worker}"
  git config user.email "${GIT_AUTHOR_EMAIL:-codex-repo-task-worker@users.noreply.github.com}"

  stage='typed issue ingestion'
  ingest_issue

  stage='baked dependency and submodule verification'
  manifest=$(verify_baked_manifest)
  workspace_head=$(git rev-parse HEAD)
  source_delivery_id=$(jq -r '.parameters.source_delivery_id' /input/task.json)
  issue_number=$(jq -r '.parameters.issue_number' /input/task.json)
  jq -n \
    --arg run_id "$AGENT_RUN_ID" --arg repo "$AGENT_REPO" --arg branch "$AGENT_BRANCH" \
    --arg head "$workspace_head" --arg manifest "$manifest" --arg source_delivery_id "$source_delivery_id" \
    --argjson issue_number "$issue_number" \
    '{version:"codex-preparation-result/v1",status:"prepared",run_id:$run_id,repository:$repo,
      branch:$branch,workspace_head:$head,manifest_sha256:$manifest,issue_number:$issue_number,
      source_delivery_id:$source_delivery_id}' > /work/prepared/preparation.json
  chmod 0444 /work/prepared/preparation.json /work/prepared/issue-context.md
  stage='prepared'
fi
