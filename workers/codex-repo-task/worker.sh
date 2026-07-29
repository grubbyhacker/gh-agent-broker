#!/usr/bin/env bash
set -euo pipefail

readonly worker_name='agent-codex-repo-task-worker'
readonly dependency_manifest_path='/usr/local/share/agent-image/dependency-manifest.sha256'
readonly credential_bundle_path='/credentials/codex/auth.json'
readonly codex_home_base='/dev/shm/codex-home'
readonly token_expiry_margin_seconds=300
stage='initializing'

fail() { printf '%s: %s\n' "$worker_name" "$*" >&2; exit 1; }
require_env() { [[ -n "${!1:-}" ]] || fail "missing required environment variable: $1"; }

write_result() {
  local outcome="$1" detail="$2"
  mise exec -- jq -n --arg outcome "$outcome" --arg detail "$detail" --arg stage "$stage" \
    --arg run_id "$AGENT_RUN_ID" --arg repository "$AGENT_REPO" --arg base_branch "$AGENT_BASE_BRANCH" \
    --arg branch "$AGENT_BRANCH" --arg verify_task "${AGENT_VERIFY_TASK:-}" \
    --arg manifest_status "${manifest_status:-not_checked}" \
    '{outcome: $outcome, detail: $detail, stage: $stage, run_id: $run_id, repository: $repository, base_branch: $base_branch, branch: $branch, worker: "codex", verify_task: $verify_task, dependency_manifest: $manifest_status}' \
    > /output/result.json
}

on_exit() {
  local status=$?
  trap - EXIT
  if (( status != 0 )); then
    write_result failed "worker failed during $stage" || true
    printf 'Codex repository task worker failed during %s. See worker logs and /output/result.json.\n' "$stage" > /output/final-summary.md
  fi
  exit "$status"
}

validate_inputs() {
  local value
  for value in "$AGENT_REPO" "$AGENT_BASE_BRANCH" "$AGENT_RUN_ID"; do
    [[ "$value" != *$'\n'* && "$value" != *$'\r'* ]] || fail 'configuration values must not contain line breaks'
  done
  [[ "$AGENT_REPO" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || fail 'AGENT_REPO must be owner/name'
  [[ "$AGENT_RUN_ID" =~ ^[A-Za-z0-9_.:-]+$ ]] || fail 'AGENT_RUN_ID must contain only letters, numbers, dot, underscore, colon, or hyphen'
  if [[ -n "${AGENT_VERIFY_TASK:-}" ]]; then
    [[ "$AGENT_VERIFY_TASK" =~ ^[A-Za-z0-9_.:-]+$ ]] || fail 'AGENT_VERIFY_TASK must be a single mise task name'
  fi
}

validate_credential_sources() {
  local name value path
  while IFS='=' read -r name value; do
    [[ "$name" == OPENAI_* ]] && fail "alternate credential environment variable is visible: $name"
  done < <(mise exec -- env)

  [[ -f "$credential_bundle_path" ]] || fail "missing required credential bundle: $credential_bundle_path"
  if bash -c 'echo should-not-write > /credentials/codex/write-test' 2>/tmp/codex-credential-write.err; then
    fail 'credential bundle is writable'
  fi
  for path in /credentials/auth.json /input/auth.json /opt/data/auth.json; do
    [[ ! -e "$path" ]] || fail "alternate credential material is visible: $path"
  done
  while IFS= read -r path; do
    [[ "$path" == "$credential_bundle_path" ]] || fail "credential bundle is visible at unexpected path: $path"
  done < <(mise exec -- find /credentials -xdev -type f -name auth.json -print)
}

prepare_codex_home() {
  local filesystem_type mode
  filesystem_type=$(mise exec -- stat -f -c %T /dev/shm) || fail '/dev/shm is required for tmpfs-only CODEX_HOME'
  [[ "$filesystem_type" == 'tmpfs' ]] || fail "/dev/shm must be tmpfs, found $filesystem_type"
  CODEX_HOME="${codex_home_base}-${AGENT_RUN_ID}"
  export CODEX_HOME
  mise exec -- mkdir -p "$CODEX_HOME"
  mise exec -- cp "$credential_bundle_path" "$CODEX_HOME/auth.json"
  mise exec -- chmod 0600 "$CODEX_HOME/auth.json"
  mode=$(mise exec -- stat -c %a "$CODEX_HOME/auth.json")
  [[ "$mode" == 600 ]] || fail 'copied Codex credential bundle must have mode 0600'
  export HOME="$CODEX_HOME/home"
  mise exec -- mkdir -p "$HOME"
}

decode_access_token_payload() {
  mise exec -- jq -er '.tokens.access_token | select(type == "string" and length > 0) | split(".") | if length == 3 then .[1] else error("access token is not a JWT") end | gsub("-"; "+") | gsub("_"; "/") | . + ("=" * ((4 - (length % 4)) % 4)) | @base64d' "$1"
}

validate_access_token_expiry() {
  local payload exp now issued_at refresh_token
  refresh_token=$(mise exec -- jq -er '.tokens.refresh_token | if type == "string" and . == "" then . else error("refresh token must be present and empty") end' "$CODEX_HOME/auth.json") || fail 'credential bundle must be access-token-only with an empty refresh token'
  payload=$(decode_access_token_payload "$CODEX_HOME/auth.json") || fail 'credential bundle does not contain a decodable access token'
  exp=$(printf '%s' "$payload" | mise exec -- jq -er '.exp | if type == "number" and floor == . then . else error("JWT exp must be an integer") end') || fail 'access token JWT is missing a valid exp claim'
  issued_at=$(printf '%s' "$payload" | mise exec -- jq -er 'if .iat == null then empty elif (.iat | type) == "number" and (.iat | floor) == .iat then .iat else error("JWT iat must be an integer") end') || fail 'access token JWT has an invalid iat claim'
  now=$(mise exec -- date +%s)
  (( exp > now + token_expiry_margin_seconds )) || fail 'access token is expired or expires too soon to start work'
  printf 'Codex access token current time: %s\n' "$(mise exec -- date -u -d "@$now" '+%Y-%m-%dT%H:%M:%SZ')"
  printf 'Codex access token expiration: %s\n' "$(mise exec -- date -u -d "@$exp" '+%Y-%m-%dT%H:%M:%SZ')"
  if [[ -n "$issued_at" ]]; then
    printf 'Codex access token issued at: %s\n' "$(mise exec -- date -u -d "@$issued_at" '+%Y-%m-%dT%H:%M:%SZ')"
  fi
}

load_prompt() {
  local supplied=0
  [[ -n "${AGENT_CODEX_PROMPT:-}" ]] && ((supplied += 1))
  [[ -n "${AGENT_CODEX_PROMPT_FILE:-}" ]] && ((supplied += 1))
  (( supplied == 1 )) || fail 'set exactly one of AGENT_CODEX_PROMPT or AGENT_CODEX_PROMPT_FILE'
  if [[ -n "${AGENT_CODEX_PROMPT_FILE:-}" ]]; then
    [[ -f "$AGENT_CODEX_PROMPT_FILE" ]] || fail 'AGENT_CODEX_PROMPT_FILE must name a readable regular file'
    codex_task_prompt=$(mise exec -- cat "$AGENT_CODEX_PROMPT_FILE")
  else
    codex_task_prompt="$AGENT_CODEX_PROMPT"
  fi
  [[ -n "$codex_task_prompt" ]] || fail 'Codex task prompt must not be empty'
}

# This matches publish-agent-image.yml for repositories without submodules.
has_submodules() {
  local entry metadata
  while IFS= read -r -d '' entry; do
    metadata="${entry%%$'\t'*}"
    [[ "${metadata%% *}" == '160000' ]] && return 0
  done < <(mise exec -- git ls-files --stage -z)
  return 1
}

collect_lockfiles() {
  local path
  lockfiles=()
  while IFS= read -r path; do
    case "$path" in
      package-lock.json|pnpm-lock.yaml|yarn.lock|bun.lock|bun.lockb|uv.lock|poetry.lock|Pipfile.lock|go.sum|Cargo.lock|Gemfile.lock|requirements*.txt) lockfiles+=("$path") ;;
      */*lock*|*lock*.json|*lock*.yaml|*lock*.yml|*Lock*|*requirements*.txt) fail "unsupported dependency lockfile: $path; extend publish-agent-image.yml before using this worker" ;;
    esac
  done < <(mise exec -- git ls-files)
}

compute_dependency_manifest() {
  local manifest_file
  collect_lockfiles
  manifest_files=()
  for manifest_file in package.json go.mod pyproject.toml Cargo.toml; do
    mise exec -- git ls-files --error-unmatch -- "$manifest_file" >/dev/null 2>&1 && manifest_files+=("$manifest_file")
  done
  {
    mise exec -- sha256sum mise.toml
    for manifest_file in "${lockfiles[@]}"; do mise exec -- sha256sum "$manifest_file"; done
    for manifest_file in "${manifest_files[@]}"; do mise exec -- sha256sum "$manifest_file"; done
  } | LC_ALL=C mise exec -- sort | mise exec -- sha256sum | {
    IFS=' ' read -r manifest_sha _
    printf '%s\n' "$manifest_sha"
  }
}

install_repository_dependencies() {
  local lockfile package_locks=0
  collect_lockfiles
  mise trust --yes mise.toml
  mise install --yes
  for lockfile in package-lock.json pnpm-lock.yaml yarn.lock bun.lock bun.lockb; do [[ -f "$lockfile" ]] && ((package_locks += 1)); done
  (( package_locks <= 1 )) || fail 'more than one JavaScript lockfile is present'
  if [[ -f package-lock.json ]]; then
    [[ -f package.json ]] || fail 'package-lock.json requires package.json'; mise exec -- npm ci
  elif [[ -f pnpm-lock.yaml ]]; then
    [[ -f package.json ]] || fail 'pnpm-lock.yaml requires package.json'; mise exec -- corepack pnpm install --frozen-lockfile
  elif [[ -f bun.lock || -f bun.lockb ]]; then
    [[ -f package.json ]] || fail 'bun lockfiles require package.json'; mise exec -- bun install --frozen-lockfile
  elif [[ -f yarn.lock ]]; then
    fail 'yarn.lock is not supported by publish-agent-image.yml'
  fi
  if [[ -f uv.lock ]]; then [[ -f pyproject.toml ]] || fail 'uv.lock requires pyproject.toml'; mise exec -- uv sync --frozen --no-install-project; fi
  [[ ! -f poetry.lock && ! -f Pipfile.lock && ! -f Gemfile.lock ]] || fail 'unsupported dependency manager lockfile'
  for lockfile in "${lockfiles[@]}"; do
    [[ "$lockfile" == requirements*.txt ]] || continue
    mise exec -- grep -Eq -- '--hash=' "$lockfile" || fail "$lockfile must use pip hashes"
    mise exec -- python -m pip install --require-hashes -r "$lockfile"
  done
  if [[ -f go.sum ]]; then [[ -f go.mod ]] || fail 'go.sum requires go.mod'; mise exec -- go mod download; fi
  if [[ -f Cargo.lock ]]; then [[ -f Cargo.toml ]] || fail 'Cargo.lock requires Cargo.toml'; mise exec -- cargo fetch --locked; fi
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
require_env BROKER_URL
require_env AGENT_REPO
require_env AGENT_BASE_BRANCH
require_env AGENT_RUN_ID
AGENT_BRANCH="agent/contributor/${AGENT_RUN_ID}"
export AGENT_BRANCH
validate_inputs
mise exec -- mkdir -p /work/repo /output
trap on_exit EXIT

stage='credential safety checks'
validate_credential_sources
prepare_codex_home
validate_access_token_expiry
load_prompt

stage='broker health check'
mise exec -- /usr/local/bin/gh-agent-broker-cli health -broker "$BROKER_URL" > /output/broker-health.txt
mise exec -- /usr/local/bin/gh-agent-broker-cli probe -broker "$BROKER_URL" -repo "$AGENT_REPO" > /output/broker-repo-probe.json

stage='broker-mediated checkout'
cd /work/repo
mise exec -- git init --quiet
mise exec -- git check-ref-format --branch "$AGENT_BASE_BRANCH" >/dev/null || fail 'AGENT_BASE_BRANCH must be a valid Git branch name'
mise exec -- git remote add origin placeholder
mise exec -- /usr/local/bin/gh-agent-broker-cli configure -broker "$BROKER_URL" -repo "$AGENT_REPO" -remote origin > /output/broker-remote.txt
mise exec -- git fetch --quiet origin "$AGENT_BASE_BRANCH"
mise exec -- git checkout --quiet -B "$AGENT_BRANCH" FETCH_HEAD
mise exec -- git config user.name "${GIT_AUTHOR_NAME:-Codex Repository Task Worker}"
mise exec -- git config user.email "${GIT_AUTHOR_EMAIL:-codex-repo-task-worker@users.noreply.github.com}"

stage='dependency manifest check'
manifest_status='missing baked manifest'
if [[ -f "$dependency_manifest_path" ]]; then
  IFS= read -r baked_manifest < "$dependency_manifest_path" || true
  if [[ ! "$baked_manifest" =~ ^[a-fA-F0-9]{64}$ ]]; then
    fail "invalid baked dependency manifest hash: $dependency_manifest_path"
  elif has_submodules; then
    manifest_status='unverifiable: checkout contains submodules; reinstalling dependencies'
  else
    current_manifest=$(compute_dependency_manifest)
    if [[ "$current_manifest" == "$baked_manifest" ]]; then
      manifest_status='match'
      printf 'manifest match, using baked dependencies\n' | mise exec -- tee /output/dependency-manifest.txt
    else
      manifest_status="mismatch: baked=$baked_manifest checkout=$current_manifest; reinstalling dependencies"
    fi
  fi
fi
if [[ "$manifest_status" != 'match' ]]; then
  printf 'DEPENDENCY MANIFEST %s\n' "$manifest_status" | mise exec -- tee /output/dependency-manifest.txt
  stage='dependency installation after manifest mismatch'
  install_repository_dependencies
fi

stage='Codex repository task'
codex_prompt=$(printf '%s\n\n%s\n' "$codex_task_prompt" '- Work only in this repository checkout.
- Keep the diff focused on the requested work.
- Do not read, print, or store credentials or authorization headers.
- Do not push, create a pull request, or contact GitHub directly; the wrapper owns all broker-mediated actions.')
mise exec -- codex exec \
  --ephemeral \
  --dangerously-bypass-approvals-and-sandbox \
  --skip-git-repo-check \
  -C /work/repo \
  -o /output/codex-final.txt \
  "$codex_prompt" \
  > /output/codex-events.jsonl

if [[ -n "${AGENT_VERIFY_TASK:-}" ]]; then
  stage='repository verification task'
  mise run "$AGENT_VERIFY_TASK" > /output/verify.txt 2>&1
fi

stage='change detection'
if mise exec -- git diff --quiet && mise exec -- git diff --cached --quiet && [[ -z "$(mise exec -- git status --porcelain)" ]]; then
  fail 'Codex completed without a repository change'
fi

stage='commit and push'
mise exec -- git add --all
mise exec -- git commit --quiet -m "Implement Codex repository task ${AGENT_RUN_ID}"
mise exec -- git push --quiet origin "HEAD:${AGENT_BRANCH}"

stage='pull request creation'
pr_title="${AGENT_PR_TITLE:-Codex repository task}"
pr_body="${AGENT_PR_BODY:-Codex repository task completed for run ${AGENT_RUN_ID}.}"
mise exec -- /usr/local/bin/gh-agent-broker-cli pr -broker "$BROKER_URL" -repo "$AGENT_REPO" -title "$pr_title" -head "$AGENT_BRANCH" -base "$AGENT_BASE_BRANCH" -body "$pr_body" \
  -metadata "Agent-Id=${BROKER_AGENT_ID:?BROKER_AGENT_ID is required for pull request metadata}" -metadata "Run-Id=${AGENT_RUN_ID}" > /output/pull-request.json

stage='completed'
write_result ready_for_review 'Codex changed the repository and a pull request was created'
printf 'Codex repository task completed on %s and opened a ready-for-review pull request.\n' "$AGENT_BRANCH" > /output/final-summary.md
fi
