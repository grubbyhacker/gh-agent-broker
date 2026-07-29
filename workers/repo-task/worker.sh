#!/usr/bin/env bash
set -euo pipefail

readonly worker_name='agent-repo-task-worker'
readonly dependency_manifest_path="${AGENT_IMAGE_DEPENDENCY_MANIFEST_PATH:-/usr/local/share/agent-image/dependency-manifest.sha256}"
readonly dependency_manifest_output_path="${AGENT_IMAGE_DEPENDENCY_MANIFEST_OUTPUT_PATH:-/output/dependency-manifest.txt}"
# publish-agent-image.yml copies initialized submodule content to /workspace.
readonly baked_workspace_path="${AGENT_IMAGE_WORKSPACE:-/workspace}"
stage='initializing'

fail() { printf '%s: %s\n' "$worker_name" "$*" >&2; exit 1; }
require_env() { [[ -n "${!1:-}" ]] || fail "missing required environment variable: $1"; }

write_result() {
  local outcome="$1" detail="$2"
  mise exec -- jq -n --arg outcome "$outcome" --arg detail "$detail" --arg stage "$stage" \
    --arg run_id "$AGENT_RUN_ID" --arg repository "$AGENT_REPO" --arg base_branch "$AGENT_BASE_BRANCH" \
    --arg branch "$AGENT_BRANCH" --arg task "$AGENT_TASK" --arg verify_task "${AGENT_VERIFY_TASK:-}" \
    --arg manifest_status "${manifest_status:-not_checked}" \
    '{outcome: $outcome, detail: $detail, stage: $stage, run_id: $run_id, repository: $repository, base_branch: $base_branch, branch: $branch, task: $task, verify_task: $verify_task, dependency_manifest: $manifest_status}' \
    > /output/result.json
}

on_exit() {
  local status=$?
  trap - EXIT
  if (( status != 0 )); then
    write_result failed "worker failed during $stage" || true
    printf 'Repository task worker failed during %s. See worker logs and /output/result.json.\n' "$stage" > /output/final-summary.md
  fi
  exit "$status"
}

validate_inputs() {
  local value
  for value in "$AGENT_REPO" "$AGENT_BASE_BRANCH" "$AGENT_RUN_ID" "$AGENT_TASK"; do
    [[ "$value" != *$'\n'* && "$value" != *$'\r'* ]] || fail 'configuration values must not contain line breaks'
  done
  [[ "$AGENT_REPO" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || fail 'AGENT_REPO must be owner/name'
  [[ "$AGENT_RUN_ID" =~ ^[A-Za-z0-9_.:-]+$ ]] || fail 'AGENT_RUN_ID must contain only letters, numbers, dot, underscore, colon, or hyphen'
  [[ "$AGENT_TASK" =~ ^[A-Za-z0-9_.:-]+$ ]] || fail 'AGENT_TASK must be a single mise task name'
  if [[ -n "${AGENT_VERIFY_TASK:-}" ]]; then
    [[ "$AGENT_VERIFY_TASK" =~ ^[A-Za-z0-9_.:-]+$ ]] || fail 'AGENT_VERIFY_TASK must be a single mise task name'
  fi
}

# publish-agent-image.yml records these gitlinks as
# "submodule <sha> <path>" in dependency-manifest.inputs. Comparing the
# resulting manifest before copying from the image proves the baked content was
# built for the same submodule pointers as this checkout.
has_submodules() {
  local entry metadata
  while IFS= read -r -d '' entry; do
    metadata="${entry%%$'\t'*}"
    [[ "${metadata%% *}" == '160000' ]] && return 0
  done < <(git ls-files --stage -z)
  return 1
}

collect_submodule_manifest_entries() {
  local entry metadata path mode sha
  while IFS= read -r -d '' entry; do
    metadata="${entry%%$'\t'*}"
    path="${entry#*$'\t'}"
    mode="${metadata%% *}"
    [[ "$mode" == '160000' ]] || continue
    sha="${metadata#* }"
    sha="${sha%% *}"
    printf 'submodule %s %s\n' "$sha" "$path"
  done < <(git ls-files --stage -z)
}

hydrate_baked_submodules() {
  local entry metadata path mode baked_path
  while IFS= read -r -d '' entry; do
    metadata="${entry%%$'\t'*}"
    path="${entry#*$'\t'}"
    mode="${metadata%% *}"
    [[ "$mode" == '160000' ]] || continue
    [[ "$path" != /* && "$path" != *'..'* ]] || fail "invalid submodule path in checkout: $path"
    baked_path="$baked_workspace_path/$path"
    if [[ ! -d "$baked_path" ]]; then
      manifest_status="mismatch: baked submodule content is missing at $baked_path"
      fail "baked submodule content is missing for $path"
    fi
    rm -rf -- "$path"
    mkdir -p "$path"
    cp -a "$baked_path/." "$path/"
  done < <(git ls-files --stage -z)
}

collect_lockfiles() {
  local path
  lockfiles=()
  while IFS= read -r path; do
    case "$path" in
      package-lock.json|pnpm-lock.yaml|yarn.lock|bun.lock|bun.lockb|uv.lock|poetry.lock|Pipfile.lock|go.sum|Cargo.lock|Gemfile.lock|requirements*.txt) lockfiles+=("$path") ;;
      */*lock*|*lock*.json|*lock*.yaml|*lock*.yml|*Lock*|*requirements*.txt) fail "unsupported dependency lockfile: $path; extend publish-agent-image.yml before using this worker" ;;
    esac
  done < <(git ls-files)
}

compute_dependency_manifest() {
  local manifest_file
  collect_lockfiles
  manifest_files=()
  for manifest_file in package.json go.mod pyproject.toml Cargo.toml; do
    git ls-files --error-unmatch -- "$manifest_file" >/dev/null 2>&1 && manifest_files+=("$manifest_file")
  done
  {
    mise exec -- sha256sum mise.toml
    for manifest_file in "${lockfiles[@]}"; do mise exec -- sha256sum "$manifest_file"; done
    for manifest_file in "${manifest_files[@]}"; do mise exec -- sha256sum "$manifest_file"; done
    collect_submodule_manifest_entries
  } | LC_ALL=C mise exec -- sort | mise exec -- sha256sum | {
    IFS=' ' read -r manifest_sha _
    printf '%s\n' "$manifest_sha"
  }
}

check_dependency_manifest() {
  local baked_manifest current_manifest
  manifest_status='missing baked manifest'
  [[ -f "$dependency_manifest_path" ]] || return
  IFS= read -r baked_manifest < "$dependency_manifest_path" || true
  [[ "$baked_manifest" =~ ^[a-fA-F0-9]{64}$ ]] || fail "invalid baked dependency manifest hash: $dependency_manifest_path"
  current_manifest=$(compute_dependency_manifest)
  if [[ "$current_manifest" == "$baked_manifest" ]]; then
    manifest_status='match'
    hydrate_baked_submodules
    printf 'manifest match, using baked dependencies\n' | mise exec -- tee "$dependency_manifest_output_path"
    return
  fi
  manifest_status="mismatch: baked=$baked_manifest checkout=$current_manifest"
  if has_submodules; then
    fail 'baked submodule SHA does not match the checkout; rebuild the agent image before running this worker'
  fi
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
require_env AGENT_TASK
AGENT_BRANCH="agent/contributor/${AGENT_RUN_ID}"
export AGENT_BRANCH
validate_inputs
mkdir -p /work/repo /output
trap on_exit EXIT

stage='broker health check'
/usr/local/bin/gh-agent-broker-cli health -broker "$BROKER_URL" > /output/broker-health.txt
/usr/local/bin/gh-agent-broker-cli probe -broker "$BROKER_URL" -repo "$AGENT_REPO" > /output/broker-repo-probe.json

stage='broker-mediated checkout'
cd /work/repo
git init --quiet
git check-ref-format --branch "$AGENT_BASE_BRANCH" >/dev/null || fail 'AGENT_BASE_BRANCH must be a valid Git branch name'
git remote add origin placeholder
/usr/local/bin/gh-agent-broker-cli configure -broker "$BROKER_URL" -repo "$AGENT_REPO" -remote origin > /output/broker-remote.txt
git fetch --quiet origin "$AGENT_BASE_BRANCH"
git checkout --quiet -B "$AGENT_BRANCH" FETCH_HEAD
git config user.name "${GIT_AUTHOR_NAME:-Repository Task Worker}"
git config user.email "${GIT_AUTHOR_EMAIL:-repository-task-worker@users.noreply.github.com}"

stage='dependency manifest check'
check_dependency_manifest
if [[ "$manifest_status" != 'match' ]]; then
  printf 'DEPENDENCY MANIFEST %s\n' "$manifest_status" | mise exec -- tee "$dependency_manifest_output_path"
  stage='dependency installation after manifest mismatch'
  install_repository_dependencies
fi

stage='repository task'
mise run "$AGENT_TASK" > /output/task.txt 2>&1
if [[ -n "${AGENT_VERIFY_TASK:-}" ]]; then stage='repository verification task'; mise run "$AGENT_VERIFY_TASK" > /output/verify.txt 2>&1; fi

stage='change detection'
if git diff --quiet && git diff --cached --quiet && [[ -z "$(git status --porcelain)" ]]; then
  write_result no_change_required 'task completed successfully; repository is unchanged'
  printf 'No change required: mise task %s completed successfully.\n' "$AGENT_TASK" > /output/final-summary.md
  exit 0
fi

stage='commit and push'
git add --all
git commit --quiet -m "Run repository task ${AGENT_RUN_ID}"
git push --quiet origin "HEAD:${AGENT_BRANCH}"

stage='pull request creation'
pr_title="${AGENT_PR_TITLE:-Repository task: ${AGENT_TASK}}"
pr_body="${AGENT_PR_BODY:-Automated repository task ${AGENT_TASK} completed for run ${AGENT_RUN_ID}.}"
/usr/local/bin/gh-agent-broker-cli pr -broker "$BROKER_URL" -repo "$AGENT_REPO" -title "$pr_title" -head "$AGENT_BRANCH" -base "$AGENT_BASE_BRANCH" -body "$pr_body" \
  -metadata "Agent-Id=${BROKER_AGENT_ID:?BROKER_AGENT_ID is required for pull request metadata}" -metadata "Run-Id=${AGENT_RUN_ID}" > /output/pull-request.json

stage='completed'
write_result ready_for_review 'task changed the repository and a pull request was created'
printf 'Repository task %s completed on %s and opened a ready-for-review pull request.\n' "$AGENT_TASK" "$AGENT_BRANCH" > /output/final-summary.md
fi
