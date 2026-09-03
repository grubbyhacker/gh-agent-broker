#!/usr/bin/env bash
set -euo pipefail

# This worker is intentionally credential-free. It validates the candidate
# prepared by the delivery worker after a positive stale-lease detection.
for name in AGENT_RUN_ID AGENT_REPO AGENT_BRANCH AGENT_VERIFY_TASK; do
  [[ -n "${!name:-}" ]] || { echo "missing $name" >&2; exit 1; }
done
for name in $(env | cut -d= -f1); do
  case "$name" in BROKER_*|OPENAI_*|CODEX_*|AGENT_MODEL|AGENT_REASONING_EFFORT) echo "credential authority forbidden" >&2; exit 1;; esac
done
readonly git_env=("PATH=$PATH" HOME=/nonexistent LANG=C LC_ALL=C GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null GIT_TERMINAL_PROMPT=0 GIT_ASKPASS=/bin/false)
trusted_git() { env -i "${git_env[@]}" git -c core.hooksPath=/dev/null -c core.fsmonitor=false "$@"; }
input=/output/stale-lease.json
[[ -f "$input" ]] || { echo 'missing stale lease input' >&2; exit 1; }
jq -e --arg run "$AGENT_RUN_ID" --arg repo "$AGENT_REPO" --arg branch "$AGENT_BRANCH" '
  .version == "codex-stale-lease/v2" and .status == "stale_lease" and .run_id == $run and .repository == $repo and .branch == $branch and
  (.winner_head_sha | test("^[a-f0-9]{40}$")) and (.candidate_head_sha | test("^[a-f0-9]{40}$"))
' "$input" >/dev/null
candidate=$(jq -r .candidate_head_sha "$input")
winner=$(jq -r .winner_head_sha "$input")
[[ "$(trusted_git -C /work/repo rev-parse HEAD)" == "$candidate" ]] || { echo 'candidate changed' >&2; exit 1; }
trusted_git -C /work/repo -c core.hooksPath=/dev/null -c filter.*.clean= -c filter.*.smudge= status --porcelain | grep -q . && { echo 'candidate worktree dirty' >&2; exit 1; }
verify=/work/recovery/verify.txt
mkdir -p /work/recovery
(cd /work/repo && env -i "${git_env[@]}" PATH="$PATH" mise run "$AGENT_VERIFY_TASK") >"$verify" 2>&1
tree=$(trusted_git -C /work/repo rev-parse 'HEAD^{tree}')
digest=$(sha256sum "$verify" | cut -d' ' -f1)
jq -n --arg run "$AGENT_RUN_ID" --arg repo "$AGENT_REPO" --arg branch "$AGENT_BRANCH" --arg winner "$winner" --arg candidate "$candidate" --arg tree "$tree" --arg digest "$digest" \
  '{version:"codex-recovery-validation/v1",status:"passed",run_id:$run,repository:$repo,branch:$branch,winner_head_sha:$winner,candidate_head_sha:$candidate,validated_tree_sha:$tree,verify_sha256:$digest}' > /work/recovery/recovery-validation.json
