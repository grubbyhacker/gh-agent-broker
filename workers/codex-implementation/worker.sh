#!/usr/bin/env sh
set -eu

fail() {
  printf '%s\n' "$*" >&2
  exit 1
}

require_file() {
  [ -f "$1" ] || fail "missing required file: $1"
}

require_file /input/task.md
require_file /input/task.json
require_file /input/sandbox-rules.md
require_file /credentials/codex/auth.json

if sh -c 'echo should-not-write >/credentials/codex/write-test' 2>/tmp/credential-write.err; then
  fail "credential bundle is writable"
fi

mkdir -p /work/home/.codex /work/repo /output /lessons
cp /credentials/codex/auth.json /work/home/.codex/auth.json
chmod 0600 /work/home/.codex/auth.json
if [ -f /credentials/codex/config.toml ]; then
  cp /credentials/codex/config.toml /work/home/.codex/config.toml
  chmod 0600 /work/home/.codex/config.toml
fi

export HOME=/work/home
export CODEX_HOME=/work/home/.codex

if [ -e /opt/data/auth.json ] || [ -e /input/auth.json ]; then
  fail "parent credential material is visible in the worker"
fi

/usr/local/bin/gh-agent-broker-cli health -broker "$BROKER_URL" >/output/broker-health.txt
/usr/local/bin/gh-agent-broker-cli probe -repo "$SANDBOX_REPO" >/output/broker-repo-probe.json

cd /work/repo
git init --quiet
git remote add origin placeholder
/usr/local/bin/gh-agent-broker-cli configure -repo "$SANDBOX_REPO" -remote origin >/output/broker-remote.txt
git fetch --quiet origin "$SANDBOX_BASE_BRANCH"
git checkout --quiet -B "$SANDBOX_BRANCH" FETCH_HEAD
git config user.name "${GIT_AUTHOR_NAME:-Codex Sandbox Worker}"
git config user.email "${GIT_AUTHOR_EMAIL:-codex-sandbox@users.noreply.github.com}"

{
  printf '# Sandbox Rules\n\n'
  cat /input/sandbox-rules.md
  printf '\n# Implementation Task\n\n'
  cat /input/task.md
  printf '\n# Execution Contract\n\n'
  printf '%s\n' '- Work only in this repository checkout.'
  printf '%s\n' '- Implement the requested change and keep the diff focused.'
  printf '%s\n' '- Do not read, print, or store credentials or authorization headers.'
  printf '%s\n' '- Do not push, create a pull request, or contact GitHub directly; the wrapper owns those broker-mediated actions.'
  printf '%s\n' '- Run focused checks while implementing. The wrapper will run uv run pytest -q before it creates a pull request.'
} >/work/codex-prompt.md

codex exec \
  --ephemeral \
  --model gpt-5.5 \
  --sandbox workspace-write \
  --skip-git-repo-check \
  -C /work/repo \
  -o /output/codex-final.txt \
  "$(cat /work/codex-prompt.md)" \
  >/output/codex-events.jsonl

if git diff --quiet; then
  fail "Codex completed without a repository change"
fi

uv run pytest -q >/output/pytest.txt

git add --all
git commit --quiet -m "Implement sandbox task ${SANDBOX_RUN_ID}"
git push --quiet origin "HEAD:${SANDBOX_BRANCH}"

pr_title="Implementation: $(sed -n '1p' /input/task.md | tr '\n' ' ' | cut -c1-96)"
if [ "$pr_title" = "Implementation: " ]; then
  pr_title="Implementation: sandbox task"
fi
pr_body="Implemented by sandbox run ${SANDBOX_RUN_ID}.\n\nValidation: \`uv run pytest -q\`."
/usr/local/bin/gh-agent-broker-cli pr \
  -repo "$SANDBOX_REPO" \
  -title "$pr_title" \
  -head "$SANDBOX_BRANCH" \
  -base "$SANDBOX_BASE_BRANCH" \
  -body "$pr_body" \
  >/output/pull-request.json

python3 - <<'PY' >/output/result.json
import json
import os
from pathlib import Path

result = {
    "run_id": os.environ["SANDBOX_RUN_ID"],
    "repository": os.environ["SANDBOX_REPO"],
    "base_branch": os.environ["SANDBOX_BASE_BRANCH"],
    "branch": os.environ["SANDBOX_BRANCH"],
    "validation": "uv run pytest -q",
    "pull_request": json.loads(Path("/output/pull-request.json").read_text()),
    "outcome": "ready_for_review",
}
print(json.dumps(result, indent=2, sort_keys=True))
PY

printf 'Codex implemented the sandbox task on %s and opened a ready-for-review pull request.\n' "$SANDBOX_BRANCH" > /output/final-summary.md
printf 'Credential bundle copied to a run-local CODEX_HOME; wrapper owns Git and PR operations.\n' > /lessons/run-summary.md
