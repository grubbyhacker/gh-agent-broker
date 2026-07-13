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

issue_number=$(python3 - <<'PY'
import json
import re
from pathlib import Path

contract = json.loads(Path("/input/task.json").read_text())
params = contract.get("parameters") or {}
issue_number = params.get("issue_number")
delivery_id = params.get("source_delivery_id")
if isinstance(issue_number, bool) or not isinstance(issue_number, int) or issue_number < 1:
    raise SystemExit("typed task contract requires a positive integer issue_number")
if not isinstance(delivery_id, str) or not re.fullmatch(r"[A-Za-z0-9-]{1,128}", delivery_id):
    raise SystemExit("typed task contract requires a valid source_delivery_id")
print(issue_number)
PY
)

/usr/local/bin/gh-agent-broker-cli issue -repo "$SANDBOX_REPO" -number "$issue_number" >/work/issue.json
/usr/local/bin/gh-agent-broker-cli issue-comments -repo "$SANDBOX_REPO" -number "$issue_number" >/work/issue-comments.json

python3 - <<'PY'
import json
from pathlib import Path

issue = json.loads(Path("/work/issue.json").read_text())
comments = json.loads(Path("/work/issue-comments.json").read_text())
if not isinstance(issue, dict) or "pull_request" in issue:
    raise SystemExit("typed issue reference resolved to a pull request or invalid issue")
if issue.get("state") != "open":
    raise SystemExit("typed issue reference is not open")

number = issue.get("number")
title = issue.get("title")
if not isinstance(number, int) or not isinstance(title, str) or not title.strip():
    raise SystemExit("broker issue response is missing number or title")
if not isinstance(comments, list):
    raise SystemExit("broker issue comments response is invalid")

remaining = 24 * 1024

def clipped(value):
    global remaining
    if not isinstance(value, str) or remaining <= 0:
        return ""
    value = value.strip()
    if len(value) <= remaining:
        remaining -= len(value)
        return value
    result = value[:remaining] + "\n\n[truncated by worker input limit]"
    remaining = 0
    return result

lines = [
    "# Authoritative GitHub Issue",
    "",
    f"Issue: #{number} — {title.strip()}",
    "",
    "## Body",
    "",
    clipped(issue.get("body")) or "[no issue body]",
]
for comment in comments:
    if remaining <= 0:
        break
    if not isinstance(comment, dict):
        continue
    user = comment.get("user")
    author = user.get("login") if isinstance(user, dict) else None
    body = clipped(comment.get("body"))
    if body:
        lines.extend(["", f"## Comment from {author or 'unknown'}", "", body])

Path("/work/issue-context.md").write_text("\n".join(lines) + "\n")
Path("/work/issue-title.txt").write_text(title.strip() + "\n")
PY

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
  printf '\n# Authoritative Issue Context\n\n'
  cat /work/issue-context.md
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
  --dangerously-bypass-approvals-and-sandbox \
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

pr_title="Implementation: $(tr '\n' ' ' </work/issue-title.txt | cut -c1-96)"
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
    "issue_number": json.loads(Path("/input/task.json").read_text())["parameters"]["issue_number"],
    "source_delivery_id": json.loads(Path("/input/task.json").read_text())["parameters"]["source_delivery_id"],
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
