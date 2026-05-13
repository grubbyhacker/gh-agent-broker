#!/usr/bin/env sh
set -eu

umask 0000

mkdir -p /work/home /work/hermes/skills /work/hermes/logs /output /lessons

diagnostics=/output/wrapper-diagnostics.json

write_diagnostics() {
  status="$1"
  exit_code="$2"
  message="$3"
  missing="${4:-}"
  python3 - "$status" "$exit_code" "$message" "$missing" >"$diagnostics" <<'PY'
import json
import sys

status, exit_code, message, missing = sys.argv[1:5]
doc = {
    "status": status,
    "exit_code": int(exit_code),
    "message": message,
}
if missing:
    doc["missing_deliverables"] = [item for item in missing.split("\n") if item]
print(json.dumps(doc, indent=2, sort_keys=True))
PY
}

fail() {
  code="$1"
  shift
  message="$*"
  write_diagnostics "failed" "$code" "$message"
  printf '%s\n' "$message" >&2
  exit "$code"
}

if sh -c 'echo should-not-write >/credentials/hermes/write-test' 2>/tmp/credential-write.err; then
  rm -f /credentials/hermes/write-test
  fail 20 "credential bundle is writable"
fi

if [ ! -f /input/task.json ] || [ ! -f /input/task.md ] || [ ! -f /input/sandbox-rules.md ]; then
  fail 21 "missing broker task input files"
fi

if [ ! -f /credentials/hermes/auth.json ]; then
  fail 22 "missing Hermes auth.json in credential bundle"
fi
cp /credentials/hermes/auth.json /work/hermes/auth.json
if [ -f /credentials/hermes/config.yaml ]; then
  cp /credentials/hermes/config.yaml /work/hermes/config.yaml
fi
cp -R /opt/hermes-sandbox/skills/gh-agent-broker /work/hermes/skills/gh-agent-broker
chmod 0600 /work/hermes/auth.json
if [ -f /work/hermes/config.yaml ]; then
  chmod 0640 /work/hermes/config.yaml
fi

export HOME=/work/home
export HERMES_HOME=/work/hermes
export HERMES_ACCEPT_HOOKS=1
export HERMES_INFERENCE_PROVIDER="${HERMES_INFERENCE_PROVIDER:-openai-codex}"
export HERMES_INFERENCE_MODEL="${HERMES_INFERENCE_MODEL:-gpt-5.5}"
export HERMES_MAX_TURNS="${HERMES_MAX_TURNS:-90}"

if [ -f /opt/data/auth.json ] || [ -f /input/auth.json ]; then
  fail 23 "parent Hermes auth leaked into sandbox-visible paths"
fi

/usr/local/bin/gh-agent-broker-cli health -broker "$BROKER_URL" >/output/broker-cli-health.txt
/opt/hermes/.venv/bin/hermes auth status openai-codex >/output/hermes-auth-status.txt

{
  printf '# Sandbox Instructions\n\n'
  cat /input/sandbox-rules.md
  printf '\n# User Task\n\n'
  cat /input/task.md
  printf '\n# Required Output Check\n\n'
  printf 'Before exiting, ensure every sandbox filesystem deliverable listed in /input/task.json under /output or /lessons exists and contains the requested task-specific evidence. Repo-relative deliverables are task requirements but are not wrapper-validated as sandbox files.\n'
} >/work/composed-prompt.md

set +e
/opt/hermes/.venv/bin/hermes chat \
  --query "$(cat /work/composed-prompt.md)" \
  --quiet \
  --skills gh-agent-broker \
  --max-turns "$HERMES_MAX_TURNS" \
  --accept-hooks \
  --source sandbox \
  >/output/hermes-stdout.log \
  2>/output/hermes-stderr.log
hermes_status="$?"
set -e

cp /output/hermes-stdout.log /output/hermes-final.txt

if [ "$hermes_status" -ne 0 ]; then
  write_diagnostics "failed" "$hermes_status" "Hermes exited nonzero"
  exit "$hermes_status"
fi

missing="$(
  python3 - <<'PY'
import json
from pathlib import Path

contract = json.loads(Path("/input/task.json").read_text())
deliverables = contract.get("deliverables") or []

def candidates(item):
    if item.startswith("/output/") or item.startswith("/lessons/"):
        return [Path(item)]
    if item.startswith("output/") or item.startswith("lessons/"):
        return [Path("/") / item]
    return []

missing = []
for item in deliverables:
    paths = candidates(str(item))
    if not paths:
        continue
    if not any(path.is_file() and path.stat().st_size > 0 for path in paths):
        missing.append(str(item))
print("\n".join(missing))
PY
)"

if [ -n "$missing" ]; then
  write_diagnostics "failed" 30 "required deliverables missing" "$missing"
  printf 'missing required deliverables:\n%s\n' "$missing" >&2
  exit 30
fi

write_diagnostics "ok" 0 "Hermes completed and required deliverables exist"
