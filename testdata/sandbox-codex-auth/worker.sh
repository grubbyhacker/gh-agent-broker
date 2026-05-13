#!/usr/bin/env sh
set -eu

umask 0000
mkdir -p /work/home/.codex /work/hermes /output /lessons

if sh -c 'echo should-not-write >/credentials/codex/write-test' 2>/tmp/credential-write.err; then
	echo "credential bundle was writable" >&2
	exit 20
fi

cp /credentials/codex/auth.json /work/home/.codex/auth.json
cp /credentials/codex/config.toml /work/home/.codex/config.toml
chmod 0600 /work/home/.codex/auth.json /work/home/.codex/config.toml

export HOME=/work/home
export HERMES_HOME=/work/hermes
export CODEX_HOME=/work/home/.codex

if [ -e /opt/data/auth.json ] || [ -e /input/auth.json ]; then
  echo "parent Hermes auth unexpectedly visible" >&2
  exit 21
fi

codex exec \
  --ephemeral \
  --json \
  --sandbox read-only \
  --skip-git-repo-check \
  -C /work \
  -o /output/codex-final.txt \
  'Reply with exactly: SANDBOX_CODEX_AUTH_OK' \
  >/output/codex-events.jsonl

grep -qx 'SANDBOX_CODEX_AUTH_OK' /output/codex-final.txt

printf 'codex auth succeeded for run %s\n' "$SANDBOX_RUN_ID" > /output/final-summary.md
printf 'credential bundle copied into task-local CODEX_HOME\n' > /lessons/run-summary.md
