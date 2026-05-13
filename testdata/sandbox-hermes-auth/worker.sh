#!/usr/bin/env sh
set -eu

umask 0000
mkdir -p /work/home /work/hermes/skills /work/hermes/logs /output /lessons

if sh -c 'echo should-not-write >/credentials/hermes/write-test' 2>/tmp/credential-write.err; then
	echo "credential bundle was writable" >&2
	exit 20
fi

cp /credentials/hermes/auth.json /work/hermes/auth.json
cp /credentials/hermes/config.yaml /work/hermes/config.yaml
cp -R /opt/hermes-sandbox/skills/gh-agent-broker /work/hermes/skills/gh-agent-broker
chmod 0600 /work/hermes/auth.json
chmod 0640 /work/hermes/config.yaml

export HOME=/work/home
export HERMES_HOME=/work/hermes
export HERMES_ACCEPT_HOOKS=1
export HERMES_INFERENCE_PROVIDER=openai-codex
export HERMES_INFERENCE_MODEL="${HERMES_INFERENCE_MODEL:-gpt-5.5}"

if [ -e /opt/data/auth.json ] || [ -e /input/auth.json ]; then
	echo "parent Hermes auth unexpectedly visible" >&2
	exit 21
fi

/usr/local/bin/gh-agent-broker-cli health -broker "$BROKER_URL" >/output/broker-cli-health.txt
/opt/hermes/.venv/bin/hermes auth status openai-codex >/output/hermes-auth-status.txt
/opt/hermes/.venv/bin/hermes \
	-z 'Reply with exactly: HERMES_AUTH_OK' \
	--ignore-rules \
	--skills gh-agent-broker \
	>/output/hermes-final.txt

grep -qx 'HERMES_AUTH_OK' /output/hermes-final.txt

printf 'hermes auth succeeded for run %s\n' "$SANDBOX_RUN_ID" > /output/final-summary.md
printf 'hermes credential bundle copied into task-local HERMES_HOME\n' > /lessons/run-summary.md
