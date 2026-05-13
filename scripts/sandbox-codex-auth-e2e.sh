#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
NET="ghab-codex-auth-e2e-$RANDOM-$$"
BROKER_CID=""
SANDBOX_CID=""

cleanup() {
  if [[ -n "${SANDBOX_CID}" ]]; then
    docker rm -f "${SANDBOX_CID}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${BROKER_CID}" ]]; then
    docker rm -f "${BROKER_CID}" >/dev/null 2>&1 || true
  fi
  docker network rm "${NET}" >/dev/null 2>&1 || true
  if [[ -d "${TMP}" ]]; then
    docker run --rm -v "${TMP}:${TMP}" busybox:latest chmod -R a+rwX "${TMP}" >/dev/null 2>&1 || true
  fi
  rm -rf "${TMP}"
}
trap cleanup EXIT

if [[ ! -r "${HOME}/.codex/auth.json" || ! -r "${HOME}/.codex/config.toml" ]]; then
  echo "missing ${HOME}/.codex/auth.json or config.toml" >&2
  exit 1
fi

RUNS="${TMP}/runs"
CREDS="${TMP}/credentials/codex"
SNAPS="${TMP}/snapshots"
AUDIT="${TMP}/audit"
CONFIG="${TMP}/sandbox.yaml"

mkdir -p "${RUNS}" "${CREDS}" "${SNAPS}" "${AUDIT}"
chmod 0777 "${RUNS}" "${AUDIT}"
install -m 0444 "${HOME}/.codex/auth.json" "${CREDS}/auth.json"
install -m 0444 "${HOME}/.codex/config.toml" "${CREDS}/config.toml"
printf 'sandbox codex auth e2e snapshot\n' >"${SNAPS}/project-brief.md"
chmod 0444 "${SNAPS}/project-brief.md"

cat >"${CONFIG}" <<YAML
listen: "0.0.0.0:8091"
mcp_path: "/mcp"
auth_token_env: "SANDBOX_MCP_TOKEN"
runs_dir: "${RUNS}"
broker_url: "http://broker:8080"
production: false
max_task_bytes: 2048
log_byte_limit: 32768
stop_grace: "2s"
audit:
  path: "${AUDIT}/sandbox-audit.jsonl"
repositories:
  - "owner/repo"
network_policies:
  worker-net:
    network: "${NET}"
credential_bundles:
  codex:
    source_path: "${CREDS}"
    mount_path: "/credentials/codex"
    readonly: true
    allowed_templates:
      - "codex-auth"
    secret_files:
      - "auth.json"
    redact_files:
      - "config.toml"
templates:
  codex-auth:
    image: "gh-agent-broker/sandbox-codex-auth:local"
    command:
      - "probe"
    user: "1000:1000"
    resources:
      cpu_shares: 256
      memory_mb: 1024
      pids_limit: 256
    network_policy: "worker-net"
    max_runtime_minutes: 10
    broker_agent_id: "hermes-coder-01"
    broker_agent_secret_env: "HERMES_CODER_01_BROKER_SECRET"
    credential_bundle: "codex"
    branch_policy:
      generate_prefix: "agent"
      allowed_patterns:
        - "^agent/hermes-coder-01/[A-Za-z0-9_.:-]+$"
      base_branches:
        - "main"
    deliverables:
      - "final-summary.md"
      - "codex-final.txt"
      - "run-summary.md"
    knowledge_snapshots:
      - "${SNAPS}/project-brief.md"
YAML
chmod 0444 "${CONFIG}"

echo "building sandbox Codex auth worker image"
docker build -t gh-agent-broker/sandbox-codex-auth:local "${ROOT}/testdata/sandbox-codex-auth" >/dev/null

echo "building gh-agent-broker:sandbox-e2e"
docker build -t gh-agent-broker:sandbox-e2e "${ROOT}" >/dev/null

echo "creating Docker network ${NET}"
docker network create "${NET}" >/dev/null

echo "starting fake broker on ${NET}"
BROKER_CID="$(
  docker run -d \
    --network "${NET}" \
    --network-alias broker \
    busybox:latest \
    sh -c 'mkdir -p /www && printf "{\"status\":\"ok\"}\n" > /www/healthz && httpd -f -p 8080 -h /www'
)"

DOCKER_SOCK_GID="$(stat -c '%g' /var/run/docker.sock)"
echo "starting sandbox-broker with Docker socket group ${DOCKER_SOCK_GID}"
SANDBOX_CID="$(
  docker run -d \
    --group-add "${DOCKER_SOCK_GID}" \
    -p 127.0.0.1:18092:8091 \
    -e SANDBOX_MCP_TOKEN=sandbox-token-codex-auth-e2e \
    -e HERMES_CODER_01_BROKER_SECRET=broker-secret-codex-auth-e2e \
    -v "${CONFIG}:${CONFIG}:ro" \
    -v "${RUNS}:${RUNS}" \
    -v "${CREDS}:${CREDS}:ro" \
    -v "${SNAPS}:${SNAPS}:ro" \
    -v "${AUDIT}:${AUDIT}" \
    -v /var/run/docker.sock:/var/run/docker.sock \
    --entrypoint /usr/local/bin/sandbox-broker \
    gh-agent-broker:sandbox-e2e \
    -config "${CONFIG}" -allow-public-bind
)"

for _ in {1..60}; do
  if curl -fsS http://127.0.0.1:18092/healthz >/dev/null; then
    break
  fi
  sleep 0.5
done
curl -fsS http://127.0.0.1:18092/healthz >/dev/null || {
  docker logs "${SANDBOX_CID}" >&2 || true
  echo "sandbox-broker did not become healthy" >&2
  exit 1
}

echo "running sandbox Codex auth E2E client"
(
  cd "${ROOT}"
  SANDBOX_E2E_ENDPOINT=http://127.0.0.1:18092/mcp \
  SANDBOX_MCP_TOKEN=sandbox-token-codex-auth-e2e \
  SANDBOX_E2E_RUNS_DIR="${RUNS}" \
  SANDBOX_E2E_WORKER_TEMPLATE=codex-auth \
  SANDBOX_E2E_SLEEPER_TEMPLATE=codex-auth \
  SANDBOX_E2E_EXPECT_REDACTED_FILE="${CREDS}/auth.json" \
    mise exec -- go run ./cmd/sandbox-e2e --codex-auth-only
)

if grep -R 'broker-secret-codex-auth-e2e' "${AUDIT}" >/dev/null 2>&1; then
  echo "audit log leaked broker secret" >&2
  exit 1
fi

echo "sandbox Codex auth E2E completed successfully"
