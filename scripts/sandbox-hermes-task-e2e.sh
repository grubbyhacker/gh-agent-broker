#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
NET="ghab-hermes-task-e2e-$RANDOM-$$"
BROKER_CID=""
SANDBOX_CID=""

cleanup() {
  if [[ -n "${SANDBOX_CID}" ]]; then
    docker rm -f "${SANDBOX_CID}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${BROKER_CID}" ]]; then
    docker rm -f "${BROKER_CID}" >/dev/null 2>&1 || true
  fi
  if docker network inspect "${NET}" >/dev/null 2>&1; then
    docker ps -aq --filter "network=${NET}" --filter "name=sandbox-" | xargs -r docker rm -f >/dev/null 2>&1 || true
  fi
  docker network rm "${NET}" >/dev/null 2>&1 || true
  if [[ -d "${TMP}" ]]; then
    docker run --rm -v "${TMP}:${TMP}" busybox:latest chmod -R a+rwX "${TMP}" >/dev/null 2>&1 || true
  fi
  rm -rf "${TMP}"
}
trap cleanup EXIT

docker_sock_gid() {
  if docker run --rm -v /var/run/docker.sock:/var/run/docker.sock busybox:latest stat -c '%g' /var/run/docker.sock >/dev/null 2>&1; then
    docker run --rm -v /var/run/docker.sock:/var/run/docker.sock busybox:latest stat -c '%g' /var/run/docker.sock
  elif stat -c '%g' /var/run/docker.sock >/dev/null 2>&1; then
    stat -c '%g' /var/run/docker.sock
  else
    stat -f '%g' /var/run/docker.sock
  fi
}

SOURCE_DIR="${SANDBOX_HERMES_AUTH_SOURCE_DIR:-}"
if [[ -z "${SOURCE_DIR}" ]]; then
  if [[ -r "/docker/hermes-agent-6aso/data/auth.json" ]]; then
    SOURCE_DIR="/docker/hermes-agent-6aso/data"
  elif [[ -n "${HERMES_HOME:-}" && -r "${HERMES_HOME}/auth.json" ]]; then
    SOURCE_DIR="${HERMES_HOME}"
  else
    SOURCE_DIR="${HOME}/.hermes"
  fi
fi
SOURCE_AUTH="${SOURCE_DIR}/auth.json"
if [[ ! -r "${SOURCE_AUTH}" ]]; then
  echo "missing Hermes auth store at ${SOURCE_AUTH}" >&2
  echo "set SANDBOX_HERMES_AUTH_SOURCE_DIR to a directory containing auth.json" >&2
  exit 1
fi

RUNS="${TMP}/runs"
CREDS="${TMP}/credentials/hermes"
SNAPS="${TMP}/snapshots"
AUDIT="${TMP}/audit"
CONFIG="${TMP}/sandbox.yaml"

mkdir -p "${RUNS}" "${CREDS}" "${SNAPS}" "${AUDIT}"
chmod 0777 "${RUNS}" "${AUDIT}"
install -m 0444 "${SOURCE_AUTH}" "${CREDS}/auth.json"
cat >"${CREDS}/config.yaml" <<YAML
model:
  provider: openai-codex
  base_url: https://chatgpt.com/backend-api/codex
  default: ${SANDBOX_HERMES_MODEL:-gpt-5.5}
max_turns: 20
terminal:
  backend: local
  timeout: 240
hooks_auto_accept: true
YAML
chmod 0444 "${CREDS}/config.yaml"
printf 'sandbox hermes task e2e snapshot\n' >"${SNAPS}/project-brief.md"
chmod 0444 "${SNAPS}/project-brief.md"

cat >"${CONFIG}" <<YAML
listen: "0.0.0.0:8091"
mcp_path: "/mcp"
auth_token_env: "SANDBOX_MCP_TOKEN"
runs_dir: "${RUNS}"
broker_url: "http://broker:8080"
production: false
max_task_bytes: 4096
log_byte_limit: 131072
stop_grace: "2s"
audit:
  path: "${AUDIT}/sandbox-audit.jsonl"
repositories:
  - "owner/repo"
network_policies:
  worker-net:
    network: "${NET}"
credential_bundles:
  hermes:
    source_path: "${CREDS}"
    mount_path: "/credentials/hermes"
    readonly: true
    allowed_templates:
      - "hermes-task-worker"
    secret_files:
      - "auth.json"
    redact_files:
      - "config.yaml"
templates:
  hermes-task-worker:
    image: "gh-agent-broker/sandbox-hermes-task:local"
    command:
      - "run"
    user: "10000:10000"
    resources:
      cpu_shares: 512
      memory_mb: 4096
      pids_limit: 512
    network_policy: "worker-net"
    max_runtime_minutes: 10
    broker_agent_id: "hermes-coder-01"
    broker_agent_secret_env: "HERMES_CODER_01_BROKER_SECRET"
    credential_bundle: "hermes"
    branch_policy:
      generate_prefix: "agent"
      allowed_patterns:
        - "^agent/hermes-coder-01/[A-Za-z0-9_.:-]+$"
      base_branches:
        - "main"
    deliverables:
      - "/output/final-summary.md"
      - "/lessons/run-summary.md"
    knowledge_snapshots:
      - "${SNAPS}/project-brief.md"
YAML
chmod 0444 "${CONFIG}"

echo "building gh-agent-broker:sandbox-e2e"
docker build -t gh-agent-broker:sandbox-e2e "${ROOT}" >/dev/null

echo "building sandbox Hermes task worker image"
docker build -f "${ROOT}/testdata/sandbox-hermes-task/Dockerfile" \
  -t gh-agent-broker/sandbox-hermes-task:local "${ROOT}" >/dev/null

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

DOCKER_SOCK_GID="$(docker_sock_gid)"
echo "starting sandbox-broker with Docker socket group ${DOCKER_SOCK_GID}"
SANDBOX_CID="$(
  docker run -d \
    --group-add "${DOCKER_SOCK_GID}" \
    -p 127.0.0.1:18094:8091 \
    -e SANDBOX_MCP_TOKEN=sandbox-token-hermes-task-e2e \
    -e HERMES_CODER_01_BROKER_SECRET=broker-secret-hermes-task-e2e \
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
  if curl -fsS http://127.0.0.1:18094/healthz >/dev/null; then
    break
  fi
  sleep 0.5
done
curl -fsS http://127.0.0.1:18094/healthz >/dev/null || {
  docker logs "${SANDBOX_CID}" >&2 || true
  echo "sandbox-broker did not become healthy" >&2
  exit 1
}

echo "running sandbox Hermes task marker E2E client"
(
  cd "${ROOT}"
  export SANDBOX_E2E_ENDPOINT=http://127.0.0.1:18094/mcp
  export SANDBOX_MCP_TOKEN=sandbox-token-hermes-task-e2e
  export SANDBOX_E2E_RUNS_DIR="${RUNS}"
  export SANDBOX_E2E_WORKER_TEMPLATE=hermes-task-worker
  export SANDBOX_E2E_EXPECT_REDACTED_FILE="${CREDS}/auth.json"
  export SANDBOX_E2E_EXPECT_REDACTED=broker-secret-hermes-task-e2e
  export SANDBOX_E2E_TIMEOUT="${SANDBOX_E2E_TIMEOUT:-10m}"
  if command -v mise >/dev/null 2>&1; then
    mise exec -- go run ./cmd/sandbox-e2e --task-marker-only
  elif command -v go >/dev/null 2>&1; then
    go run ./cmd/sandbox-e2e --task-marker-only
  else
    docker run --rm \
      --network host \
      -v "${ROOT}:${ROOT}" \
      -v "${TMP}:${TMP}" \
      -w "${ROOT}" \
      -e SANDBOX_E2E_ENDPOINT \
      -e SANDBOX_MCP_TOKEN \
      -e SANDBOX_E2E_RUNS_DIR \
      -e SANDBOX_E2E_WORKER_TEMPLATE \
      -e SANDBOX_E2E_EXPECT_REDACTED_FILE \
      -e SANDBOX_E2E_EXPECT_REDACTED \
      -e SANDBOX_E2E_TIMEOUT \
      golang:1.26 \
      go run ./cmd/sandbox-e2e --task-marker-only
  fi
)

if grep -R 'broker-secret-hermes-task-e2e' "${AUDIT}" >/dev/null 2>&1; then
  echo "audit log leaked broker secret" >&2
  exit 1
fi

echo "sandbox Hermes task marker E2E completed successfully"
