#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
NET="ghab-sandbox-e2e-$RANDOM-$$"
IMAGE="${SANDBOX_E2E_IMAGE:-gh-agent-broker:sandbox-e2e}"
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

docker_sock_gid() {
  if docker run --rm -v /var/run/docker.sock:/var/run/docker.sock busybox:latest stat -c '%g' /var/run/docker.sock >/dev/null 2>&1; then
    docker run --rm -v /var/run/docker.sock:/var/run/docker.sock busybox:latest stat -c '%g' /var/run/docker.sock
  elif stat -c '%g' /var/run/docker.sock >/dev/null 2>&1; then
    stat -c '%g' /var/run/docker.sock
  else
    stat -f '%g' /var/run/docker.sock
  fi
}

RUNS="${TMP}/runs"
CREDS="${TMP}/credentials/codex"
SNAPS="${TMP}/snapshots"
AUDIT="${TMP}/audit"
CONFIG="${TMP}/sandbox.yaml"

mkdir -p "${RUNS}" "${CREDS}" "${SNAPS}" "${AUDIT}"
chmod 0777 "${RUNS}" "${AUDIT}"
printf 'bundle-secret-e2e\n' >"${CREDS}/token.txt"
chmod 0444 "${CREDS}/token.txt"
printf 'sandbox knowledge snapshot\n' >"${SNAPS}/project-brief.md"
chmod 0444 "${SNAPS}/project-brief.md"

cat >"${CONFIG}" <<YAML
listen: "0.0.0.0:8091"
mcp_path: "/mcp"
auth_token_env: "SANDBOX_MCP_TOKEN"
runs_dir: "${RUNS}"
broker_url: "http://broker:8080"
production: false
max_task_bytes: 2048
log_byte_limit: 4096
stop_grace: "1s"
audit:
  path: "${AUDIT}/sandbox-audit.jsonl"
repositories:
  - "owner/repo"
network_policies:
  worker-net:
    network: "${NET}"
  none:
    none: true
credential_bundles:
  codex:
    source_path: "${CREDS}"
    mount_path: "/credentials/codex"
    readonly: true
    allowed_templates:
      - "worker"
      - "sleeper"
      - "missing-deliverable"
    secret_files:
      - "token.txt"
templates:
  worker:
    image: "busybox:latest"
    command:
      - "/bin/sh"
      - "-ceu"
      - |
        mkdir -p /work/home /work/hermes
        grep -q 'Sandbox Rules' /input/sandbox-rules.md
        grep -q 'Broker remote URL' /input/sandbox-rules.md
        wget -qO /output/broker-health.json "\$BROKER_URL/healthz"
        echo stdout \$BROKER_AGENT_SECRET \$(cat /credentials/codex/token.txt)
        printf 'task=%s\nrun=%s\nbroker=%s\nbundle=%s\n' "\$(cat /input/task.md)" "\$SANDBOX_RUN_ID" "\$BROKER_AGENT_SECRET" "\$(cat /credentials/codex/token.txt)" > /output/final-summary.md
        printf 'task=%s\nlesson bundle=%s\n' "\$(cat /input/task.md)" "\$(cat /credentials/codex/token.txt)" > /lessons/run-summary.md
        grep -q '"repo/relative.md"' /input/task.json
    user: "65532:65532"
    resources:
      cpu_shares: 128
      memory_mb: 128
      pids_limit: 64
    network_policy: "worker-net"
    max_runtime_minutes: 5
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
      - "/output/final-summary.md"
      - "/lessons/run-summary.md"
    knowledge_snapshots:
      - "${SNAPS}/project-brief.md"
  missing-deliverable:
    image: "busybox:latest"
    command:
      - "/bin/sh"
      - "-ceu"
      - |
        printf '{"status":"failed","message":"required deliverables missing"}\n' > /output/wrapper-diagnostics.json
        exit 30
    user: "65532:65532"
    resources:
      cpu_shares: 128
      memory_mb: 128
      pids_limit: 64
    network_policy: "worker-net"
    max_runtime_minutes: 5
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
      - "/output/final-summary.md"
      - "/lessons/run-summary.md"
  sleeper:
    image: "busybox:latest"
    command:
      - "/bin/sh"
      - "-ceu"
      - |
        trap 'exit 0' TERM
        echo ready
        sleep 300
    user: "65532:65532"
    resources:
      cpu_shares: 128
      memory_mb: 128
      pids_limit: 64
    network_policy: "worker-net"
    max_runtime_minutes: 5
    broker_agent_id: "hermes-coder-01"
    broker_agent_secret_env: "HERMES_CODER_01_BROKER_SECRET"
    credential_bundle: "codex"
    branch_policy:
      generate_prefix: "agent"
      allowed_patterns:
        - "^agent/hermes-coder-01/[A-Za-z0-9_.:-]+$"
      base_branches:
        - "main"
YAML
chmod 0444 "${CONFIG}"

if [[ "${SANDBOX_E2E_SKIP_IMAGE_BUILD:-}" == "1" ]]; then
  echo "using prebuilt ${IMAGE}"
  if ! docker image inspect "${IMAGE}" >/dev/null 2>&1; then
    echo "SANDBOX_E2E_SKIP_IMAGE_BUILD=1 but ${IMAGE} is not available" >&2
    exit 1
  fi
else
  echo "building ${IMAGE}"
  docker build -f "${ROOT}/Dockerfile.sandbox-e2e" -t "${IMAGE}" "${ROOT}" >/dev/null
fi

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
    -p 127.0.0.1:18091:8091 \
    -e SANDBOX_MCP_TOKEN=sandbox-token-e2e \
    -e HERMES_CODER_01_BROKER_SECRET=broker-secret-e2e \
    -v "${CONFIG}:${CONFIG}:ro" \
    -v "${RUNS}:${RUNS}" \
    -v "${CREDS}:${CREDS}:ro" \
    -v "${SNAPS}:${SNAPS}:ro" \
    -v "${AUDIT}:${AUDIT}" \
    -v /var/run/docker.sock:/var/run/docker.sock \
    --entrypoint /usr/local/bin/sandbox-broker \
    "${IMAGE}" \
    -config "${CONFIG}" -allow-public-bind
)"

for _ in {1..60}; do
  if curl -fsS http://127.0.0.1:18091/healthz >/dev/null; then
    break
  fi
  sleep 0.5
done
curl -fsS http://127.0.0.1:18091/healthz >/dev/null || {
  docker logs "${SANDBOX_CID}" >&2 || true
  echo "sandbox-broker did not become healthy" >&2
  exit 1
}

status="$(curl -sS -o /dev/null -w '%{http_code}' http://127.0.0.1:18091/mcp || true)"
if [[ "${status}" != "401" ]]; then
  echo "unauthenticated MCP request returned ${status}, want 401" >&2
  exit 1
fi
status="$(curl -sS -o /dev/null -w '%{http_code}' -H 'Authorization: Bearer wrong' http://127.0.0.1:18091/mcp || true)"
if [[ "${status}" != "401" ]]; then
  echo "bad-token MCP request returned ${status}, want 401" >&2
  exit 1
fi

echo "running MCP-driven sandbox E2E client"
(
  cd "${ROOT}"
  export SANDBOX_E2E_ENDPOINT=http://127.0.0.1:18091/mcp
  export SANDBOX_MCP_TOKEN=sandbox-token-e2e
  export SANDBOX_E2E_RUNS_DIR="${RUNS}"
  export SANDBOX_E2E_TIMEOUT="${SANDBOX_E2E_TIMEOUT:-180s}"
  if command -v mise >/dev/null 2>&1; then
    mise exec -- go run ./cmd/sandbox-e2e
  else
    go run ./cmd/sandbox-e2e
  fi
)

if grep -R 'broker-secret-e2e\|bundle-secret-e2e' "${AUDIT}" >/dev/null 2>&1; then
  echo "audit log leaked a configured secret" >&2
  exit 1
fi

echo "sandbox E2E completed successfully"
