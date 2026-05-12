#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
CID=""

cleanup() {
  if [[ -n "${CID}" ]]; then
    docker rm -f "${CID}" >/dev/null 2>&1 || true
  fi
  rm -rf "${TMP}"
}
trap cleanup EXIT

KEY="${TMP}/github-app.pem"
CONFIG="${TMP}/config.yaml"
AUDIT="${TMP}/audit"
mkdir -p "${AUDIT}"
chmod 0777 "${AUDIT}"

openssl genrsa -out "${KEY}" 2048 >/dev/null 2>&1
chmod 0444 "${KEY}"

cat >"${CONFIG}" <<'YAML'
server:
  listen: "127.0.0.1:8080"
  admin_secret_env: "BROKER_ADMIN_SECRET"
audit:
  path: "/var/log/gh-agent-broker/audit.jsonl"
github:
  app_id: 1
  private_key_path: "/run/secrets/github-app.pem"
  api_base_url: "https://api.github.com"
  git_base_url: "https://github.com"
  installations:
    owner/repo: 2
agents:
  - id: "agent-1"
    enabled: true
    secret_env: "BROKER_AGENT_SECRET"
    repositories: ["owner/repo"]
    operations: ["repo.probe", "git.upload-pack", "git.receive-pack"]
YAML
chmod 0444 "${CONFIG}"

docker build -t gh-agent-broker:smoke "${ROOT}"
docker run --rm --entrypoint /usr/local/bin/gh-agent-broker-cli gh-agent-broker:smoke \
  config-check -config /no/such/config >/dev/null 2>&1 && {
    echo "config-check unexpectedly passed for missing config" >&2
    exit 1
  }

CID="$(
  docker run -d \
    -e BROKER_ADMIN_SECRET=admin-secret \
    -e BROKER_AGENT_SECRET=agent-secret \
    -v "${CONFIG}:/etc/gh-agent-broker/config.yaml:ro" \
    -v "${KEY}:/run/secrets/github-app.pem:ro" \
    -v "${AUDIT}:/var/log/gh-agent-broker" \
    gh-agent-broker:smoke -config /etc/gh-agent-broker/config.yaml
)"

for _ in {1..30}; do
  if docker exec "${CID}" gh-agent-broker-cli health -broker http://127.0.0.1:8080 >/dev/null 2>&1; then
    echo "container smoke ok"
    exit 0
  fi
  sleep 1
done

docker logs "${CID}" >&2 || true
echo "broker did not become healthy" >&2
exit 1
