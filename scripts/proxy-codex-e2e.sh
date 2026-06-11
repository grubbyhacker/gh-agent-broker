#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cd "${ROOT}"
if command -v mise >/dev/null 2>&1; then
  mise exec -- go run ./cmd/proxy-codex-e2e -repo-root "${ROOT}" "$@"
else
  go run ./cmd/proxy-codex-e2e -repo-root "${ROOT}" "$@"
fi
