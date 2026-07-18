#!/bin/sh
set -eu

repo="${REPOSITORY_PATH:-/var/lib/repository-backend/repository-agent-lifecycle-fixture.git}"
root=$(dirname "$repo")
mkdir -p "$root"
chmod 0750 "$root"
if [ ! -d "$repo" ]; then
  git init --bare "$repo"
fi
chmod 0750 "$repo"
git -C "$repo" config http.getanyfile false
git -C "$repo" config http.receivepack true
git -C "$repo" config uploadpack.hideRefs refs/heads/
git -C "$repo" config --add uploadpack.hideRefs '!refs/heads/main'
git -C "$repo" config --add uploadpack.hideRefs '!refs/heads/agent/repository-proof/'
git -C "$repo" config uploadpack.allowTipSHA1InWant false
git -C "$repo" config uploadpack.allowReachableSHA1InWant false
git -C "$repo" config uploadpack.allowAnySHA1InWant false
git -C "$repo" config receive.hideRefs refs/heads/
git -C "$repo" config --add receive.hideRefs '!refs/heads/agent/repository-proof/'
git -C "$repo" config receive.denyDeletes true
git -C "$repo" config receive.denyNonFastForwards true
mkdir -p "$repo/hooks"
cp /usr/local/libexec/repository-backend-pre-receive "$repo/hooks/pre-receive"
chmod 0755 "$repo/hooks/pre-receive"
exec /usr/local/bin/repository-backend -repository "$repo" "$@"
