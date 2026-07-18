#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
image=${REPOSITORY_BACKEND_IMAGE:-gh-agent-broker/repository-backend:proof}
tmp=$(mktemp -d)
container=""

cleanup() {
  if [[ -n "$container" ]]; then docker rm -f "$container" >/dev/null 2>&1 || true; fi
  rm -rf "$tmp"
}
trap cleanup EXIT

fail() { echo "repository-backend image proof: $*" >&2; exit 1; }
expect_fail() { "$@" && fail "unexpected success: $*" || true; }
expect_rejected() {
  local output
  if output=$("$@" 2>&1); then
    fail "unexpected success: $*"
  fi
  grep -Fq "$EXPECT_REJECTION" <<<"$output" || fail "rejection for $* did not contain $EXPECT_REJECTION: $output"
}

git init --initial-branch=main "$tmp/source" >/dev/null
git -C "$tmp/source" config user.email proof@example.invalid
git -C "$tmp/source" config user.name proof
printf 'main\n' >"$tmp/source/file"
git -C "$tmp/source" add file
git -C "$tmp/source" commit -m main >/dev/null
git -C "$tmp/source" checkout -b hidden >/dev/null
printf 'hidden\n' >"$tmp/source/hidden"
git -C "$tmp/source" add hidden
git -C "$tmp/source" commit -m hidden >/dev/null
git -C "$tmp/source" checkout main >/dev/null
git -C "$tmp/source" checkout -b agent/repository-proof/initial >/dev/null
printf 'initial\n' >"$tmp/source/agent"
git -C "$tmp/source" add agent
git -C "$tmp/source" commit -m initial >/dev/null
git -C "$tmp/source" checkout main >/dev/null

container=$(docker run -d -p 127.0.0.1::8081 -v "$tmp/source:/seed:ro" "$image" -listen 0.0.0.0:8081)
port=$(docker port "$container" 8081/tcp | sed 's/.*://')
url="http://127.0.0.1:${port}/repository-agent-lifecycle-fixture.git"
for _ in {1..30}; do
  if curl --fail --silent "http://127.0.0.1:${port}/healthz" >/dev/null; then break; fi
  sleep 1
done
curl --fail --silent "http://127.0.0.1:${port}/healthz" >/dev/null || fail "health never became ready"

for path in /var/lib/repository-backend /var/lib/repository-backend/repository-agent-lifecycle-fixture.git; do
  [[ "$(docker exec "$container" stat -c '%u:%g %a' "$path")" == "65532:65532 750" ]] || fail "mode/owner mismatch for $path"
done
docker exec -u 0 "$container" chmod 0755 /var/lib/repository-backend/repository-agent-lifecycle-fixture.git
if curl --silent --output /dev/null --write-out '%{http_code}' "http://127.0.0.1:${port}/healthz" | grep -qx 200; then
  fail "health accepted an incorrect repository mode"
fi
docker exec -u 0 "$container" chmod 0750 /var/lib/repository-backend/repository-agent-lifecycle-fixture.git
curl --fail --silent "http://127.0.0.1:${port}/healthz" >/dev/null || fail "health did not recover after mode restoration"

docker exec -u 65532:65532 "$container" git -c safe.directory=/seed -C /var/lib/repository-backend/repository-agent-lifecycle-fixture.git fetch /seed \
  refs/heads/main:refs/heads/main \
  refs/heads/hidden:refs/heads/hidden \
  refs/heads/agent/repository-proof/initial:refs/heads/agent/repository-proof/initial >/dev/null
hidden=$(git -C "$tmp/source" rev-parse hidden)
for version in 0 1; do
  if ! advertisement=$(git -c protocol.version="$version" ls-remote "$url" 2>&1); then
    docker logs "$container" >&2 || true
    fail "v${version} advertisement failed: $advertisement"
  fi
  grep -q 'refs/heads/main$' <<<"$advertisement" || fail "v${version} omitted main advertisement"
  grep -q 'refs/heads/agent/repository-proof/initial$' <<<"$advertisement" || fail "v${version} omitted proof advertisement"
  ! grep -q 'refs/heads/hidden$' <<<"$advertisement" || fail "v${version} advertised hidden ref"
  git init "$tmp/fetch-v${version}" >/dev/null
  expect_fail git -C "$tmp/fetch-v${version}" -c protocol.version="$version" fetch "$url" "$hidden"
done

git -c protocol.version=1 clone "$url" "$tmp/writer-a" >/dev/null
git -C "$tmp/writer-a" config user.email proof@example.invalid
git -C "$tmp/writer-a" config user.name proof
git -C "$tmp/writer-a" config protocol.version 1
git -C "$tmp/writer-a" fetch origin refs/heads/agent/repository-proof/initial:refs/remotes/origin/proof
git -C "$tmp/writer-a" checkout -b proof origin/proof >/dev/null
EXPECT_REJECTION='deletion prohibited' expect_rejected git -C "$tmp/writer-a" push origin :refs/heads/agent/repository-proof/initial
EXPECT_REJECTION='outside writable namespace' expect_rejected git -C "$tmp/writer-a" push origin HEAD:refs/tags/repository-proof-outside
printf 'fast-forward\n' >>"$tmp/writer-a/agent"
git -C "$tmp/writer-a" commit -am fast-forward >/dev/null
git -C "$tmp/writer-a" push origin HEAD:refs/heads/agent/repository-proof/initial >/dev/null
git -C "$tmp/writer-a" reset --hard HEAD~1 >/dev/null
printf 'force\n' >>"$tmp/writer-a/agent"
git -C "$tmp/writer-a" commit -am force >/dev/null
EXPECT_REJECTION='non-fast-forward' expect_rejected git -C "$tmp/writer-a" push --force origin HEAD:refs/heads/agent/repository-proof/initial

cas="$tmp/writer-a"
git -C "$cas" fetch origin refs/heads/agent/repository-proof/initial:refs/remotes/origin/proof
git -C "$cas" checkout proof >/dev/null
git -C "$cas" reset --hard origin/proof >/dev/null
advertised_old=$(git -C "$cas" rev-parse HEAD)
printf 'winner\n' >>"$cas/agent"
git -C "$cas" commit -am winner >/dev/null
winner=$(git -C "$cas" rev-parse HEAD)
printf 'loser\n' >>"$cas/agent"
git -C "$cas" commit -am loser >/dev/null
loser=$(git -C "$cas" rev-parse HEAD)
git -C "$cas" merge-base --is-ancestor "$advertised_old" "$winner" || fail "winner did not descend from advertised old SHA"
git -C "$cas" merge-base --is-ancestor "$advertised_old" "$loser" || fail "loser did not descend from advertised old SHA"
git -C "$cas" merge-base --is-ancestor "$winner" "$loser" || fail "loser did not pass current-tip ancestry policy"
git -C "$cas" push origin "$winner":refs/heads/agent/repository-proof/initial >/dev/null

# Send the losing receive-pack request with the old SHA both proposals observed.
# Its new tip fast-forwards the winning ref, so the receive-pack update failure
# is solely the stale expected-old compare-and-swap check.
update="$advertised_old $loser refs/heads/agent/repository-proof/initial"
request="$tmp/stale-receive-pack.request"
{ printf '%04x%s\0report-status\n0000' $(( ${#update} + 19 )) "$update"; printf '%s\n^%s\n' "$loser" "$winner" | git -C "$cas" pack-objects --stdout --revs; } >"$request"
response=$(curl --silent --show-error --fail --header 'Content-Type: application/x-git-receive-pack-request' --data-binary @"$request" "$url/git-receive-pack") || fail "stale receive-pack RPC failed"
grep -Fq 'ng refs/heads/agent/repository-proof/initial failed to update ref' <<<"$response" || fail "fast-forward stale CAS rejection did not fail its expected-old update: $response"

echo "repository-backend image proof passed"
