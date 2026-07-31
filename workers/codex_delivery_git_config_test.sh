#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
test_root=$(mktemp -d)
trap 'rm -rf -- "$test_root"' EXIT
export BROKER_AGENT_ID='delivery-test'
export BROKER_AGENT_SECRET='delivery-test-secret'
export BROKER_URL='http://broker.invalid'
source "$repo_root/workers/codex-delivery/worker.sh"

repository="$test_root/repo"
git init -q -b agent/test "$repository"
printf '%s\n' initial > "$repository/tracked.txt"
git -C "$repository" -c user.name=test -c user.email=test@example.invalid add tracked.txt
git -C "$repository" -c user.name=test -c user.email=test@example.invalid commit -q -m initial

sentinel="$test_root/local-config-executed"
install -d -m 0700 "$repository/.git/malicious-hooks"
printf '#!/usr/bin/env bash\ntouch %q\n' "$sentinel" > "$repository/.git/malicious-hooks/pre-commit"
chmod 0700 "$repository/.git/malicious-hooks/pre-commit"
git -C "$repository" config core.hooksPath .git/malicious-hooks
git -C "$repository" config core.fsmonitor "!touch $sentinel"
git -C "$repository" config core.pager "touch $sentinel"
git -C "$repository" config pager.status true
git -C "$repository" config filter.host.clean "touch $sentinel"
git -C "$repository" config filter.host.smudge "touch $sentinel"
git -C "$repository" config diff.host.command "touch $sentinel"
git -C "$repository" config credential.helper "!touch $sentinel"
git -C "$repository" config sequence.editor "touch $sentinel"
printf '%s\n' '* filter=host diff=host' > "$repository/.gitattributes"
printf '%s\n' changed > "$repository/tracked.txt"

seal_repository_git_config "$repository"
trusted_git -C "$repository" status --porcelain >/dev/null
trusted_git -C "$repository" add --all
trusted_git -C "$repository" commit -q -m hardened

[[ ! -e "$sentinel" ]]
[[ ! -e "$repository/.git/config.worktree" ]]
[[ "$(git config --file "$repository/.git/config" core.hooksPath)" == /dev/null ]]
[[ "$(git config --file "$repository/.git/config" core.fsmonitor)" == false ]]
if git config --file "$repository/.git/config" --get-regexp \
  '^(filter|diff|credential|include|sequence|pager|core\.(editor|pager))' >/dev/null; then
  printf 'sealed delivery config retained an executable local setting\n' >&2
  exit 1
fi
