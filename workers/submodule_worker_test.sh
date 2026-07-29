#!/usr/bin/env bash
set -euo pipefail

fail_test() { printf 'worker submodule regression test: %s\n' "$*" >&2; exit 1; }

[[ $# == 1 ]] || fail_test 'expected the worker path as the only argument'
worker_path="$1"

# Production runs commands through Mise. The CI test job invokes this script
# directly, so emulate the `mise exec --` form used by worker helpers.
mise() {
  [[ "$1" == 'exec' && "$2" == '--' ]] || fail_test 'unexpected mise invocation'
  shift 2
  command "$@"
}

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT
export AGENT_IMAGE_WORKSPACE="$tmpdir/image-workspace"
export AGENT_IMAGE_DEPENDENCY_MANIFEST_PATH="$tmpdir/dependency-manifest.sha256"
export AGENT_IMAGE_DEPENDENCY_MANIFEST_OUTPUT_PATH="$tmpdir/dependency-manifest-output.txt"

source "$worker_path"

checkout="$tmpdir/checkout"
mkdir -p "$checkout" "$AGENT_IMAGE_WORKSPACE/theme"
printf 'baked theme layout\n' > "$AGENT_IMAGE_WORKSPACE/theme/baseof.html"
git -C "$checkout" init --quiet
git -C "$checkout" config user.name 'worker test'
git -C "$checkout" config user.email 'worker-test@example.invalid'
printf '[tools]\n' > "$checkout/mise.toml"
printf 'module example.test/worker-fixture\n\ngo 1.25.0\n' > "$checkout/go.mod"
printf 'example.test/module v0.0.0 h1:fixture\n' > "$checkout/go.sum"
git -C "$checkout" add mise.toml go.mod go.sum
git -C "$checkout" commit --quiet -m 'test fixture'

expected_sha='10d3dcc0aabbccddeeff00112233445566778899'
git -C "$checkout" update-index --add --cacheinfo "160000,$expected_sha,theme"
cd "$checkout"

matching_manifest=$(compute_dependency_manifest)
printf '%s\n' "$matching_manifest" > "$AGENT_IMAGE_DEPENDENCY_MANIFEST_PATH"
[[ "$(collect_submodule_manifest_entries)" == "submodule $expected_sha theme" ]] || fail_test 'manifest must include the checkout submodule SHA'
check_dependency_manifest
[[ "$manifest_status" == 'match' ]] || fail_test 'matching submodule SHA did not match the baked manifest'
[[ "$(<theme/baseof.html)" == 'baked theme layout' ]] || fail_test 'matching submodule was not hydrated from the baked workspace'
[[ ! -e theme/.git ]] || fail_test 'hydration must not require baked VCS metadata'

stale_sha='20d3dcc0aabbccddeeff00112233445566778899'
git update-index --cacheinfo "160000,$stale_sha,theme"
if mismatch_output=$( (check_dependency_manifest) 2>&1); then
  fail_test 'stale submodule SHA unexpectedly passed the baked manifest check'
fi
[[ "$mismatch_output" == *'baked submodule SHA does not match the checkout'* ]] || fail_test "stale submodule SHA was rejected for the wrong reason: $mismatch_output"
