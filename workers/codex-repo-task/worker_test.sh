#!/usr/bin/env bash
set -euo pipefail

fail_test() { printf 'worker JWT regression test: %s\n' "$*" >&2; exit 1; }

# Production runs commands through Mise. The CI test job invokes this script
# directly, so emulate only the `mise exec --` form used by the exercised code.
mise() {
  [[ "$1" == 'exec' && "$2" == '--' ]] || fail_test 'unexpected mise invocation'
  shift 2
  command "$@"
}

source workers/codex-repo-task/worker.sh

tmpdir=$(mise exec -- mktemp -d)
trap 'mise exec -- rm -rf "$tmpdir"' EXIT
CODEX_HOME="$tmpdir"

now=$(mise exec -- date +%s)
issued_at=$((now - 60))
expires_at=$((now + token_expiry_margin_seconds + 60))
payload=$(mise exec -- jq -cnr --argjson iat "$issued_at" --argjson exp "$expires_at" --arg marker '􏿿' '{iat: $iat, exp: $exp, marker: $marker} | @base64')
payload=${payload//+/-}
payload=${payload//\//_}
payload=${payload//=}
[[ "$payload" == *'_'* ]] || fail_test 'synthetic JWT payload must exercise base64url underscore decoding'
[[ "$payload" != *'='* ]] || fail_test 'synthetic JWT payload must omit base64 padding'
token="eyJhbGciOiJub25lIn0.${payload}.synthetic-signature"
mise exec -- jq -n --arg token "$token" '{tokens: {access_token: $token, refresh_token: ""}}' > "$CODEX_HOME/auth.json"

decoded_payload=$(decode_access_token_payload "$CODEX_HOME/auth.json")
decoded_issued_at=$(printf '%s' "$decoded_payload" | mise exec -- jq -er '.iat')
decoded_expires_at=$(printf '%s' "$decoded_payload" | mise exec -- jq -er '.exp')
[[ "$decoded_issued_at" == "$issued_at" ]] || fail_test 'decoder returned the wrong JWT iat'
[[ "$decoded_expires_at" == "$expires_at" ]] || fail_test 'decoder returned the wrong JWT exp'
validate_access_token_expiry >/dev/null 2>&1

expired_at=$((now - 1))
expired_payload=$(mise exec -- jq -cnr --argjson iat "$issued_at" --argjson exp "$expired_at" --arg marker '􏿿' '{iat: $iat, exp: $exp, marker: $marker} | @base64')
expired_payload=${expired_payload//+/-}
expired_payload=${expired_payload//\//_}
expired_payload=${expired_payload//=}
expired_token="eyJhbGciOiJub25lIn0.${expired_payload}.synthetic-signature"
mise exec -- jq -n --arg token "$expired_token" '{tokens: {access_token: $token, refresh_token: ""}}' > "$CODEX_HOME/auth.json"
if expired_output=$( (validate_access_token_expiry) 2>&1); then
  fail_test 'expired JWT unexpectedly passed validation'
fi
[[ "$expired_output" == *'access token is expired or expires too soon to start work'* ]] || fail_test 'expired JWT was rejected for the wrong reason'

near_expiry_at=$((now + token_expiry_margin_seconds - 1))
near_expiry_payload=$(mise exec -- jq -cnr --argjson iat "$issued_at" --argjson exp "$near_expiry_at" --arg marker '􏿿' '{iat: $iat, exp: $exp, marker: $marker} | @base64')
near_expiry_payload=${near_expiry_payload//+/-}
near_expiry_payload=${near_expiry_payload//\//_}
near_expiry_payload=${near_expiry_payload//=}
near_expiry_token="eyJhbGciOiJub25lIn0.${near_expiry_payload}.synthetic-signature"
mise exec -- jq -n --arg token "$near_expiry_token" '{tokens: {access_token: $token, refresh_token: ""}}' > "$CODEX_HOME/auth.json"
if near_expiry_output=$( (validate_access_token_expiry) 2>&1); then
  fail_test 'JWT inside the safety margin unexpectedly passed validation'
fi
[[ "$near_expiry_output" == *'access token is expired or expires too soon to start work'* ]] || fail_test 'JWT inside the safety margin was rejected for the wrong reason'

submodule_test_root=$(mise exec -- mktemp -d)
trap 'mise exec -- rm -rf "$tmpdir" "$submodule_test_root"' EXIT
mise exec -- git init --quiet "$submodule_test_root/submodule-origin"
mise exec -- git -C "$submodule_test_root/submodule-origin" config user.name test
mise exec -- git -C "$submodule_test_root/submodule-origin" config user.email test@example.invalid
printf 'baked theme content\n' > "$submodule_test_root/submodule-origin/theme.txt"
mise exec -- git -C "$submodule_test_root/submodule-origin" add theme.txt
mise exec -- git -C "$submodule_test_root/submodule-origin" commit --quiet -m initial
submodule_sha=$(mise exec -- git -C "$submodule_test_root/submodule-origin" rev-parse HEAD)

mise exec -- git init --quiet "$submodule_test_root/super-origin"
mise exec -- git -C "$submodule_test_root/super-origin" config user.name test
mise exec -- git -C "$submodule_test_root/super-origin" config user.email test@example.invalid
mise exec -- git -C "$submodule_test_root/super-origin" -c protocol.file.allow=always submodule add --quiet "$submodule_test_root/submodule-origin" theme
mise exec -- git -C "$submodule_test_root/super-origin" commit --quiet -am submodule
mise exec -- git clone --quiet "$submodule_test_root/super-origin" "$submodule_test_root/checkout"

mise exec -- mkdir -p "$submodule_test_root/baked/theme" "$submodule_test_root/output"
mise exec -- cp "$submodule_test_root/submodule-origin/theme.txt" "$submodule_test_root/baked/theme/theme.txt"
printf 'submodule %s theme\n' "$submodule_sha" > "$submodule_test_root/dependency-manifest.inputs"
baked_manifest=$(mise exec -- sha256sum "$submodule_test_root/dependency-manifest.inputs" | mise exec -- cut -d ' ' -f 1)

cd "$submodule_test_root/checkout"
SUBMODULE_RESTORE_LOG_PATH="$submodule_test_root/output/submodules.txt" restore_baked_submodules "$submodule_test_root/dependency-manifest.inputs" "$submodule_test_root/baked" "$baked_manifest"
[[ "$(mise exec -- cat theme/theme.txt)" == 'baked theme content' ]] || fail_test 'baked submodule content was not restored'
mise exec -- git diff --ignore-submodules=all --quiet || fail_test 'restored submodule content must not create a diff'
[[ -z "$(mise exec -- git status --porcelain --ignore-submodules=all)" ]] || fail_test 'restored submodule content must not appear in status'

printf 'submodule %040d theme\n' 0 > "$submodule_test_root/stale-manifest.inputs"
stale_manifest=$(mise exec -- sha256sum "$submodule_test_root/stale-manifest.inputs" | mise exec -- cut -d ' ' -f 1)
if stale_output=$(SUBMODULE_RESTORE_LOG_PATH="$submodule_test_root/output/stale-submodules.txt" restore_baked_submodules "$submodule_test_root/stale-manifest.inputs" "$submodule_test_root/baked" "$stale_manifest" 2>&1); then
  fail_test 'stale baked submodule SHA unexpectedly passed restoration'
fi
[[ "$stale_output" == *"baked submodule theme is stale: checkout expects $submodule_sha"* ]] || fail_test 'stale baked submodule SHA was rejected for the wrong reason'
