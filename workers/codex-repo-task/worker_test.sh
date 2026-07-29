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
