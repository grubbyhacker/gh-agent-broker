# PR10 Asynchronous Push Tripwire

This slice preserves ordinary Git smart-HTTP push and the agent's existing
GitHub App selection. It adds bounded preflight and post-admission security
seams; it does not enable production configuration or deploy anything.

## Opaque push preflight

For every `refs/heads/*` update in `git-receive-pack`, the broker parses only
the bounded update command prefix. Deletions are rejected. A creation requires
the GitHub ref to be absent; an update requires the current GitHub ref SHA to
equal the advertised `before` SHA. These reads and the eventual push use the
same configured App and installation. The pack remains opaque and is forwarded
unchanged after preflight. GitHub still enforces protected-branch and
non-fast-forward policy. Any receive-pack `ng <ref>` status is surfaced
unchanged and audited as `github_ref_update_rejected` without interpreting
English reason text. Upload-pack remains streamed and unbuffered.

## Scanner material

`POST /v1/security/push-tripwire/material` accepts a dedicated Bearer scanner
principal and strict `broker/push-tripwire/v1` identity:

```json
{"version":"broker/push-tripwire/v1","delivery_id":"delivery-01","repository":"owner/repo","ref":"refs/heads/agent/worker/change","before":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","after":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
```

Repository, App, installation, base ref, and anchored admitted-ref patterns are
selected only from reviewed broker configuration. Requests cannot supply a URL,
command, App, installation, or base. Existing branches traverse the exact
`before...after` commit set. New branches resolve the configured base ref and
accept bounded `ahead` or `diverged` head-side history, which tolerates the base
advancing after checkout. Each pushed commit is diffed against its first parent
using complete recursive trees. Both before and after blob sides are returned,
so deleted files and content introduced then removed in the same push remain
scannable.

The response includes deterministic commit/path ordering, exact decoded
`size`, and `bounds` with emitted commit count, emitted file-side count, and
decoded bytes. Limits charge every emitted file side, including repeated blob
SHAs. Missing pages, truncated trees, unsupported entries, invalid encodings,
unavailable sides, ancestry ambiguity, and any bound overflow return HTTP 200
with `complete:false`, a bounded `reason_code`, empty commits/files, and zero
bounds. Consumers must treat incomplete material as high severity, never clean.

## Response controls

`POST /v1/security/push-tripwire/respond` uses the canonical request fixture at
`testdata/push-tripwire/response-request.json`. Strict parsing rejects extra
fields. The configured response profile fixes the exact active generation,
allowed actions, and complete worker binding: logical session, session lineage,
worker, storage lineage, and positive fence epoch. Caller-named profiles,
generations, actions, and unreviewed bindings are rejected before persistence.

`Idempotency-Key` is mandatory. The SQLite transaction durably records
`halt_issuance` before returning `halted`; `CheckIssuance` fails closed on a
halt or state read error. The current live sandbox API has no safe fencing
operation, so the strict fence adapter seam returns `fence_requested` unless an
adapter confirms the complete binding, when it advances to `fenced`. Exact
replays retry a still-requested fence, allowing recovery after a transient
adapter failure or restart. Every action carries an RFC3339Nano `completed_at`.
The state enum is exactly `halted`, `fence_requested`, and `fenced`; requested
work is never reported as fenced.

Reload cannot change whether the tripwire is enabled or its state path. A
restart is required, preventing an ordinary SIGHUP from abandoning durable
issuance halts. Enabling the feature and providing a live fence adapter remain
separate reviewed deployment work in `vps-ops`.

