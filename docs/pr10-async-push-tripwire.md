# PR10 Asynchronous Push Tripwire

This slice preserves ordinary Git smart-HTTP push and the agent's existing
GitHub App selection. It adds bounded preflight and post-admission security
seams; it does not enable production configuration or deploy anything.

## Opaque push preflight

For every `refs/heads/*` update in `git-receive-pack`, the broker parses only
the update command prefix, capped at 64 updates and 256 KiB. Malformed prefixes
are rejected with 400 and over-limit prefixes with 413; consumed bytes are
never forwarded after a parse failure. Deletions are rejected. A creation requires
the GitHub ref to be absent; an update requires the current GitHub ref SHA to
equal the advertised `before` SHA. These reads and the eventual push use the
same configured App and installation. The pack remains opaque and streams
unchanged after preflight without whole-body buffering; original content length
and protocol headers are preserved. GitHub still enforces protected-branch and
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

`Idempotency-Key` is mandatory. The main broker and sandbox broker open the
same SQLite authority state file. Sandbox startup atomically registers every
reviewed `authority_profiles.*.issuance_generation`; the response transaction
refuses to record or return `halted` unless that exact profile/generation is
registered. Both halt application and every authority-issuing store operation
use `BEGIN IMMEDIATE`. Provision/CreateWorker, lease acquisition (including
combined session admission), replacement, reassignment, and agentd session
creation query the exact catalog row and halt row on the same SQLite connection
and inside the transaction that owns the issuance mutation. Missing catalog
rows and catalog/halt read failures roll back without issuing authority.

The writer lock is the linearization boundary. If issuance owns it first,
`/respond` waits until that issuance commits or rolls back before it can return
`halted`. If the halt owns and commits the lock first, a fresh issuance observes
the halt and rolls back. Agentd session creation deliberately holds the writer
transaction across the external create and the durable session-ID bind, so the
same ordering covers that authority mutation. Combined session admission is
linearized by its lease commit; workspace allocation is non-authority
preparation, and the later agentd create has its own guarded transaction.
Already-committed exact lease, replacement, and reassignment results are read
before the fresh-issuance check and remain replayable after a halt; new effects
are denied.

Deployment must bind-mount the containing state directory read-write into both
containers, because SQLite also owns adjacent WAL/SHM files. Set main-broker
`push_tripwire.state_path` to the same underlying file as sandbox-broker
`authority_worker_store_path` (recommended canonical path:
`/srv/hermes-sandbox-broker/state/authority-workers.sqlite`) and keep each main
broker response-profile generation equal to the matching sandbox authority
profile `issuance_generation`. A file-only mount is not sufficient.

The current live sandbox API has no safe fencing
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
