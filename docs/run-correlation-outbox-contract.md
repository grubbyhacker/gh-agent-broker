# Run-to-PR correlation and outbox handoff contract — `run-correlation-outbox/v1`

Contract version: **`run-correlation-outbox/v1`**
Status: **specification + configuration handoff. It does NOT authorize any
production deployment or activation.** The broker-side surface it describes is
implemented and unit-tested but ships **inert**: no listener, port, Cloudflare
route, or firewall rule is added, and every activation field is deployment-owned
and defaults to off.

This is the versioned interface between the **dispatcher** (Signal Plane),
the **broker** (`gh-agent-broker` + its private `sandbox-broker` capability
API), and the **launched run** (an AgentType-backed sandbox worker). It composes
the merged foundations:

- **#187** launch-time minting of one opaque per-run capability (AgentType-backed).
- **#188** proxy per-run capability enforcement on model surfaces.
- **#189 / #178** authenticated run-to-PR correlation on `pull.create` with a
  transactional outbox (`run-pr-correlation/v2` event envelope).
- **#181** the durable opaque-handle capability store + private verify/reserve/revoke API.

This contract adds the **outbox claim/ack/reclaim consumer protocol** and the
**production-activation configuration** the dispatcher needs, without changing
any of the above.

## Mechanical trust boundary

> **The broker owns durable side effects. The agent owns reasoning.**

Correlation identity is derived **only** from a broker-verified capability, never
from caller-supplied metadata, agent output, branch names, or PR-body markers. A
caller metadata field that disagrees with a verified claim is rejected
(`identity_mismatch`); absent fields are ignored. There is no path to synthesize
a correlation the broker cannot prove.

## 1. Dispatcher launch request

Signal Plane launches an AgentType-backed run through the existing reviewed
launch profile (e.g. `POST /v1/launch-profiles/terra-medium-v1/launch`) with a
stable `Idempotency-Key`. It does **not** supply `run_id`, `work_item_id`, or any
capability claim: `LaunchAgentInput` rejects unknown fields, and the broker
derives all capability claims from **deployment-owned policy + broker-generated
run identity**. The dispatcher supplies only the reviewed typed parameters and
the optional single `max_runtime_seconds` override.

## 2. Authoritative `work_item_id`

The broker holds no separate upstream WorkItem source, so **the broker-generated
run identity is the authority**: at launch the broker mints one capability whose
immutable `run_id` and `work_item_id` claims come from `newRunID()`. Every
downstream artifact — the verified capability, the correlation row, and the
outbox event — carries this same authoritative `work_item_id`. The dispatcher
correlates its own WorkItem to the run by the launch `Idempotency-Key` and the
returned `run_id`; it must treat the `work_item_id` in an outbox event as
authoritative and never overwrite it from its own records.

## 3. Capability handle transport

The plaintext opaque handle (256-bit, SHA-256 at rest) is injected **only into
the launched run's container environment transport** — never into logs, audit,
metadata, disk, or any response. Inside the run it rides a dedicated
**`X-Agent-Capability`** request header to the broker. The `Authorization`
header stays the agent credential that authorizes the GitHub repo/operation; the
capability establishes the originating run. The broker verifies the handle
against its private capability API (`/v1/capabilities/verify`) using the
deployment-owned `capability_api_token`, which is held **only by the broker** and
is never a run's handle and never enters a launched run's environment.

## 4. `pull.create` header + idempotency behavior

When correlation is configured, `POST /v1/repos/{owner}/{repo}/pulls`:

- **requires** `X-Agent-Capability` (a run handle) and a stable `Idempotency-Key`;
- verifies the handle and derives `agent_type` / `mode` / `run_id` /
  `work_item_id` from the **verified claims** and `operation_id` from the broker;
- fails closed: `401 capability_required` (missing), `403 capability_denied`
  (invalid/revoked/expired), `503 capability_unavailable` (API unreachable);
- after GitHub returns the PR number, records the correlation + outbox event in
  **one transaction**, idempotent on the broker `operation_id`.

The crash seam (GitHub success / local commit) is **bounded-recoverable**, not
best-effort: `GetByOperation` lets a retry after a crash learn whether the
correlation was already recorded and converge on exactly one event.

## 5. Correlation event — `run-pr-correlation/v2`

The versioned, bounded (≤ 8 KiB) outbox envelope. Every field is broker-derived:

```json
{
  "version": "run-pr-correlation/v2",
  "agent_type": "coder",
  "mode": "launch",
  "run_id": "run-...",
  "work_item_id": "wi-...",
  "operation_id": "op-...",
  "repo": "owner/repo",
  "pr_number": 190,
  "recorded_at": "2026-09-22T17:00:00Z"
}
```

A consumer must refuse an envelope `version` it does not understand.

## 6. Outbox claim/ack/reclaim protocol

The private consumer API lives on the broker's **existing authenticated
listener** under `/v1/correlation/outbox/`. Every request is `POST`, carries
`Authorization: Bearer <consumer_token>` (constant-time compared, never echoed),
and has a bounded (≤ 8 KiB) JSON body. The API is unmounted (404) unless the
correlation store **and** an outbox consumer token are configured.

Durable invariants (enforced by `internal/correlation`, not the endpoint):
one active claim per event (`UNIQUE(correlation_id)`), lease expiry / reclaim,
idempotent acknowledgement, bounded payloads, crash recovery (WAL,
`synchronous=FULL`, `quick_check`, single connection).

### `POST /v1/correlation/outbox/claim`

Claims up to `limit` pending (or lease-expired) events, stamping the consumer's
`claim_token` and incrementing `attempts`. `limit` is clamped to the
deployment-owned `max_claim_batch`; a non-positive limit means 1.

```json
// request
{ "claim_token": "signal-plane-instance-7", "limit": 50 }
// response 200
{ "events": [
  { "id": 12, "version": "run-pr-correlation/v2", "status": "claimed",
    "attempts": 1, "payload": { /* envelope from §5 */ },
    "claim_token": "signal-plane-instance-7",
    "claimed_at": "2026-09-22T17:00:01Z",
    "created_at": "2026-09-22T17:00:00Z", "updated_at": "2026-09-22T17:00:01Z" } ] }
```

A fresh claim is invisible to other consumers until it is acked, reclaimed, or
its lease expires (crash recovery).

### `POST /v1/correlation/outbox/ack`

Marks a claimed event delivered. Claim-token gated: `409 claim_mismatch` if the
event is not still claimed by this exact token (e.g. the lease expired and it was
reclaimed). `204` on success.

```json
{ "event_id": 12, "claim_token": "signal-plane-instance-7" }
```

### `POST /v1/correlation/outbox/reclaim`

The **negative acknowledgement**: releases a claimed event straight back to
pending so it is immediately claimable again, without waiting out the lease. Use
it for a transient downstream failure or a graceful shutdown. Claim-token gated
(`409 claim_mismatch`); `attempts` is **preserved** so a repeatedly-reclaimed
poison event stays visible to any future dead-letter policy. `204` on success.

```json
{ "event_id": 12, "claim_token": "signal-plane-instance-7" }
```

### Consumer loop

1. `claim` a bounded batch with a stable per-instance `claim_token`.
2. Deliver each event's `payload` idempotently downstream.
3. `ack` on success; `reclaim` on a deferrable failure; on a crash, do nothing —
   the lease expires and another instance reclaims it via `claim`.

Error codes are bounded and never echo a secret: `unauthorized` (401),
`method_not_allowed` (405), `claim_token_required` /
`event_id_and_claim_token_required` / `invalid json` / `request body invalid or
too large` (400), `claim_mismatch` (409), `not_found` (404).

## Production activation configuration (inert; not enabled here)

`internal/config` — `correlation.outbox`. Validated but never auto-enabled;
frozen across reload (a change requires a restart). Correlation **recording** and
the **outbox API** are independently gated: recording may be on with the outbox
API off. The consumer token is deployment-owned, sourced from an environment
variable via `consumer_token_env`, and is **distinct** from
`capability_api_token`.

```yaml
correlation:
  store_path: /srv/hermes-broker/correlation.sqlite
  capability_api_url: https://sandbox-broker.internal
  capability_api_token_env: BROKER_CAPABILITY_API_TOKEN
  outbox:
    # Signal Plane presents this bearer token to the broker to drain the outbox.
    # Empty (the default) leaves the outbox API inert / unmounted.
    consumer_token_env: BROKER_OUTBOX_CONSUMER_TOKEN
    claim_ttl_seconds: 300      # 30..3600, default 300 (lease before reclaimable)
    max_claim_batch: 100        # 1..1000, default 100 (hard claim-batch backstop)
```

Activation (setting the consumer token in the deployment environment, and any
listener/route exposure) is a separate, explicitly authorized deployment change
owned by the Signal Plane / vps-ops workstream. This contract does not perform it.
