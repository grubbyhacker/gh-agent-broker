# Per-run capabilities (Stage 4)

Broker-side implementation of the per-run capabilities required by
`agent-infra-docs/design/agent-platform-coupling.md`. The transport decision is
settled: capabilities are broker-verified opaque handles, not self-verifying
signed tokens.

## Claims and policy

`internal/capability` defines immutable claims:

```
work_item_id, agent_type, mode, run_id, allowed_models, call_budget,
token_budget, expiry
```

`Claims` keeps fields private and copies the allowed-model set in and out. Model
access has exactly two coherent states:

- **disabled:** no allowed models and both budgets zero; only identity-only
  operations with zero reservation are permitted.
- **enabled:** at least one allowed model and both budgets positive.

`PolicyEvaluator` validates expiry and exact identity, then enforces model
membership and call/token headroom with overflow-safe arithmetic. Consumers use
verified claims rather than caller-supplied `run_id` or other identity fields.
`cmd/capability-validate` checks these semantics offline.

## Opaque-handle store

`internal/capability/store.go` is the broker's sole mint authority:

- `Issue` generates a random 256-bit bearer handle, returns its plaintext once,
  and stores only the SHA-256 digest with server-side claims.
- `Verify` hashes the presented handle and returns trusted claims plus current
  reservation state. Malformed, unknown, revoked, expired, or incoherent state
  fails closed.
- `Reserve` performs read, authorization, and budget update in one transaction;
  concurrent or overflowing requests cannot exceed either budget.
- `Revoke` idempotently disables a handle.

Allowed model identifiers are stored as JSON, not a delimiter-joined string, so
serialization cannot split one identifier into multiple grants. Storage follows
the release registry's discipline: modernc SQLite, WAL, `synchronous=FULL`,
`quick_check`, versioned STRICT schema, one connection, absolute path, and
`0600` mode. `cmd/capability-store-validate` checks durable state offline.

## Private API and rollout state

`internal/capability/rest.go` provides authenticated private endpoints:

```
POST /v1/capabilities/verify
POST /v1/capabilities/reserve
POST /v1/capabilities/revoke
```

The sandbox broker mounts them only when `capability_store_path` and a nonempty
`capability_api_token` (normally via `capability_api_token_env`) are configured.
The handle is accepted only in the request body and is never echoed or logged.

## Model-proxy consumer integration

`internal/proxy` consumes the private capability API. When `capability_api_url`
and a nonempty `capability_api_token` are configured, `gh-agent-proxy` enforces
per-run capabilities on both model surfaces (`POST /v1/model/call` and the
Codex-compatible `POST /v1/responses`):

- The run authenticates with its opaque handle as the `Bearer` credential. The
  plaintext handle travels only in the proxy→broker request body, and is never
  logged, audited, persisted, or echoed to the caller.
- The proxy VERIFIES the handle against the broker, then ATOMICALLY RESERVES one
  call (with the model checked) BEFORE forwarding, and reserves observed tokens
  after. The broker's single-transaction `Reserve` is the only serialization
  point, so concurrent calls across goroutines/instances cannot exceed a budget.
- `run_id`, `work_item_id`, `agent_type`, and `mode` are derived from the
  verified claims. Caller-supplied identity is no longer trusted: a legacy body
  `run_id` or `X-GH-Agent-Run-ID` header that disagrees with the verified
  `run_id` is rejected rather than overridden.
- The allowed model is enforced against the verified `allowed_models`; a
  model-disabled capability may make no model call.
- It FAILS CLOSED on a missing handle, an unreachable/erroring API, expiry,
  revocation, budget exhaustion, and model denial.

The proxy authenticates to the API with the deployment-owned
`capability_api_token` (the same token the broker mounts the API with) — NOT any
run's handle, and that token is never injected into a launched run. When
`capability_api_url` is unset the proxy keeps its legacy static-token behavior,
so this is a safe additive rollout slice. Publisher/promoter separation and the
Codex alias→upstream mapping are unchanged.

## Rollout state

This line does **not** enable production, validate GitHub operations, migrate
static principals, or deploy. Those remaining consumer integrations are separate
rollout steps. `make check` is the gate.
