# Per-run capability foundation (Stage 4, inert)

Broker-side foundation for the per-run capabilities the agent platform coupling
design commits to. The cross-repo architecture lives in
`agent-infra-docs/design/agent-platform-coupling.md` ("Per-mode authority must be
enforced at call time") and is authoritative; this note records only what is true
of `gh-agent-broker`.

## What is decided and implemented (inert)

`internal/capability` ships the strongly-typed **immutable claims** the design
binds into a per-run capability:

```
agent_type, mode, run_id, allowed_models, call_budget, token_budget, expiry
```

plus `work_item_id`, added because the merged (inert) run-to-PR correlation
outbox (`internal/correlation`) binds a correlation to its originating WorkItem.

`Claims` has only unexported fields and copies its allowed-model set in and out,
so a holder cannot mutate or widen a capability after construction. The identity
claims (agent_type, mode, run_id, work_item_id) and expiry are always required.
Model access has exactly two coherent states, matching AgentType declarations
like the deployed youknowme-curator `reconcile` mode (`model.access=false`):

- **model-disabled** — `allowed_models` empty AND both budgets zero. Authorizes
  identity-only broker operations; any model/call/token request is denied.
- **model-enabled** — `allowed_models` non-empty AND both budgets positive.

`NewClaims` rejects any mixed state (models without budget, budget without
models, one budget zero and the other positive, a blank model, a negative
budget).

`PolicyEvaluator` implements the mechanism-independent `Validator` and
`Authorizer` seams a consumer uses **instead of caller headers/body**: it checks
well-formedness, model-access coherence, expiry (a capability at or past its
expiry instant is expired), exact identity match on
agent_type / mode / run_id / work_item_id, and — for a model-enabled
capability — model membership in `allowed_models` and call/token budget headroom.
Against a model-disabled capability it allows an identity-only operation with
zero reservation and denies any model, call, or token request.
`cmd/capability-validate` is the offline claims-semantics validator.

## What is NOT decided, and therefore NOT implemented

The design commits to per-run capabilities as the mechanism but does **not**
decide **how a minted capability is serialized, signed, and its keys managed**
for transport from the broker (issuer) to a consumer (verifier). This package
represents those two roles as explicit, unimplemented seams:

- `Issuer.Issue(Claims) ([]byte, error)` — broker mints a transportable
  capability. Return type is opaque `[]byte` so the seam does not prejudge a
  token format.
- `Verifier.Verify([]byte) (Claims, error)` — consumer authenticates a
  transported capability back into trusted `Claims`.

**Remaining Stage-4 decision:** pick the concrete mechanism — a signed token
format (e.g. a compact JWS/PASETO-style envelope vs. a broker-verified opaque
handle), the key hierarchy, and rotation/escrow. The `Claims`, their validation,
and the authorization evaluator do not depend on that choice, so they land now;
the Issuer/Verifier implementations wait on the decision.

## Deliberately out of scope here

No production config, no launch wiring, no model-proxy consumer change, no static
per-mode principal migration, no deploy. Static per-mode principals remain the
design's migration fallback; nothing in this package migrates them. This is an
inert foundation, not the design complete.

## Durable store slice (broker-verified opaque handle)

The signing/serialization decision the seams left open is now DECIDED
(agent-infra-docs PR #19): a **broker-verified opaque 256-bit handle**, its
**SHA-256 hash stored at rest** in durable SQLite, **server-side claims**, an
**atomic verify+model-budget reservation**, a **private API**, and the broker as
**sole mint authority**. `internal/capability/store.go` implements exactly that,
reusing the merged immutable `Claims`/`PolicyEvaluator`:

- `Issue(claims)` mints a `crypto/rand` 256-bit handle, returns the plaintext
  **once**, and persists only its SHA-256. The plaintext is never stored, logged,
  or audited and cannot be recovered from the store.
- `Verify(handle)` hashes the presented handle, matches the stored hash (a
  malformed handle is rejected before lookup; the digest compare is
  constant-time), and returns trusted server-side `Claims` plus the current
  reservation. It fails closed on malformed/unknown/revoked/expired.
- `Reserve(handle, req)` authorizes and records a call/token reservation in ONE
  transaction against the CURRENT durable reserved totals, so concurrent
  reservations cannot exceed the budget. Model-disabled capabilities deny any
  model/call/token reservation.
- `Revoke(handle)` marks the capability revoked (idempotent); later
  verify/reserve fail closed.

Storage discipline matches `internal/release`: modernc sqlite, WAL,
`synchronous=FULL`, `quick_check`, `user_version` migration, STRICT tables,
single connection, absolute path, `0600`.

`internal/capability/rest.go` is the **private** sandbox-broker surface —
`POST /v1/capabilities/{verify,reserve,revoke}` — mounted by `cmd/sandbox-broker`
only when `capability_store_path` is configured, and every request must carry the
configured `capability_api_token` bearer (constant-time compared). The handle
travels in the request body and never appears in a response, log, or error.
`cmd/capability-store-validate` is the offline store validator.

Still deliberately out of scope in this slice: launch minting is NOT wired (no
launch path calls `Issue` yet), and neither the model proxy nor the GitHub broker
consumers are changed. No production config or deploy.
