# AgentRelease registry

Stage 3 (broker side) of the agent platform coupling work. The cross-repo
architecture lives in `agent-infra-docs/design/agent-platform-coupling.md` and is
authoritative; this note records only what is true of `gh-agent-broker`.

If implementation shows the architecture is wrong, the correction lands in
`agent-infra-docs` first and this note follows.

## Why the broker owns this state

Today an agent's image reference is rendered into broker-owned configuration at
deploy time, so publishing a new agent requires converging the broker role — which
drags in the broker's entire deploy secret contract. That coupling is what this
design removes.

An AgentRelease is therefore **data the broker owns and resolves at launch**, not
configuration delivered by someone else's deploy. `internal/release` is that registry.

## Authority split

- a **publisher** may publish a candidate; it cannot promote and cannot launch;
- a **promoter** may promote a verified, acquired generation; it cannot launch;
- the **broker** resolves the active generation and is the sole runtime authority;
- **callers** name an agent type — never an image, release, or generation.

The registry enforces the state machine. It does not authenticate principals: every
mutating operation takes an `actor` string, recorded in the audit trail, and refuses
an empty one. Binding those operations to authenticated identities is the next piece
of work (see below).

## The five operations

`publish` → `verify` → `acquire` → `promote`, with `rollback` as a separate,
audited operation. Availability changes are recorded as `acquire` / `evict`.

Two properties are load-bearing.

**Monotonic generations.** Generations are broker-assigned via
`INTEGER PRIMARY KEY AUTOINCREMENT` and strictly increasing. `Promote` refuses a
generation at or below the currently active one, because neither digests nor commits
have a reliable total order. Returning to an earlier generation is `Rollback`, which
is deliberately a distinct operation rather than a side effect of promotion.

**Digest-pinned references only.** `PublishCandidate` refuses anything that is not
`<reference>@sha256:<64 hex>`. A tag can move underneath a run.

## Failing closed on image availability

The sandbox launches an image that is **already present**; it does not pull. The
registry is durable and backed up, but Docker image state is not — so a host
recovery, an image prune, or a state restore can leave an active release pointing at
an absent image.

`Resolve` therefore refuses when the active release is not locally available, rather
than attempting a launch. `Reconcile` re-checks every active release against a
supplied availability probe, marks the differences, and returns the generations that
need reacquiring by digest.

`DockerBackend.ImageAvailable` is that probe. It verifies the **digest**, not just
the reference, because a tag can resolve to a different image than the one a release
pins. A missing image is a negative answer; a transport failure is an error, so a
Docker hiccup is never mistaken for absence.

`cmd/sandbox-broker` runs reconciliation at startup when `release_store_path` is
configured. Startup does not abort on a missing image: the service has other duties
and refusing the affected launches is the correct blast radius. Missing generations
are logged loudly instead.

## What this deliberately does not do

**There is no authenticated promotion HTTP surface.** The design defers the promoter
identity — the exact GitHub OIDC claims and the broker token-exchange protocol — to
implementation, and shipping an endpoint that can change which executable code runs
in production before that authority is settled would be the wrong order.

**Nothing resolves releases at launch yet.** The sandbox still uses its configured
profile image. Switching the launch path to registry resolution is a separate change,
reviewed separately, because it alters runtime behaviour.

> **CI prerequisite for that change.** The `sandbox_e2e` path filter in
> `.github/workflows/ci.yml` enumerates packages explicitly rather than matching
> `internal/**`, and `internal/release/**` is deliberately absent while the registry is
> inert. The change that puts resolution in the launch path **must add it**, or a
> release-only change will silently skip the suite covering the code it feeds. This is
> correct today and wrong the moment resolution lands.

**The registry is not yet backed up.** The broker state backup allowlist admits
`manifest.json`, `launch-intents.sqlite`, `runs/`, and `issuance/issuance.json`, and
would reject a release registry. Extending that contract — and validating that a
restore can recover the artifacts the registry references, not just the SQLite file —
is a `vps-ops` change.

Until those land, `release_store_path` is unset in production and this package is
inert.

## Conventions followed

Same storage discipline as `internal/sandbox/launch_intents.go`: `modernc.org/sqlite`,
WAL journal, `synchronous=FULL`, verified `quick_check`, `PRAGMA user_version` schema
versioning, `STRICT` tables, a single connection, an absolute path, and `0600` file
mode. Every mutation is a transaction that also writes its audit row, so an operation
and its record cannot diverge.
