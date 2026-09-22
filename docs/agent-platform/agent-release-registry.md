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

- a **publisher** may submit one Docker archive and provenance; it cannot promote or launch;
- a **promoter** may promote a verified, acquired generation; it cannot launch;
- the **broker** derives the immutable local image ID, verifies policy, and records availability;
- runtime callers name an agent type — never an image, release, or generation.

The registry enforces the state machine. It does not authenticate principals: every
mutating operation takes an `actor` string, recorded in the audit trail, and refuses
an empty one. Binding those operations to authenticated identities is the next piece
of work (see below).

## Publish and broker-owned acquisition

The sole caller-facing artifact endpoint is `POST /v1/releases/publish`, guarded
by `release.publish`. It accepts the versioned `docker-archive/v1` multipart
protocol: provenance plus one bounded, single-image Docker archive produced by
trusted protected-main CI. The separate `release_artifact_byte_limit` applies to
this binary upload. Docker archives may identify the image config using either
the legacy `<sha256>.json` member or Buildx's `blobs/sha256/<sha256>` member;
both names are path-validated and the config bytes must hash to that identity.
Validation uses two targeted archive passes: first `manifest.json`, then only its
exact config member. Buildx layer blobs are never buffered or parsed as metadata.
When a Buildx `index.json` is present, the broker verifies its single
index→manifest→config digest/size/platform chain and uses the OCI manifest digest
that Docker exposes as the loaded image ID. Legacy archives without an index use
the verified config digest as Docker's image ID.

`release.verify` and `release.acquire` are not public routes or caller actions.
The broker derives provenance fields and accepted platforms from deployment-owned
`agent_release_policies`. It hashes the archive's image config to derive Docker's
immutable local image ID, checks the image platform, loads the archive through the
Docker Engine, then inspects that exact ID and platform locally. Only then does it
mark the candidate available. The publisher cannot supply requirements, an image
reference, or an availability assertion. Verification and acquisition carry
distinct internal audit actors.

`publish` → internal `verify` → internal `acquire` → `promote`, with `rollback`
as a separate, audited operation. A missing, mismatched, or load-failed image stays
non-promotable.

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

**The authenticated promotion HTTP surface uses action-scoped operator principals.**
`/v1/releases` exposes `release.publish`, `release.promote`, and
`release.rollback`; only the latter two are action-scoped operator transitions.
The current verifier compares a dedicated
promoter bearer token with the configured `OperatorPrincipal`, while protected-main
CI is the trust anchor for issuing that credential.

Authentication and authorization are deliberately separate. The REST handler asks a
`PromoterAuthenticator` to verify a request into a `VerifiedPromoter`, then checks
the requested action against that identity's `allowed_actions` before calling the
registry. Replacing bearer verification with GitHub OIDC will therefore change only
the authenticator implementation and its configuration, not registry operations or
their audit records. There is no OIDC fallback or partial verifier.

Binding is enforced at configuration load: a principal with `release.promote` cannot
also hold either launch action (`launch` or `dry_run`), and `release.rollback` is a
separate permission which promotion never implies.

**Release resolution remains independently scoped.** The launch path resolves the
active digest-pinned generation only for templates that declare an `agent_type`.
The promotion API changes registry state but does not otherwise change launch
behaviour or let callers choose an image, release, or generation.

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
