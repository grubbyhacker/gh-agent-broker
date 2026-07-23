# Future C4 bilateral Docker-harness contract

This is a test-only contract. It is not a product configuration override.
The future opt-in Go test must refuse to start unless every item below holds.

## OCI source identity mapping

The future orchestrator verifies each digest-pinned image's OCI revision,
source, title, and target labels before creating its Docker network. These
checked-in mappings prevent a similarly named image from being accepted as a
C4 input:

| Logical image input | OCI title / target | Source location | Build revision input | Status |
| --- | --- | --- | --- | --- |
| `C4_GIT_HTTP_FIXTURE_IMAGE` | `c4-bilateral-git-http-fixture` | `testdata/c4-bilateral-fixture/Dockerfile` and `main.go` | Docker build arg `C4_FIXTURE_REVISION` | Implemented; the Dockerfile applies fixed source/title/target labels and the supplied revision label. |
| `C4_BROKER_FIXTURE_BOOTSTRAP_IMAGE` | `c4-bilateral-broker-bootstrap` | No checked-in bootstrap source or Dockerfile exists yet. | None; no image may be accepted. | **Fail closed.** The C4 orchestrator must not be run until a broker-owned bootstrap source and Dockerfile are added with the same OCI-label contract. |

The bootstrap image must never be mapped to the production broker Dockerfile:
its test-only source must be explicit and independently identity-labeled.

1. Docker must already target the disposable `greenpr` Colima context. The test
   must require an explicit opt-in and immutable agentd and broker image
   references; it must not select a Docker context, fall back to the default
   daemon, or use a tag-only image reference.
2. Create one internal Docker network and attach the real broker, fixture, and
   exact `git-push-smoke` agentd child to it. The real broker is the **only**
   container with the network alias `broker`. The child remote is exactly
   `http://broker:8080/git/grubbyhacker/repository-worker-lifecycle-test.git`.
   `--add-host`, `127.0.0.1`, host networking, and a fake or in-process broker
   are forbidden.
3. Generate one disposable RSA key pair. Mount the private key read-only into
   the real broker and its paired public key read-only into this fixture; the
   agentd child receives neither. Set the fixture issuer to the broker's exact
   configured App ID. The fixture validates the broker JWT as GitHub documents:
   RS256 signature using that public key, exact `iss`, present/non-future
   `iat`, and non-expired `exp` no more than ten minutes ahead. The generated,
   test-only broker config must set both GitHub API and Git base URLs to the
   fixture container's DNS name (which is not `broker`), use installation `42`,
   and contain only the exact fixture repository. It provides the real broker
   App private-key path, never a worker credential. The fixture starts with
   `main` containing the required pending `fixture-task.md` (therefore the
   child sees `origin/main`), and rejects requests outside that API and
   repository path.
4. Seed the broker authority SQLite store only through
   `newC4BilateralAuthorityFixture`. That helper provisions a real authority
   worker, marks it ready, acquires the exact registered lease, binds the
   agentd session, records an authorized effect custody record, and mints the
   effect credential through `MintGitCredential`. Direct SQL seed rows are
   forbidden.
5. Configure `general-writer-v1 -> fleiglabs-repo-agent` as the sole
   profile-to-policy-agent mapping while the durable authority principal is
   `authority-worker-operator`. The identities must remain distinct. This is
   the regression predicate: an implementation that looks up the control
   principal as a configured Git/App agent must stop at `credential_rejected`.
6. The future opt-in orchestrator is the sole producer of the key pair, broker
   authority fixture, Docker network, containers, and bounded evidence bundle.
   On any failed assertion it must fail-stop: retain only bounded sanitized
   child status/stderr, broker stage audit records, and transport rows; never
   write the effect credential, App JWT, installation token, private key, or an
   authorization header. Do not continue to another case. Structural cleanup
   is only `colima delete --profile greenpr`.

The first positive Git discovery must prove, in order: DNS/connect to the
`broker` alias, unauthenticated challenge, credential-helper Basic retry,
`credential_accepted`, `custody_barrier_committed`, `received`, `forwarded`,
and a successful smart-Git advertisement. The fixture's token endpoint and
real `git http-backend` ensure that this also crosses the broker's real App
installation-token flow without GitHub access.
