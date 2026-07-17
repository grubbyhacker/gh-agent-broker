# Sandbox E2E CI Strategy

The sandbox E2E suite protects a real container boundary, but the complete
suite is too broad and redundant to run after every broker edit. CI therefore
uses a fast representative path for pull requests while preserving the full
suite on `main`, releases, and a schedule.

## Baseline

The baseline sample is the 30 most recent completed pull-request runs returned
by the GitHub Actions API on 2026-07-16:

- sandbox E2E ran in 24 of 30 runs (80% trigger frequency);
- selected sandbox E2E jobs averaged 76.8 seconds, with a 66-90 second range;
- complete workflow elapsed time averaged 127 seconds, with a 52-163 second
  range; and
- sandbox E2E waited for the serial `check` job before it could start.

These are runner wall-clock measurements, not estimates from local execution.
The old path filter selected the suite for every change under `cmd/**` or
`internal/**`, including proxy, reporter, deploy-contract, and CLI-only work.

## Scenario-to-contract coverage

| Scenario | Contract or regression class | PR fast | Full |
| --- | --- | --- | --- |
| MCP authentication, tool discovery, template validation | Broker endpoint and fail-closed API surface | Yes | Yes |
| Rejected image override, repository, branch, and oversized task | Policy and input isolation | Yes | Yes |
| Dry-run branch generation | Broker launch contract | Yes | Yes |
| Live worker launch and clean exit | Docker lifecycle and broker/runtime integration | Yes | Yes |
| Container inspection | Non-root user, resource limits, network, mounts, and credential isolation | Yes | Yes |
| Logs, artifacts, lessons, and audit scan | Collection and secret redaction | Yes | Yes |
| Run cleanup | Container and run-directory cleanup | Yes | Yes |
| Second task marker | Cross-run artifact isolation | No | Yes |
| Missing required deliverables | Wrapper failure diagnostics | No | Yes |
| Forced deadline | Timeout, termination, and timeout diagnostics | No | Yes |
| Explicit stop of a running worker | Operator stop lifecycle | No | Yes |

Unit, race, and package integration tests remain the primary coverage for
policy permutations, service state transitions, retention, reconciliation,
REST authorization, runtime request construction, and kernel UID isolation.
The Dockerized fast path proves that representative broker, lifecycle,
isolation, redaction, and cleanup behavior is wired together in a real runtime.

## Test split and invalidation

Pull requests run `make sandbox-e2e-fast` in parallel with `check` when a
sandbox runtime dependency changes. The filter is the dependency closure of
`cmd/sandbox-broker` and `cmd/sandbox-e2e`, plus their Dockerfile, build inputs,
harness, Makefile, and CI workflows. Proxy-only, reporter-only,
deploy-contract-only, worker-image-only, documentation, and unrelated CLI
changes do not invalidate this boundary. A newer package import must be added
to the filter in the same change that introduces the dependency.

Relevant pushes to `main` run `make sandbox-e2e`, so no PR-fast change reaches
the published broker image without the full suite. Every version tag also runs
the full suite before release artifacts publish, regardless of changed paths.
The scheduled workflow runs the full suite weekly and supports manual dispatch
to detect runner, base-image, and other environmental drift.

Superseded runs for the same pull request are cancelled. Push, release, and
scheduled runs are never cancelled by this policy.

## Incremental landing

The fast mode is a strict prefix of the existing full client flow; the full
mode remains the default. The rollout therefore does not remove a scenario
from `main` or release gating. Further optimization of the serial hygiene gate
or Docker build reuse can land independently after its own measurements,
without changing this coverage split.
