# Phase 2 Plan

## Goal

Harden broker behavior after the v1 no-token flow is working.

## Candidate Work

- Add mTLS or stronger agent auth option.
- Add SSH Git transport if needed.
- Add broker-terminated Git receive for strict commit trailer enforcement.
- Add commit status/check creation.
- Add richer admin tooling for config validation and reload diagnostics.
- Keep the strict hygiene gate green: formatting, linting, tests, race tests, vulnerability checks, and builds.
- Add fake GitHub REST and fake Git smart-HTTP integration tests.
