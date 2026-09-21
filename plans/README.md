# plans/ — design records, not current architecture

**`plans/` is not a description of the current system.** These files are dated
design notes, milestone plans, and handoffs. Several describe work that is now
substantially implemented, so a reader could mistake them for the intended
architecture. For current state, read the code and `../AGENTS.md`; for
deployment, read `../docs/deploy.md`. Do not rebuild from a plan without first
confirming against the code whether it already exists.

Each file carries a status banner at its top. Classifications:

| File | Status | Why |
|------|--------|-----|
| `agent-handoff.md` | CURRENT HANDOFF | Living handoff context `AGENTS.md` requires be kept current; latest state-of-the-work note. |
| `codex-compatible-proxy-surface.md` | IMPLEMENTED — HISTORICAL PLAN | `/v1/responses`, `codex_allowed_models`, run-ID budgeting exist in `internal/proxy/proxy.go`. |
| `compose-production-deploy.md` | IMPLEMENTED — HISTORICAL PLAN | Topology realized in `docker-compose.production.example.yml`; deploy now automated via Actions + vps-ops. |
| `operator-rest-launch-profiles.md` | IMPLEMENTED — HISTORICAL PLAN | Launch-profile REST surface in `internal/sandbox/rest.go` + `launch_profiles` config. |
| `phase1.md` | IMPLEMENTED — HISTORICAL PLAN | v1 broker (auth, policy, GitHub App tokens, Git proxy, CLI) is the current production surface. |
| `phase2.md` | IMPLEMENTED — HISTORICAL PLAN | Hygiene gate, reload tooling, status/check-run observation, receive-pack policy landed; speculative mTLS/SSH bullets deliberately not built. |
| `sandbox-mcp-v1.md` | IMPLEMENTED — HISTORICAL PLAN | Sandbox broker exists as `cmd/sandbox-broker` + `internal/sandbox`. |
| `webhook-codex-worker-milestone.md` | RETIRED | Self-declared retired; defines no active production route. |

Roger intends to relocate these out of `plans/` gradually; that move is not part
of this note.
