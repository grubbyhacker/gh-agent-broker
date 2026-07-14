# Retired Webhook-Derived Codex Worker Proof

## Status

This milestone is retired. It recorded the narrow Phase 5 proof that a GitHub
event could drive an idempotent sandbox launch and produce a ready-for-review
pull request against `grubbyhacker/apple-jobs-matcher`.

The proof established reusable broker mechanics:

- fixed launch profiles and deny-by-default caller overrides;
- durable idempotency and launch-intent recovery;
- launch-principal ownership and scoped run visibility;
- brokered Git and GitHub REST operations without exposing App credentials; and
- separate sandbox identities, credentials, and lifecycle policy.

It does not define an active production route, an authorized repository, a
showcase, or a future implementation plan. Do not restore its dispatcher
principal, repository authorization, webhook admission, or profile from this
record.

The authoritative post-proof architecture and implementation sequence live in
`vps-ops/docs/repository-agent-automation-roadmap.md`. Future tests and examples
must use the synthetic, non-production repository
`example/automation-target`.

The resident Hermes agent's legacy repository access is intentionally outside
this retired generalized route and remains managed by `vps-ops`.
