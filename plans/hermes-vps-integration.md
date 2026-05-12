# Hermes VPS Integration Plan

This plan is safe to keep in the public repo. Replace every placeholder in a
private VPS config before running the broker.

## Topology

- Run `gh-agent-broker` as its own Docker Compose project on the VPS.
- Keep Hermes and the broker on the same host, connected by either:
  - a private Docker network shared with the Hermes agent container, or
  - a localhost port published only on `127.0.0.1`.
- Point Hermes Git remotes at the broker:
  `http://127.0.0.1:8080/git/OWNER/REPO.git` or
  `http://gh-agent-broker:8080/git/OWNER/REPO.git` on a shared Docker network.
- The broker is the only component that mounts the GitHub App private key.
- Hermes agents receive only broker credentials: agent ID and broker agent
  secret.

## Ports, Volumes, And Secrets

- Broker listen address: `127.0.0.1:8080` for host-local access, or
  `0.0.0.0:8080` inside a private Docker network with no public port publish.
- Host port publish, when used: `127.0.0.1:8080:8080`.
- Config mount: `./configs/production.yaml:/etc/gh-agent-broker/config.yaml:ro`.
- GitHub App key mount:
  `./secrets/github-app.pem:/run/secrets/github-app.pem:ro`.
- Audit mount: prefer a named Docker volume at `/var/log/gh-agent-broker`.
  If using a host bind mount such as `./audit:/var/log/gh-agent-broker`, make
  it writable by container UID `65532`.
- Required environment variables:
  - `BROKER_ADMIN_SECRET`
  - `HERMES_AGENT_BROKER_SECRET`
- Required private values in the config:
  - GitHub App ID
  - GitHub App installation ID for each repository
  - allowed repository names
  - agent ID and branch prefix

## First Install

1. Create a private copy of `configs/production.example.yaml`.
2. Fill in the GitHub App ID, installation IDs, repository names, agent ID, and
   branch patterns.
3. Put the GitHub App PEM at the configured key path with owner-only
   permissions.
4. Start the broker Compose project with the admin and agent secrets provided
   as environment variables.
5. Verify readiness:
   `gh-agent-broker-cli health -broker http://127.0.0.1:8080`.
6. Run a broker policy dry-run for the Hermes branch prefix before changing
   Hermes remotes.
7. Update the Hermes agent environment with `BROKER_URL`, `BROKER_AGENT_ID`,
   and `BROKER_AGENT_SECRET`.
8. Update Hermes Git remotes to the broker URL and perform a clone/fetch before
   attempting a push.

## Hermes Agent Guidance

- Use the broker remote only; do not configure GitHub token remotes inside
  Hermes.
- Use `BROKER_URL`, `BROKER_AGENT_ID`, and `BROKER_AGENT_SECRET` from the
  container environment.
- Include configured metadata such as `Agent-Id` and `Hermes-Run-Id` on broker
  PR/comment calls.
- Use distinct `Hermes-Run-Id` values for parent and subagent work so audit
  events can be separated.
- Subagents with the same permission set may share one broker identity.
- Subagents needing different repository access, branch rules, or GitHub
  permissions should use separate broker identities and policy blocks; prefer
  separate containers when stronger runtime isolation matters.
- A Hermes skill or runbook should document these broker-specific rules so
  agents do not fall back to direct GitHub-token workflows.

## Rollback

1. Stop the broker Compose project.
2. Restore the Hermes Git remote to the previous GitHub URL.
3. Remove `BROKER_URL`, `BROKER_AGENT_ID`, and `BROKER_AGENT_SECRET` from the
   Hermes agent environment.
4. Preserve `./audit/audit.jsonl` for investigation.
5. Restore the last known-good broker config before restarting the broker.
6. If GitHub App permissions were changed, restore the prior permission set and
   reinstall or refresh the installation as required by GitHub.
