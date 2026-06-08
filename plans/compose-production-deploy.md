# Compose Production Deployment

This plan is safe to keep in the public repo. Replace every placeholder in a
private deployment config before running the broker.

## Topology

- Run `gh-agent-broker` as its own Docker Compose project on the deployment
  host.
- Keep Hermes and the broker on the same host, connected by either:
  - a private Docker network shared with the Hermes agent container, or
  - a localhost port published only on `127.0.0.1`.
- Point Hermes Git remotes at the broker:
  `http://127.0.0.1:8080/git/OWNER/REPO.git` or
  `http://gh-agent-broker:8080/git/OWNER/REPO.git` on a shared Docker network.
- The broker is the only component that mounts GitHub App private keys. The
  reporter MCP service uses a broker credential, not a GitHub App key.
- Hermes agents receive only broker credentials: agent ID and broker agent
  secret.

## Ports, Volumes, And Secrets

- Broker listen address: `127.0.0.1:8080` for host-local access, or
  `0.0.0.0:8080` inside a private Docker network with no public port publish.
- Host port publish, when used: `127.0.0.1:8080:8080`.
- Config mount: `./configs/production.yaml:/etc/gh-agent-broker/config.yaml:ro`.
- GitHub App key mounts:
  `./secrets/github-coder-app.pem:/run/secrets/github-coder-app.pem:ro` and
  `./secrets/github-reporter-app.pem:/run/secrets/github-reporter-app.pem:ro`.
  Curator deployments also mount
  `./secrets/github-ykm-curator-app.pem:/run/secrets/github-ykm-curator-app.pem:ro`.
- Audit mount: prefer a named Docker volume at `/var/log/gh-agent-broker`.
  If using a host bind mount such as `./audit:/var/log/gh-agent-broker`, make
  it writable by container UID `65532`.
- Image source: use a CI-published pinned image tag through
  `BROKER_IMAGE=ghcr.io/grubbyhacker/gh-agent-broker:sha-COMMIT`.
- Required environment variables:
  - `BROKER_ADMIN_SECRET`
  - `HERMES_AGENT_BROKER_SECRET`
  - `BROKER_REPORTER_01_SECRET`
- Required private values in the config:
  - GitHub App IDs
  - GitHub App installation ID for each repository
  - allowed repository names
  - agent ID and branch prefix

## First Install

1. Create a private copy of `configs/production.example.yaml`.
2. Fill in the GitHub App IDs, installation IDs, repository names, agent ID, and
   branch patterns.
3. Put the GitHub App PEM files at the configured key paths with owner-only
   permissions.
4. Put the admin and agent secrets in the host-owned `.env` file, using
   `.env.example` only as a variable-name template.
5. Pull and start the pinned image:

   ```sh
   BROKER_IMAGE=ghcr.io/grubbyhacker/gh-agent-broker:sha-COMMIT \
     docker compose -f docker-compose.production.example.yml pull
   BROKER_IMAGE=ghcr.io/grubbyhacker/gh-agent-broker:sha-COMMIT \
     docker compose -f docker-compose.production.example.yml up -d
   ```

6. Verify readiness:
   `docker compose -f docker-compose.production.example.yml exec broker gh-agent-broker-cli health -broker http://127.0.0.1:8080`
   or `gh-agent-broker-cli health -broker http://127.0.0.1:8080` from a host
   install.
7. Run a broker policy dry-run for the Hermes branch prefix before changing
   Hermes remotes.
8. Update the Hermes agent environment with `BROKER_URL`, `BROKER_AGENT_ID`,
   and `BROKER_AGENT_SECRET`.
9. Update Hermes Git remotes to the broker URL and perform a clone/fetch before
   attempting a push.

## Artifact And Release Policy

- `main` should stay releasable and protected by required CI.
- Use short-lived feature branches and PRs; avoid a long-lived `develop`
  branch unless multiple active release trains become necessary.
- CI publishes `ghcr.io/grubbyhacker/gh-agent-broker` as the broker service
  artifact.
- After the first publish, confirm the GHCR package is public if deployment
  hosts should pull without registry credentials.
- Image tags:
  - immutable deploy tags: `sha-COMMIT`
  - convenience branch tag: `main`
  - release tags: `v0.1.0`, `v0.1.1`, and so on
- Deployment hosts should pin `sha-COMMIT` or semver release tags, not `main` or
  `latest`.
- Semver tag builds also publish `gh-agent-broker-linux-amd64`,
  `gh-agent-broker-cli-linux-amd64`, and `SHA256SUMS` on GitHub Releases.
- Treat the CLI binary as an agent runtime artifact; treat the OCI image as the
  broker service artifact.
- CI does not deploy to production. Deployment is manual after verifying the
  commit; a future `workflow_dispatch` deploy job can add an environment
  approval gate.

## Agent CLI Distribution

The broker image includes `/usr/local/bin/gh-agent-broker-cli` for operator
checks inside the broker container. Agent containers should also have the CLI
when they need broker-mediated probe, dry-run, PR, or comment operations.
Issue creation is intentionally not a CLI workflow in the current deployment
model; expose it through the host-side reporter MCP service instead.

Short-term, extract the CLI from the same pinned broker image and bind-mount it
into the agent container:

```sh
mkdir -p ./bin
docker create --name broker-extract ghcr.io/grubbyhacker/gh-agent-broker:sha-COMMIT
docker cp broker-extract:/usr/local/bin/gh-agent-broker-cli ./bin/gh-agent-broker-cli
docker rm broker-extract
chmod 0755 ./bin/gh-agent-broker-cli
```

Long-term, download the pinned release binary and verify its checksum before
baking it into an agent image or bind-mounting it:

```sh
curl -fsSLO https://github.com/grubbyhacker/gh-agent-broker/releases/download/v0.1.0/gh-agent-broker-cli-linux-amd64
curl -fsSLO https://github.com/grubbyhacker/gh-agent-broker/releases/download/v0.1.0/SHA256SUMS
grep 'gh-agent-broker-cli-linux-amd64' SHA256SUMS | sha256sum -c -
install -m 0755 gh-agent-broker-cli-linux-amd64 ./bin/gh-agent-broker-cli
```

If the agent runtime supports skills, install `skills/gh-agent-broker` so the
agent prefers CLI commands over ad hoc REST calls.

## Reporter MCP Service

Run `broker-issue-reporter` as a separate service from the same pinned image
when agents need to file issues. Override the image entrypoint to
`/usr/local/bin/broker-issue-reporter`, mount a private
`configs/reporter.yaml`, and provide only `BROKER_REPORTER_01_SECRET` to that
service. Do not mount that reporter credential into Hermes or other agent
containers.

The reporter should point at a broker principal such as `broker-reporter-01`
that uses a separate issues-only GitHub App context. Configure Hermes MCP with
the reporter URL, for example `http://broker-issue-reporter:8090/mcp`, and let
agents call only `broker_report_issue` for issue creation.

## Hermes Agent Guidance

- Use the broker remote only; do not configure GitHub token remotes inside
  Hermes.
- Use `BROKER_URL`, `BROKER_AGENT_ID`, and `BROKER_AGENT_SECRET` from the
  container environment.
- Include configured metadata such as `Agent-Id` and `Hermes-Run-Id` on broker
  PR/comment calls.
- Use the reporter MCP tool for issue creation. Do not inject reporter broker
  credentials into Hermes containers or subagent sandboxes.
- Use distinct `Hermes-Run-Id` values for parent and subagent work so audit
  events can be separated.
- Subagents with the same permission set may share one broker identity.
- Subagents needing different repository access, branch rules, or GitHub
  permissions should use separate broker identities and policy blocks; prefer
  separate containers when stronger runtime isolation matters.
- A Hermes skill or runbook should document these broker-specific rules so
  agents do not fall back to direct GitHub-token workflows.

## Rollback

1. Set `BROKER_IMAGE` back to the previous known-good SHA or semver tag.
2. Run the same `docker compose pull` and `docker compose up -d` commands.
3. Verify readiness before sending Hermes traffic back through the broker.
4. Preserve `./audit/audit.jsonl` for investigation.
5. Restore the last known-good broker config if the rollback is config-related.
6. If GitHub App permissions were changed, restore the prior permission set and
   reinstall or refresh the installation as required by GitHub.
7. If disabling broker usage entirely, restore the Hermes Git remote to the
   previous GitHub URL and remove `BROKER_URL`, `BROKER_AGENT_ID`, and
   `BROKER_AGENT_SECRET` from the Hermes agent environment.
