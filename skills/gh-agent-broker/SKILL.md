---
name: gh-agent-broker
description: Use when an agent environment uses GitHub Agent Access Broker, gh-agent-broker-cli, BROKER_URL, BROKER_AGENT_ID, BROKER_AGENT_SECRET, broker Git remotes, or broker-mediated GitHub repo probe, policy dry-run, pull request, or issue comment workflows. Prefer the CLI and broker remote over direct GitHub tokens or ad hoc REST calls.
---

# GitHub Agent Access Broker

Use `gh-agent-broker-cli` as the stable agent interface for broker-mediated
GitHub operations. Do not ask for, print, store, or bypass with GitHub App
private keys, GitHub App JWTs, installation tokens, broker secrets, or
authorization headers.

## Required Environment

Expect these variables to be present in the agent runtime:

```sh
BROKER_URL=http://gh-agent-broker:8080
BROKER_AGENT_ID=agent-id
BROKER_AGENT_SECRET=agent-secret
```

If they are missing, stop and report the missing variable names. Do not invent
credentials.

## Default Workflow

1. Use broker Git remotes for normal `git clone`, `git fetch`, and `git push`.
2. Use `gh-agent-broker-cli probe` to confirm repository access.
3. Use `gh-agent-broker-cli dry-run` before creating a pull request or comment
   when policy metadata or branch rules may matter.
4. Use `gh-agent-broker-cli pr` and `gh-agent-broker-cli comment` instead of
   constructing raw REST requests.
5. Treat policy denials as self-correction feedback. Adjust repo, branch, base
   branch, operation, or required metadata; do not bypass the broker.

Read `references/cli.md` for command examples when composing actual commands.

## Safety Rules

- Never configure a direct GitHub-token remote inside the agent container.
- Never log broker secrets or auth headers.
- Never request a GitHub token from the broker; the broker intentionally keeps
  GitHub installation tokens internal.
- Use only metadata names required by the local broker policy or user-provided
  runbook. Do not assume Hermes-specific metadata names unless they appear in
  the environment, config, or task instructions.
