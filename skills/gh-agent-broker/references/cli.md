# gh-agent-broker-cli Reference

The CLI reads `BROKER_URL`, `BROKER_AGENT_ID`, and `BROKER_AGENT_SECRET`.
Pass flags only when overriding those environment values.

## Git Remote

```sh
gh-agent-broker-cli configure -repo OWNER/REPO -remote origin
git remote -v
```

After the remote points at the broker, use normal Git commands:

```sh
git fetch origin
git push origin HEAD:agent/AGENT_ID/TASK_SLUG
```

## Health And Probe

```sh
gh-agent-broker-cli health
gh-agent-broker-cli probe -repo OWNER/REPO
```

## Policy Dry-Run

```sh
gh-agent-broker-cli dry-run \
  -repo OWNER/REPO \
  -operation pull.create \
  -branch agent/AGENT_ID/TASK_SLUG \
  -base main \
  -metadata Agent-Id=AGENT_ID \
  -metadata Run-Id=RUN_ID
```

Use metadata keys required by the configured broker policy. The names above are
examples only.

## Pull Request

```sh
gh-agent-broker-cli pr \
  -repo OWNER/REPO \
  -title "Agent change" \
  -head agent/AGENT_ID/TASK_SLUG \
  -base main \
  -body "Summary of the change." \
  -metadata Agent-Id=AGENT_ID \
  -metadata Run-Id=RUN_ID
```

## Issue Or Pull Request Comment

```sh
gh-agent-broker-cli comment \
  -repo OWNER/REPO \
  -issue 123 \
  -body "Agent run completed." \
  -metadata Agent-Id=AGENT_ID \
  -metadata Run-Id=RUN_ID
```

## Issue Creation

Do not create issues with the broker CLI. If issue creation is needed and the
runtime exposes `broker_report_issue`, use that MCP tool with `repo`, `title`,
`body`, and `dedupe_key`. The reporter service owns the narrower issue-only
broker identity.

## Denials

If the broker returns a structured denial, use its safe correction details to
change the operation, repo, branch, base branch, permissions, or metadata. Do
not switch to direct GitHub credentials.
