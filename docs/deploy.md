# Production Deploy

Production deploys run from GitHub Actions after the `CI` workflow successfully
builds and publishes the `gh-agent-broker` image from `main`.

The deploy workflow checks out `grubbyhacker/vps-ops`, installs Ansible,
installs the Ansible collections pinned by `vps-ops/requirements.yml`, writes
the deploy SSH key to a temporary file on the GitHub-hosted runner, and runs:

```sh
ansible-playbook -i inventory/production.yml playbooks/deploy-gh-agent-broker.yml \
  -e "broker_image=ghcr.io/grubbyhacker/gh-agent-broker:sha-<CI_HEAD_SHA>" \
  -e "ansible_ssh_private_key_file=/tmp/hermes-deploy"
```

The VPS hostname and target connection details come from
`vps-ops/inventory/production.yml`; they are not hardcoded in this repository's
deploy workflow.

## Required Secrets

Configure these as repository secrets before enabling production deploys:

- `DEPLOY_SSH_PRIVATE_KEY`: ed25519 private key for
  `github-deployer@srv1656293.hstgr.cloud`.
- `VPS_OPS_READ_TOKEN`: fine-grained PAT with read access to
  `grubbyhacker/vps-ops`.

Do not commit secret values to this repository or to `vps-ops`.

## Production Approval Gate

The deploy job runs in the GitHub Actions `production` environment. Configure
that environment with required reviewers so a human must approve before the job
can proceed.

The approval gate pauses the deploy job before it runs production steps. After
approval, the runner can access the configured secrets and execute the Ansible
playbook against the production inventory.

## Manual Redeploy

To redeploy the same image, rerun the `Deploy Production` workflow from the
GitHub Actions UI. The rerun uses the same triggering `CI` workflow run and
therefore the same `workflow_run.head_sha` image tag.

Use this when the image already exists in GHCR and the deployment should be
re-applied without building a new image.

## Rotate The Deploy Key

1. Generate a new ed25519 keypair for the `github-deployer` VPS user.
2. Install the new public key for `github-deployer` on the production VPS.
3. Replace the `DEPLOY_SSH_PRIVATE_KEY` repository secret with the new private
   key.
4. Rerun the production deploy workflow and confirm the Ansible playbook can
   connect and complete.
5. Remove the old public key from the production VPS.

Keep the old key installed only long enough to verify the replacement.
