# C4 bilateral fixture service

This directory builds a test-only container; the product Dockerfile never
includes it. The container exposes two deliberately narrow local substitutes
on one disposable internal Docker network:

- `POST /app/installations/42/access_tokens` accepts only a GitHub-App-shaped
  JWT that verifies against the paired fixture public key: RS256 signature,
  exact issuer, valid `iat`, and non-expired `exp` no more than ten minutes
  ahead. It then returns the fixed non-secret test installation token.
- Smart Git HTTP accepts only the exact external repository path
  `/grubbyhacker/repository-worker-lifecycle-test.git`, requires that returned
  installation token as Basic authentication, and executes `git http-backend`
  against the disposable bare repository named by `C4_FIXTURE_REPOSITORY`.

It writes neither request headers nor credentials to its output. If its local
`git http-backend` subprocess fails, it logs only a stable stage/reason, exit
status, and printable stderr capped at 2 KiB (with the fixed fixture token
redacted and a truncation flag); no header or request body is retained.

At startup it seeds exactly `grubbyhacker/repository-worker-lifecycle-test.git`
with `main` containing a pending `fixture-task.md`; a Git client sees that
served branch as `origin/main`. It refuses a pre-existing repository whose
`main` does not contain that exact file, rather than silently changing the
fixture state.

The test-only producer must mount the paired public key read-only and set
`C4_FIXTURE_APP_PUBLIC_KEY_PATH` and `C4_FIXTURE_APP_ISSUER`. The matching
private key is mounted only into the real broker container. Neither key nor any
JWT, installation token, effect credential, or authorization header may enter
test output or retained evidence.
