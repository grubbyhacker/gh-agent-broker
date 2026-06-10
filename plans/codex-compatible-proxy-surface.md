# Codex-Compatible Proxy Surface For YKM Curator

## Summary

Add a restricted OpenAI-compatible surface to `gh-agent-proxy` so a sandboxed
Curator worker can run `codex exec` using only a scoped proxy token, with no
provider key in the container.

Primary target is the Responses API path because Codex supports custom
providers with `base_url`, `env_key`, and `wire_api = "responses"`; Chat
Completions is deprecated for Codex custom model usage. Implement
`/v1/responses` with streaming pass-through as required, plus `/v1/models`. Add
`/v1/chat/completions` only as a compatibility passthrough if needed by
LiteLLM/Codex E2E.

## Key Changes

- Extend `gh-agent-proxy` config with a new Codex-compatible executor surface:
  `codex_auth_token_env`, `codex_upstream_key_env`, and
  `codex_allowed_models` as a list of sandbox-visible aliases mapped to
  upstream LiteLLM model IDs. Start with Haiku, but keep Sonnet or other
  operator-approved aliases configurable without code changes.
- Add `POST /v1/responses`: require `Authorization: Bearer <executor token>`
  and `X-GH-Agent-Run-ID`; enforce model allowlist, byte limits, call budget,
  and token budget; forward to LiteLLM `/v1/responses`; pass non-streaming JSON
  and streaming SSE responses through unchanged enough for Codex CLI.
- Add `GET /v1/models`: return only allowed proxy aliases, initially including
  `ykm-codex-haiku` and optionally `ykm-codex-sonnet` when the operator
  enables it.
- Add `POST /v1/chat/completions` only if E2E shows Codex or LiteLLM needs it,
  using the same auth, run ID, model, budget, byte-limit, and audit behavior.
- Preserve existing `/v1/model/call` behavior for current Curator/model-proxy
  users.
- Use `X-GH-Agent-Run-ID` as the budget key for OpenAI-compatible endpoints;
  reject missing or blank run IDs.
- Reserve one call before forwarding. Count tokens from upstream
  `usage.total_tokens` when present; for streaming, parse SSE events
  opportunistically for final usage without buffering private body content.
- Audit `timestamp`, `run_id`, `model`, `endpoint`, `decision`, `tokens`, and
  `error`; never log prompt/response bodies or auth headers.
- Add a LiteLLM restricted virtual key or equivalent scoped upstream credential
  for the proxy to use instead of the LiteLLM master key.
- Curator sandbox gets only `OPENAI_API_KEY=<scoped executor token>`, Codex
  config pointing provider `base_url` at `http://gh-agent-proxy:8092/v1`,
  `wire_api = "responses"`, and an operator-approved model alias such as
  `ykm-codex-haiku` or `ykm-codex-sonnet`.
- Curator sandbox must not receive `OPENROUTER_API_KEY`, `LITELLM_MASTER_KEY`,
  or provider credentials.

## Test Plan

- Unit tests for `internal/proxy`:
  - missing/bad bearer token returns `401`;
  - missing `X-GH-Agent-Run-ID` returns `400`;
  - disallowed model returns `403`;
  - allowed model alias forwards to expected upstream model;
  - call budget exhaustion returns `429`;
  - token budget exhaustion returns `429` when upstream usage exceeds budget;
  - request and response byte caps are enforced;
  - audit records include endpoint/run/model/decision/tokens/error and exclude
    private bodies/secrets;
  - streaming `/v1/responses` returns SSE chunks without buffering or reshaping
    private content.
- Integration-style proxy tests:
  - fake LiteLLM `/v1/responses` non-streaming response passes through;
  - fake LiteLLM `/v1/responses` streaming response passes through with correct
    content type and flush behavior;
  - fake `/v1/models` returns only configured proxy aliases.
- Live acceptance test:
  - In Curator sandbox, run `codex exec` with custom provider config:
    `model = "ykm-codex-haiku"` or `model = "ykm-codex-sonnet"`,
    `model_provider = "ykm-proxy"`,
    `[model_providers.ykm-proxy] base_url = "http://gh-agent-proxy:8092/v1"`,
    `env_key = "OPENAI_API_KEY"`, and `wire_api = "responses"`.
  - Provide `X-GH-Agent-Run-ID` through static config if Codex can inject it,
    otherwise through a command-backed auth/header helper or wrapper script.
  - Confirm a tiny noninteractive edit task completes.
  - Confirm provider keys are absent from container env/files.
  - Confirm proxy audit shows allow decision and token count.
  - Confirm budget state records the run.
  - Confirm no prompt/response bodies are logged.

## Assumptions

- Use a new scoped executor token, not the existing Curator proxy token.
- Expose initial operator-approved aliases such as `ykm-codex-haiku` and, when
  useful for task quality, `ykm-codex-sonnet`; map each alias to the intended
  LiteLLM/OpenRouter model ID in config.
- Streaming support is required for v1.
- `/v1/responses` is the primary compatibility contract;
  `/v1/chat/completions` is fallback compatibility only.
- Codex compatibility is based on documented custom model provider support for
  `base_url`, `env_key`, and `wire_api = "responses"`, and the
  OpenAI-compatible Responses API endpoint.
