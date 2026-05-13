FROM node:24-bookworm-slim

ARG CODEX_VERSION=0.130.0

RUN apt-get update \
	&& apt-get install -y --no-install-recommends ca-certificates \
	&& rm -rf /var/lib/apt/lists/* \
	&& npm install -g @openai/codex@${CODEX_VERSION}
COPY worker.sh /usr/local/bin/sandbox-codex-auth-probe
RUN chmod 0755 /usr/local/bin/sandbox-codex-auth-probe

USER 1000:1000
ENTRYPOINT ["/usr/local/bin/sandbox-codex-auth-probe"]
