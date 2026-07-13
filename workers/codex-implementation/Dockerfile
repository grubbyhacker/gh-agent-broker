FROM golang:1.26-bookworm AS broker-cli

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/gh-agent-broker-cli ./cmd/gh-agent-broker

FROM node:24-bookworm-slim

ARG CODEX_VERSION=0.130.0
ARG UV_VERSION=0.6.10

ENV UV_PYTHON_INSTALL_DIR=/opt/uv/python

RUN apt-get update \
	&& apt-get install -y --no-install-recommends \
		bash \
		build-essential \
		ca-certificates \
		curl \
		git \
		jq \
		python3 \
		python3-pip \
		python3-venv \
		ripgrep \
	&& rm -rf /var/lib/apt/lists/* \
	&& npm install -g @openai/codex@${CODEX_VERSION} \
	&& python3 -m pip install --break-system-packages uv==${UV_VERSION} \
	&& uv python install 3.12

COPY --from=broker-cli /out/gh-agent-broker-cli /usr/local/bin/gh-agent-broker-cli
COPY workers/codex-implementation/worker.sh /usr/local/bin/codex-implementation-worker

RUN chmod 0755 /usr/local/bin/gh-agent-broker-cli /usr/local/bin/codex-implementation-worker

USER 1000:1000
ENTRYPOINT ["/usr/local/bin/codex-implementation-worker"]
