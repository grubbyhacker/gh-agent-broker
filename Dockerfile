FROM golang:1.26.5 AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/gh-agent-broker ./cmd/broker \
 && CGO_ENABLED=0 GOOS=linux go build -o /out/gh-agent-broker-cli ./cmd/gh-agent-broker \
 && CGO_ENABLED=0 GOOS=linux go build -o /out/broker-issue-reporter ./cmd/broker-issue-reporter \
 && CGO_ENABLED=0 GOOS=linux go build -o /out/sandbox-broker ./cmd/sandbox-broker \
 && CGO_ENABLED=0 GOOS=linux go build -o /out/gh-agent-proxy ./cmd/gh-agent-proxy \
 && CGO_ENABLED=0 GOOS=linux go build -o /out/codex-subscription-relay ./cmd/codex-subscription-relay \
 && mkdir -p /out/audit

FROM gcr.io/distroless/static-debian11
COPY --from=build /out/gh-agent-broker /usr/local/bin/gh-agent-broker
COPY --from=build /out/gh-agent-broker-cli /usr/local/bin/gh-agent-broker-cli
COPY --from=build /out/broker-issue-reporter /usr/local/bin/broker-issue-reporter
COPY --from=build /out/sandbox-broker /usr/local/bin/sandbox-broker
COPY --from=build /out/gh-agent-proxy /usr/local/bin/gh-agent-proxy
COPY --from=build /out/codex-subscription-relay /usr/local/bin/codex-subscription-relay
COPY --chmod=0755 workers/result.sh /usr/local/lib/agent-worker-result.sh
COPY --chmod=0755 workers/repo-task/worker.sh /usr/local/bin/agent-repo-task-worker
COPY --chmod=0755 workers/codex-repo-task/worker.sh /usr/local/bin/agent-codex-repo-task-worker
COPY --chmod=0755 workers/codex-repo-prep/worker.sh /usr/local/bin/agent-codex-repo-prep-worker
COPY --chmod=0755 workers/codex-delivery/worker.sh /usr/local/bin/agent-codex-delivery-worker
COPY --from=build --chown=65532:65532 /out/audit /var/log/gh-agent-broker
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/gh-agent-broker"]
