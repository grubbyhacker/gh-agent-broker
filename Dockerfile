FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/gh-agent-broker ./cmd/broker \
 && CGO_ENABLED=0 GOOS=linux go build -o /out/gh-agent-broker-cli ./cmd/gh-agent-broker \
 && CGO_ENABLED=0 GOOS=linux go build -o /out/broker-issue-reporter ./cmd/broker-issue-reporter \
 && CGO_ENABLED=0 GOOS=linux go build -o /out/sandbox-broker ./cmd/sandbox-broker \
 && CGO_ENABLED=0 GOOS=linux go build -o /out/gh-agent-proxy ./cmd/gh-agent-proxy \
 && mkdir -p /out/audit

FROM gcr.io/distroless/static-debian11
COPY --from=build /out/gh-agent-broker /usr/local/bin/gh-agent-broker
COPY --from=build /out/gh-agent-broker-cli /usr/local/bin/gh-agent-broker-cli
COPY --from=build /out/broker-issue-reporter /usr/local/bin/broker-issue-reporter
COPY --from=build /out/sandbox-broker /usr/local/bin/sandbox-broker
COPY --from=build /out/gh-agent-proxy /usr/local/bin/gh-agent-proxy
COPY --from=build --chown=65532:65532 /out/audit /var/log/gh-agent-broker
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/gh-agent-broker"]
