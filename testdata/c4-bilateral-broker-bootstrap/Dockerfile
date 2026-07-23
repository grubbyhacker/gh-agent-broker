ARG C4_BROKER_BOOTSTRAP_REVISION=unpublished

FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/gh-agent-broker ./cmd/broker \
 && CGO_ENABLED=0 GOOS=linux go build -o /out/c4-bilateral-broker-bootstrap ./testdata/c4-bilateral-broker-bootstrap

FROM alpine:3.21
ARG C4_BROKER_BOOTSTRAP_REVISION
RUN apk add --no-cache ca-certificates wget
COPY --from=build /out/gh-agent-broker /usr/local/bin/gh-agent-broker
COPY --from=build /out/c4-bilateral-broker-bootstrap /usr/local/bin/c4-bilateral-broker-bootstrap
LABEL org.opencontainers.image.source="https://github.com/grubbyhacker/gh-agent-broker" \
      org.opencontainers.image.revision="${C4_BROKER_BOOTSTRAP_REVISION}" \
      org.opencontainers.image.title="c4-bilateral-broker-bootstrap" \
      org.opencontainers.image.target="c4-bilateral-broker-bootstrap"
EXPOSE 8080
HEALTHCHECK --interval=1s --timeout=1s --start-period=2s --retries=12 CMD wget -q -O /dev/null http://127.0.0.1:8080/readyz || exit 1
ENTRYPOINT ["/usr/local/bin/c4-bilateral-broker-bootstrap"]
