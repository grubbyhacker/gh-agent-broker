ARG C4_FIXTURE_REVISION=unpublished

FROM golang:1.26-alpine AS build
WORKDIR /src
COPY main.go .
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/c4-bilateral-fixture main.go

FROM alpine:3.21
ARG C4_FIXTURE_REVISION
RUN apk add --no-cache git git-daemon wget \
 && test -x "$(git --exec-path)/git-http-backend"
COPY --from=build /out/c4-bilateral-fixture /usr/local/bin/c4-bilateral-fixture
LABEL org.opencontainers.image.source="https://github.com/grubbyhacker/gh-agent-broker" \
      org.opencontainers.image.revision="${C4_FIXTURE_REVISION}" \
      org.opencontainers.image.title="c4-bilateral-git-http-fixture" \
      org.opencontainers.image.target="c4-bilateral-git-http-fixture"
EXPOSE 18080
HEALTHCHECK --interval=1s --timeout=1s --start-period=2s --retries=12 CMD wget -q -O /dev/null http://127.0.0.1:18080/healthz || exit 1
ENTRYPOINT ["/usr/local/bin/c4-bilateral-fixture"]
