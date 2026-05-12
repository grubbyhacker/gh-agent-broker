FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/gh-agent-broker ./cmd/broker \
 && CGO_ENABLED=0 GOOS=linux go build -o /out/gh-agent-broker-cli ./cmd/gh-agent-broker

FROM gcr.io/distroless/static-debian11
COPY --from=build /out/gh-agent-broker /usr/local/bin/gh-agent-broker
COPY --from=build /out/gh-agent-broker-cli /usr/local/bin/gh-agent-broker-cli
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/gh-agent-broker"]
