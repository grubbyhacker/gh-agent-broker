SHELL := /usr/bin/env bash

GO ?= go
TOOLS_DIR := .tools/bin
GO_ROOT := $(shell $(GO) env GOROOT)
GO_PATH_ENV := env PATH="$(GO_ROOT)/bin:$(PATH)"
GOLANGCI_LINT_VERSION := v2.12.2
GOFUMPT_VERSION := v0.9.2
GOIMPORTS_VERSION := v0.36.0
GOVULNCHECK_VERSION := v1.1.4

GOFILES := $(shell find . -name '*.go' -not -path './.git/*' -not -path './.tools/*')
PACKAGES := ./...

.PHONY: check ci fmt fmt-check lint test race vuln build tidy-check tools clean-tools smoke-container

check: fmt-check tidy-check lint test race vuln build

ci: check

tools: $(TOOLS_DIR)/golangci-lint $(TOOLS_DIR)/gofumpt $(TOOLS_DIR)/goimports $(TOOLS_DIR)/govulncheck

fmt: $(TOOLS_DIR)/gofumpt $(TOOLS_DIR)/goimports
	$(TOOLS_DIR)/goimports -w $(GOFILES)
	$(TOOLS_DIR)/gofumpt -w $(GOFILES)

fmt-check: $(TOOLS_DIR)/gofumpt $(TOOLS_DIR)/goimports
	@out="$$($(TOOLS_DIR)/goimports -l $(GOFILES))"; \
	if [[ -n "$$out" ]]; then echo "goimports required:"; echo "$$out"; exit 1; fi
	@out="$$($(TOOLS_DIR)/gofumpt -l $(GOFILES))"; \
	if [[ -n "$$out" ]]; then echo "gofumpt required:"; echo "$$out"; exit 1; fi

lint: $(TOOLS_DIR)/golangci-lint
	$(GO_PATH_ENV) $(TOOLS_DIR)/golangci-lint run

test:
	$(GO) test $(PACKAGES)

race:
	$(GO) test -race $(PACKAGES)

vuln: $(TOOLS_DIR)/govulncheck
	$(GO_PATH_ENV) $(TOOLS_DIR)/govulncheck $(PACKAGES)

build:
	$(GO) build ./cmd/broker ./cmd/gh-agent-broker ./cmd/broker-issue-reporter ./cmd/sandbox-broker

smoke-container:
	./scripts/container-smoke.sh

tidy-check:
	@tmp="$$(mktemp -d)"; \
	cp go.mod "$$tmp/go.mod"; \
	cp go.sum "$$tmp/go.sum"; \
	$(GO) mod tidy; \
	status=0; \
	diff -u "$$tmp/go.mod" go.mod || status=$$?; \
	diff -u "$$tmp/go.sum" go.sum || status=$$?; \
	cp "$$tmp/go.mod" go.mod; \
	cp "$$tmp/go.sum" go.sum; \
	rm -rf "$$tmp"; \
	if [[ $$status -ne 0 ]]; then echo "go mod tidy drift detected; run 'make tidy'"; exit $$status; fi

.PHONY: tidy
tidy:
	$(GO) mod tidy

$(TOOLS_DIR):
	mkdir -p $(TOOLS_DIR)

$(TOOLS_DIR)/golangci-lint: | $(TOOLS_DIR)
	GOBIN=$$(pwd)/$(TOOLS_DIR) $(GO) install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)

$(TOOLS_DIR)/gofumpt: | $(TOOLS_DIR)
	GOBIN=$$(pwd)/$(TOOLS_DIR) $(GO) install mvdan.cc/gofumpt@$(GOFUMPT_VERSION)

$(TOOLS_DIR)/goimports: | $(TOOLS_DIR)
	GOBIN=$$(pwd)/$(TOOLS_DIR) $(GO) install golang.org/x/tools/cmd/goimports@$(GOIMPORTS_VERSION)

$(TOOLS_DIR)/govulncheck: | $(TOOLS_DIR)
	GOBIN=$$(pwd)/$(TOOLS_DIR) $(GO) install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)

clean-tools:
	rm -rf .tools
