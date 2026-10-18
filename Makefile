.DEFAULT_GOAL := help

.PHONY: build test vet coverage check demo clean help

build: ## Build all Go packages
	go build ./...

test: ## Run all Go tests with the race detector
	go test -race ./...

vet: ## Run Go static analysis
	go vet ./...

coverage: ## Run race tests and print total coverage
	go test -race -coverprofile=coverage.out -covermode=atomic ./...
	go tool cover -func=coverage.out | tail -1

check: ## Run vet, build, and tests in sequence
	$(MAKE) vet
	$(MAKE) build
	$(MAKE) test

demo: ## Regenerate the demo GIF when VHS is installed
	@if command -v vhs >/dev/null 2>&1; then vhs demo/demo.tape; fi

clean: ## Remove the root binary, coverage profile, and release artifacts
	rm -f mcp-audit mcp-audit.exe coverage.out
	rm -rf dist/

help: ## List available development tasks
	@awk 'BEGIN { FS = ":.*## " } /^[a-zA-Z_-]+:.*## / { printf "  %-12s %s\n", $$1, $$2 }' $(MAKEFILE_LIST)
