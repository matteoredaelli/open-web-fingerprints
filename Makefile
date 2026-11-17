.DEFAULT_GOAL := help
BIN := bin/owf

.PHONY: help build test lint fmt vet check hooks clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  %-10s %s\n",$$1,$$2}'

build: ## Build the owf CLI
	go build -o $(BIN) ./cmd/owf

test: ## Run tests
	go test -race -cover ./...

lint: ## Run golangci-lint
	golangci-lint run ./...

fmt: ## Format code
	gofmt -s -w .

vet: ## Run go vet
	go vet ./...

check: fmt-check vet lint test ## Run all checks (CI)

fmt-check:
	@test -z "$$(gofmt -s -l .)" || (gofmt -s -l .; echo "gofmt needed"; exit 1)

hooks: ## Install git hooks (lefthook)
	lefthook install

clean: ## Remove build artifacts
	rm -rf bin dist coverage.out
