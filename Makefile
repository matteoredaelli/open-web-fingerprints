.DEFAULT_GOAL := help
BIN := bin/owf

.PHONY: help build test lint fmt vet check hooks clean addlicense license-check validate-corpus registry

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  %-10s %s\n",$$1,$$2}'

build: ## Build the owf and owfscan CLIs
	go build -o $(BIN) ./cmd/owf
	go build -o bin/owfscan ./cmd/owfscan

test: ## Run tests
	go test -race -cover ./...

lint: ## Run golangci-lint
	golangci-lint run ./...

fmt: ## Format code
	gofmt -s -w .

vet: ## Run go vet
	go vet ./...

check: fmt-check license-check vet lint test ## Run all checks (CI)

fmt-check:
	@test -z "$$(gofmt -s -l .)" || (gofmt -s -l .; echo "gofmt needed"; exit 1)

ADDLICENSE ?= $(HOME)/go/bin/addlicense
ADDLICENSE_ARGS = -c "Matteo Redaelli" -l GPL-3.0-or-later -s

addlicense: ## Add license headers to tracked .go files
	git ls-files '*.go' | xargs $(ADDLICENSE) $(ADDLICENSE_ARGS)

license-check: ## Verify license headers
	git ls-files '*.go' | xargs $(ADDLICENSE) -check $(ADDLICENSE_ARGS)

hooks: ## Install git hooks (lefthook)
	lefthook install

# The corpus targets the pinned Enthec revision, so it is deterministic. Set
# CORPUS_REVISION=<sha> to see whether newer upstream rules made a case stale.
CORPUS_REVISION ?= 9e52f10a9533c8f7f8d0703c843f7295d56c95a3
CORPUS_DB := .corpus.db
# The nuclei cases are written against this nuclei-templates commit, in a registry
# that holds only that source (slugs get numeric suffixes when sources collide).
CORPUS_NUCLEI_REVISION ?= 7fba833dacc1ea8f737fed34d01cc404a17e3424
# The OpenTechalyzer cases are written against this commit, in a registry that holds only that source.
CORPUS_OPENTECHALYZER_REVISION ?= a3d30e479c91c06732ef88867d69b7feef8f3f35
validate-corpus: build ## Fetch Enthec, nuclei and OpenTechalyzer and run validation/cases* (needs git and network)
	rm -f $(CORPUS_DB)
	$(BIN) --db $(CORPUS_DB) init
	$(BIN) --db $(CORPUS_DB) source refresh enthec-webappanalyzer --revision $(CORPUS_REVISION)
	$(BIN) --db $(CORPUS_DB) fingerprint test validation/cases
	rm -f $(CORPUS_DB) $(CORPUS_DB)-shm $(CORPUS_DB)-wal
	$(BIN) --db $(CORPUS_DB) init
	$(BIN) --db $(CORPUS_DB) source refresh projectdiscovery-nuclei-templates --revision $(CORPUS_NUCLEI_REVISION)
	$(BIN) --db $(CORPUS_DB) fingerprint test validation/cases-nuclei
	rm -f $(CORPUS_DB) $(CORPUS_DB)-shm $(CORPUS_DB)-wal
	$(BIN) --db $(CORPUS_DB) init
	$(BIN) --db $(CORPUS_DB) source refresh houseofmvps-opentechalyzer --revision $(CORPUS_OPENTECHALYZER_REVISION)
	$(BIN) --db $(CORPUS_DB) fingerprint test validation/cases-opentechalyzer
	rm -f $(CORPUS_DB) $(CORPUS_DB)-shm $(CORPUS_DB)-wal

# registry: refresh every source (fetch the pinned tip of its branch and import it), then
# export. The export keeps the redistribution guard: it refuses sources that are not
# reviewed. For internal use pass EXPORT_FLAGS=--include-unreviewed (the file says so).
# Needs git and network. Example: make registry DB=owf.db EXPORT_FLAGS=--include-unreviewed
DB ?= owf.db
EXPORT_FILE ?= registry.json
EXPORT_FLAGS ?=
registry: build ## Create the registry if missing, refresh all sources (import) and export JSON
	@test -f $(DB) || $(BIN) --db $(DB) init
	$(BIN) --db $(DB) source refresh --all
	$(BIN) --db $(DB) export $(EXPORT_FLAGS) -o $(EXPORT_FILE)

clean: ## Remove build artifacts
	rm -rf bin dist coverage.out
