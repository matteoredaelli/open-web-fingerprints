.DEFAULT_GOAL := help
BIN := bin/owf

.PHONY: help build test lint fmt vet check hooks clean addlicense license-check validate-corpus registry stats stats-page tranco filters filters-check

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

# stats: aggregate a batch (owfscan batch run) into the JSON statistics (schema "stats").
BATCH_DB ?= batch.db
STATS_FILE ?= stats.json
STATS_HTML ?= stats.html
STATS_FLAGS ?=
stats: build ## Aggregate the batch DB into JSON statistics (BATCH_DB, STATS_FILE, STATS_FLAGS)
	bin/owfscan stats --db $(BATCH_DB) -o $(STATS_FILE) $(STATS_FLAGS)

# stats-page: static summary page (no script, escaped, deterministic).
# Also writes $(STATS_FILE) (the page is made from the same aggregates).
stats-page: build ## Write the static HTML summary page of the statistics (STATS_HTML)
	bin/owfscan stats --db $(BATCH_DB) -o $(STATS_FILE) --html $(STATS_HTML) $(STATS_FLAGS)

# tranco: download the top TOP sites of a Tranco list, scan their home pages, write the statistics.
# Home page only, aggregates only. Work files go to TRANCO_DIR (outside the repository).
TOP ?= 100
TRANCO_ID ?= 46YVX
TRANCO_DIR ?= /tmp/tranco
REGISTRY ?= registry.json
DEPTH ?= 0
# Generic detectors that fire on almost any page (not products): left out of the statistics.
EXCLUDE ?=
tranco: build ## Scan the top TOP sites of Tranco list TRANCO_ID and write stats (TOP, TRANCO_ID, TRANCO_DIR, DEPTH)
	mkdir -p $(TRANCO_DIR)
	curl -fsSL https://tranco-list.eu/download/$(TRANCO_ID)/$(TOP) -o $(TRANCO_DIR)/top$(TOP).txt
	bin/owfscan batch run $(TRANCO_DIR)/top$(TOP).txt --db $(TRANCO_DIR)/batch.db --registry $(REGISTRY) --depth $(DEPTH) --quiet
	bin/owfscan stats --db $(TRANCO_DIR)/batch.db -o $(TRANCO_DIR)/stats.json --exclude '$(EXCLUDE)' --html $(TRANCO_DIR)/stats.html

# filters: download the block lists of the crawler (needs the network, so it is not part of `make check`).
# Fails when no list is configured; the lists are chosen in the configuration, none is shipped.
filters: build ## Download the crawler's block lists (configured in owfscan.toml)
	bin/owfscan bot filter refresh

# filters-check: say whether a domain is blocked, and by which list (DOMAIN=example.com).
filters-check: build ## Check DOMAIN against the downloaded block lists
	@test -n "$(DOMAIN)" || { echo "usage: make filters-check DOMAIN=example.com"; exit 2; }
	bin/owfscan bot filter check $(DOMAIN)

clean: ## Remove build artifacts
	rm -rf bin dist coverage.out
