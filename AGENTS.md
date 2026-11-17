# AGENTS.md

## Project overview

This repository is intended to become an open-source registry and
toolkit for cataloguing web technologies and infrastructure, and for
identifying them through fingerprints.

The project is broader than a collection of detection signatures. It
should maintain a structured catalogue of technologies, products,
vendors, categories, versions, relationships, fingerprints, provenance,
and validation metadata.

The initial workflow is CLI-first. The architecture should leave room
for a future collaborative platform and documentation/wiki without
making the CLI or a particular database the source of truth.

## Goals

-   Build a reusable, well-structured catalogue of web technologies and
    infrastructure.
-   Import and consolidate data from existing fingerprint repositories
    and other useful sources.
-   Preserve source provenance, original identifiers, revisions, and
    licensing information.
-   Normalize different source formats into a stable canonical data
    model.
-   Detect duplicates and conflicting rules without losing
    source-specific information.
-   Validate fingerprints and track their quality over time.
-   Publish language-neutral data artifacts, especially JSON, with a
    documented schema.
-   Keep the registry separate from the runtime detection engine.
-   Start with a local CLI and evolve later toward contributions, review
    workflows, an API, and a collaborative web UI.

## Decisions and working assumptions

These are the decisions reached so far. Treat them as the current
direction, not as immutable requirements; document and discuss material
changes before implementing them.

### Language and repository strategy

-   Use **Go** as the primary implementation language.
-   Use **multiple repositories** rather than putting the registry,
    detection engine, and website into one codebase.
-   The exact repository names and boundaries still need to be
    confirmed.
-   Keep core packages independent from the CLI so that a future API or
    web application can reuse them.

### Storage and publication

Use a hybrid approach:

-   **SQLite** for the initial local operational registry.
-   **Git** for reviewable history, change tracking, and published
    source-controlled data.
-   **JSON** as the primary public interchange and distribution format.
-   **JSON Schema** as the language-neutral contract for exported data.
-   YAML may be supported for hand-authored data or configuration where
    it improves readability.
-   Consider PostgreSQL only when multi-user collaboration or service
    deployment justifies it.

Do not make consumers depend on Go structs, SQLite, or an ORM. The
public schema and exported data must remain language-neutral.

### Architecture

Keep these responsibilities separate:

1.  **Source**: describes an upstream data source, such as a fingerprint
    repository.
2.  **Extractor**: understands one upstream source's layout and format
    and converts it into an intermediate extraction result.
3.  **Normalizer**: maps extracted records into the project's canonical
    model.
4.  **Pipeline/importer**: coordinates download, extraction,
    normalization, validation, deduplication, diffing, and persistence.
5.  **Registry/repository**: stores and queries canonical records.
6.  **Detection engine**: consumes the published registry and analyzes
    targets. It is a separate project/component from source importers.

An extractor must not write directly to the database. It should return
data and provenance that later pipeline stages can validate and persist.

### Design patterns

Use patterns where they simplify extension and testing:

-   **Strategy**: each upstream source has its own extractor
    implementation behind a shared interface.
-   **Adapter**: each extractor adapts its source-specific format to a
    common intermediate representation.
-   **Registry/factory**: register and resolve available extractors by
    stable source ID.
-   **Pipeline**: compose extraction, normalization, validation,
    deduplication, and persistence.
-   **Dependency injection**: pass HTTP clients, loggers, configuration,
    and repositories explicitly.

Prefer ordinary Go interfaces and static registration initially. Do not
introduce Go's dynamic `plugin` mechanism, `.so` modules, or a
subprocess plugin protocol unless a concrete requirement emerges.

## Important domain concepts

The canonical model should be designed before implementing multiple
importers. At minimum, evaluate these entities:

-   `Technology`: a recognizable technology, product, service, or
    platform.
-   `Vendor`: organization responsible for a product or technology,
    where applicable.
-   `Category`: taxonomy for technologies.
-   `Version`: version information and matching constraints, where
    supported.
-   `Fingerprint`: a detection rule associated with a technology.
-   `Evidence`: an observation or match supporting a detection result.
-   `Source`: an upstream repository, dataset, or other source.
-   `Provenance`: the origin of an imported record, including original
    IDs and revisions.
-   `Relationship`: relationships such as technology dependencies,
    integrations, or implications.
-   `Validation`: test results, validation timestamps, false-positive
    observations, and rule health.

Use stable canonical IDs that do not depend on upstream names or IDs.
Preserve original source IDs and source records wherever licensing
permits.

### Fingerprint observations

The model should be extensible to multiple observation types, including:

-   HTTP response headers
-   Cookies
-   HTML and meta tags
-   Script and stylesheet URLs
-   JavaScript indicators
-   DOM and browser-runtime observations
-   Redirects and URL paths
-   DNS records
-   IP/ASN information
-   TLS certificate or handshake characteristics
-   Optional active HTTP probes

Do not assume that a single observation proves a technology. Rules
should support confidence, evidence, and provenance. Treat OS and
infrastructure identification as heuristic unless there is strong
evidence.

Active probes must be safe and non-destructive, with explicit
method/path/matching criteria, rate limits, and clear policy. Do not
implement exploit attempts, authentication attempts, or intrusive checks
as ordinary fingerprint probes.

## Extractor contract: initial proposal

The exact interface is a TODO and must be finalized after reviewing real
source formats. A starting point:

``` go
type Extractor interface {
    ID() string
    Name() string

    Extract(
        ctx context.Context,
        src Source,
    ) (*ExtractionResult, error)
}
```

A `Detect` method may be useful when an extractor must identify whether
a source descriptor or local snapshot is compatible, but avoid adding it
if source-to-extractor mapping is already explicit.

Possible intermediate structures:

``` go
type Source struct {
    ID       string
    URL      string
    Revision string
    License  string
}

type ExtractionResult struct {
    Technologies []ExtractedTechnology
    Fingerprints []ExtractedFingerprint
    Warnings     []string
    Metadata     map[string]any
}
```

These are sketches, not finalized public APIs. Keep source-specific raw
fields or raw-record references where useful, so normalization can be
improved later without downloading everything again.

### Capabilities

Extractors may optionally declare capabilities, for example:

-   technology metadata
-   fingerprints
-   versions
-   categories
-   vendor information
-   relationships

This can support CLI commands that list sources and explain what each
source contributes. Do not over-engineer capability negotiation in the
first implementation.

## Import, provenance, and refresh rules

Treat source refresh as a repeatable ETL and review workflow:

1.  Fetch or update a source snapshot.
2.  Record its revision (commit SHA, dataset version, or equivalent),
    retrieval time, and checksum.
3.  Parse source records with the relevant extractor.
4.  Normalize into the canonical model.
5.  Validate schema and semantic constraints.
6.  Deduplicate and reconcile records while preserving provenance.
7.  Generate a diff showing additions, modifications, removals, and
    conflicts.
8.  Persist changes and make them reviewable.
9.  Publish versioned exports only through an explicit release process.

Important rules:

-   Never discard source provenance during normalization or
    deduplication.
-   Do not treat two similarly named rules as duplicates without
    comparing their semantics.
-   Multiple sources supporting the same canonical rule should be
    recorded as multiple provenance entries; do not automatically
    inflate confidence.
-   Do not automatically delete a canonical rule just because one
    upstream source removed it. Mark it for review or detach that
    source's provenance.
-   Re-check source licensing and provenance when adding or refreshing
    an upstream source.
-   Keep source-specific confidence and matching semantics when they
    differ.
-   Automated refresh should create reviewable changes (for example, a
    pull request); it must not publish a release automatically.

Potential upstream sources discussed include Enthec WebAppAnalyzer,
WhatWeb, HTTP Archive Wappalyzer, CERN WAD, ProjectDiscovery
wappalyzergo, and OpenTechalyzer. Their current status, licenses, data
provenance, and compatibility must be verified before importing. In
particular, do not assume that a repository's code license automatically
applies to embedded fingerprint data. Obtain legal review for license
compatibility before redistributing imported rules.

## Suggested Go implementation choices

These are candidate choices, not mandatory dependencies:

-   Cobra for the CLI.
-   SQLite for the initial local registry.
-   sqlc for type-safe code generated from explicit SQL queries.
-   Goose for database migrations.
-   Go standard library `encoding/json` for JSON.
-   A maintained YAML library only if YAML input/output is required.
-   A JSON Schema validator for exported-data validation.
-   Hugo for a future static catalogue/documentation site.
-   GitHub Actions for source refresh, validation, and release
    automation.

Prefer explicit SQL and small interfaces over introducing a large ORM or
framework without a clear need.

## CLI direction

A provisional command set:

``` text
owf init
owf source list
owf source info <source>
owf source add <source>
owf source refresh [<source>]
owf import [<source>|all]
owf technology list
owf technology show <technology>
owf fingerprint list [--technology <id>]
owf fingerprint validate
owf fingerprint diff
owf export --format json
owf stats
```

Command names and exact UX are not final. Keep CLI commands thin:
business logic belongs in reusable packages.

## Repository layout direction

A possible initial layout for the registry repository:

``` text
open-web-fingerprints/
├── cmd/
│   └── owf/
├── internal/
│   ├── domain/
│   ├── source/
│   ├── extractor/
│   │   ├── enthec/
│   │   ├── whatweb/
│   │   └── httparchive/
│   ├── normalizer/
│   ├── pipeline/
│   ├── validator/
│   ├── deduplicator/
│   └── repository/
│       └── sqlite/
├── schemas/
├── migrations/
├── testdata/
└── go.mod
```

The directory structure should follow actual package boundaries as they
emerge; do not create empty packages just to match this sketch.

The detection engine and the public website should be separate
repositories or independently deployable projects. The website can
initially be generated from registry exports using Hugo. The structured
registry remains the source of truth, not the wiki.

## Development principles for coding agents

-   Before implementing a feature, inspect the existing code and follow
    established project conventions.
-   Keep changes small, testable, and focused.
-   Prefer clear domain types and explicit interfaces over generic
    abstractions.
-   Do not couple extractors to SQLite or CLI packages.
-   Do not silently discard unknown source fields; preserve them when
    practical or emit a warning.
-   Add unit tests for parsing, normalization, deduplication, and
    validation.
-   Use fixture files from pinned source revisions for deterministic
    tests; do not make ordinary unit tests depend on live network
    access.
-   Add integration tests for database migrations and repository
    behavior.
-   Handle context cancellation, timeouts, HTTP errors, retries, and
    rate limits explicitly.
-   Avoid logging secrets or sensitive response data.
-   Document provenance and licensing decisions for every imported
    source.
-   Update JSON Schema and compatibility tests when the public data
    model changes.
-   Do not claim a fingerprint is reliable without test evidence.
-   Run formatting, tests, static analysis, and schema validation before
    considering work complete.
-   Record unresolved design choices rather than hiding them in
    implementation details.

## TODO / implementation roadmap

The order below is intentional. Avoid implementing many source-specific
extractors before the canonical model and contracts are stable.

### Phase 0 --- Project foundations

-   [ ] Confirm project/repository names and check for naming
    collisions.
-   [ ] Create the registry repository and initialize the Go module.
-   [ ] Add `AGENTS.md`, README, LICENSE, contribution guidelines, and
    code of conduct.
-   [ ] Confirm the project's licensing strategy (GPLv3+ was the initial
    preference) and define how third-party fingerprint data with
    different licenses will be handled.
-   [ ] Set up formatting, linting, tests, and CI.
-   [ ] Decide the minimum supported Go version.

### Phase 1 --- Domain model and public contract

-   [ ] Define canonical IDs and naming conventions.
-   [ ] Define `Technology`.
-   [ ] Define `Vendor` and `Category`.
-   [ ] Define `Version` and version constraints.
-   [ ] Define `Fingerprint`, including observation type, operator,
    pattern/value, confidence, and status.
-   [ ] Define `Evidence` and the distinction between a rule and a
    runtime detection observation.
-   [ ] Define `Source` and `Provenance`, including original source ID,
    source revision, license, and retrieval metadata.
-   [ ] Define technology relationships and implication semantics.
-   [ ] Define validation/test metadata and lifecycle states (draft,
    active, deprecated, experimental).
-   [ ] Decide how raw source records or source-specific extensions are
    preserved.
-   [ ] Write representative examples for several different fingerprint
    types.
-   [ ] Create JSON Schema for the first public data format.
-   [ ] Add schema fixtures and compatibility tests.

### Phase 2 --- Interfaces and core architecture

-   [ ] Finalize the `Extractor` interface.
-   [ ] Decide whether source detection belongs in `Extractor.Detect` or
    in explicit source-to-extractor registration.
-   [ ] Define the intermediate extraction result types.
-   [ ] Define the `Normalizer` interface and normalized result types.
-   [ ] Define the source registry/factory and static registration
    mechanism.
-   [ ] Define pipeline stages and error/warning handling.
-   [ ] Define repository interfaces independently of SQLite.
-   [ ] Define dependency injection for HTTP clients, logger,
    configuration, and repositories.
-   [ ] Define optional extractor capabilities without over-engineering
    them.
-   [ ] Add contract tests that every extractor must satisfy.

### Phase 3 --- Storage and CLI skeleton

-   [ ] Design the initial SQLite schema.
-   [ ] Add migrations.
-   [ ] Implement repository methods using explicit SQL (evaluate sqlc).
-   [ ] Implement `owf init`.
-   [ ] Implement source listing and source metadata commands.
-   [ ] Implement technology and fingerprint read/list commands.
-   [ ] Implement JSON export and JSON Schema validation.
-   [ ] Add deterministic fixtures and end-to-end CLI tests.

### Phase 4 --- First extractors

-   [ ] Inspect and document the exact data formats and current licenses
    of candidate sources.
-   [ ] Select one source for the first end-to-end importer (Enthec
    WebAppAnalyzer is a candidate).
-   [ ] Implement its source snapshot/revision handling.
-   [ ] Implement the source-specific parser/adapter.
-   [ ] Preserve original identifiers and provenance.
-   [ ] Normalize extracted records into the canonical model.
-   [ ] Add positive, negative, and edge-case parser fixtures.
-   [ ] Compare imported counts and representative records against the
    upstream source.
-   [ ] Implement a second extractor (for example, WhatWeb or HTTP
    Archive) to validate that the abstraction is genuinely
    source-independent.
-   [ ] Document any source that cannot be redistributed because of
    licensing constraints.

### Phase 5 --- Import pipeline quality

-   [ ] Implement semantic deduplication.
-   [ ] Preserve multiple provenance records for equivalent canonical
    fingerprints.
-   [ ] Implement conflict reporting and manual resolution.
-   [ ] Implement added/changed/removed diff reports.
-   [ ] Ensure upstream deletions do not silently delete canonical
    records.
-   [ ] Implement repeatable refresh/import commands.
-   [ ] Add tests for idempotency: importing the same source revision
    twice must not create duplicate records.
-   [ ] Add import statistics and warnings.

### Phase 6 --- Validation and publication

-   [ ] Define fingerprint quality metrics and validation states.
-   [ ] Build a test harness for rule matching.
-   [ ] Track last validated time, test outcomes, and known false
    positives where available.
-   [ ] Generate complete and optionally partitioned JSON exports.
-   [ ] Generate a manifest with schema version, registry version,
    source revisions, and checksums.
-   [ ] Define semantic versioning for registry data.
-   [ ] Generate changelog and release notes.
-   [ ] Configure CI to validate and propose updates through reviewable
    changes.
-   [ ] Ensure releases are explicit and immutable.

### Phase 7 --- Documentation and collaboration

-   [ ] Generate a searchable technology catalogue with Hugo from
    published exports.
-   [ ] Document how to add a technology and a fingerprint.
-   [ ] Document source licensing and provenance requirements.
-   [ ] Define a contribution/review workflow using Git pull requests.
-   [ ] Keep records in a reviewable draft/pending state where
    appropriate.
-   [ ] Reassess whether an API, PostgreSQL, accounts, and collaborative
    UI are justified.
-   [ ] Keep any future wiki as a presentation/editorial layer, not the
    authoritative structured registry.

### Phase 8 --- Separate detection engine

-   [ ] Define the engine's input/output contract independently from
    source importers.
-   [ ] Consume versioned registry exports rather than depending on
    registry internals.
-   [ ] Define observation providers for HTTP, DNS, TLS, and
    (optionally) browser/runtime data.
-   [ ] Define matching strategies for headers, cookies, HTML, scripts,
    URLs, DNS, TLS, and active probes.
-   [ ] Keep passive checks separate from active probes.
-   [ ] Add confidence aggregation and evidence reporting.
-   [ ] Add safe defaults, timeouts, concurrency limits, and rate
    limiting.
-   [ ] Test against controlled fixtures and known websites where
    permitted.

## First milestone

The first meaningful milestone should be deliberately small:

1.  Agree on the canonical domain model and JSON Schema.
2.  Finalize the extractor and normalizer contracts.
3.  Implement the pipeline with fixture-based tests.
4.  Import one upstream source end to end.
5.  Export a validated JSON registry.

Only after that milestone should the project add several more importers
or start the detection engine.
