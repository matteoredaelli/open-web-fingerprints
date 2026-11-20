# AGENTS.md

Guidance for coding agents working in this repository. Keep it short and true:
update it when a decision changes.

## What this is

An open registry and toolkit that catalogues web technologies and the
fingerprints that identify them. It imports rules from upstream projects,
normalizes them into one model, keeps provenance, reconciles overlaps, tests
rules, and exports language-neutral JSON. The CLI is `owf`; the module is
`github.com/matteoredaelli/open-web-fingerprints`; Go 1.25.

The scanner (`owfscan`: give it a URL, get a structured result with technologies,
links, linked domains and social profiles) is a **separate component** in this
repository: its own binary (`cmd/owfscan`, no database) and public package
(`scan/`). It reads a registry export and applies the rules. Go only, no Python
layer. It makes only `GET`s, refuses non-public addresses (also after redirects)
and does not run probes. It does not refuse unreviewed sources (it repeats the
export's notice). `internal/matcher` still exists only to test rules offline; the scanner
may reuse its code, but do not grow the matcher itself into a scanner. Design
and plan: `docs/scan.md`.

## Rules that must hold

- **Provenance is never lost.** Every imported record keeps source, revision,
  original ID and licence. Upstream removal marks provenance `removed_upstream`;
  it never deletes a canonical record. Only a reviewer-approved merge deletes.
- **Nothing merges across sources by itself.** Same-name technologies and
  categories become *candidate conflicts*. A reviewer runs `owf conflict
  resolve`. (Vendors are the exception: they are keyed by the CPE vendor
  identifier, an external dictionary key.)
- **Agreement is not confidence.** Equivalent rules combine into one record with
  several provenance entries; canonical confidence is the *lowest explicit*
  value. Sources that share an ancestor are not independent evidence.
- **`health: ok` needs evidence**: a passing positive and a passing negative
  test, each run labelled with its origin (`upstream_example` when the source's
  own examples). Imports start `unknown`. Never call a rule reliable without tests.
- **Active probes are safe by construction**: explicit path, imported as `draft` with
  `safety_review: pending`, never approved by an extractor or by an agent: approving a
  path is the maintainer's decision (`owf probe review`, with a note). The scanner sends
  a probe only if its path is approved **and** the scan asks for `--active`; it sends
  `GET` only, honours robots.txt with no override, pauses and caps the requests. It never
  exploits and never authenticates. Out of scope: CVE, vulnerability, misconfiguration
  and default-login templates.
- **One licence: GPL-3.0-or-later for all that the project writes** (code, `scan` and
  `schemas` packages, schemas, docs, cases). Decided by the maintainer; do not propose
  a second licence for part of it.
- **Redistribution is guarded.** Sources are `unreviewed` by default;
  `owf export` refuses them unless `--include-unreviewed` (internal use, noted in
  the file). `no` is never exported. Decisions are recorded with
  `owf source review --note`. A repository licence is not proof of the licence of
  its data. The tool records legal decisions; it does not make them.
- **Reviewer decisions survive refreshes**: record status, validation, probe
  review, curated vendors, source decisions, resolved conflicts, rule corrections
  (`owf fingerprint correct`: kept with the source's value and a reason; the importer
  never corrects a rule by itself).
- **A source cannot overwrite another's content.** The source of a record's first
  provenance entry owns its content; others only add provenance.
- **Do not drop information silently.** Keep the upstream fragment in `raw`,
  count skips in warnings, and prefer skipping a whole unrepresentable rule to
  keeping a weaker one (a partial clause matches more than the original).
- **Extractors are pure.** They read a local snapshot (`fs.FS`) and return data;
  no network, no database, no CLI imports. Unit tests never touch the network.

## Layout

```
cmd/owf/                    thin Cobra CLI; logic lives in internal/
internal/domain             canonical model, IDs (prefix_UUIDv7), semantic key
internal/extractor          Extractor contract, registry, contract tests
  wappalyzer/ recog/ nuclei/  one package per source format
internal/normalizer         extraction -> domain (IDs, slugs, vendors, defaults)
internal/reconciler         cross-source candidates, alias translation
internal/merge, review      conflict decisions and record merges (atomic)
internal/curate             reviewer edits (vendors)
internal/pipeline           checksum, extract, normalize, validate, diff, store
internal/repository         interface; memory/ and sqlite/ (goose migrations)
internal/validator          semantic checks of records
internal/matcher            offline rule evaluation (rules and groups)
internal/scan/web           links, domains, social profiles, contacts from HTML
internal/scan/fetch         guarded HTTP fetch with redirects, limits, disk cache
internal/scan/observe       page -> matcher observation (favicon hashes, DNS, TLS)
internal/scan/engine        applies a registry to an observation; coverage
internal/scan/scanner       a whole scan: observe, engine, web, result
internal/scan/scantest      test export and test site from the source fixtures
internal/validation         test cases, health, static lint
internal/fetch              pinned single-commit git fetch
internal/export             schema-validated JSON with the redistribution guard
internal/builtin            static catalogue of sources and extractors
scan/                       public result types of the scanner
schemas/                    public JSON Schemas (registry, validation cases, scan result)
validation/cases/           corpus of cases on real rules
examples/  docs/  testdata under each package
```

## Model in brief

Technology, Vendor, Category, Fingerprint (one observation rule), Relationship,
Source, Snapshot, Provenance, Conflict, Alias. A fingerprint has observation,
target, operator, pattern, `regex_flavor` (`re2` | `ecmascript` | `pcre`),
optional `version_extract`, `role` (`version` for a rule that only reads a version), `group_id` (rules that must hold together), optional
`probe`, confidence, status, validation, provenance, `raw`. Observation types
are an open set. Details: `docs/domain-model.md`.

IDs are opaque and stable (`tech_<uuidv7>`); slugs are unique and never change
once assigned. The registry is SQLite; the public contract is the JSON export
(schema `0.2.0`, draft, with a manifest and content hash). Conflicts and aliases
are not exported.

## Sources (all `unreviewed`)

| Slug | Extractor | Note |
|---|---|---|
| `enthec-webappanalyzer` | wappalyzer | main Wappalyzer-format source |
| `httparchive-wappalyzer` | wappalyzer | fork of the same ancestor, adds ~1.5% |
| `rapid7-recog` | recog | web databases only; new data (favicon md5, title, cookie) |
| `projectdiscovery-nuclei-templates` | nuclei | `http/technologies`; groups and probes |

Adding a source: extractor package with real fixtures from a pinned revision
and a `testdata/README.md` (licence notice), contract test, catalogue entry in
`internal/builtin`, a short survey in `docs/sources.md`. Measure real overlap
before claiming value. Prefer sources with different data and clear licences.

## CLI

`init`, `source list|info|refresh|review`, `import`, `technology list|show`,
`vendor list|show|set`, `fingerprint list|validate|test|lint|correct`, `probe list|review`,
`conflict list|show|resolve`, `export`, `verify`, `stats`. `owfscan`:
`scan`, `extract`, `links`, `social`, `observe`. `refresh` fetches one commit
with `git` (sparse, pinned by SHA) and imports it; `--dry-run` first.

## Working conventions

- Run `make check` (gofmt, license headers, vet, golangci-lint, tests with
  `-race`) before finishing. `make validate-corpus` needs git and network.
- New files need the SPDX header: `git add` them, then `make addlicense`
  (it only sees tracked files). Lefthook hooks run via `make hooks`.
- Tests use fixtures copied unmodified from pinned revisions; opt-in tests on a
  full clone use `OWF_*_SNAPSHOT` (see `docs/`). Memory and SQLite must pass the
  same contract tests. Changes to the public model update the schema and its
  tests.
- Keep changes small and tested. Prefer explicit SQL and plain interfaces; no
  ORM, no Go plugins. Handle context cancellation and errors explicitly; do not
  log secrets.
- Measure before deciding (real data, not guesses), report numbers honestly, and
  record limits and unresolved choices in `docs/`.

## State and next steps

Done: model and schema, four importers, pinned fetch, reconciliation and merges,
vendors from CPE, offline matcher and validation harness (case files and
upstream examples, with the origin of each piece of evidence), redistribution
guard.

Open, roughly in order:
0. Scanner `owfscan` (docs/scan.md): links, domains, social profiles and contacts
   `owfscan scan` works (fetch, observe, engine, links, social, contacts, `--depth`, friend domains, `--browser`,
   `excludes`/`requires`, `--active` with `owf probe review`). Next: browser on more pages, a reviewed list of related domains.
1. More cases: 115 Enthec rules and 2 nuclei groups have test evidence (Recog has
   685 from upstream examples). Next: the remaining popular technologies, nuclei
   groups, and cookie rules whose names look like patterns.
2. Review the 281 candidate conflicts; legal review of every source.
3. Releases: semantic versioning of the data, a published schema URL, release
   notes (always explicit, never automatic); export of conflicts and aliases if
   a consumer needs them.
4. Separate repositories for the detection engine and the public site.

Docs: `docs/domain-model.md`, `sources.md`, `dedup-design.md`, `validation.md`,
`redistribution.md`, `scan.md` (scanner design and decisions), `owfscan.md`
(scanner user guide).
