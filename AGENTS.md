# AGENTS.md

Guidance for coding agents working in this repository. Keep it short and true:
update it when a decision changes.

## What this is

An open registry and toolkit that catalogues web technologies and the
fingerprints that identify them. It imports rules from upstream projects,
normalizes them into one model, keeps provenance, reconciles overlaps, tests
rules, and exports language-neutral JSON. The CLI is `owf`; the module is
`github.com/matteoredaelli/open-web-fingerprints`; Go 1.25.

The runtime detection engine is a **separate project**. `internal/matcher`
exists only to test rules offline. Do not grow it into a scanner.

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
  test. Imports start `unknown`. Never call a rule reliable without tests.
- **Active probes are safe by construction**: `GET`/`HEAD` only, explicit path,
  imported as `draft` with `safety_review: pending`, never approved by an
  extractor. The project never runs probes, never exploits, never authenticates.
  Out of scope: CVE, vulnerability, misconfiguration and default-login templates.
- **Redistribution is guarded.** Sources are `unreviewed` by default;
  `owf export` refuses them unless `--include-unreviewed` (internal use, noted in
  the file). `no` is never exported. Decisions are recorded with
  `owf source review --note`. A repository licence is not proof of the licence of
  its data. The tool records legal decisions; it does not make them.
- **Reviewer decisions survive refreshes**: record status, validation, probe
  review, curated vendors, source decisions, resolved conflicts.
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
internal/validation         test cases, health, static lint
internal/fetch              pinned single-commit git fetch
internal/export             schema-validated JSON with the redistribution guard
internal/builtin            static catalogue of sources and extractors
schemas/                    public JSON Schemas (registry, validation cases)
validation/cases/           corpus of cases on real rules
examples/  docs/  testdata under each package
```

## Model in brief

Technology, Vendor, Category, Fingerprint (one observation rule), Relationship,
Source, Snapshot, Provenance, Conflict, Alias. A fingerprint has observation,
target, operator, pattern, `regex_flavor` (`re2` | `ecmascript` | `pcre`),
optional `version_extract`, `group_id` (rules that must hold together), optional
`probe`, confidence, status, validation, provenance, `raw`. Observation types
are an open set. Details: `docs/domain-model.md`.

IDs are opaque and stable (`tech_<uuidv7>`); slugs are unique and never change
once assigned. The registry is SQLite; the public contract is the JSON export
(schema `0.1.0`, draft). Conflicts, aliases and a manifest are not exported yet.

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
`vendor list|show|set`, `fingerprint list|validate|test|lint`,
`conflict list|show|resolve`, `export`, `stats`. `refresh` fetches one commit
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
vendors from CPE, offline matcher and validation harness, redistribution guard.

Open, roughly in order:
1. Validation cases from Recog's own examples (positive; negatives from other
   products' examples). Decide whether they count toward `ok`.
2. Validation cases that select groups (grouped rules cannot be tested yet).
3. nuclei version extractors (209 templates lose versions).
4. Review the 281 candidate conflicts; legal review of every source.
5. Export 0.2: conflicts, aliases, test evidence, manifest with revisions and
   checksums; semantic versioning and releases (always explicit, never
   automatic).
6. Separate repositories for the detection engine and the public site.

Docs: `docs/domain-model.md`, `sources.md`, `dedup-design.md`, `validation.md`,
`redistribution.md`.
