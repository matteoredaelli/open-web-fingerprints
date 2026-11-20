# Canonical domain model (draft v0)

Status: **draft for review**. Nothing here is implemented yet. It follows
from [sources.md](sources.md). The public contract is the JSON export, and
this model is not tied to Go structs or SQLite.

## Principles

- Canonical IDs are opaque and stable. They never derive from upstream names
  or IDs.
- Every record keeps provenance. Imports never overwrite or delete canonical
  records silently.
- One fingerprint equals one observation rule. Grouping is explicit.
- A match is a hint, not a proof. Confidence and evidence are first-class.

## ID convention (proposal)

`<kind>_<ulid-or-uuidv7>`, e.g. `tech_01J...`, `fp_01J...`, `src_...`.

- Lower-case prefix identifies the kind. The suffix is a time-ordered unique
  value, generated once and never reused.
- Human-readable `slug` fields (`wordpress`) are separate. They are unique and
  stable, but can be renamed, with the old values kept as aliases.
- Open question: ULID vs UUIDv7. Both sort by time. UUIDv7 is more standard.

## Entities

### Technology
`id`, `slug`, `name`, `aliases[]`, `description`, `website`, `kind`
(`software` | `service` | `platform` | `infrastructure`), `category_ids[]`,
`vendor_id?`, `cpe[]`, `open_source?` (bool), `saas?` (bool), `status`,
`created_at`, `updated_at`.

### Vendor
`id`, `slug`, `name`, `website?`, `aliases[]`.

### Category
`id`, `slug`, `name`, `parent_id?`, `group?`. Upstream numeric IDs live in
provenance, not here.

### Fingerprint
One observation rule for one technology.

| Field | Notes |
|---|---|
| `id`, `technology_id` | |
| `group_id?` | Rules that must hold together (AND). Rules with no group stand alone. Different groups are alternatives (OR). |
| `observation` | Type enum, below |
| `target?` | Name inside the observation: header name, cookie name, meta name, JS path, DOM selector, DNS record type |
| `operator` | `exists`, `equals`, `contains`, `regex`, `hash_equals` |
| `pattern?` | The value, with no upstream modifiers |
| `version_extract?` | Capture-group reference or template, separate from `pattern` |
| `confidence` | 0.0 to 1.0. The author's estimate is stored separately from any validated score |
| `probe?` | Present only for active rules: `method`, `path`, `rate_limit_class`, `safety_review` |
| `status` | `draft`, `active`, `experimental`, `deprecated` |
| `validation` | See below |
| `provenance[]` | See below |
| `raw?` | Upstream fragment, kept for re-normalization |

Observation types:
`http_header`, `cookie`, `html`, `meta_tag`, `script_url`, `stylesheet_url`,
`js_global`, `dom`, `url_path`, `redirect`, `dns_record`, `ip_asn`,
`tls_cert`, `tls_handshake`, `favicon_hash`, `xhr`, `robots`, `probe_response`.
The set is open: unknown values are preserved, not rejected.

Semantic equality (for deduplication) is defined on
`(technology, observation, target, operator, normalized pattern, version_extract)`.
Names and wording do not count.

### Relationship
`id`, `from_technology_id`, `to_technology_id`, `type`
(`implies`, `requires`, `excludes`, `integrates_with`, `variant_of`),
`confidence?`, `provenance[]`. A category-level requirement
(`requiresCategory`) is `to_category_id`.

### Version
Version information is split in two pieces:
- `version_extract` on fingerprints says how to read a version from a match.
- A later `VersionConstraint` (semver or other scheme, range) is reserved for
  rules that only apply to some releases. **Not in v0.**

### Source
`id`, `name`, `url`, `license` (SPDX), `extractor_id`, `notes`,
`redistributable` (`yes` | `no` | `unreviewed`).

### SourceSnapshot
`source_id`, `revision` (commit SHA or dataset version), `retrieved_at`,
`checksum`, `files[]` with per-file checksums.

### Provenance
Attached to Technology, Fingerprint, Relationship and Category links.
`source_id`, `snapshot_revision`, `original_id` (upstream name or path+key),
`original_file`, `original_confidence?`, `license`, `imported_at`,
`state` (`present` | `removed_upstream`). When upstream removes a record the
state changes and the canonical record is flagged for review.

### Validation
`last_validated_at?`, `test_runs[]` (`result`, `fixture_ref`, `at`),
`known_false_positives[]`, `health` (`unknown` | `ok` | `degraded` | `broken`).
A rule without test evidence is `health: unknown`, and never reported as
reliable.

### Evidence (runtime, not part of the registry)
Defined in the detection engine's contract: `rule_id`, `observed_value`,
`matched_at`, `target`. It is kept distinct from a fingerprint because it is
a result of applying a rule to a real target.

## Mapping from Enthec

| Enthec | Canonical |
|---|---|
| technology key | `Technology.name` plus provenance `original_id` |
| `cats` | `category_ids` through mapping from numeric ID |
| `website`, `description`, `oss`, `saas`, `cpe`, `icon` | fields (`icon` stays in `raw`, no image import) |
| `headers`, `cookies`, `meta`, `html`, `scriptSrc`, `js`, `dom`, `dns`, `url`, `css`, `xhr`, `text`, `certIssuer`, `robots` | one Fingerprint per entry, observation by key |
| `scripts` | `script_content` (inline script text) |
| `url`, `text`, `css` | `page_url`, `page_text`, `css_rule` |
| `dom` | `dom`; targets `sel`, `sel::text`, `sel::attr(n)`, `sel::prop(n)` |
| `probe` | Fingerprint with `probe`, status `draft` |
| `implies`, `requires`, `excludes`, `requiresCategory` | Relationship |
| `\;version:\1`, `\;confidence:N` | `version_extract`, `confidence` (N/100) |
| `pricing` | `raw` only for now |

## Decisions

1. **IDs:** UUIDv7 with a kind prefix (`tech_<uuidv7>`).
2. **AND/OR:** `group_id` is enough for v0. An expression tree can be added
   later without breaking the existing fields.
3. **OS, CDN, hosting, WAF:** modelled as categories. `Technology.kind` stays
   as it is.
4. **Regex flavor:** the rule keeps `pattern` as the upstream string and
   gets a `regex_flavor` field (`re2` or `ecmascript`). Measured on Enthec
   (2026-11-15, `9e52f10`): of 8258 non-empty patterns, 8239 (99.8%) compile
   with Go RE2 after adding `(?i)`. 19 do not, in 11 technologies:
   17 use lookahead `(?!...)` and 2 use lookbehind `(?<!...)`. Those 19 are
   stored as `ecmascript`, so that engines without a backtracking regex can
   skip them with a warning rather than silently misfiring. This checks
   compilation only. Matching behavior differences are not tested yet.

## Open questions

1. Where do `pricing`, `saas` and `oss` belong? They are properties of
   technologies.
2. How do we merge author-estimated and validated confidence values?
3. Matching semantics: now fixed in `internal/matcher` and documented in
   [validation.md](validation.md). A comparison with another engine on real
   captures is still open.

## Public schema (v0.1.0, draft)

`schemas/registry.schema.json` (JSON Schema 2020-12) describes the export.
`examples/registry.json` is a hand-written example covering header, cookie,
meta tag, script URL, HTML, JS global, favicon hash, DNS, TLS and an active
probe. `schemas/schemas_test.go` checks the example, 20 invalid mutations
and 3 valid edge cases. Active probes cannot be `status: active` until
their `safety_review` is `approved`.

## Enthec extractor (implemented)

`internal/extractor/wappalyzer` maps the fields above. Run against Enthec
`9e52f10`: 7704 technologies, 109 categories, 15843 fingerprints, 2290
relationships. It emits 19 `unsupported_regex` warnings, matching the
measurement above, and 16 `multiple_category_groups` warnings. Wappalyzer
entries are OR-combined, so no `group_id` is produced. Probes are always
`pending`. The full-snapshot test is opt-in: set `OWF_ENTHEC_SNAPSHOT` to a
local clone.

## Normalizer (implemented)

`internal/normalizer` maps any `ExtractionResult` to canonical records.

- IDs come from an `IDAllocator` keyed by `(kind, source, upstream key)`, so
  re-importing a revision yields the same IDs. The in-memory allocator is
  for tests and one-shot runs; the repository will provide a persistent one.
- Slugs are derived from names (`C++` becomes `c-plus-plus`) with `-2`, `-3`
  on collision. Collision order depends on extraction order, so the
  repository must persist slugs once assigned. This is still open.
- A rule's upstream ID is `<technology>#<hash of the source fragment>`.
- Technologies start `active`, rules `active`, probes `draft`. Probe
  `safety_review` is always reset to `pending`. Validation health starts
  `unknown`.
- A rule with no source confidence gets 0.5. This is an unvalidated
  estimate; `provenance.original_confidence` stays unset in that case.
- Unknown references (categories, technologies) produce warnings and the
  record is skipped, never an invented placeholder.
- Full Enthec snapshot (`9e52f10`): 7704 technologies, 15839 fingerprints
  (4 skipped as `duplicate_rule`), 2290 relationships (none unresolved). The
  result validates against the JSON Schema.
- Vendors are not created yet (open question 4 earlier: manual only).

## Repository, validator and pipeline (implemented)

- `internal/repository`: backend-independent interface. An in-memory
  implementation lives in `repository/memory`. `Apply` is atomic.
- `internal/validator`: referential integrity, unique IDs and slugs,
  regex/flavor consistency, and probe rules (allowed methods, absolute
  path, no active probe without approved review). Errors stop the import.
- `internal/pipeline`: checksum, extract, normalize, validate, diff, persist.
  `DryRun` computes the diff without writing (new IDs may still be
  reserved).

Import rules:

- A pinned revision must not change: the same revision with another
  checksum is rejected.
- The diff is computed per source as added, modified and removed records.
  Re-importing the same revision gives an empty diff and an unchanged store.
- Records the source no longer provides are never deleted. Their provenance
  entry becomes `removed_upstream` and they are listed as removed. If they
  come back they show up as modified and return to `present`.
- Reviewer decisions survive re-imports: `status`, `validation`, a
  probe's `safety_review`, and a rule's `correction` (see `validation.md`).
- Provenance of other sources is kept untouched. Unchanged records keep the
  revision where they last changed.

Full Enthec snapshot through the pipeline: 7704 technologies, 15839
fingerprints, 2289 relationships, valid and idempotent. Real-data finding:
`Niagahoster` lists itself in `implies`; the normalizer drops it with a
`self_relationship` warning.

## SQLite, CLI and export (implemented)

- `internal/repository/sqlite`: pure-Go driver (`modernc.org/sqlite`), goose
  migrations embedded in the binary, explicit SQL. Each entity has indexed
  columns plus the full record as JSON, so the public model stays the source
  of truth. Foreign keys and unique slugs are enforced. Memory and SQLite
  both pass the shared contract in `repositorytest`, and the pipeline tests
  run on both.
- `cmd/owf` (Cobra, thin): `init`, `source list|info`, `import`,
  `technology list|show`, `fingerprint list|validate`, `export`, `stats`.
- `internal/export` builds the document in a stable order and refuses to
  return anything that violates the JSON Schema.
- Full Enthec `9e52f10`: import 2.4 s, 37 MB database, 21.7 MB export.

Not implemented yet: snapshot fetching (`source add|refresh`),
`fingerprint diff`, vendors, and deduplication across sources.

## Reconciliation, step 1 (implemented)

See [dedup-design.md](dedup-design.md). Records of different sources are
never merged automatically. Equivalent rules of one source share a canonical
ID derived from the semantic key, with one provenance entry per upstream
rule. Conflicts are internal review items and are not part of the public
schema 0.1.0.

## Reconciliation, step 2 (implemented)

`owf conflict resolve` merges or separates records. See
[dedup-design.md](dedup-design.md) for the merge rules, ownership of merged
records and real-data numbers. `repository.ChangeSet` gained `Delete` (only
used by merges) and `Aliases`; SQLite has the `aliases` table (migration
`00003`).

## Fetching snapshots (implemented)

`owf source refresh <source>` uses the `git` command line (`internal/fetch`):

1. `git ls-remote` resolves the branch tip to a commit ID. Nothing is
   downloaded. With `--revision <40-char sha>` this step is skipped.
2. `git fetch --depth 1 --filter=blob:none` of that one commit, plus a cone
   sparse checkout of the directories the source needs. Enthec: 5 MB and 37
   files instead of 115 MB and 7000 files. If the server rejects filters the
   fetch is retried in full.
3. The snapshot goes to `<cache>/<source>/<sha>`. A clean copy at the right
   commit is reused offline; a modified one is downloaded again.
4. The pipeline runs on it with the full commit ID as revision. The result of
   a live run is identical to a manual clone: same checksum
   `sha256:86c1d7b0...` for Enthec `9e52f10`.

Safety: only `https` URLs without credentials are accepted (`file://` only in
tests); branch names, commit IDs and sparse paths are validated so they cannot
be read as git options; hooks and auto-gc are disabled; prompts for
credentials are disabled; downloads go to a temporary directory and are moved
into place only after the commit is verified. The command never publishes
anything: it creates records and conflicts for review.

Each catalogue entry has `Branch` and `SparsePaths`. HTTP Archive and other
sources are not in the catalogue yet.

## Validation (implemented)

`owf fingerprint test` runs recorded observations against rules and stores
test evidence in `validation` (new optional `expect` field on `test_runs`);
`owf fingerprint lint` reports rules likely to match too much. See
[validation.md](validation.md).

## Vendors from CPE (implemented)

A technology's first usable CPE 2.3 string gives its vendor
(`cpe:2.3:a:<vendor>:<product>:...`). `Vendor` has two new optional fields:
`cpe_vendor` and `provenance`.

- The CPE vendor field is an identifier of an external dictionary, not a free
  name, so it identifies the same vendor in every source. Vendors are
  therefore **created and shared automatically** (the ID is allocated per CPE
  vendor, not per source). This is unlike technologies, whose names are
  matched only as candidates for review.
- The display name is derived from the identifier (`experience_manager`
  becomes `Experience Manager`) and is a guess: `Angularjs`, `Php`. Curate it;
  a stored vendor is never overwritten by a refresh, only its provenance grows.
- A vendor whose technologies all disappear from one source gets that
  source's provenance marked `removed_upstream`; it is not deleted.
- Merging two technologies whose vendors differ keeps the survivor's vendor and
  opens a `metadata_conflict` for `vendor`.
- `owf vendor list`; `technology show` names the vendor; `stats` counts vendors.
- Real data (Enthec + HTTP Archive, merged): 407 vendors, 468 of 7743
  technologies have one (only 6% of technologies carry a CPE), export valid.

### Curating vendors

```sh
owf vendor list --uncurated          # names that are still guesses
owf vendor show php
owf vendor set php --name "The PHP Group" --website https://www.php.net --alias PHP
owf vendor set php --clear-website --remove-alias PHP
```

`set` changes the name, website and aliases, validates them (non-empty name,
http(s) URL without credentials, no duplicate or self aliases), and marks the
vendor `curated` (new optional field, `curated: true` in the export). The slug,
the CPE identifier and the provenance never change. Refreshes do not overwrite
a stored vendor, curated or not. Read-modify-write is not locked against a
concurrent import: run them one at a time.

Not done: merging two vendors that are the same organization under different
CPE identifiers, and a bulk way to curate (for example from a CSV).

## Redistribution guard (implemented)

`owf export` refuses data from sources whose redistribution is `unreviewed`,
never exports `no`, and writes an `export` section (new optional object in the
schema) when it was filtered or includes unreviewed data. `owf source review`
records the decision with a required note; `Source` has new optional
`review_note` and `reviewed_at`. See [redistribution.md](redistribution.md).

## Recog source and new observation types (implemented)

`regex_flavor` gains `pcre` for patterns that need a backtracking engine and
come from a Perl/Ruby-style dialect (RE2 cannot run them, and they are not
ECMAScript). New open observation types: `page_title` (the HTML `<title>`),
`set_cookie` (a raw `Set-Cookie` line) and `favicon_hash` with the algorithm in
the target (`md5`). The matcher evaluates them offline; fixtures use `title`,
`set_cookies` and `favicon_hashes`. See [sources.md](sources.md#recog-imported-rapid7-recog).

## Nuclei source, groups and new observation types (implemented)

`group_id` is now used: rules that share one must all hold, on the same
request. A rule inside a group is a different rule from the same condition on
its own, so the group is part of the semantic key. The validator checks that a
group has at least two rules, one technology and one probe path.
`matcher.EvaluateGroup` evaluates a group.

New open observation types: `response_headers` (the raw header block, as
`Name: value` lines sorted by name), `http_response` (headers and body),
`http_status` (the status code), and `probe_response` now takes the targets
`status`, `body`, `headers`, `response`, `content_type` and `server`. Probed
answers are read whatever their status; only a rule on `status` with the
`exists` operator means "any 2xx". `favicon_hash` with target `mmh3` carries the
hash used by Shodan-style databases. See
[sources.md](sources.md#nuclei-technology-templates-imported-projectdiscovery-nuclei-templates).

## Version rules (implemented)

`Fingerprint.role` is absent for a rule that detects and `version` for a rule
that only reads a version (a regex with a `version_extract`, never in a group).
It does not detect by itself: it applies when a detection rule of the same
technology matched on the same request (`matcher.Version`). The role is part of
the semantic key and of the public schema. Validation cases select such a rule
with `"role": "version"` in the selector; a selector without a role selects
detection rules only. Detection rules that carry `version_extract` (Wappalyzer,
Recog) are unchanged.

## Export 0.2 (implemented)

Schema `0.2.0` adds the optional `manifest` (generator, counts, per-source
revision and snapshot checksum, `content_sha256`), plus what earlier steps added:
`role`, `curated`, `origin` and `expect` on test runs, the `export` section and
source review fields. Test evidence is exported with each rule's `validation`.
