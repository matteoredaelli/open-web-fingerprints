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
| `scripts` | `script_url` or `js_global` (to confirm) |
| `probe` | Fingerprint with `probe`, status `draft` |
| `implies`, `requires`, `excludes`, `requiresCategory` | Relationship |
| `\;version:\1`, `\;confidence:N` | `version_extract`, `confidence` (N/100) |
| `pricing` | `raw` only for now |

## Open questions

1. ID scheme: ULID or UUIDv7?
2. AND/OR: is `group_id` enough, or do we need a boolean expression tree?
3. Does `Technology.kind` need more values (OS, CDN, hosting, WAF)? Or should
   that be a category?
4. Should vendors be created from CPE automatically, or only by hand?
5. Where do `pricing`, `saas` and `oss` belong? They are properties of
   technologies.
6. How do we treat unsupported regex flavors? Wappalyzer uses JavaScript
   regular expressions, and Go uses RE2. Do we keep the flavor in the rule,
   or convert it?
7. Confidence: how do we merge author-estimated and validated values?
