# Cross-source reconciliation and deduplication (draft)

Status: **implemented (steps 1 and 2)**. Based on a
measurement of two real sources.

## Decisions

1. **No automatic merge between sources.** A same-slug match is only a
   *candidate*. Technologies and categories from different sources stay
   separate records until a reviewer approves the merge.
2. Target normalization as in section 2 (cookie names stay case-sensitive).
3. Canonical confidence is the **lowest explicit** value; each source's value
   stays in its provenance.
4. Conflicts are **stored**. Step 1 adds `owf conflict list`; step 2 adds
   `owf conflict resolve` (merge or keep separate), which is required because
   nothing merges without it.

Implementation steps:

- **Step 1 (this change):** semantic key, merging of equivalent rules inside a
  source, stable slugs across sources, stored conflicts, identity and category
  candidates, `owf conflict list`.
- **Step 2:** `conflict resolve`, record merge with aliases for old IDs,
  cross-source rule merge, metadata and confidence conflicts, order
  independence test.

## Measurement: Enthec `9e52f10` vs HTTP Archive `35b0847`

Both were normalized with the current normalizer and compared by slug and by
a candidate semantic key (technology, observation, target, operator, pattern,
version extract).

| Measure | Value |
|---|---|
| Technologies Enthec / HTTP Archive | 7704 / 4009 |
| Same slug in both | 3996 (99.7% of HTTP Archive) |
| Common technologies with a different website (exact string compare) | 65 |
| Common technologies with different categories | 49 |
| Distinct semantic keys Enthec / HTTP Archive | 15803 / 5848 |
| Identical rules in both | 5700 (97% of HTTP Archive) |
| Identical rules with different confidence | 1 |
| Only in HTTP Archive | 148 (128 of them for technologies Enthec also has) |
| Only in Enthec, on technologies both have | 3749 |
| Enthec rules with the same technology, observation and target as an HTTP Archive rule, but a different pattern | 61 |
| Enthec rules with a mixed-case target (header, cookie, meta names) | 5373 |
| Equivalent rules inside Enthec alone, with the final semantic key | 3 (plus 4 byte-identical ones) |

Reading: the sources overlap heavily and mostly agree. True disagreements are
rare, but they exist and must be visible. The two datasets share an ancestor,
so agreement is not independent evidence.

## 1. Technology identity

Today every source allocates its own technology IDs, so nothing merges. The
proposal adds a *reconcile* stage between normalize and diff.

- **Identity key:** the slug of the name, plus the registrable domain of the
  website when both sides have one.
- Same slug: an `identity_candidate` conflict is recorded with the evidence
  (`websites`: `same_domain`, `different` or `unknown`). Nothing is merged.
  Reviewers can approve the cases with `same_domain` in bulk.
- Different slug, same website: no candidate. Manual aliases can join them
  later.
- Categories follow the same rule (`category_candidate`, same normalized
  name).
- Until a merge is approved, the later record gets a suffixed slug
  (`wordpress-2`). Slugs of existing records never change.
- Slugs stay unique. A manual alias table (`slug -> canonical technology`) is
  the escape hatch.

## 2. Fingerprint semantic key

Two rules are the same rule when their key is equal. The key is computed
after normalizing the fields below and does not depend on names or wording:

`(canonical technology ID, observation, normalized target, operator, pattern, regex_flavor, version_extract)`

Target normalization depends on the observation:

| Observation | Normalization |
|---|---|
| `http_header`, `meta_tag` | lower case (names are case-insensitive) |
| `dns_record` | upper case (record type) |
| `cookie`, `js_global`, `dom`, others | unchanged (case-sensitive) |

Patterns are compared as strings. There is no regex rewriting, and two
different strings are never assumed to be equivalent. Both sources use the
same Wappalyzer semantics, so equal strings mean equal rules here. A new
source with other semantics will need its own mapping to the model before its
rules can match.

Equal key: one canonical fingerprint, with one provenance entry per
`(source, original_id)`. Confidence is not raised by agreement.

## 3. Conflicts

Wappalyzer-style rules are OR-combined, so a different pattern on the same
header is another rule, not a contradiction. Only these cases are conflicts:

| Kind | Trigger | Handling |
|---|---|---|
| `identity_candidate`, `category_candidate` | same normalized name in two sources | never merged automatically; review |
| `metadata_conflict` | merged technologies differ in website, description or categories | canonical value from the higher-priority source; alternatives kept in the conflict |
| `confidence_disagreement` | sources give different explicit confidence | canonical value is the lowest explicit one (conservative); each source's value stays in its provenance |
| `variant_candidate` | same technology, observation and target, different pattern | informational only, no change |

A conflict is a stored record: `id`, `kind`, `record_ids`, `sources`,
`detail`, `state` (`open`, `resolved`, `ignored`), `resolution`,
`created_at`. Re-running an import must not reopen a resolved conflict
unless the underlying values change.

Source priority is a static integer in the built-in catalogue (for example
Enthec 100, HTTP Archive 90). It only decides which metadata value becomes
canonical.

## 4. Removal with several sources

A canonical rule is "removed upstream" only when **every** source provenance
entry is `removed_upstream`. It is then flagged for review and never deleted,
as today. If one of two sources drops it, only that provenance entry changes.

## 5. What changes in the code

- Provenance merge keys on `(source, original_id)`, not `source`. This also
  handles the 36 duplicates inside Enthec.
- `fingerprints` and `technologies` get an indexed `semantic_key` /
  `identity_key` column (migration `00002`). It is internal, not part of the
  public schema.
- New `internal/reconciler` stage. It looks records up through the key index
  and returns canonical IDs. It must not depend on SQLite.
- New `conflicts` table and `repository` methods. The report lists conflicts
  opened or changed by an import. A `owf conflict list` command comes before
  any resolve command.
- Export: conflicts are not in schema 0.1.0. Add them in a later minor
  version if consumers need them.

## 6. Tests required

- Order independence: import A then B, and B then A. The set of semantic keys
  and the provenance of each must be equal (canonical IDs may differ).
- Idempotency still holds with two sources.
- Same fixtures from both sources produce one canonical rule with two
  provenance entries and unchanged confidence.
- A different website produces an `identity_conflict` and two technologies.
- A different explicit confidence produces `confidence_disagreement`.
- Removing a rule from one source keeps the other source's entry present.
- A resolved conflict stays resolved after a re-import.

## Open questions

None for step 1. For step 2: which technology survives a merge. Proposal:
the older record (UUIDv7 sorts by time), with the other ID kept as an alias.

## Step 1 results (implemented)

- `domain.Fingerprint.SemanticKey`, with the case rules of section 2.
- The normalizer merges equivalent rules inside a source into one record
  with one provenance entry per upstream rule. The canonical ID comes from
  the semantic key, not from the order of the duplicates, and the canonical
  confidence is the lowest explicit value (`confidence_disagreement` warning).
- Slugs are stable (a known record keeps its slug) and unique across sources.
  The later source gets `-2`.
- `internal/reconciler` proposes `identity_candidate` and
  `category_candidate` conflicts. The evidence uses sides ordered by record
  ID, so it is identical whichever source is imported first. Websites are
  compared by registrable domain (public suffix list).
- Conflicts are stored (migration `00002`). A known conflict keeps its state
  and resolution on re-import and is reopened only if its evidence changes.
- `owf conflict list [--kind --state --websites --json]`, and open conflicts
  in `owf stats`.

Real data, Enthec `9e52f10` plus HTTP Archive `35b0847`, imported as two
sources: 11713 technologies (nothing merged), 3973 identity candidates with
the same website domain, 27 with a different domain, 108 category candidates.
Importing either source again changes nothing.

## Step 2 results (implemented)

Commands: `owf conflict show <id>` and
`owf conflict resolve [id...] (--merge | --keep-separate) [--all --kind K --websites W] [--note ...] [--dry-run]`.
A bulk request needs `--all` and at least one filter; a bulk merge only
touches candidate conflicts. All decisions of one request are applied in one
transaction.

What a merge does (`internal/merge`, applied by `internal/review`):

- The **older record survives** (UUIDv7 sorts by time). The other ID becomes
  an **alias**; chains are collapsed, and imports translate old IDs.
- Provenance is unioned, with the survivor's source first. Extra names go to
  `aliases`, CPEs and categories are unioned, empty fields are filled.
- Rules of the absorbed technology move to the survivor. A rule that means the
  same as an existing one is combined with it (provenance unioned, canonical
  confidence is the lowest explicit value). If sources stated different
  confidence values, an open `confidence_disagreement` conflict is created.
- Relationships follow; equivalent ones are combined, and one that became a
  self reference is dropped.
- If both technologies had a website and the domains differ, an open
  `metadata_conflict` records both values.
- Candidate conflicts that involved the absorbed record are closed as
  superseded, and the pair that remains is opened again with the same key and
  evidence the detector uses, so it is not lost and not duplicated.
- Category merges rewrite references in technologies, parents and
  relationships.

Ownership of merged records. The source of the first provenance entry owns the
content. A refresh from the owner updates it, but keeps what other sources
contributed (extra names, CPEs, categories, and fields the owner leaves
empty). A refresh from any other source only updates its own provenance
entries, so one source cannot overwrite another. Provenance order is
preserved on update. Fingerprint confidence is always the lowest explicit
value over all entries. Reviewer decisions (status, validation, probe safety
review) are never overwritten.

New upstream rules that mean the same as a stored rule of a merged
technology take the stored rule's ID and get an alias, so rules of different
sources keep converging after the merge.

Real data, Enthec `9e52f10` plus HTTP Archive `35b0847`:

| | Before review | After approving `same_domain` + categories |
|---|---|---|
| Technologies | 11713 | 7743 |
| Fingerprints | 21706 | 16034 (5672 rules combined) |
| Relationships absorbed | | 644 |
| Categories merged | | 108 |
| Open conflicts | 4108 | 30 |

Re-importing either source after the merge changes nothing. Merging in either
import order gives the same registry (test on fixtures).

Known limits: matching is by slugified name, so differently named products
need a manual alias; there is no `unmerge`; alias and conflict data are
internal and not part of export schema 0.1.0.
