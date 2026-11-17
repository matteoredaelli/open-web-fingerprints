# Cross-source reconciliation and deduplication (draft)

Status: **proposal, not implemented**. It is the design for Phase 5, based on
a measurement of two real sources.

## Measurement: Enthec `9e52f10` vs HTTP Archive `35b0847`

Both were normalized with the current normalizer and compared by slug and by
a candidate semantic key (technology, observation, target, operator, pattern,
version extract).

| Measure | Value |
|---|---|
| Technologies Enthec / HTTP Archive | 7704 / 4009 |
| Same slug in both | 3996 (99.7% of HTTP Archive) |
| Common technologies with a different website | 65 |
| Common technologies with different categories | 49 |
| Distinct semantic keys Enthec / HTTP Archive | 15803 / 5848 |
| Identical rules in both | 5700 (97% of HTTP Archive) |
| Identical rules with different confidence | 1 |
| Only in HTTP Archive | 148 (128 of them for technologies Enthec also has) |
| Only in Enthec, on technologies both have | 3749 |
| Enthec rules with the same technology, observation and target as an HTTP Archive rule, but a different pattern | 61 |
| Enthec rules with a mixed-case target (header, cookie, meta names) | 5373 |
| Semantic duplicates inside Enthec alone (15839 rules, 15803 keys) | 36 |

Reading: the sources overlap heavily and mostly agree. True disagreements are
rare, but they exist and must be visible. The two datasets share an ancestor,
so agreement is not independent evidence.

## 1. Technology identity

Today every source allocates its own technology IDs, so nothing merges. The
proposal adds a *reconcile* stage between normalize and diff.

- **Identity key:** the slug of the name, plus the registrable domain of the
  website when both sides have one.
- Same slug and compatible website (same domain, or one side empty): the
  fresh record takes the existing canonical ID and gains one more provenance
  entry.
- Same slug but different website (65 cases here): **not merged**. Both stay
  separate and an `identity_conflict` is recorded for review.
- Different slug, same website: not merged, no conflict. Manual aliases can
  join them later.
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
| `identity_conflict` | same slug, different website | not merged, review |
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

1. Is slug plus website domain acceptable for technology identity, or do you
   want every cross-source merge to be reviewed first?
2. Is the target normalization table right? In particular, are cookie names
   case-sensitive for this project?
3. Should the canonical confidence be the lowest explicit value (proposed),
   or the value of the highest-priority source?
4. Are stored conflicts with a later resolve command wanted now, or is a
   report-only first step enough?
