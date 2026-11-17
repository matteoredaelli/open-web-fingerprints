# Redistribution of imported data

Every source has a redistribution status. The export only contains data a
source allows, and it refuses to guess.

| Status | Meaning | Exported |
|---|---|---|
| `unreviewed` | nobody has checked the terms (the default for every source) | refused, unless `--include-unreviewed` |
| `yes` | reviewed: the data may be redistributed | yes |
| `no` | reviewed: it may not | never, not even with the flag |

This tool records decisions; it does not make them and it is not legal
advice. Check the license of the data, not only of the code
([sources.md](sources.md) lists what is known and what is open).

## Recording a decision

```sh
owf source review enthec-webappanalyzer --redistributable yes \
  --note "reviewed by <who> on <date>: <what was checked, reference>"
owf source review enthec-webappanalyzer --redistributable unreviewed   # withdraw
```

A `yes` or `no` needs a note: the basis travels with the export
(`review_note`, `reviewed_at` on the source). The decision belongs to the
reviewer: a later import or refresh does not reset it. `owf source info` and
`owf source list` show the stored decision, not the catalogue default.

## What an export contains

- A record is exported only if **every** source that contributed to it is
  allowed. A merged record that a `no` source contributed to is left out as a
  whole, because its content cannot be separated. Records made by hand (no
  provenance) are exported.
- What depends on a left-out record goes too: rules of an excluded
  technology, relationships with an excluded end, snapshots of excluded
  sources. References from what remains (categories, parent categories,
  vendor) are removed instead of dangling.
- If a source with records is still `unreviewed`, `owf export` fails and names
  it. With `--include-unreviewed` the file carries an `export` section with
  `include_unreviewed: true`, the list of unreviewed sources and a notice that
  it is for internal use only. `owf export` also prints a warning.
- `export.excluded_sources` and `export.excluded_records` say what was left
  out. A fully reviewed export has no `export` section unless something was
  excluded.
- A provenance entry naming a source that is not in the registry counts as
  unreviewed, because its decision cannot be found.

## Limits

- The unit of exclusion is the record. A merged technology that one `no`
  source touched disappears even if most of it came from allowed sources.
  Detaching a source's contribution from a merged record is not implemented.
- Merging is irreversible and merged records carry every contributing source.
  On the real registry (Enthec merged with HTTP Archive), marking HTTP
  Archive `no` leaves 3734 of 7743 technologies and drops 16395 records. Decide
  the redistribution status of both sources **before** approving bulk merges.
- Conflicts and aliases are not exported, so they cannot leak excluded data.
- The status is per source, not per record or per file: a source whose files
  have different licenses needs splitting into several catalogue entries.
- Nothing stops someone from copying the database file itself. The guard is on
  the export path.
