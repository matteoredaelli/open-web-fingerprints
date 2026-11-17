# Upstream sources: analysis

Snapshot taken on 2026-11-17 from shallow clones of each default branch.
This is a technical survey, **not legal advice**. Every license conclusion
below needs a legal review before any data is redistributed (see AGENTS.md).

| ID (proposed) | Upstream | Revision | Repo license | Data type | Priority |
|---|---|---|---|---|---|
| `enthec-webappanalyzer` | github.com/enthec/webappanalyzer | `9e52f10` (2026-11-15) | GPL-3.0 | JSON, Wappalyzer format | **1** |
| `httparchive-wappalyzer` | github.com/HTTPArchive/wappalyzer | `35b0847` (2026-11-17) | GPL-3.0 | JSON, Wappalyzer format | 2 |
| `whatweb` | github.com/urbanadventurer/WhatWeb | `d279d93` (v0.6.4, 2026-04) | GPL-2.0 (see below) | Ruby DSL plugins | 3 |
| `wappalyzergo` | github.com/projectdiscovery/wappalyzergo | `a702881` | MIT (code) | Derived JSON, Go | reference only |
| `opentechalyzer` | github.com/Houseofmvps/opentechalyzer | `a3d30e4` | MIT | TypeScript objects | reference only |
| `cern-wad` | github.com/CERN-CERT/WAD | not cloned | GPL-3.0 | n/a | skipped |

## Enthec WebAppAnalyzer (first importer candidate)

- A community continuation of Wappalyzer, which went closed source in
  August 2023. Enthec states it keeps the same JSON structure.
- Layout: `src/technologies/{_,a..z}.json` (one object per technology, keyed
  by name), `src/categories.json`, `src/groups.json`, and a `schema.json`
  for validation. `icon` references images in the upstream repo.
- **7704 technologies.** Field usage (count of technologies):
  `cats` 7704, `website` 7704, `description` 7226, `saas` 5023,
  `pricing` 4518, `scriptSrc` 3913, `js` 3366, `dom` 1644, `implies` 1025,
  `oss` 852, `scripts` 814, `meta` 765, `requires` 700, `headers` 674,
  `cpe` 466, `cookies` 379, `html` 359, `xhr` 147, `dns` 145,
  `requiresCategory` 90, `url` 86, `text` 61, `excludes` 47, `css` 22,
  `certIssuer` 6, `probe` 3, `robots` 1.
- Categories are numeric IDs (`cats: [1, 25]`) resolved through
  `categories.json`, which also has `groups` and `priority`.
- Pattern strings carry inline modifiers after `\;`, e.g.
  `"^(.+)$\\;version:\\1"` and `\\;confidence:50`. The extractor must parse
  these and keep the raw string.
- The format already supports DNS records, DOM queries, cookies, headers,
  meta tags, script URLs, JS globals, XHR, `implies`/`requires`/`excludes`,
  CPE (a vendor/product hint) and `probe` (active). It covers most
  observation types in AGENTS.md. TLS is only partly covered (`certIssuer`).
- There is **no** per-rule ID, revision, license, or test evidence. The
  technology name is the only upstream identifier, and it can change.
  Provenance must be stored as (source, revision, file, technology name).
- Active probes (`probe`, `robots`) are very rare. Import them as
  `status=draft` and review them against the project's active-probe policy.

### Licensing concerns
- The repo is GPL-3.0, which fits this project's GPLv3+ preference.
- The data descends from the older Wappalyzer project, which was MIT-licensed
  before the 2023 closure, plus later contributions. Lineage and any
  per-file notices must be checked. The GPL-3.0 on the repo may not map
  one-to-one onto every record.
- Icons are third-party logos and trademarks. **Do not import icons**. Keep
  only the icon file name as raw data.

## HTTP Archive Wappalyzer

- A fork of the last open-source Wappalyzer. It powers the monthly HTTP
  Archive crawl. The README says the Wappalyzer site and extension are not
  part of it.
- Same layout and schema as Enthec, with 4009 technologies against Enthec's
  7704. 3992 names overlap, 3712 are only in Enthec, and 17 are only in HTTP
  Archive. Of the overlapping names, 3311 have different definitions, so the
  two sets have diverged.
- A good second source for testing deduplication and conflict handling,
  because it has the same format and different content. It may also share
  provenance with Enthec for the older records.
- It is not independent evidence, since both derive from the same ancestor.
  Per AGENTS.md, do not raise confidence when both agree.

## WhatWeb

- Ruby plugins: 1835 files in `plugins/`, each a `Plugin.define do … end`
  DSL block with `name`, `authors`, `version`, `description`, `website`,
  `dorks`, `matches`, and `passive`/`aggressive` blocks.
- `matches` entries use `:text`, `:regexp`, `:version`, `:url` (an extra
  request), `:md5` (favicon or file hash), `:tagpattern`, `:certainty` and
  `:name`. Passive blocks hold arbitrary Ruby code.
- Roughly 282 plugins use `:url` or `:md5`, and 24 use `aggressive` blocks.
  These are active probes and need explicit review.
- **Parsing is hard.** A static extractor can handle the declarative
  `matches` and `dorks`. The Ruby logic in `passive`/`aggressive` blocks
  cannot be converted faithfully. The extractor should import the
  declarative part, record a warning for the code, and keep the plugin
  file reference.
- Licensing: the LICENSE file is GPL-2.0. Source headers say "version 2 of
  the License, or (at your option) any later version", which is
  GPL-2.0-or-later and would be compatible with GPL-3.0-or-later.
  However, each plugin header says it "may be subject to redistribution
  and commercial restrictions", so **per-plugin terms need checking**.
  This is the biggest licensing risk of the sources surveyed.
- Plugin authorship lists are useful provenance. Preserve them.

## wappalyzergo and opentechalyzer (references only)

- `wappalyzergo` (MIT) consumes Enthec and HTTP Archive data. Its
  `fingerprints_data.json` is a normalized derivative of upstream data,
  not an independent source. Use it as a **reference matching engine**
  (regex normalization, performance) for the future detection engine. Do
  not import its data.
- `opentechalyzer` (MIT, 588 hand-written fingerprints, one commit) has
  its own TypeScript fingerprint format with confidence scores and
  evidence. It is useful as a design reference for confidence and
  evidence. It is young and small, and it explicitly avoids redistributing
  GPL data, which is the opposite of this project's approach. Its own
  README notes that mixing GPL data would change the license of the
  combined work.
- `CERN-CERT/WAD` (last push 2023-09) is skipped because it is unmaintained.

## Consequences for the domain model

1. A rule needs an observation type, operator (regex, substring, exists,
   equals), pattern, optional version extraction, and confidence. Enthec's
   `\;version:` and `\;confidence:` modifiers map to those fields.
2. Wappalyzer groups several observations under one technology with
   implicit OR semantics. The model needs one fingerprint per observation,
   with an explicit grouping, so provenance and validation are tracked
   per rule.
3. Categories are numeric upstream IDs and must map to canonical category
   IDs. The upstream ID is stored as provenance.
4. `implies`, `requires`, `excludes` become `Relationship` entries.
5. `cpe` should populate Vendor/Product data and a version-matching hint.
6. Upstream has no stable rule IDs. Canonical IDs must be generated and
   mapped to (source, name, rule hash).
7. Active probes (WhatWeb `:url`/`:md5`, Enthec `probe`) are a separate
   kind with an explicit safety policy.
8. Raw source records must be preserved. Pattern modifiers and DSL
   details will need re-normalizing later.

## Recommended import order

1. Enthec: the largest source, a simple JSON format, a GPL-3.0 repo, and a
   JSON Schema from upstream we can reuse for validation.
2. HTTP Archive: the same extractor with a different source config. It
   tests deduplication and conflicts.
3. WhatWeb: a different format, after the licensing review. It proves the
   abstraction is source-independent.

## Open questions

- Legal review of data lineage (Wappalyzer MIT → GPL) and of WhatWeb's
  per-plugin redistribution terms.
- **Decided:** published data uses the same license as the code
  (GPL-3.0-or-later). Sources with incompatible or unclear terms are not
  redistributed until reviewed. WhatWeb is the main open case.
- Pin snapshots by commit SHA and store a checksum of each imported file.
