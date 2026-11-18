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

## Status in the catalogue

Both Enthec and HTTP Archive are in the built-in catalogue and share the
`wappalyzer` extractor (`internal/extractor/wappalyzer`). `owf source refresh
<slug>` fetches either. Both are `redistributable: unreviewed`.

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

## Value of the sources (measured 2026-11-17)

**HTTP Archive adds almost nothing to Enthec.** It is a fork of the same
ancestor. Compared by technology (slugified name) and by rule (technology,
observation, normalized target, operator, pattern, version extract):

| | Enthec `9e52f10` | HTTP Archive `35b0847` |
|---|---|---|
| Technologies | 7696 | 4009 (13 not in Enthec) |
| Distinct rules | 15830 | 8918 (8680 identical to Enthec) |
| Rules only here | | 238 (212 on technologies Enthec has, 26 on the 13 new ones) |

Combined, HTTP Archive adds 1.5% of the rules. Its use is as a drift check and
as a test of the reconciliation machinery, not as coverage. Agreement between
the two is not independent evidence.

**Candidate sources with different data** (all surveyed through the GitHub
API; repository licenses are not proof of the license of the data, and some of
these derive from Wappalyzer data, which would carry its lineage):

| Source | Repo license | Active | What it holds |
|---|---|---|---|
| projectdiscovery/nuclei-templates (`http/technologies`) | MIT | yes | 766 per-product detection templates plus ~400 in subfolders, mostly self-hosted and enterprise products; a name match finds only 120 of the 766 in Enthec, so up to ~650 may be new. `tech-detect.yaml` is itself Wappalyzer-derived. Templates use matchers (words, regex, status, favicon) and extractors for versions. |
| same repo, `http/exposed-panels` | MIT | yes | 1589 login/admin panel detections, ~1489 with no name match. Path probes: they would become `draft` probes with `safety_review: pending`. |
| rapid7/recog | BSD-2-Clause (Debian copyright file) | yes | Banner and header fingerprints with product, vendor, version and CPE: 458 `Server` headers, 548 favicons, 460 HTML titles, 86 cookies, 80 `WWW-Authenticate`. Different data from Wappalyzer, and it carries CPE vendor/product. |
| RetireJS/retire.js | Apache-2.0 | yes | 77 JavaScript libraries with version extractors (uri, filename, file content, hashes). Small; also holds vulnerability data, out of scope. |
| EnableSecurity/wafw00f | BSD-3-Clause | slowly | 173 WAF plugins written as Python code, hard to import faithfully. |
| 0x727/FingerprintHub | MIT | yes | Nuclei-style web fingerprints; lineage unclear (may reuse other projects' rules). |
| EdgeSecurityTeam/EHole | Apache-2.0 | stale (2024-04) | Fingerprints focused on Chinese systems. |
| urbanadventurer/WhatWeb | GPL-2.0 | yes | 1835 Ruby plugins; each plugin header says it may carry redistribution restrictions. Not before a license review. |
| CMSeeK | GPL-3.0 | yes | CMS detection inside Python code. |

Out of scope by AGENTS.md: the CVE, vulnerability, misconfiguration and
default-login templates of nuclei-templates. They are exploit or
authentication checks, not fingerprints.

These overlap figures are rough: they match names, not rules. Real rule
overlap is known only after an extractor exists.

## Recog (imported, `rapid7-recog`)

Extractor: `internal/extractor/recog`. Snapshot `f1191e2`, 3.6 MB, refresh in
about 2 s. Only the web databases are read: `http_servers`, `http_cookies`,
`http_xpoweredby`, `http_wwwauth`, `http_header.x-fortisandbox-version`,
`html_title` and `favicons`. The other 45 databases (SSH, SMTP, SNMP, DHCP,
x509, JARM, ...) are not web data and are out of scope for now.

| | |
|---|---|
| Fingerprints in the 7 databases | 1630 |
| Imported as rules | 1176 (317 with a version) |
| Skipped, counted in warnings | 454: 448 identify only an OS or hardware, 6 take the product from a capture group |
| Technologies | 794 (758 product names; names shared by several vendors are shown as `<vendor> <product>`) |
| Rules by kind | favicon MD5 460, header 411, page title 226, Set-Cookie line 79 |
| Vendors | 190, of which 65 already existed from Enthec's CPEs |
| Identity candidates with Enthec | 74, all with unknown websites: about 9% of Recog's technologies match an Enthec name, so about 720 are new |
| Patterns RE2 cannot run | 0 |

What is different from the Wappalyzer-format sources:

- **New kinds of observation.** Enthec has no favicon, page title or raw
  `Set-Cookie` rules. Recog's 686 of them are new data. (Favicon rules carry
  the algorithm in the target, `md5`.)
- **Source confidence.** Recog states a preference per database (0.85 to
  0.90) and, sometimes, a per-fingerprint certainty. Both are kept as the
  rule's original confidence.
- **Case sensitivity.** Recog patterns are case-sensitive unless flagged
  `REG_ICASE`; the registry matches case-insensitively by default, so
  case-sensitive patterns get an explicit `(?-i)` prefix. Patterns RE2 cannot
  run would be marked `pcre` (new `regex_flavor`); none of these do.
- **Product names are not identities.** `Dashboard`, `HTTP`, `Media Server`,
  `CMS` and `Horizon` are products of several vendors. A technology is a
  (vendor, product) pair. This was found by importing real data: keying by
  product name alone merged unrelated products.
- **Upstream ships its own tests.** Every fingerprint has `<example>` strings
  (1662 on the imported rules), often with the expected version. They are kept
  in each rule's raw fragment. As a conformance check, all 1662 pass with the
  registry's matcher, including version extraction and case sensitivity.
  That confirms the mapping. `owf fingerprint test --upstream-examples
  --apply` also uses them as test evidence, with negatives from other products'
  banners (see validation.md): 685 of the 1176 rules reach `ok`, marked as resting
  on upstream examples only.

Licensing: `debian/copyright` says BSD-2-Clause, Copyright 2014 Rapid7, Inc.
The GitHub API reports no license for the repository. The data has many
contributors. The source stays `unreviewed` until someone reviews it; the BSD
notice must be kept when redistributing.

Not done: the vendor name of a Recog product without a CPE is not used (vendors
are keyed by CPE identifier), and the operating-system and hardware entries
(448) are skipped rather than modelled.

## Nuclei technology templates (imported, `projectdiscovery-nuclei-templates`)

Extractor: `internal/extractor/nuclei`. Snapshot `91be390`, `http/technologies`
only (27 MB with git data, about 4 s). The repository is MIT, Copyright 2025
ProjectDiscovery, Inc. Out of scope by AGENTS.md: CVE, vulnerability,
misconfiguration and default-login templates, which are exploit or
authentication checks.

A template is a request plus matchers combined with `and`/`or`. The extractor
turns that formula into an OR of clauses; a clause with several terms becomes a
**group** of rules that must all hold (`group_id`), which is what the model had
been reserving it for. Real data:

| | |
|---|---|
| Templates in `http/technologies` | 1164 |
| Templates that produced at least one rule | 779 (67%); 5 generated ones are not read as products |
| Technologies | 1421 (775 from the favicon table, the rest from per-product templates) |
| Rules | 4994 stored (5151 extracted; equivalent rules merged) |
| Groups | 1627 groups, 3866 grouped rules |
| Probe rules | 2172, on 304 distinct paths, all `GET`; each is a draft with a pending safety review |
| Favicon hashes | 765 mmh3 (new: Recog's 460 are md5) |
| Vendors | 128, of which 63 were already known from CPEs |
| Identity candidates with Enthec and Recog | 207, so about 85% of the technologies have no name match |

**Skipped, counted in warnings:** payload lists (241 templates, wordlist-driven
probes), `dsl` outside the supported subset (58 blocks), `POST` (23), raw
requests (22), request headers or bodies (7), flows (8), negative matchers (3),
paths with variables (8), and a favicon hash on a probed path (53). A clause is
all or nothing: if one term cannot be represented the whole clause is dropped,
because keeping the rest would make the rule match more than the template does.

**Generated templates are not read as products:** `tech-detect` is generated
from Wappalyzer data (it duplicates the Wappalyzer-format sources and has its
lineage), `fingerprinthub-web-fingerprints` from FingerprintHub data, and the
WordPress plugin and theme lists and `waf-detect` are lists of thousands of
entries. `favicon-detect` is read as a table of favicon hashes (the status
condition is dropped, because a matching hash already implies a favicon was
served).

**Not mapped yet: version extractors.** 209 templates have extractors that read
versions. Their rules detect the product but not the version, so version
information from this source is missing. The DSL subset is deliberately small.
Redirect settings of the requests (`host-redirects`, `max-redirects`) are
ignored, and `{{RootURL}}` is treated like `{{BaseURL}}`.

**Safety.** Probes are only imported, never run by this project. Review them
before approving: `owf fingerprint list --observation probe_response`, and
`owf fingerprint lint` flags the 83 whose path has a query string. Several
paths are error-page triggers or configuration files; a reviewer decides whether
a probe is harmless before its `safety_review` becomes `approved`.

**Licensing.** The repository license is MIT. Templates have many authors, and
some derive from other projects; the generated ones that say so are skipped, but
nothing proves that the others are free of such lineage. The source stays
`unreviewed`.
