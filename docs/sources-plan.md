# Plan: more sources of fingerprints

State of 2026-11-20. Four sources are imported (`sources.md`). This page decides which others
to add, in what order and what has to be settled first. **Nothing here is imported yet.** What
was checked is marked; what was not is said.

The rules that apply to every new source are in `AGENTS.md`: an extractor package with real
fixtures from a pinned revision and a `testdata/README.md` (licence notice), a contract test, a
catalogue entry in `internal/builtin`, a short survey in `sources.md`, **real overlap measured
before any claim of value**, `unreviewed` redistribution status until a human decides. CVE,
vulnerability, misconfiguration and default-login content is out of scope.

## What was checked

Facts read from the repositories on 2026-11-20 (GitHub API and raw files). "Not checked" means
exactly that.

| Project | Licence (checked) | What is in it (checked) | Format |
|---|---|---|---|
| Retire.js | Apache-2.0 | `repository/jsrepository.json`: 77 libraries, 405 extractor patterns, 70 libraries with a `vulnerabilities` list | JSON with a `§§version§§` placeholder in regexes; extractor kinds `uri`, `filename`, `filecontent`, `filecontentreplace`, `hashes`, `func` |
| CMSeeK | GPL-3.0 | Python tool; signatures in `cmseekdb/` (13 files) and per-CMS `deepscans/` modules | Python dictionaries and code |
| OpenTechalyzer | MIT (the README says the built-in database is written for the project and is not a copy of another dataset) | 588 fingerprints in `src/fingerprints/*.ts` (11 files, about 140 KB); signals include `scriptSrc`, `html`, `js`, `requestHost`, `implies` | TypeScript object literals |
| WhatWeb | GPL-2.0 (repository) | about 1000 Ruby plugin files in `plugins/` | Ruby DSL with lambdas and regexes |
| Nmap | the GitHub API says `NOASSERTION`: the Nmap Public Source License, a custom licence | `nmap-service-probes`: 11969 `match` lines for network services, of which only the web ones are of interest | text, PCRE regexes |
| Inoue | **proprietary**: `LICENSE` reads "Inoue Freelance Proprietary License ... All rights reserved ... may not be copied, modified, distributed ... without the express written permission of the copyright holder" | a tech-stack tool with test fixtures | not applicable |

Not checked: the quality of any project's rules, how many of them duplicate what is already
imported, the exact structure of CMSeeK's signature files and of WhatWeb's plugins beyond their
count, and whether OpenTechalyzer's fingerprints really are independent of the Wappalyzer sets.

## Assessment and order

1. **Retire.js** (measured: see below; the value is smaller than I expected). Cleanest licence (Apache-2.0 can be combined into a GPL-3.0 work) and a
   JSON file. It gives **versions of JavaScript libraries** from file names and contents, which the
   Wappalyzer sources do less well. Import only the `extractors` of each library; **skip
   `vulnerabilities` entirely** (out of scope). The `§§version§§` placeholder becomes
   `version_extract`. `func` extractors are JavaScript expressions over globals (for example a
   version property): they map to `js_global` rules and need `--browser`. `hashes` (file digests)
   need a new observation type and the scanner does not fetch scripts yet: **kept in `raw`, not
   imported**, and counted as skipped. Expected size is small (hundreds of rules), so the overlap
   measurement is quick.
2. **OpenTechalyzer.** MIT, newest data model, 588 fingerprints, and it has an observation the
   registry lacks, `requestHost` (the host of a request the page makes), which fits the XHR work. The
   work is the **format**: the rules are TypeScript source, not JSON. The extractor is a pure Go
   reader, so it needs a parser for the subset of TypeScript object literals used (strings, arrays,
   objects, regex strings, no code). That is a bounded job but real. Alternative: ask the author for
   a JSON export. **Overlap with Enthec has to be measured first**: if most of it duplicates
   Wappalyzer names, the value is the minority that does not.
3. **CMSeeK.** GPL-3.0, so the licence is the easiest after the Apache one. Its signatures are Python
   dictionaries and code, per CMS: paths to request and strings to look for. They are mostly
   **probes** (a path), so they would be imported as drafts with a pending safety review, like the
   nuclei ones, and need the `owf probe` review. The value is CMS-specific paths and version
   detection; the cost is reading Python. To be looked at in detail before deciding.
4. **WhatWeb.** The richest and the oldest, with about 1000 plugins, but they are Ruby code (lambdas,
   `passive`/`aggressive` methods, regexes in Ruby syntax). Only plugins that are pure data (a
   `matches` list) can be imported without executing or interpreting Ruby; the rest would be skipped
   and counted, which the project's rule prefers to keeping a weaker rule. The licence is
   **GPL-2.0**: whether data taken from GPL-2.0-only code can sit in a GPL-3.0-or-later work is a
   **legal question for you**, not settled here.
5. **Nmap: not recommended now.** It is about network services, not web technologies (the web part
   is a fraction of 11969 lines, and those are mostly server banners the registry already has from
   Recog). The licence is a custom one with restrictions of its own, and I have not established
   that it is compatible with GPL-3.0-or-later. If you want network services, it is a separate
   scope decision first.
6. **Inoue: excluded.** Its licence is proprietary and forbids copying and redistribution. There is
   nothing to negotiate unless the author grants permission in writing.

## What a source costs

Each source is an extractor (a few hundred lines and tests), fixtures, the catalogue entry and
the documentation, then the **same decisions you already make**: `owf source review` for
redistribution, conflicts for same-name technologies. The registry will grow again in candidate
conflicts (the four current sources produced about 4500). Retire.js and CMSeeK add few
technologies that others already have under a different name, so expect more
`identity_candidate` work for names that differ by punctuation.

## Decisions that are yours

1. **Which to do.** My order is Retire.js, then OpenTechalyzer, then CMSeeK; WhatWeb after a legal answer.
2. **WhatWeb's GPL-2.0** and **Nmap's licence**: compatibility with this project's GPL-3.0-or-later.
3. **Inoue**: confirmed excluded, unless the author gives written permission.
4. **Scope**: whether network services (Nmap) belong in this registry at all.

## Per source, before the code

For each source I start with a measurement, not an extractor: fetch a pinned revision, count the
rules that map to the model, count the technologies that already exist under the same name or
slug, and write the number in `sources.md`. If the new data is mostly duplicate, the source waits.

## Measurements

### Retire.js (2026-11-20, `RetireJS/retire.js` @ `8d814f3c023a909b26be6a35a45b54163c2d95fe`, `repository/jsrepository.json`)

Measured against the registry of this repository (four sources, 9694 technologies).

- **76 libraries** (the file also has a `retire-example` entry and one named `dont check`, both
  to be skipped) and **405 extractor patterns**: `filecontent` 207, `uri` 78, `func` 48, `filename`
  43, `hashes` 17, `filecontentreplace` 8.
- **What the scanner could use today.** Only `uri` and `filename` (122 patterns, 119 with a
  `§§version§§` placeholder) match something the scanner already has: the URL of a script. The 32
  `func` extractors that are plain property paths (`jQuery.mobile.version`) would be `js_global`
  rules, usable with `--browser`. The other 17 `func`, the 207 + 8 `filecontent`/`filecontentreplace`
  patterns and the 17 `hashes` need **the content of the script file**, which the scanner does not
  fetch: 280 of the 405 patterns (69%) cannot be applied until it does. Two of them need
  look-behind or a back-reference and would be skipped as not RE2.
- **Overlap.** 56 of the 76 libraries already have a technology (by name, slug or package name, with
  a handful of aliases I wrote by hand); 44 of those already have `script_url` rules and 23 already
  read a version from one. 20 libraries have none, among them `DOMPurify`, `ua-parser-js`,
  `markdown-it`, `c3`, `bootstrap-select`, `jquery-validation`, `protobufjs`, `pdfobject`; the
  matching is by name, so a few may exist under a name I did not try.
- **Value.** Small for the scanner as it is: about 120 URL rules, about 20 new libraries, versions
  for roughly 30 libraries that have a `script_url` rule without one, and 32 version paths for the
  browser. Most of the file's weight (the content and hash patterns) is unusable until the
  scanner can fetch scripts, which is a scanner feature of its own (more requests to the site,
  so it would need the same limits as a crawl). The 70 libraries' vulnerability lists, the part
  Retire.js is known for, are out of scope and would be dropped.
- **Recommendation.** Retire.js is worth importing only together with that scanner feature, or
  as a small import (URL rules, `func` paths, new libraries) if cheap. It is not the best next
  source on this evidence; OpenTechalyzer (588 fingerprints, independent database) should be
  measured next. The licence (Apache-2.0) is not the obstacle.
