# Plan: statistics from the most visited sites

Not built yet. Decisions so far: Tranco list, home page only (no `--depth`, `--friends`,
`--related`, `--active`, `--browser` in a mass run), publish aggregates only and only after the
legal review of the sources, SQLite (WAL) as the store of a later crawler behind small
`Frontier` and `Store` interfaces, Pebble only if measurement shows SQLite is the limit.

## First measurement (2026-11-22)

Tranco list `46YVX` (created 2026-11-20, top 100 of 1,000,000), `owfscan scan https://<domain>`
with the registry of this repository, 6 in parallel, no DNS or favicon switched off, 2 min 30 s.

- **61 of 100 scanned; 39 failed**: 33 DNS (`no such host` or lookup timeout: the list holds
  infrastructure names such as `akamai.net` or `gtld-servers.net` that have no website; some only
  answer on `www.`), 2 certificate for another name, 1 refused as non-public, 1 reset, 2 other.
- Of the 61, **53 answered 2xx**; the others 404 (4), 403 (2), 400, 429.
- On the 53: median 13 technologies per site (mean 15.8, none with zero), **64% of the rules
  applied** (the rest need a browser, probes, the favicon).
- HSTS present on 44 of 53, CSP on 32.

## What the numbers say about the method

- A top-N list is not a list of websites. A run needs a step that drops names without a web home
  (and tries `www.`), and the statistics must always say how many sites were reached out of N.
- Most frequent "technologies" are mail, DNS and certificate signals (Microsoft 365 25, Atlassian
  Cloud 16, Google Workspace 14, Anthropic 14, DigiCert 14), not web stack. Some are suspect
  (`Anthropic` on 14 sites, `Meta`, `daisyUI` on 11) and were **not checked by hand**: before
  any statistic is published, a sample of detections must be verified and weak rules filtered by
  confidence or health, stated on the page.
- Every figure is "detected on the home page", never "used by the site".

## Checking the suspect detections (2026-11-22)

Read the evidence of the odd ones among the 53 sites:

- **Anthropic (14), Meta (23), Atlassian Cloud (16), Apple iCloud Mail (17)** come only from DNS
  TXT records (`anthropic-domain-verification`, `facebook-domain-verification=`,
  `atlassian-domain-verification=`, `apple-domain`). They are true statements about the *domain*
  (it was verified with that vendor) and not about the web stack. Statistics must keep them in
  their own group ("domain verifications and mail"), apart from the web technologies.
- **daisyUI (11)** is a **false positive**: one rule from OpenTechalyzer matches
  `class="...btn-primary|card-body|navbar-start|drawer-toggle"`, and `btn-primary` is Bootstrap's.
  The rule is weak upstream; the fix is a negative validation case (not done) and, for statistics,
  a filter that ignores technologies whose only evidence is a rule of `html` class names.
- **PWA (14), Priority Hints (14)** match `link[rel=manifest]` and `fetchpriority`: correct, but
  they describe page features, not products.

## Batch (built)

`owfscan batch run LIST --db batch.db --registry registry.json` scans the home page of each site of
a list (one domain per line or Tranco's `rank,domain`; CR/LF tolerated; names that are not host
names skipped) into SQLite (WAL; gzip JSON per site; table `sites` with state pending, done or
failed, and `meta`). A name that does not exist is retried as `www.`. `--workers` (at most 32),
`--rate` scans started per second (at most 20), `--timeout`, `--limit`, `--retry-failed`.
Ctrl-C leaves the sites in flight pending; run again to resume. `owfscan batch status` counts
states, HTTP statuses and failure reasons. Home page only: no depth, friends, related, probes or
browser. The file holds full results (contacts too): private.

Same top 100 as above, with the `www.` retry: **72 scanned** (was 61), 28 failed (21 no such host,
4 certificate, 1 refused, 1 reset, 1 connection refused); 63 answered 200.

## daisyUI and Prism corrected (2026-11-22)

`validation/cases-opentechalyzer/` has 52 cases (a positive and a negative for each of the 26
class-name `html` rules of OpenTechalyzer). Two negatives failed on the uncorrected rules:
daisyUI matched Bootstrap's `btn-primary` and `card-body`, and Prism matched any
`class="language-xxx"`. They are kept in `validation/known-failing/` (not run by `make`) and the
rules were corrected in the registry with `owf fingerprint correct` (reason recorded; the
importer stays faithful): daisyUI keeps only `navbar-start|drawer-toggle`, Prism becomes
`class="token [a-z-]+"`. The new patterns pass a positive and a negative case; the
replacements are my choice, not upstream's. The other 24 rules passed, but those negatives are
only a plain page and one lookalike for a few: this is a floor, not proof.

## `owfscan stats` (built)

`owfscan stats --db batch.db [-o stats.json] [--min-confidence 0.5] [--min-sites 3] [--exclude A,B] [--top 30]`
writes aggregates that follow `schemas/stats.schema.json` (Go types `scan.Stats`) and prints a summary.
Shares are of the sites reached (2xx); status and failure shares are of scanned and failed. Web
technologies and **domain signals** (evidence only in DNS records) are separate lists. A technology
or pair on fewer than `--min-sites` sites is counted in `other.technologies_hidden`, not named. The
document carries no domain, handle, address or contact of any site (a test checks it), plus the list
name, the registry hash and notices, and a `notes` array with the reading rules.

Run on the same 72 scanned (63 reached) top-100 sites, with the registry before the daisyUI and
Prism corrections (so Prism 11 sites is still the old false positive): median 8 web technologies per
site, 63.7% of rules applied; HSTS on 84%, CSP 63%, X-Frame-Options 60%, Referrer-Policy 27%,
Permissions-Policy 22%; certificates mostly under 90 days left (the 90-day Let's Encrypt style
cycle). Domain signals: Meta 54%, Microsoft 365 52%, Apple iCloud Mail 38%, Atlassian 35%.

Known problems seen in this output: category names differ by source ("js library" from
OpenTechalyzer next to "JavaScript libraries", "web server" next to "Web servers"), so category
shares are split; the categories need a mapping before they are published. Generic buckets
("Miscellaneous", "Security") dominate. The next steps are a web page for these aggregates, the
category mapping, and the 1000-site run.

## Category names (2026-11-22)

OpenTechalyzer's category keys are spelled differently from the Wappalyzer format ("js-library" next to
"JavaScript libraries"), which split every category figure. The extractor now names 27 of its keys
after the equivalent Wappalyzer category (`categoryNames`; the key stays the original), the others
are capitalised ("Error tracking"). On a refresh the renamed records became 23 category candidates,
all merged in `owf.db` after review (backup `/tmp/owf.db.before-catmap`); a new database gets the
candidates on first import. Left separate because there is no equivalent: apm, baas, devops, media,
platform, runtime, subscription, support, error tracking, ecommerce app. The mapping is mine:
`bot-protection` and `captcha` go to Security, `backend-framework` to Web frameworks,
`css-framework` to UI frameworks, `product-analytics` to Analytics.
