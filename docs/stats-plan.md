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
