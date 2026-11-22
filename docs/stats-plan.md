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
