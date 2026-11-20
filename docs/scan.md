# owfscan: scanning a site

Status: **plan; only the result contract exists** (`scan/result.go`,
`schemas/scan-result.schema.json`, `examples/scan-result.json`). Go only.

Given a URL (usually the root of a domain), `owfscan` returns a structured
result: what was fetched, the technologies recognised and the evidence for each,
the links found, the domains they point to, and the social profiles. It applies
the rules of a registry export; it does not import sources or touch the
database.

```
owfscan scan   https://www.example.org --registry registry.json [--json]
owfscan links  https://www.example.org
owfscan social https://www.example.org
```

## Principles

- **Passive by default.** The page asked for, its redirects, the favicon, DNS
  and TLS of the host. Active probes of the registry (all `draft`, review
  `pending`) are never run; later, only with an explicit flag and only the ones
  with an approved safety review, rate limited, with an identifying
  User-Agent. No exploitation, no login, no CVE checks. Scan targets you are
  allowed to scan.
- **Say what was not done.** `coverage` counts the rules that could not be
  evaluated and why. About a quarter of the rules read JavaScript globals, which
  need a browser (deferred). A result never implies more than it observed.
- **Evidence, not a score.** Every technology lists the rules that matched, the
  `health` of each rule (most are `unknown`) and the source. Agreement between
  rules does not raise confidence, and sources with a common ancestor are not
  independent.
- **Redistribution travels along.** If the export contains unreviewed data, the
  result repeats the notice.
- **Pure where possible.** Link and social extraction take HTML and return data,
  without network. Tests use local servers only; a live check on a domain you own
  is opt-in.

## Result

`scan.Result` (JSON Schema `schemas/scan-result.schema.json`, example in
`examples/scan-result.json`): `target` (input, final URL, registrable domain),
`pages` (status, redirects, headers, timing, from cache or not), `host` (IPs,
DNS, TLS), `technologies` (ID, name, vendor, version, categories, evidence),
`links` (URL, kind, rel, internal, domain, page), `domains` (registrable domain,
count, examples), `socials` (platform, kind, handle, canonical URL, where found),
`coverage`, `registry` (hash and sources of the export), `warnings`.

## Layout

```
cmd/owfscan/        CLI (cobra), no database
scan/               public result types
internal/scan/...   links, social, fetch, observe, engine (public later if needed)
```

## Phases

0. **Contract** (done): result types, schema, example, tests, this plan.
1. **Links, domains, social profiles.** Pure functions. Links from `a`, `link`,
   `script`, `iframe`, `form`, `img`, `source`, `srcset`, `<base>`; relative URLs
   resolved, fragments dropped, hosts lower-cased; registrable domains with
   `x/net/publicsuffix`. Social profiles from a table of patterns kept as data
   (platform, profile kinds, exclusions, normalisation), read from links, `meta`,
   JSON-LD `sameAs` and `rel="me"`. Platforms: LinkedIn (company, in, school,
   showcase), GitHub (user, organisation), GitLab, Bitbucket, Facebook, Instagram,
   X/Twitter, TikTok, Threads, Bluesky, Mastodon, Snapchat, Reddit, Pinterest,
   Tumblr, Weibo, VK, YouTube, Vimeo, Twitch, SoundCloud, Spotify, Flickr,
   Telegram, WhatsApp, Discord, Behance, Dribbble, Medium, Stack Overflow, Docker
   Hub, npm, PyPI, Crunchbase, Xing; email, `tel:` and app store pages as their own
   kind. Share and intent URLs are not profiles. The PyPI package `socials`
   (GPL-3.0-or-later, 7 platforms, no TikTok) is a reference for a comparison test
   only.
2. **Fetch and observe.** `net/http` with redirect chain, cookies, size and time
   limits; favicon (md5, mmh3); DNS and TLS of the host; on-disk response cache so
   a scan can be re-evaluated offline. Page to `matcher.Observation`.
3. **Engine.** Load and verify the export, evaluate rules, groups and versions
   with the matcher's semantics, aggregate evidence, fill `coverage`.
4. **CLI and docs.**
5. **Later:** a browser for JavaScript rules; `--active` for approved probes.

## Open points

- The exact fields of `Technology.confidence` (now: highest confidence among the
  matching rules that are not broken).
- How much of `internal/matcher` to promote to a public package.
- Which platforms' patterns need live verification against real profile URLs.
