# owfscan: scanning a site

Status: **phases 1 to 3 done**: `owfscan scan <url> --registry FILE` returns the
technologies, links, domains, social profiles and contacts of a live page, with the
coverage of the rules. `--depth` works; a browser and approved probes are still to do. Go only.
Contract: `scan/result.go`, `schemas/scan-result.schema.json`, examples in
`examples/`. Try it: `owfscan extract --url https://site.example/ page.html`.

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

User guide: [owfscan.md](owfscan.md).

## Decisions

Taken with the maintainer, in the order they were made:

1. **Go only.** The scanner is part of this repository and uses the registry's
   code. No Python layer, no pydantic: the contract is the JSON Schema of the
   result.
2. **Licence:** GPL-3.0-or-later, like the rest of the repository.
3. **Browser:** later. The first version evaluates only what a plain HTTP request
   shows.
4. **Social platforms:** all the well-known ones (37 in the table plus Mastodon),
   email and telephone as contacts. The PyPI package `socials` is not a dependency.
5. **Unreviewed sources are not refused.** `owf export` stops on a source whose
   redistribution is unreviewed; the scanner does not, because it only reads the
   data. The result repeats the export's notice (`registry.notice`) when the export
   carries one, and a result is not meant to be published as registry data.
6. **`technologies[].confidence`** is the highest confidence among the matching
   rules that are not `broken`. Agreement between rules never raises it, and rules
   of sources with a common ancestor are not independent evidence.
7. **Rules with `health: unknown` are used.** Almost every rule is `unknown`;
   ignoring them would leave the result empty. The health of each rule is shown in
   its evidence, and `--min-health` (planned) will let a user ask for more.
8. **Passive by default; no probes.** Active probes of the registry (all drafts with
   a pending review) are not run. Later, only with `--active` and only approved ones.
9. **Safe network defaults.** Public addresses only, also across redirects, no
   environment proxy, bounded size, time and redirects (see
   [owfscan.md](owfscan.md#what-the-scanner-does-to-the-network)).
10. **Examples use local servers** and domains of the maintainer (`mr70.eu`);
    tests never depend on a third-party site.

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
  result repeats the notice (it does not refuse to run: decision 5).
- **Pure where possible.** Link and social extraction take HTML and return data,
  without network. Tests use local servers only; a live check on a domain you own
  is opt-in.

## Result

`scan.Result` (JSON Schema `schemas/scan-result.schema.json`, example in
`examples/scan-result.json`): `target` (input, final URL, registrable domain),
`pages` (status, redirects, headers, timing, from cache or not), `host` (IPs,
DNS, TLS), `technologies` (ID, name, vendor, version, categories, evidence),
`links` (URL, kind, rel, internal, domain, page), `domains` (registrable domain,
count, examples), `socials` (platform, kind, handle, canonical URL, where found), `contacts`
(email, phone, where found),
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
   *Done.* `internal/scan/web`: 37 platforms and 66 profile rules as data
   (`platforms.json`), `Extract(pages, target)`, and `owfscan extract`. Facts worth
   knowing:
   - Rules are an allow-list of profile shapes, so share links, intents, posts
     and product pages are not profiles (`linkedin.com/shareArticle`,
     `github.com/features`, `instagram.com/p/...`, 61 tested non-profile URLs).
     Single-segment platforms also have reserved names.
   - GitHub, GitLab, Bitbucket and Telegram say `account`: a URL does not tell a
     user from an organisation. Mastodon (any host) is recognised only on links
     the page marks `rel="me"`. Handles are lower-cased except where the platform
     is case-sensitive; profile URLs are written in canonical form.
   - Links: `a`, `area`, `link`, `script`, `iframe`, `form`, `img`, `source` and
     `srcset`; `<base>` honoured; fragments, credentials and default ports
     dropped; `javascript:`, `data:` and bare fragments ignored. A URL found by
     two kinds of element is two links; the same URL on two pages says where.
   - Contacts: `mailto:` (several addresses, parameters dropped), `tel:`
     (digits and a leading `+`; `00` read as `+`; numbers without a prefix keep
     their national form because the country is unknown), JSON-LD and visible
     text for email. File names such as `logo@2x.png` and obfuscated addresses
     (`name [at] host`) are not addresses. Phone numbers in plain text are not
     read: too noisy.
   - Not seen without running the page: links, handles and widgets added by
     JavaScript.
   - Compared once with the PyPI package `socials` 0.3.0 on our own URL set (so
     biased towards us): on the six platforms it supports it recognised 12 of 20
     profile URLs (missed `linkedin.com/school`, `showcase`, `m.facebook.com`,
     Facebook groups and `/pg/`, `x.com`, YouTube `@handle` and `channel/UC…`) and
     accepted 7 of 38 non-profile URLs (`github.com/features`, `/login`,
     `/sponsors`, `twitter.com/home`, `facebook.com/login`,
     `instagram.com/explore`). It is not a dependency.
2. **Fetch and observe.** *Done.* `internal/scan/fetch` and `internal/scan/observe`.
   - **Requests:** one GET of the page, following redirects (recorded, at most 10),
     cookies kept along the chain, a 20 s timeout and a 5 MiB cap per request, all
     settable. An identifying User-Agent. Only `http`/`https`. Crawling only with `--depth`
     (see `owfscan.md`), no probes. A bare `host` is tried over https, and over http only
     if the connection cannot be made (a warning says so).
   - **Safety:** addresses that are not public (loopback, private ranges,
     link-local including the cloud metadata address, CGNAT, unique-local) are
     refused at connect time, so also when a public site *redirects* to one; the
     environment's proxy is ignored; `--allow-private` opts in for your own
     network and `--insecure` accepts bad certificates (the certificate is still
     recorded). A request to a blocked address is never made.
   - **Observation** (what the matcher reads): headers, `Set-Cookie` lines and
     cookies, the page decoded to UTF-8 from its declared charset, HTTP status,
     the favicon (the declared icon, else `/favicon.ico`; a response that is HTML
     is not a favicon) as md5 and as Shodan-style mmh3 (verified against the
     reference implementation), DNS (IPs, CNAME, NS, MX, TXT; a failed lookup is a
     warning), and the certificate (issuer, subject, validity, names). An IP-literal
     host is not looked up. The favicon is one extra request.
   - **Cache:** `--cache-dir` stores responses on disk (body with its SHA-256, so a
     damaged entry is ignored), reused for `--max-age` (24 h); 5xx are not cached;
     results say `cached`. It lets a scan be repeated offline.
   - `owfscan observe <url>` prints the observation as JSON: the input of a
     validation case from a real page, once its licence allows keeping it.
   - Live check on `mr70.eu` (yours): 86 links to 9 domains, GitHub, GitLab, X and
     Mastodon (`rel="me"`), certificate, NS records and the favicon hashes, in
     1.6 s. The legacy YouTube URL `youtube.com/<name>` was not recognised at first
     and now is (with a reserved list: `watch`, `playlist`, `shorts`, ...).
   - Not done: HTTP/2 and HTTP/3 information, `robots.txt`, SOA records (the
     standard library cannot ask), IDN handling beyond what `net/url` does.
3. **Engine.** *Done.* `internal/scan/engine`, `internal/scan/scanner`.
   - The export is loaded with `export.Verify` (schema, content hash, counts), so an
     edited or damaged file is refused; sources that are unreviewed are accepted and
     the notice is repeated (decision 5).
   - Each technology's rules are applied to the observation with the matcher:
     single rules, groups (all members must match, on the same observation) and
     version rules (applied only to a detected technology). The observation is
     prepared once, so 22 000 rules take well under a second.
   - Evidence per technology: rule ID, observation, target, the text that matched
     (cut to 300 characters), the rule's health, its source, and the group. At most
     50 per technology. Technologies are sorted by name.
   - `confidence`: highest among matching rules that are not `broken`; `version`:
     best health, then highest confidence, with a `conflicting_versions` warning.
   - Coverage is exact: every rule is either evaluated or counted under a reason
     (see [owfscan.md](owfscan.md#how-to-read-a-result)). Rules that need a
     browser, a probe, `robots.txt`, DNS/TLS/favicon data that was not collected, a
     backtracking regex, or that are deprecated or below `--min-health`, are not
     treated as misses. A group with an unsupported member is skipped as a whole.
   - Found while building it: header names were lower-cased in the observation,
     which silently broke the nuclei rules that read the raw header block
     (`Server: 4D…`); they now keep the case the server sent.
   - Real check: Enthec + Recog + nuclei (22 178 rules) on `mr70.eu`, in 1.3 s:
     11 technologies (Hugo 0.119.0, Netlify, Google Analytics/Tag Manager/AdSense,
     Let's Encrypt, HSTS, PWA, RSS, Open Graph, and Metatag CMS), 13 967 rules
     evaluated, 8 061 not (5 867 need a browser, 2 174 are probes, 19 need
     backtracking, 1 needs `robots.txt`).
   - Weakness shown by that check: `Metatag CMS` matches because its nuclei group
     ("text/html" and a generator meta tag) is true for any Hugo site. Rules from
     public projects are not tested; this is why the health of each rule is part of
     the evidence and why `--min-health` exists.
4. **CLI and docs.** *Done:* `owfscan scan|links|social|observe|extract`, the user
   guide [owfscan.md](owfscan.md).
5. **Later:** a browser for JavaScript rules; `--active` for approved probes.

## Open points

- How much of `internal/matcher` to promote to a public package (or whether the
  scanner keeps importing it from inside the module).
- Which words select pages for `--depth`; they are a judgement call, not measured on many sites.
- Loading is still decode + regex compilation on each run (about 0.3 s for 22000 rules);
  an index that is not JSON would save the decode only. Not done: not worth it yet.
- Same-name technologies are shown as one in a result (`same_name` lists the other IDs);
  the registry still keeps them apart until a reviewer merges them. Two different products
  with the same name would be shown as one: not seen in practice, not measured either.
- Rules that are true for any site of a kind (`Metatag CMS`): flag them in the registry with tests rather than in the scanner.
- Which platforms' patterns need live verification against real profile URLs.
