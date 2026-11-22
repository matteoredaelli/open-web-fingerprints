# owfscan: user guide

`owfscan` looks at a web site and tells you what it finds: the technologies it
runs, with the evidence for each, the links on the page and the domains they point
to, and the social profiles and contact details it publishes.
It is a separate program from `owf`: it has no database and makes requests to the
network. Design, decisions and roadmap: [scan.md](scan.md).

**Status.** Working: `scan`, `links`, `social`, `observe`, `extract`. See
[What is not there yet](#what-is-not-there-yet) for the limits.

## Install and build

```sh
make build            # builds bin/owf and bin/owfscan
go install github.com/matteoredaelli/open-web-fingerprints/cmd/owfscan@latest
```

Requires Go 1.25. No other dependency at run time.

## Use only on sites you are allowed to scan

A scan is a normal HTTP request to the page you name, its favicon, and DNS and TLS
lookups of its host. Even so: scan your own sites, or sites whose owners allow it.
`owfscan` never logs in, never sends anything but GET requests, never tries paths
you did not name, and never runs the active probes of the registry.

## Commands

All commands that fetch a page take a URL. A bare host such as `mr70.eu` is tried
over https, and over http only if the connection cannot be made (a warning says
so). Add `--json` to any command for machine-readable output.

| Command | What it does | Requests |
|---|---|---|
| `owfscan scan <url> --registry FILE` | technologies with their evidence, plus links, domains, social profiles, contacts and the coverage of the rules | the page, its favicon, DNS lookups |
| `owfscan links <url>` | links of the page and the registrable domains they point to | the page |
| `owfscan social <url>` | social profiles, email addresses and telephone numbers | the page |
| `owfscan observe <url>` | the observation the rules read, as JSON | the page, its favicon, DNS lookups |
| `owfscan extract --url <page-url> <file\|->` | the same extraction as `links` and `social` on saved HTML | none |

### Flags of the commands that fetch (and `scan`)

| Flag | Default | Meaning |
|---|---|---|
| `--json` | off | JSON output |
| `--cache-dir DIR` | `$OWFSCAN_CACHE` or none | keep responses on disk and reuse them |
| `--max-age D` | `24h` | how long a cached response is reused |
| `--timeout D` | `20s` | timeout of each request |
| `--allow-private` | off | allow private and local addresses (your own network) |
| `--insecure` | off | accept invalid TLS certificates (the certificate is still recorded) |

`observe` and `scan` also have `--no-dns`, `--no-favicon` and `--all-headers` (see
"What is left out of the output"); `observe` has `--html` (include the body; it is left out
by default). `scan` has `--registry FILE`
(env `OWFSCAN_REGISTRY`), `--min-health` and `-e/--evidence`. There is a hard cap of 5 MiB per body and at most 10 redirects.

## Scanning for technologies

`scan` applies the rules of a registry export to the page. The export is what
`owf export` writes ([redistribution.md](redistribution.md)); build one from the
sources you imported:

```sh
owf export --include-unreviewed -o registry.json   # internal use: the sources are unreviewed
owfscan scan https://mr70.eu --registry registry.json -e
```

The export is verified first against its manifest (schema, content hash, counts);
a damaged or edited file is refused. It may contain data of sources whose
redistribution has not been reviewed: `scan` uses it anyway and repeats the
export's notice in the result, which is then **not** meant to be published as
registry data.

Real output, abridged (a Hugo site on Netlify; export of Enthec, Recog and nuclei,
22178 rules):

```
https://www.mr70.eu/  (200, 1303 ms, cached)
registry sha256:d3fc565733b3: enthec-webappanalyzer, projectdiscovery-nuclei-templates, rapid7-recog
NOTICE: This export contains data from sources whose redistribution terms have not been reviewed. ...

TECHNOLOGIES (11)
NAME                VERSION  CONFIDENCE  BEST HEALTH  RULES  SOURCES
Google Analytics    GA4      0.50        unknown      2      enthec-webappanalyzer
  script_url                             unknown             "googletagmanager.com/gtag/js"
  script_content    GA4                  unknown             "gtag('config', 'G-"
Hugo                0.119.0  0.50        unknown      1      enthec-webappanalyzer
  meta_tag generator 0.119.0             unknown             "Hugo 0.119.0"
Let's Encrypt                0.50        unknown      1      enthec-webappanalyzer
  tls_cert issuer                        unknown             "Let's Encrypt"
Metatag CMS                  0.50        unknown      2      projectdiscovery-nuclei-templates
  response_headers                       unknown             "text/html" [group]
  html                                   unknown             "<meta name=\"generator\" content=\"Hugo 0.119.0\"" [group]
Netlify                      0.50        unknown      2      enthec-webappanalyzer
  http_header Server                     unknown             "Netlify"
  ...                                                       (Google AdSense, Tag Manager, HSTS, Open Graph, PWA, RSS)

LINKS: 86 to 9 domains (mr70.eu 78, creativecommons.org 1, fosstodon.org 1, ...)

SOCIAL    KIND     HANDLE
github    account  matteoredaelli
gitlab    account  matteoredaelli
mastodon  user     @matteoredaelli@fosstodon.org
x         user     matteoredaelli
youtube   channel  matteoredaelli

COVERAGE: 13967 of 22178 rules evaluated, 8061 could not be: needs a browser 5867, probe disabled 2174, pattern needs a backtracking engine 19, robots.txt not fetched 1
```

It runs in about 1.3 s, including the load and verification of a 34 MB export.

### How to read a result

- **Evidence.** Each technology lists the rules that matched: the kind of
  observation, the target (header name, selector, …), the text that matched (cut to
  300 characters), the rule's `health`, and its source. Rules of a group (several
  conditions that must hold together, from nuclei templates) are marked `[group]`
  and are listed together. Up to 50 rules are listed per technology; a warning says
  when there are more.
- **`health` is mostly `unknown`.** Almost no rule has tests ([validation.md](validation.md)),
  so "detected" means "a rule from a public project matched", not "confirmed".
  The example above shows it: `Metatag CMS` comes from a nuclei group whose conditions
  ("the response is text/html" and a generator meta tag) are met by any Hugo site.
  Look at the evidence before believing a technology; `--min-health ok` keeps only
  rules that have passing positive and negative tests (today a small minority).
- **`confidence`** is the highest confidence among the matching rules that are not
  `broken`. Several rules agreeing do **not** raise it: sources with a common
  ancestor are not independent evidence. It is a property of the rules, not a
  probability that the technology is there.
- **`version`** comes from the rules that read one: a regex with a capture group
  (Wappalyzer, Recog), a literal, or a version rule (nuclei extractors). If rules
  disagree, the rule with the best health, then the highest confidence, wins, and
  a `conflicting_versions` warning lists them.
- **Technologies with the same name** can appear twice (for example `PHP` from two
  sources): the registry does not merge records of different sources without a
  review.
- **Coverage.** `rules_total` is every rule of the export. `rules_evaluated` counts
  rules that were applied (matching or not). `rules_unsupported` counts rules that
  could not be applied, with the reasons in `skipped`:

  | Reason | Meaning |
  |---|---|
  | `needs a browser` | the rule reads a JavaScript variable, an XHR request or a DOM property (about a quarter of all rules) |
  | `probe disabled` | the rule needs a request to another path; probes are never run |
  | `pattern needs a backtracking engine` | a lookahead or similar that Go's RE2 cannot run |
  | `no DNS data`, `no TLS data`, `favicon not fetched` | the observation was not made (`--no-dns`, `--no-favicon`, plain http) |
  | `robots.txt not fetched` | not fetched |
  | `below the minimum health` | excluded by `--min-health` |
  | `cookie name is a pattern (inert upstream too)` | a cookie rule whose name has regex syntax (13 rules); the reference engines never match it either, see [validation.md](validation.md#findings-from-writing-the-corpus) |
  | `deprecated` | deprecated rules and technologies |
  | `invalid rule`, `not supported by the matcher` | a rule that does not compile, or an observation type the matcher does not know |

  The remainder (`total - evaluated - unsupported`) are version rules of
  technologies that were not detected: they have nothing to read.
  A technology can be missing because its rules were skipped, not because it is
  absent. Compare the coverage with what you expect.

## Examples

### Links and domains

```
$ owfscan links mr70.eu
https://www.mr70.eu/: 86 links, 9 domains

DOMAIN                 LINKS  INTERNAL  EXAMPLE
mr70.eu                78     true      https://www.mr70.eu/index.xml
creativecommons.org    1      false     https://creativecommons.org/licenses/by/4.0/
fosstodon.org          1      false     https://fosstodon.org/@matteoredaelli
github.com             1      false     https://github.com/matteoredaelli
gitlab.com             1      false     https://gitlab.com/matteoredaelli
googlesyndication.com  1      false     https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client=ca-pub-…
googletagmanager.com   1      false     https://www.googletagmanager.com/gtag/js?id=G-…
twitter.com            1      false     https://twitter.com/matteoredaelli
youtube.com            1      false     https://youtube.com/matteoredaelli
```

A link is internal when it points to the same *registrable domain* as the target
(`mr70.eu` for `www.mr70.eu`). The domain is computed with the public suffix list,
so `blog.example.co.uk` belongs to `example.co.uk`.

### Social profiles and contacts

```
$ owfscan social mr70.eu
PLATFORM  KIND     HANDLE                         FOUND VIA
github    account  matteoredaelli                 a
gitlab    account  matteoredaelli                 a
mastodon  user     @matteoredaelli@fosstodon.org  rel-me
x         user     matteoredaelli                 a

CONTACT  VALUE
```

(The page publishes no email address or telephone number.)

### The observation

```
$ owfscan observe mr70.eu            # no body, no headers that change on every call
{ "page":        {... "status": 200, "redirects": [...], "headers": {...}},
  "host":        {"ips": [...], "dns": {"NS": [...]}, "tls": {"issuer": "CN=YE2,O=Let's Encrypt,C=US", ...}},
  "observation": {"headers": {...}, "cookies": {...}, "favicon_hashes": {"md5": "…", "mmh3": "…"}, ...},
  "warnings":    [] }
```

This is exactly what the registry's rules are applied to. Saved to a file, it is
the input of a validation case made from a real page (mind the licence of the page
before keeping it in a repository).

### Saved HTML, offline

```sh
owfscan extract --url https://www.example.org/ page.html          # text
curl -s https://www.example.org/ | owfscan extract --url https://www.example.org/ --json -
```

`--url` is the address the page came from: relative links are resolved against it
(and against the page's own `<base href>`), and links to its registrable domain
are internal.

## What is extracted

### Links

From `a`, `area`, `link`, `script`, `iframe`, `form`, `img` and `source`
(including every URL in `srcset`). Each link records its kind, the `rel` of the
element, the registrable domain, whether it is internal, and the page it was found
on. URLs are made absolute and comparable: scheme and host in lower case, no
fragment, no credentials, no default port, a path of at least `/`. Ignored:
`javascript:`, `data:`, bare `#fragment`, empty values, CSS `url()`. The same URL
found by two kinds of element is two links; the same URL on two pages is two links.

### Domains

One entry per registrable domain: number of links, whether it is internal, up to
three example URLs. The target's own domain comes first, then by number of links.

### Social profiles

Read from `<a>`/`<link>` elements, from `<meta name="twitter:site">` and
`twitter:creator`, from JSON-LD `sameAs`, and from links marked `rel="me"`. The
result says *how* each profile was found (`a`, `link`, `meta`, `jsonld`,
`rel-me`). The same account found in several ways is one profile.

Only URLs that *are* profiles count. Share links, intents, posts and product pages
are not profiles: `linkedin.com/shareArticle`, `twitter.com/intent/tweet`,
`facebook.com/sharer/sharer.php`, `instagram.com/p/…`, `github.com/features` and
similar are ignored. Handles are normalised (lower case unless the platform is
case-sensitive) and each profile gets a canonical URL.

| Platform | Hosts | Kinds |
|---|---|---|
| linkedin | linkedin.com | company, user, school, showcase |
| github | github.com | account |
| gitlab | gitlab.com | group, account |
| bitbucket | bitbucket.org | account |
| facebook | facebook.com, fb.com, fb.me | profile, group, page |
| instagram | instagram.com, instagr.am | user |
| x | twitter.com, x.com | user |
| tiktok | tiktok.com | user |
| threads | threads.net, threads.com | user |
| bluesky | bsky.app | user |
| snapchat | snapchat.com | user |
| reddit | reddit.com | subreddit, user |
| pinterest | pinterest.com (and country domains) | user |
| tumblr | `<name>.tumblr.com` | blog |
| weibo | weibo.com | user |
| vk | vk.com, vk.ru | page |
| youtube | youtube.com, youtu.be | channel (`@handle`, `channel/UC…`, `c/`, legacy `/name`), user |
| vimeo | vimeo.com | user |
| twitch | twitch.tv | channel |
| soundcloud | soundcloud.com | user |
| spotify | spotify.com | artist, show, user |
| flickr | flickr.com | user |
| telegram | t.me, telegram.me, telegram.dog | account, invite |
| whatsapp | wa.me, chat.whatsapp.com, whatsapp.com | number, invite, channel |
| discord | discord.gg, discord.com | invite |
| behance | behance.net | user |
| dribbble | dribbble.com | user |
| medium | medium.com, `<name>.medium.com` | user, publication |
| stackoverflow | stackoverflow.com | user |
| dockerhub | hub.docker.com | user, organization |
| npm | npmjs.com | user, organization |
| pypi | pypi.org | user |
| crunchbase | crunchbase.com | company, person |
| xing | xing.com | company, user |
| okru | ok.ru | group, user |
| googleplay | play.google.com | app, developer |
| appstore | apps.apple.com, itunes.apple.com | app, developer |
| mastodon | any host, only on a `rel="me"` link | user |

Notes:

- `github`, `gitlab`, `bitbucket` and `telegram` say `account`: a URL does not tell a
  user from an organisation.
- Mastodon has no fixed host. `/@name` on an unknown host is a profile only when the
  page links to it with `rel="me"`, because `/@name` is also how Medium and TikTok
  write theirs. The handle is `@name@host`.
- Google Play and the App Store are listed because they identify an organisation's
  apps; they are not social networks.

### Contacts

- **Email:** from `mailto:` links (several addresses allowed, `?subject=` dropped),
  JSON-LD `email`, and the visible text of the page. Lower-cased and validated.
  Strings that look like addresses but are file names (`logo@2x.png`) and obfuscated
  forms (`name [at] host`) are not addresses.
- **Phone:** from `tel:` links, JSON-LD `telephone` and `og:phone_number`. Only the
  digits and a leading `+` are kept; a leading `00` is read as `+`; a number without
  an international prefix keeps its national form because the country cannot be
  known. Numbers of 6 to 15 digits only. Telephone numbers in running text are not
  read (too many false positives).

## Output reference

`links`, `social`, `extract` and `observe` print parts of the result defined in
[scan.md](scan.md#result): [`scan/result.go`](../scan/result.go), the JSON Schema
[`schemas/scan-result.schema.json`](../schemas/scan-result.schema.json) and two
examples in [`examples/`](../examples/) (one of them, `scan-result-homepage.json`,
is *invented* to show the full shape, including technologies; it is not a real scan).

## What the scanner does to the network

| Rule | Behaviour |
|---|---|
| Methods | `GET` only |
| Which URLs | the one you give, its redirects, the favicon, and with `--depth` a few more pages (below) |
| Redirects | followed up to 10 times, recorded; only to http and https |
| Size and time | 5 MiB per body, 20 s per request (both can be changed in code, the timeout with `--timeout`) |
| Addresses | loopback, private ranges, link-local (including the cloud metadata address `169.254.169.254`), CGNAT and unique-local addresses are refused when connecting, **including after a redirect**; `--allow-private` lifts this for your own network |
| Proxy | the environment's proxy settings are ignored |
| Identity | `User-Agent: owfscan (+https://github.com/matteoredaelli/open-web-fingerprints)` |
| Not done | probes, form submission, login, JavaScript |
| Cookies | kept in memory for the duration of the command, not stored |
| Cache | with `--cache-dir`, responses are stored on disk with the hash of the body; a damaged entry is ignored; 5xx answers are not stored |

Because the cache is plain files, do not point it at a shared location if the pages
you fetch are private.

## Reading more than one page (`--depth`)

By default only the page you name is read, so a profile or an address that appears
only on `/contact` is missed. `--depth N` (for `scan`, `links` and `social`) follows
links up to N levels, with these limits:

- **Which pages.** Only ordinary links (`<a>`) to the same registrable domain, over
  http or https, without a query string, that are not files (pdf, images, archives,
  feeds...). **All** of them are followed, subdomains of the same registrable domain
  included (`blog.example.com`, `/blog/...`). Pages whose path contains a word that
  usually marks a page with company details (`contact`, `contatti`, `kontakt`, `about`,
  `chi-siamo`, `impressum`, `legal`, `press`, `careers`, `team`, `support`, `privacy`...,
  in several languages) come first, then the others by address. Because of `--max-pages`
  the order decides what is read: raise it to read more. The word list is in
  `internal/scan/scanner/crawl.go`.
- **`robots.txt`.** Read once per host before any further page, with the rules of
  RFC 9309 (the group for `owfscan`, else `*`; longest rule wins; `Allow` wins a tie).
  A page it disallows is not fetched. If the file cannot be read because of a server
  error, nothing more is fetched from that host (the site cannot be asked), and a
  warning says so; a missing file (404) allows everything. `--ignore-robots` lifts
  this, for your own site. **The page you name is always fetched.**
- **Pace.** `--delay` (default 500 ms) before each further page, or the site's
  `Crawl-delay` if larger, at most 10 s. Requests are sequential.
- **Size.** `--max-pages` (default 50, at most 200) in total; a warning says when it stopped there.
- **Safety.** The same rules as for the first page: public addresses only, also after
  a redirect. A page that redirects to another site is dropped.
- **Result.** Technologies found on several pages are one record whose evidence says
  which page each item comes from; confidence is the highest, and if pages give
  different versions the most confident is chosen and a warning lists them. Links,
  socials and contacts say where they were found. The coverage counts rules once, not
  once per page; host-level observations (DNS, TLS, favicon, `robots.txt`) come from
  the first page.

With `--depth` the `robots.txt` file is also an observation, so the one rule that needs
it is evaluated. Without `--depth` it is not fetched.

On `mr70.eu` (my own site), `--depth 1` read the home page and `/contact/` in about 3 s
and added the contact email address that the home page does not have.

## Running the page in a browser (`--browser`)

About a quarter of the registry's rules (js_global, XHR) cannot be answered from the HTML:
they look at JavaScript variables and at the requests a page makes. `--browser` opens the
**first page** in headless Chrome (installed separately; `--chrome PATH` or
`OWFSCAN_CHROME` if it is not in the usual places) and reads, after the load and a 2 s
pause for late scripts:

- the global variables the rules look for (their dotted paths come from the registry, so
  only those are read, as strings for strings, numbers and booleans);
- the URLs of the `fetch`/XHR calls the page made;
- the **host names of every request** the page made (scripts, images, beacons too), for the
  `request_host` rules of OpenTechalyzer: lower-case, without duplicates, and including requests
  that the proxy refused, since they say what the page tried to reach;
- the DOM after the scripts ran. This **replaces** the page source for the rules and for
  the extraction of links, social profiles and contacts, so what scripts add is found
  (and a rule on something that only exists in the source, such as a comment a script
  removes, may stop matching).

On `mr70.eu` with the registry of this repository: technologies 11 → 13 (Funding Choices,
Priority Hints), rules evaluated 12739 → 18648 of 22418. `pirelli.com` 7 → 15 and
`michelin.com` 9 → 16 (jQuery 3.2.1, Lodash, RequireJS 2.3.5; Didomi, Matomo, Kameleoon,
Piano, Svelte). The coverage line then says what is still not read: `needs a browser 2`
(rules on DOM properties, `::prop(...)`) and the rest as before.

Running a site's JavaScript is not the same as reading its HTML, so the browser is held
to the scanner's rules **by construction**:

- All of its traffic goes through a proxy the scanner runs. The proxy refuses non-public
  addresses when it connects (after DNS, so redirects and DNS rebinding do not help),
  counts requests and stops at 300. The result says how many were made and how many were
  refused.
- Chrome is started with its own DNS, QUIC and WebRTC off, so nothing goes around the
  proxy; downloads are denied, extensions, sync and background networking are off, and
  the profile is a temporary directory that is removed afterwards.
- Nothing is clicked, typed or submitted. The identifying User-Agent is used.
- `--browser-timeout` (default 30 s) bounds the run; a page that is still loading gives
  what it has, with a warning.
- If Chrome cannot be started, `--browser` is an **error**, not a quiet fall back.

Limits: only the first page is run (pages added by `--depth` are read as plain HTML);
a run is **not deterministic** (two runs of `pirelli.com` differed by one library, a
carousel that loads late); a hostile page can define a global to look like something else,
as it can for any script-based detector; and shared global names give false positives
(on `pirelli.com`, `Underscore.js` was reported with Lodash's `_.VERSION`, because both
define `_`; the reference engines solve this with `excludes` between technologies, which
the registry does not carry yet).

## Related domains (`--related`, `owfscan related`)

Domains that **may** belong to the same owner as the target, with what ties each to it. It
says what two sites have in common; it never says who owns them. A domain with the same name
can be someone else's, and an agency can share an account across clients.

Candidates come from what the target says about itself (nothing is guessed yet):

- the external domains its home page links to (social platforms left out);
- the domains it declares as other-language versions (`<link rel="alternate" hreflang>`);
- the other names in its TLS certificate.

Each candidate's home page is read (the same limits as friend domains: `robots.txt` always
honoured, a pause, `--related-max` sites at most, non-public addresses refused) and compared
with the target's. The evidence, **strong** signals first:

| Evidence | Strength | Meaning |
|---|---|---|
| `cert_org` | strong | its certificate names the same organization (`O=`) as the target's |
| `cert_san` | strong | the target's certificate lists it |
| `site_verification` | strong | the same Google/Bing/Facebook/Yandex ... ownership token in a meta tag (shown shortened) |
| `analytics_id` | strong | the same Tag Manager or Analytics identifier (GTM-, G-, UA-) in a script or frame |
| `hreflang_home` | strong | the target declares it as an alternate version of itself |
| `linked_from_home`, `links_back`, `hreflang_back` | medium | the home pages link to each other, or it declares the target as an alternate |

A domain with at least one strong signal, or whose home page and the target's link to each
other, is `probable`; the rest are `candidate`. `related.probable` lists the probable ones by
name, the short answer; `related.domains` has the evidence for each.

Results (read on 2026-11-20; a home page each, nothing else):

- `michelin.com`: `michelin.fr` is `probable` (the same certificate organization,
  "Manufacture Française des Pneumatiques Michelin", and the link). `cloudimg.io`, an image
  service, stays a `candidate` and unreachable. `michelin.it` and the other country domains
  are **not found**: nobody links to them from the home page.
- `pirelli.com`: `pirelli.cn` has the same certificate organization and the same
  analytics identifier. `fondazionepirelli.org`, `pirellidesign.com` and
  `pirellihangarbicocca.org` are `probable` only because the home pages link to each other
  (no strong signal).

### Other TLDs of the same name (`--related-tlds`)

Off by default, because it means contacting names nobody pointed to. With `--related-tlds`
the target's name is tried under ten other suffixes (`com org net eu fr it de es co.uk nl`,
the target's own left out; `--related-tlds-list it,fr,...` replaces the list). Each name is
looked up in DNS (also with `www.`); the ones that do not exist are not contacted. The others
are read like any candidate (robots.txt, pause, `--related-max`) and compared. A name that
exists carries only a **weak** signal (`name_variant`): anyone can register it. What decides is
the rest: a certificate with the same organization, a shared token or identifier, or a home
page that redirects to the target (`redirects_to_target`, strong). A name variant that merely
links to the target stays a `candidate`. The default list is a judgement about where companies
register their names, not a measure. It needs DNS (`--no-dns` refuses it).

Results (read on 2026-11-20):

- `michelin.com`: 9 names tried, 7 exist. `michelin.co.uk`, `.de`, `.es`, `.fr`, `.it` and
  `.nl` are `probable`: the same certificate organization ("Manufacture Française des
  Pneumatiques Michelin") and a link back to `michelin.com`. `michelin.eu` exists but did not
  answer (timeout), so it stays a `candidate`.
- `wikipedia.com` (which redirects to `www.wikipedia.org`): 24 candidates, 18 `probable`.
  Eleven sister projects (`wikibooks.org`, `wikidata.org`, `wikimedia.org`, ...) through the
  certificate and the links; `w.wiki` and `wmfusercontent.org` through the certificate alone;
  `wikipedia.co.uk`, `.es`, `.eu` and `.com` because they redirect to the target.
  `wikipedia.de` is a `candidate` (the name exists and links to the target, nothing stronger),
  and `creativecommons.org` is a `candidate` (only linked). Six name variants were not read
  because of the limit of 20 (`not_checked`).

Limits: a signal that is only on a page other than the home page is missed; a site that
builds its links with JavaScript needs `--browser` (the first page is then the rendered
one); and a certificate that names no organization (most free certificates) gives no
`cert_org`. Trying other TLDs of the same name (`michelin.it`) is not done yet and would be
an option, because it means contacting names nobody pointed to.

## Active probes (`--active`)

Some rules need the answer to a request to a fixed path of the site: `/robots.txt`,
`/admin`, an API index (2236 rules on 305 paths in the registry, all `GET`). They are
imported as drafts with a pending safety review and, by default, **never sent**
(`probe disabled` in the coverage). Two things are needed to send one, and both are
deliberate:

1. **A reviewer approves the path**, once, in the registry:
   ```sh
   owf probe list --limit 30          # paths, how many rules need each, which technologies
   owf probe review /robots.txt /sitemap.xml /favicon.ico --decision approved --note "static files, read-only"
   ```
   The review is per path (rules that share a path share one request). Approving makes every
   rule on the path active and records the note and the time; the decision survives refreshes
   and travels in the export (`reviewed_at`, `review_note`). Approve a request you are willing
   to have sent to **any** site anyone scans with this registry. Never approve a path that
   changes state, even if it is a `GET`. Paths that are not absolute, that name another host
   (`//host`), contain a URL, a control character or a space are refused; only `GET` can be
   approved.
2. **The scan asks for it**: `owfscan scan <url> --registry ... --active`.

What the scanner then does, and no more (`internal/scan/scanner/active.go`):

- only approved probes, only `GET`, only on the host that was scanned;
- `robots.txt` is read first and a disallowed path is not requested (no option overrides
  this); if `robots.txt` cannot be read because of a server error, nothing is sent;
- a pause before each request (`--delay`) and at most `--active-max` requests (default 30),
  the ones shared by most rules first; the rest are counted as `not sent`;
- the same guard against non-public addresses; an answer that comes from another registrable
  domain (a redirect away) is thrown away;
- the result has an `active` section (approved, sent, failed, not sent, disallowed, refused)
  and the coverage says `probe not approved` for the rules whose path nobody approved, apart
  from `probe disabled` when `--active` is off.

**I have not approved any probe in your registry.** Which requests are acceptable is a
safety decision for the reviewer. On a copy of it, approving only `/robots.txt`,
`/sitemap.xml` and `/favicon.ico` (444 rules) and scanning `mr70.eu` with `--active` sent 3
requests, evaluated 443 more rules and found no new technology (a Hugo site), which is what I
expected.

## Technologies that matched but are not reported

The registry carries relationships between technologies, from its sources, and the scanner
applies two of them to what it found (`internal/scan/engine/resolve.go`). Whatever it holds
back is listed in `suppressed` (and printed as `NOT REPORTED`), with the reason and the
technologies responsible: nothing is dropped silently.

- **`excludes`.** If A excludes B and A was found, B is not reported. When two exclude each
  other (Lodash and Underscore.js both define `_`), the one with the higher confidence
  stays; with equal confidence both stay and a warning says so.
- **`requires`.** A technology is reported only if one of the technologies it requires was
  found (or is implied by one that was); a category requirement is met by another found
  technology in that category. With several required technologies, **one** is enough: I did
  not find a source that says whether Wappalyzer means "one" or "all", and "one" holds back
  less.
- **`implies`** is used for that check, and also gives the `implied` list below.

I could not read Wappalyzer's own JavaScript for these rules (its source was not at the
addresses I tried), and the two `wappalyzergo` files I read say nothing about `excludes` or
`requires`. So the semantics above are the ones of the Wappalyzer data-format description as
I know it, not checked against an engine, and the relationships are only as good as the
sources that wrote them.

### Implied technologies (`implied`)

The registry also says which technologies follow from others (WordPress implies PHP and
MySQL). Starting from the technologies that are reported, the scanner follows `implies`
through the ones it reaches and lists those no rule matched in `implied` (printed as
`IMPLIED`). They are **not detections**: there is no evidence of their own, only the technologies
that imply them (`implied_by`), and they are kept apart from `technologies` so a consumer
cannot mistake one for the other.

- Confidence is at most that of what implies it, and is lowered by the relationship's own
  confidence when the source gave one (Wappalyzer's `\;confidence:N`). With several implying
  technologies the best one counts.
- A technology that was found is not also implied; one that a found technology excludes is not
  implied; a deprecated one is not implied; a technology held back (excluded or missing a
  requirement) implies nothing.
- The chain is followed transitively, and a cycle is harmless (it can make A "implied by" B
  when B is itself implied by A: the list says what the registry says).

On `pirelli.com` (with `--browser`) the only implied technology is Amazon Web Services, from
Amazon CloudFront.

On `pirelli.com` with `--browser`, `Underscore.js` (reported before with Lodash's version
3.8.0 and confidence 0.00) is now `excluded by Lodash`.

## Friend domains (`--friends`, `owfscan friends`)

A **friend** is a domain that the target's home page links to and whose own home page
links back to the target's registrable domain. `owfscan friends <url>` prints them;
`owfscan scan <url> --friends` adds them to the result (`friends`, in the schema). It says
what two home pages link to and nothing more: not that the sites are related, owned by
the same people, or that the link is a recommendation.

How it is decided:

- **Candidates.** The external domains linked by ordinary links (`<a>`) on the home page
  that was asked for (not the pages a `--depth` crawl added). Social platforms are left out
  (their home pages link to everything), and so are links from scripts, images and
  stylesheets. Ordered by number of links, then by name.
- **The check.** The candidate's home page (`/` on the host that was linked) is fetched
  and its `<a>` links are read; one pointing to the target's registrable domain (any
  subdomain) makes it a friend. The links found are listed as `links_back`.
- **Statuses.** `friend`, `not_friend` (page read, no link back), `not_allowed` (its
  robots.txt disallows `/`, or could not be read because of a server error),
  `unreachable` (no answer, not a page, or an error status), `not_checked` (over the limit).

What it costs, because it contacts sites you did not name:

- one request for `robots.txt` and one for the home page per candidate;
- `robots.txt` is **always** honoured here; `--ignore-robots` does not apply;
- `--delay` (default 500 ms) before each request, `--friends-max` (default 20) sites at
  most; the rest are listed as `not_checked` so nothing is hidden;
- the same guard against non-public addresses as everywhere.

On `mr70.eu` (my own site) it found 2 candidates (creativecommons.org, fosstodon.org),
neither linking back: 0 friends. That is the honest result, not a sample of a busy site.

## HTML report (`owfscan report`, `scan --html`)

```sh
owfscan scan example.com --registry registry.json --depth 1 --friends --related --json > example.json
owfscan report example.json -o example.html      # or: owfscan scan ... --html example.html
```

One self-contained page: the numbers at a glance, the stack by category (a ring chart, cards with
the confidence bar, the health badge and the matching rules as evidence), implied and not-reported
technologies, the infrastructure (addresses, DNS, certificate with days left, which browser-facing
headers the first response carried), profiles, contacts and linked sites, a graph of friend and
related domains, and a section **"What was not seen"** with the share of rules that could be
applied and why the rest could not. The bar on a card is the confidence of the best rule, not a
probability, and there is no overall score: most rules have no tests, so a grade would claim
more than is known. The security-headers block lists what was sent; it is not an assessment.

The page has no script and a Content-Security-Policy that forbids loading anything, uses system
fonts and follows the light or dark setting of the system; it prints. It is made from the result
alone (nothing is fetched) and does not read the clock, so the same result gives the same bytes.
Everything that comes from the site is escaped and only http(s) links are written. `--title` sets
the heading. The registry's redistribution notice is shown on top when there is one.

## What is left out of the output

- **The page body** is never part of a `scan` result, and `observe` leaves it out unless you
  give `--html`.
- **Headers that change on every call** (`date`, `age`, `etag`, `set-cookie`, request ids,
  cache state, caller addresses, ...) are left out of `page.headers`, and the page then says
  `headers_filtered: true`. The list is `output.drop_headers` in the configuration file; a name
  or a prefix ending in `*` (`x-envoy-*`), lower case; `--all-headers` keeps everything and an
  empty list turns the filter off. **The rules still see every header**: a rule on `x-amz-cf-id`
  or `via` keeps matching. What the output does not repeat is the value: the `matched` of such
  evidence is empty. In `observe`, when `set-cookie` is on the list, the cookie names stay (rules
  look for them) and their values and the raw `Set-Cookie` lines go.
- **Why.** Two calls to the same site seconds apart should give the same result. Measured by
  scanning mr70.eu, pirelli.com, michelin.com and wikipedia.com three times each, one second
  apart: before the filter `date`, `age`, `set-cookie`, `via`, `server-timing`, `x-amz-cf-id`,
  `x-azure-ref`, `x-cache`, `x-nf-request-id`, `x-request-id` changed (and `x-client-ip`
  carried the caller's address), and their values also appeared in the `matched` of the
  technologies they identified. After it, everything except `scanned_at` and `duration_ms`
  is identical on mr70.eu, pirelli.com and wikipedia.com. On michelin.com `pages[0].bytes`
  still varies by a few bytes: the page body itself changes.
- The default list holds the headers seen changing plus the usual members of the same families
  (request ids, cache state, validators such as `etag`, `last-modified`); the second group was
  added in advance, not measured. If a header you need is dropped, take it off the list.
- For a validation case made from `observe`, give `--html --all-headers`: the rules read both.

## Configuration file (`owfscan config`)

The limits and lists that owfscan uses (timeouts, the most pages, friends, related domains
and probes, the browser's limits, the TLDs to try) can be changed in a TOML file instead of
on every command line.

```sh
owfscan config init            # writes ~/.config/owf/owfscan.toml with every default, commented
owfscan config init -o my.toml # or elsewhere; --force overwrites, --stdout only prints
owfscan config show            # the values in force, and the file they come from
owfscan config show --ceilings # also the largest value each one may have
owfscan config path
```

- **Where.** `--config FILE`, else `OWFSCAN_CONFIG`, else `$XDG_CONFIG_HOME/owf/owfscan.toml`,
  else `$HOME/.config/owf/owfscan.toml` (also on macOS). No file: the built-in values, which are
  what `config init` writes.
- **Order.** A flag beats the file, the file beats the built-in value. The flag defaults shown by
  `--help` are the ones of the file. Of the two environment variables that already existed,
  `OWFSCAN_CACHE` and `OWFSCAN_CHROME` beat the file too.
- **Sections.** `[fetch]` (timeout, max_body_bytes, max_redirects, max_age, cache_dir,
  user_agent), `[crawl]` (max_pages, delay, max_delay), `[friends]` (max), `[related]` (max,
  tlds), `[active]` (max, max_body_bytes), `[browser]` (timeout, settle, max_requests,
  chrome_path), `[result]` (max_evidence), `[output]` (drop_headers). Durations are text: `"500ms"`, `"20s"`, `"24h"`.
  A list in the file replaces the default list (`related.tlds`); a key left out keeps its default.
- **Strict.** A key or section that does not exist is an error (it is probably a typo), every
  value has a range and a ceiling, all problems are reported together, and a file that exists but
  is wrong stops every command except `config` (so you can fix it); it is never ignored silently.
  The ceilings catch typos such as ten million pages; they are not a policy, and `crawl.delay`
  cannot go below 100 ms.
- **What the file cannot do.** It does not turn on `--browser`, `--friends`, `--related`,
  `--active` or `--related-tlds`, and it cannot lift the guards `--allow-private`, `--insecure`
  or `--ignore-robots`: a file copied from somewhere else must not change whom a run contacts.
  `related.tlds` is only the list that `--related-tlds` uses.

## Loading the registry

`scan` checks the export against its schema and manifest before use. For a registry of
22000 rules that costs about 0.5 s, so after a file has passed, a stamp named by the
SHA-256 of its **bytes** is stored in the user cache directory (`owfscan/verified`, or
`--verify-cache DIR`; `--verify-cache off` always verifies). Any other content, one
changed byte included, has no stamp and is verified in full. On a real export (45 MB,
22178 rules) a scan of one page went from 0.87 s to 0.33 s, measured on one machine
without DNS or favicon. Delete the directory to start over.

## What is not there yet

- **JavaScript.** Nothing is executed. Links, handles and widgets added by scripts
  are not seen; neither are the technologies that only show in JavaScript variables
  (about a quarter of the registry's rules).
- Active probes and a browser.
- DNS `SOA` records (the standard library cannot ask for them), HTTP/2 and HTTP/3
  details.

## Troubleshooting

| Message | Cause |
|---|---|
| `address not allowed: … is not a public address` | the host (or a redirect) resolves to a private or local address; use `--allow-private` only for your own network |
| `x509: certificate signed by unknown authority` | the site's certificate is not trusted; `--insecure` accepts it (the certificate is still recorded) |
| `stopped after 10 redirects` | a redirect loop |
| `registry: verify: content hash is …` | the export was edited or damaged; write it again with `owf export` |
| `registry: verify: the document has no manifest` | the export was written by an older `owf` (schema before 0.2.0) |
| `--registry is required` | `scan` needs an export; set `--registry` or `OWFSCAN_REGISTRY` |
| few or no technologies | the page may show little without JavaScript; check `coverage.skipped` and the registry you exported |
| `https_unavailable` warning | the bare host did not answer over https and was fetched over http |
| `body_truncated` warning | the page is larger than 5 MiB and was cut |
| `invalid_jsonld` warning | a JSON-LD block on the page is not valid JSON (the rest is still read) |
| no social profile found | the page may add them with JavaScript, or publish them on another page |

## For contributors

Layout:

```
cmd/owfscan/             the CLI
scan/                    public result types
internal/scan/web/       links, domains, social profiles, contacts (pure, from HTML)
internal/scan/fetch/     guarded HTTP fetch, redirects, limits, disk cache
internal/scan/observe/   page -> observation (favicon hashes, DNS, TLS)
schemas/scan-result.schema.json    contract of the result
```

**Rules and the engine.** `internal/scan/engine` applies the registry (built once,
reusable); `internal/scan/scanner` runs a whole scan; `internal/scan/scantest` builds an
export and a local site from the source fixtures for tests. The rules are evaluated by
`internal/matcher` (`Prepare` readies an observation once for many rules; `Outcome.Value`
is what matched). Header names in the observation keep the case the server sent, because
rules on the raw header block (`Server: …`) are case-sensitive.

**Add or fix a social platform.** Edit `internal/scan/web/platforms.json`. A platform
has `hosts` and `rules`; a rule has a `kind`, a `path` regular expression with one
capture group for the handle (or a `query` parameter instead), a canonical `url`
template with `{h}` for the handle, and optionally `reserved` names that are never
handles (`features`, `intent`, …), `keep_case`, `prefix`, and `hosts` to restrict
the rule. Rules form an allow-list of profile shapes: prefer a narrow pattern. Then
add the URL to the positive table of `internal/scan/web/social_test.go` and, for
every share/intent/post URL you can think of, to `TestParseProfileRejects`.
RE2 syntax only.

**Test.** `go test ./internal/scan/... ./cmd/owfscan` needs no network: pages come
from local `httptest` servers and DNS from a fake resolver. A live check is manual
(`owfscan observe <your domain>`); never make a test depend on a third-party site.
`make check` runs everything.
