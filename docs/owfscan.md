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

`observe` and `scan` also have `--no-dns` and `--no-favicon`; `observe` has
`--no-html` (leave the body out of the output). `scan` has `--registry FILE`
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
$ owfscan observe mr70.eu --no-html
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
  feeds...). Of those, only pages whose path contains a word that usually marks a page
  with company details, in several languages: `contact`, `contatti`, `kontakt`, `about`,
  `chi-siamo`, `impressum`, `imprint`, `legal`, `press`, `stampa`, `careers`, `team`,
  `support`, `privacy`... Pages without such a word (a blog post, a product) are not
  fetched. Best candidates first, then by address. The word list is in
  `internal/scan/scanner/crawl.go`.
- **`robots.txt`.** Read once per host before any further page, with the rules of
  RFC 9309 (the group for `owfscan`, else `*`; longest rule wins; `Allow` wins a tie).
  A page it disallows is not fetched. If the file cannot be read because of a server
  error, nothing more is fetched from that host (the site cannot be asked), and a
  warning says so; a missing file (404) allows everything. `--ignore-robots` lifts
  this, for your own site. **The page you name is always fetched.**
- **Pace.** `--delay` (default 500 ms) before each further page, or the site's
  `Crawl-delay` if larger, at most 10 s. Requests are sequential.
- **Size.** `--max-pages` (default 8) in total; a warning says when it stopped there.
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
