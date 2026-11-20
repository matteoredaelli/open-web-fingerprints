# owfscan: user guide

`owfscan` looks at a web site and tells you what it finds: the links on the page
and the domains they point to, the social profiles and contact details it
publishes, and (coming) the technologies it runs, with the evidence for each.
It is a separate program from `owf`: it has no database and makes requests to the
network. Design, decisions and roadmap: [scan.md](scan.md).

**Status.** Working today: `extract`, `links`, `social`, `observe`. Not yet: `scan`
(technologies from a registry export). See [What is not there yet](#what-is-not-there-yet).

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
| `owfscan links <url>` | links of the page and the registrable domains they point to | the page |
| `owfscan social <url>` | social profiles, email addresses and telephone numbers | the page |
| `owfscan observe <url>` | the observation the rules read, as JSON | the page, its favicon, DNS lookups |
| `owfscan extract --url <page-url> <file\|->` | the same extraction as `links` and `social` on saved HTML | none |

### Flags of the commands that fetch

| Flag | Default | Meaning |
|---|---|---|
| `--json` | off | JSON output |
| `--cache-dir DIR` | `$OWFSCAN_CACHE` or none | keep responses on disk and reuse them |
| `--max-age D` | `24h` | how long a cached response is reused |
| `--timeout D` | `20s` | timeout of each request |
| `--allow-private` | off | allow private and local addresses (your own network) |
| `--insecure` | off | accept invalid TLS certificates (the certificate is still recorded) |

`observe` also has `--no-dns`, `--no-favicon` and `--no-html` (leave the body out
of the output). There is a hard cap of 5 MiB per body and at most 10 redirects.

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
| Which URLs | the one you give, its redirects, and (with `observe`) the favicon |
| Redirects | followed up to 10 times, recorded; only to http and https |
| Size and time | 5 MiB per body, 20 s per request (both can be changed in code, the timeout with `--timeout`) |
| Addresses | loopback, private ranges, link-local (including the cloud metadata address `169.254.169.254`), CGNAT and unique-local addresses are refused when connecting, **including after a redirect**; `--allow-private` lifts this for your own network |
| Proxy | the environment's proxy settings are ignored |
| Identity | `User-Agent: owfscan (+https://github.com/matteoredaelli/open-web-fingerprints)` |
| Not done | crawling, `robots.txt`, probes, form submission, login |
| Cookies | kept in memory for the duration of the command, not stored |
| Cache | with `--cache-dir`, responses are stored on disk with the hash of the body; a damaged entry is ignored; 5xx answers are not stored |

Because the cache is plain files, do not point it at a shared location if the pages
you fetch are private.

## What is not there yet

- **`owfscan scan`**: applying a registry export to the page to list technologies,
  versions and evidence. Decisions already taken are in [scan.md](scan.md#decisions).
- **Several pages** (`--depth`): today only the page you name is read, so a profile
  that appears only on `/contact` is missed.
- **JavaScript.** Nothing is executed. Links, handles and widgets added by scripts
  are not seen; neither are the technologies that only show in JavaScript variables
  (about a quarter of the registry's rules).
- Active probes, a browser, `robots.txt`.
- DNS `SOA` records (the standard library cannot ask for them), HTTP/2 and HTTP/3
  details.

## Troubleshooting

| Message | Cause |
|---|---|
| `address not allowed: … is not a public address` | the host (or a redirect) resolves to a private or local address; use `--allow-private` only for your own network |
| `x509: certificate signed by unknown authority` | the site's certificate is not trusted; `--insecure` accepts it (the certificate is still recorded) |
| `stopped after 10 redirects` | a redirect loop |
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
