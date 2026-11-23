# Rule validation

A fingerprint is not trusted because it was imported. It earns `health: ok`
from test evidence. This document describes the harness
(`owf fingerprint test`), what it can and cannot say, and the static lint.

## Health

`validation.health` is `unknown`, `ok`, `degraded` or `broken`.

| Value | Rule |
|---|---|
| `broken` | at least one stored test run fails |
| `ok` | at least one passing **positive** case and one passing **negative** case, no failing case |
| `unknown` | anything less (this includes every imported rule at first) |
| `degraded` | reserved for known false positives; not set automatically yet |

Only passing and failing cases are evidence. A case that does not fit the
registry (stale selector, ambiguous selector) or that needs something the
offline matcher cannot do is reported, and leaves the rule untouched. A
failing case is never silently ignored: `owf fingerprint test` exits with an
error.

`ok` means "this rule behaved as asserted on these inputs". It does not mean
the rule is free of false positives. Test runs are stored on the rule
(`result`, `expect`, `fixture_ref`, `at`), so a reviewer can see exactly what
supports the label.

## Case files

JSON, validated by `schemas/validation-cases.schema.json`:

```json
{
  "schema_version": "0.1.0",
  "cases": [{
    "id": "nginx-server-header-positive",
    "rule": {"technology": "nginx", "observation": "http_header", "target": "Server", "operator": "regex"},
    "input": {"headers": {"Server": "nginx/1.25.3"}},
    "expect": {"match": true, "version": "1.25.3"}
  }]
}
```

- `rule` selects a rule by **meaning**: technology slug, observation, and
  optionally target, operator and pattern. It must resolve to exactly one
  rule. Canonical IDs are not used, because they differ between registries.
- `input` is a recorded observation: headers, cookies, HTML, scripts, JS
  globals, DNS records, TLS fields, XHR URLs, robots, favicon hash and
  recorded probe answers. Meta tags, script URLs, inline scripts, stylesheets,
  CSS and page text are derived from `html` unless given.
- Active probes are never run. A probe rule is tested against a recorded
  answer (`probes`).
- Case IDs are unique across all files. Unknown fields are rejected.

## Cases for groups

Rules that share a `group_id` (nuclei templates with `and` matchers) only hold
together, so a case tests the group, not a member. Use `group` instead of `rule`
and list **every** member:

```json
{"id": "4d-action-positive",
 "group": [
   {"technology": "4d", "observation": "html", "pattern": "/4DACTION/"},
   {"technology": "4d", "observation": "http_status"}],
 "input": {"status": 200, "html": "<a href=\"/4DACTION/home\">"},
 "expect": {"match": true}}
```

Groups of a technology often share members (4D has five groups, each with
"status is 200"), so the group is found by what it contains: exactly one group
of the technology must have these members, no more and no fewer, otherwise the
case is an error ("no group has exactly these members", "N groups have these
members"). Listing only part of a group is refused, because it would test a
weaker rule. The case matches if all members match, and the evidence (with its
`fixture_ref`) is stored on **every** member of the group; a failure marks them
all `broken`. A group needs its own positive and negative case to become `ok`.
Probed members read the recorded answer to their path (`input.probes`). A nuclei
template often repeats one matcher over several paths (Apache NiFi has seven groups with
the same members), so a selector can add `probe_path` to say which one.

## Version rules

A rule with `role: version` reads a version and never detects. Select it in a
case with `"role": "version"`; a selector without it picks detection rules only.
The case's input is the observation the version is read from, and `expect`
carries `match` and `version`. It gets its own health like any rule.

## Matching semantics

These were an open question; the matcher fixes them so they are explicit:

- regex patterns are unanchored and **case-insensitive** (the semantics of the
  Wappalyzer-style sources); `equals` and `contains` are case-sensitive;
- header and meta names are case-insensitive, cookie names and JS paths are
  case-sensitive, DNS record types are upper case;
- versions come from `version_extract`: `\1` is group 1, `\1?a:b` is `a` when
  group 1 is not empty and `b` otherwise;
- rules flagged `ecmascript` are **not** evaluated (RE2 would give different
  results). They are reported as `unsupported`;
- `page_title` is the HTML `<title>` (or `input.title`); `set_cookie` is evaluated
  on each raw `Set-Cookie` line (`input.set_cookies`); a `favicon_hash` rule with
  a target such as `md5` reads `input.favicon_hashes[target]`;
- `response_headers` is the raw header block (`Name: value` lines sorted by name),
  `http_response` is that block, a blank line and the body, `http_status` is the
  status code; `probe_response` reads the recorded answer to the rule's probe path
  (`input.probes`) with the targets `status`, `body`, `headers`, `response`,
  `content_type` and `server`;
- rules that share a `group_id` hold only together: `matcher.EvaluateGroup`;
- `dom` rules are evaluated on the page's HTML with a CSS selector engine
  (`cascadia`). The target is `selector`, `selector::text`,
  `selector::attr(name)` or `selector::prop(name)`. `exists` means an element
  matches (`::attr`: the attribute is set, `::text`: the element has text).
  Text is the element's text content with whitespace collapsed. The HTML is
  parsed statically: nothing is executed. `::prop(...)` needs a browser and is
  `unsupported`. A selector that does not parse is an error in the rule.

## What the harness does not cover

- The inputs are small hand-written observations, not captures of real sites.
  They show that a rule does what its author asserts, not how it behaves on
  the web. Real captures would need rights to redistribute them.
- Rules that cannot be tested offline: 19 `ecmascript` rules and 2 `dom`
  `::prop` rules of 15836 in Enthec `9e52f10`. Rules that depend on JavaScript
  having run (globals, DOM changes made by scripts) can only be tested with the
  values you record in `input`; whether a real page produces them is not
  checked.
- There is no false-positive measurement over a corpus of sites.

## Corpus

`validation/cases/` holds cases for rules of widely used technologies, written
against the **Enthec-only registry** at the pinned revision (the technology slugs
are the ones that registry gives). `make validate-corpus` fetches that revision with
`git`, imports it, and runs every case (git and network needed); in CI it is a
separate job. `CORPUS_REVISION=<sha>` shows whether newer upstream rules made a case
stale. The cases for the small fixture snapshot are in
`internal/validation/testdata/cases` and run in every `go test`.

`validation/cases-nuclei/` is the same for nuclei groups, against a registry that holds
**only** `projectdiscovery-nuclei-templates` at its own pinned revision
(`CORPUS_NUCLEI_REVISION`); slugs there carry numeric suffixes where names collide
(`jenkins-2`). It has **158 cases on 57 groups**: web servers, the e-commerce and site-builder
families, CMS and self-hosted tools, and 20 groups whose rules need a probe (tested
against a recorded answer, nothing is requested). They are written by hand with realistic
inputs, each with its reason. On that registry 126 of 5166 rules are `ok` after
`fingerprint test --apply`.

Run against a registry that holds more sources (your working `owf.db`), these two
directories report **errors, not failures**: the nuclei groups have other slugs there
(`nginx-2` has become part of `nginx`), and two OpenTechalyzer cases name the patterns of
daisyUI and Prism as the source wrote them, which `owf fingerprint correct` has since
changed (on 2026-11-22: 55 and 2 errors). That is expected; `make validate-corpus` is the
check that counts for them, and `validation/cases/` is the one that runs on any registry
where the Enthec rules are the first provenance.

Rules that are weak by their own terms get **no positive case**, so they cannot become
`ok`: **Metatag CMS** matches any page that declares a generator (a Hugo site included),
`sentry-instance` matches any site using the Sentry browser SDK, and the Intel AMT rule
matches any header containing "intel". A case that asserts the wrong behaviour as
"expected" would turn a false positive into evidence of reliability, so those rules stay
`unknown` (Metatag keeps a negative case). The corpus does not generate cases from the
rule's own pattern for hundreds of groups: evidence that only repeats the pattern says
nothing about it.

Current state: **304 cases, all pass** on the author's registry (2026-11-23, six sources).
With the cases of this corpus applied, 34 more rules became `ok` (911 -> 945 of 29174; 685
of them only from upstream examples).
The earlier count was 236 cases and 115 Enthec rules of 61 technologies (of 15836, 0.7%).

| File | Contents |
|---|---|
| `web-servers.json`, `cms-and-libraries.json`, `dom.json` | the first 34 cases (nginx, Cloudflare, WordPress, jQuery, Google Analytics, Pixelfed, Bootstrap, ...) |
| `servers-and-hosting.json` | Apache, Akamai, CloudFront, S3, Caddy, Fastly, GitHub Pages, LiteSpeed, Netlify, OpenResty, Squarespace, Varnish, Vercel, HSTS, Wix, ASP.NET |
| `frameworks-and-cms.json` | PHP, Next.js, Express, Rails, Django, Laravel, Drupal, Joomla, Ghost, Gatsby, Hugo, WordPress, WooCommerce, Elementor, Yoast, Shopify, Matomo, Tailwind |
| `popular-sites.json` | 34 rules of the technologies most found in the 100-site Tranco sample that had no evidence: Envoy, Cloudflare Bot Management, Microsoft HTTPAPI, Azure (Front Door, Monitor, headers, cookie), AWS (headers, Route 53 NS), RSS, LinkedIn Insight, React, Astro, Stimulus, reCAPTCHA, PWA, HTML5, X-UA-Compatible, HTTP/3, Priority Hints, mailto, Permissions-Policy, TLS issuers (DigiCert, Sectigo, Let's Encrypt, Amazon) |
| `analytics-and-services.json` | Google Analytics, Tag Manager, AdSense, Hotjar, OneTrust, Cookiebot, Facebook Pixel, reCAPTCHA, Segment, Plausible, Stripe, Sentry, Maps, YouTube, HubSpot, Intercom, Google Fonts, Font Awesome, Open Graph, Moment, Swiper, Slick |

How to add one: pick a rule (`owf fingerprint list --technology <slug>`), write a
positive input that a real page would produce and a negative that is a *near miss* (a
similar header, an anchored name followed by more text, a different library with a
similar file name), and select the rule by technology, observation and, where
needed, target and pattern. Run `owf fingerprint test validation/cases`. A negative
that makes the rule match is a finding about the rule, not a case to delete:
note it (below) and write a fairer negative.

**What this evidence is worth.** The inputs are written by hand from how the
products behave; the negatives are near misses chosen by the author. A rule that
passes both is shown to behave as asserted on those inputs. It is not a measurement
of false positives on the web, and `ok` should not be read as "reliable".

### Findings from writing the corpus

- **React's script rule matches Preact.** `react(?:-dom)?[@/-]v?([\d.]+).*?\.js` is not
  anchored on a path segment, so `preact-10.19.3.min.js` matches and yields version
  `10.19.3` as React's. Found with a probe case that is not in the corpus (it would fail);
  the case in the corpus uses a different near miss (`jquery-3.6.0.min.js`). Not corrected
  yet: a reviewer can with `owf fingerprint correct`, or propose it upstream.
- **The nginx cases needed a pattern.** After the merges `nginx` has five `Server` rules;
  the three older cases now name the Enthec pattern.

- **Cookie names that are patterns are inert, upstream too.** 13 rules in the
  Wappalyzer-format sources name a cookie with regular-expression syntax
  (`connect\.sid`, `ASP\.NET_SessionId`, `\.ASPXAUTH`, `sails\.sid`,
  `SESS[a-f0-9]{32}`, `joomla_[a-z0-9]+`, `wiki\d+_session`, `_ga_*`,
  `CFID|CFTOKEN|…`, `mybb[lastvisit]`, `(?i)ltpatoken`). Both reference engines look a
  cookie up by its exact name: the JavaScript Wappalyzer reads `items[key]` in
  `analyzeManyToMany` (`src/js/wappalyzer.js`, only lower-casing the rule's key) and
  wappalyzergo reads `keyValue[data]`. No cookie is called `connect\.sid`, so these
  rules never match anywhere. `owf fingerprint lint` reports them
  (`inert_cookie_name`) and the scanner skips them and counts them in the coverage
  (`cookie name is a pattern (inert upstream too)`). Five of them only escape a dot
  (`connect\.sid`, `ASP\.NET_SessionId`, `\.ASPXAUTH`, `sails\.sid`) and would work
  if written without the backslash. The importer does not fix them (it stays faithful to
  the source); a reviewer does, with `owf fingerprint correct` (below). The HTTP Archive
  fork already writes `ASP.NET_SessionId` correctly, which is evidence for the others.

  Corrected on the author's registry on 2026-11-20 (4 rules; 13 inert rules remain, the
  ones that are genuinely patterns). On a local server that sets `connect.sid` and
  `ASP.NET_SessionId`, a scan before the correction found ASP.NET (one rule) and not
  Express; after it, Express is found and ASP.NET gains the Enthec rule. This is still
  a correction to propose upstream.

## Corrections

`owf fingerprint correct <fp-id> --field target|pattern --value V --reason R` is a
reviewer decision for a rule the source got wrong. The record keeps the value the source
gave (`correction.original`), the new value, the reason and the time, and the upstream
fragment stays in `raw`. The rule's test evidence is cleared and its health goes back to
`unknown`, because it was gathered on the old rule. `--revert` puts the source's value
back. Corrections survive refreshes. A rule's identity includes its content, so if the
source itself changes the value you corrected, that is a new rule without a correction,
and the corrected one stays as `removed_upstream` with your record. One correction per
rule (a second one on the same field replaces the new value and keeps the source's
original); a regular expression is checked before it is stored. The export carries
`correction` on the rule (schema: `correction`), so a consumer can tell a corrected rule
from what the source published.
- **`swiper(?:\.min)?\.js`** (Swiper) does not match `swiper-bundle.min.js`, the
  usual file name of the library.
- **Fixed versions on `exists` rules** (`_gat` gives version `UA`) were lost by the
  matcher; fixed, with a test.
- **Groups of rules from other projects can be true for any site** (`Metatag CMS`,
  see [owfscan.md](owfscan.md#how-to-read-a-result)); they need negative cases too.

## Static lint

`owf fingerprint lint` reports rules that are likely to match too much:

| Code | Meaning |
|---|---|
| `regex_matches_empty` | the pattern matches the empty string |
| `pattern_too_short` | under 3 characters |
| `ubiquitous_header` | `exists` on a header every site has |
| `ubiquitous_meta` | `exists` on a meta every page has |
| `inert_cookie_name` | a cookie rule whose name is a pattern: it can never match |
| `probe_query` | a probe path with a query string |

It is advisory and stores nothing. Enthec `9e52f10`: 23 findings on 22 of
15836 rules. Many are legitimate (`(.*)` on a version global is an existence
check, `h2` is a real protocol token), so a finding is a prompt for review and
not a verdict.

## Upstream examples as evidence

Some sources ship examples with their rules: strings a rule must match, often
with the version it must read. Recog does (1662 on the imported rules). They are
kept in the rule's raw fragment, and `owf fingerprint test --upstream-examples
[--apply]` turns them into cases:

- **positive:** the rule's own examples (at most 5), with the expected version
  when the rule reads one;
- **negative:** the first example of rules of *other technologies* in the same
  database that come **later** in the file. The source tries a database in
  order and stops at the first match, so an earlier rule's banner is never seen
  by a later rule; the registry reports every match, so a rule that would claim
  a later product's banner is a real false positive and fails. Every candidate
  is evaluated; at most 5 passing negatives are kept (the 3 nearest, 2 spread by
  a stable hash), and every failing one;
- **no negatives for exact digests** (favicon hashes): a hash cannot be
  over-broad, so a negative would prove nothing.

Evidence from these cases is stored with `origin: upstream_example` on each test
run, and `owf stats` says how many `ok` rules rest on it alone. A regenerated
set replaces the previous generated set of a rule; runs from case files stay.
Run it again after refreshing the source.

What it is worth, on Recog `f1191e2` (7 web databases, 1176 rules): 1602
positive and 3382 negative cases from 92861 negative checks, all pass, and 685
rules reach `ok`. Be clear about what that means: the examples and the rules
were written by the same people, so the evidence shows that a rule is
consistent with its maintainers' own data and does not match their other
products' banners. It does not show behaviour on real sites. The 460 favicon
rules stay `unknown` (positives only), and so do the last rules of each
database, which have no later rules to give negatives.

Not available for sources without examples (Wappalyzer-format, nuclei): their
rules still need case files.

## Conformance of the mapping

The Recog extractor tests run all of a source's examples against its rules with
the matcher as well (1662 examples on the full snapshot, all pass;
`OWF_RECOG_SNAPSHOT=<clone> go test ./internal/extractor/recog -run
FullSnapshot -v`). This checks the mapping (case rules, versions).
