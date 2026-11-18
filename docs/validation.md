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
- rules that share a `group_id` hold only together: `matcher.EvaluateGroup`.
  Validation cases do not select groups yet, so grouped rules cannot get test
  evidence and stay `unknown`;
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

`validation/cases/` holds cases for real, widely used rules (nginx,
Cloudflare, WordPress, jQuery, Google Analytics, Pixelfed, Bootstrap). They need the full Enthec
registry, so they run as `make validate-corpus` (git and network), against a
pinned Enthec revision. In CI this is a separate job. Running with another
`CORPUS_REVISION` shows whether upstream changes made a case stale.
Current result: 34 cases, 34 pass, 16 rules `ok`.

`internal/validation/testdata/cases/` holds cases against the small Enthec
fixture snapshot; they run in every `go test`.

## Static lint

`owf fingerprint lint` reports rules that are likely to match too much:

| Code | Meaning |
|---|---|
| `regex_matches_empty` | the pattern matches the empty string |
| `pattern_too_short` | under 3 characters |
| `ubiquitous_header` | `exists` on a header every site has |
| `ubiquitous_meta` | `exists` on a meta every page has |

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
