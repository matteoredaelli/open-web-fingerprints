# owfscan bot: the crawler

`owfscan bot` scans many sites over time. It keeps a **frontier** of domains in a SQLite file
(`bot.db`), scans the home page of each one, adds the other domains it finds, and comes back to
each domain after a while. It is part of `owfscan` (package `internal/scan/bot`); the single
scan stays in [owfscan.md](owfscan.md) and its design in [scan.md](scan.md).

**Status.** Built and tested with local servers and fake scanners. It has **not** been run on
real sites yet: the numbers below (30 days, three DNS failures, 2 requests per second) are
defaults chosen from the plan, not measurements. Measure on a small, agreed set first.

## What it does and does not do

| It does | It never does |
|---|---|
| `GET` of the home page (`--depth 1`: also up to 10 linked pages) | `POST`, or any request that changes something |
| read `robots.txt` of every host, before anything else | ignore `robots.txt` (there is no flag) |
| wait between requests to one host, limit the total rate, back off on 429 and 5xx | send probes (`--active`) or open a browser |
| identify itself with a User-Agent that has the project address | store e-mail addresses or telephone numbers |
| refuse private and local addresses, also after redirects | scan a domain on a block list or one that asked to be left out |
| keep only the last result of each domain | keep a history of results |

The configuration file cannot turn any of the right column on. There is no key for it.
Scan only what you may scan: sending requests to sites you did not name is your responsibility
(see [owfscan.md](owfscan.md#use-only-on-sites-you-are-allowed-to-scan)).

## First steps

```sh
owfscan config init                       # writes ~/.config/owf/owfscan.toml; edit [bot] and [bot.filter]
# enable at least one block list in [[bot.filter.list]] (see "Block lists"), then:
owfscan bot filter refresh                # downloads the lists (network); also: make filters
owfscan bot seed top1000.txt              # one domain per line, or "rank,domain" as Tranco
owfscan bot run --registry registry.json --budget 50 --quiet
owfscan bot status
```

`--no-filter` lets `run` start with no list. It is explicit on purpose: the default is to refuse.

Stop with Ctrl-C (or SIGTERM), or create the **stop file** (`<db>.stop`, or `--stop-file`): the
run stops before it claims anything else. Domains in flight at a clean stop are given back and
done first next time. A run killed outright (`kill -9`, power cut) loses nothing: the lease on
its domains ends after `bot.lease_ttl` and another run takes them. Run it again to resume.
Two bots on one file are refused; after a kill the lock also ends with the lease, so a restart
may have to wait up to `lease_ttl` (10 minutes by default).

## Commands

| Command | What it does |
|---|---|
| `bot seed <list>` | add domains to the frontier; those on a block list are added as `blocked` |
| `bot run` | claim, scan, record, discover; until nothing is due, the budget or time is spent, the stop file appears, or Ctrl-C |
| `bot status [--json]` | domains per state, due now, next visit, hosts in backoff, blocked per list, who is running |
| `bot exclude add\|list\|remove` | leave a domain out on request (`--note` says why); no refresh of the lists lifts it |
| `bot filter refresh\|list\|check` | download, show and test the block lists |

`bot run` flags (each is also a key of `[bot]`; a flag wins over the file, the file over the
default, and a flag is checked against the same ceilings as the file): `--db`, `--workers`,
`--rate`, `--per-host-delay`, `--budget`, `--until`, `--depth`, `--max-new-per-site`,
`--max-depth`, `--lease-ttl`, `--revisit`, `--revisit-max`, `--dns-failures`; and `--registry`,
`--filter-dir`, `--no-filter`, `--stop-file`, `--quiet`, which are not settings of the file.

## The frontier

A domain is a **registrable domain** (eTLD+1, from the public suffix list): `www.a.example` and
`shop.a.example` are `a.example`. IP addresses and bare suffixes are ignored. The first sighting
of a domain owns its row; later sightings change nothing.

States: `pending` (due), `leased` (a worker has it until `lease_until`), `done` (scanned; comes
back at `next_visit_at`), `failed` (last try failed; retried later), `blocked` (kept on purpose,
never scanned). A lease that has expired counts as `pending`.

Order of work: shallower depth first (a seed before what it linked), then better rank, then name.

**Discovery.** After a scan, the external domains of the result (`domains`, not internal) are
added: at most `max_new_per_site` per site, the most linked first, and none from a domain
`max_depth` hops from a seed (it is scanned, its links are not followed). This includes the
domains of social networks, CDNs and other ones that every site links to; they are scanned like
any other. Nothing but the first page of each is read, and the filter and `robots.txt` apply.

**One transaction per result.** Saving the result, adding the discovered domains and scheduling
the next visit happen together. A worker that lost its lease writes nothing.

## Politeness

All requests of a run go through one shared transport (`Pool`), also redirects, favicon and the
other pages of `--depth 1`. The guard against private addresses sits in the dialer underneath.

- **Rate.** `bot.rate` requests per second over all hosts (default 2).
- **Per host.** `bot.per_host_delay` between two requests to one host (default 10 s); a larger
  `Crawl-delay` in `robots.txt` wins, up to `crawl.max_delay`. The first request to a host is
  its `robots.txt`, which counts too, so a first page takes at least two delays.
- **robots.txt.** Cached for 24 hours. A 4xx means there is none (everything allowed). A 5xx, a
  429 or no answer means it cannot be read, and then **nothing** is fetched from that host
  (RFC 9309) for 10 minutes, after which it is asked again.
- **Backoff.** A 429, a 5xx or a failure makes the host rest for 1 minute, doubling at each
  failure in a row up to 6 hours; `Retry-After` is honoured within the same cap. No request is
  sent during the rest. A good answer ends it. The state is in the file, so a restart keeps it.
- **Timeouts.** One domain gets twice `fetch.timeout`, the `www.` retry included.

## Revisit

A scanned domain comes back after `bot.revisit` (30 days) if this was its first scan. After that,
the result is compared with the last one by a hash of the **technologies with their versions
and the external domains linked** (not times, headers or counts):

- changed: back after half of `revisit` (never under 24 h);
- unchanged: the wait doubles at each scan in a row (30, 60, 120 days…) up to `bot.revisit_max`.

Waits are spread by ±10 % so that domains found together do not all fall due on one day.
Because the hash includes the linked domains, a site that changes its links often looks
"changed" more than it is. Not measured.

**Failures.** The retry waits `retry`, doubled at each failure in a row, up to `revisit_max`:
a DNS failure 7 days, `robots` (disallowed) as long as `revisit`, `robots_unavailable` and
`backoff` one hour, other failures one day. After `bot.dns_failures` DNS failures in a row (3; 0 never) the domain is
`blocked` for good with list `dns`; any other failure in between resets the count. There is no
command yet to lift a `dns` block.

The failure class stored is a short word (`dns`, `timeout`, `robots`, `connection_refused`,
`tls_certificate`, `other`…); the error message is not kept, it can hold data.

## Block lists

The filter keeps the crawler away from domains you do not want to scan (adult content, gambling,
malware, phishing; ads and tracking only if you ask). It is **your** choice: no list is shipped,
because their licences differ.

```toml
[bot.filter]
mode = "mark"                                   # the only mode: a blocked domain is kept, marked, never scanned
exclude_categories = ["adult", "gambling", "malware", "phishing"]   # categories that block
require = true                                  # `bot run` refuses to start with no list

[[bot.filter.list]]
name = "my-list"                                # lower case, digits, '-'
url = "https://…"                               # https only
category = "adult"                              # adult gambling malware phishing ads tracking other
format = "hosts"                                # hosts | domains | adblock
enabled = true
```

- A list of a category that is **not** in `exclude_categories` is read but blocks nothing.
- `bot filter refresh` downloads the enabled lists into `bot.filter.dir`, one `.list` file and one
  `.json` note (URL, date, size, SHA-256, entries, what was skipped) for each. A copy is replaced
  only by a list that downloaded whole, parsed, and has at least one entry; otherwise the old copy
  stays. `make filters` does the same, `make filters-check DOMAIN=example.com` tests a domain.
- `bot filter check <domain>…` says whether a domain is blocked and by which list and entry.
  `bot filter list` shows the lists and the date of their copy.
- `bot run` warns when a copy is older than `bot.filter.refresh_every` (7 days), and refuses to
  start when an enabled list has no copy.

**Where it applies.** When a seed or a discovered domain is added; when a domain is claimed (so a
list refreshed after the domain was added still works); and on the final address after redirects
(the page of a blocked site is not kept). At the start of every `run`, domains blocked by a list
that no longer blocks them go back to `pending`. Exclusions made with `bot exclude` and `dns`
blocks are never lifted this way.

**Formats.**

| Format | Read | Skipped, and counted |
|---|---|---|
| `hosts` | `0.0.0.0 example.com`, `127.0.0.1 …` and several names on a line | `localhost`, lines that are not hosts lines |
| `domains` | one domain per line; `*.example.com` as `example.com`; `#` and `!` comments | anything else |
| `adblock` | `||example.com^`, `||example.com^$important`, exceptions `@@||example.com^` | regular expressions, rules with a path or a wildcard, rules with options other than `important` (a type, a third party…), cosmetic rules |

What cannot be read as a whole domain is skipped, never turned into a weaker rule that would
block more. A blocked domain blocks its subdomains; its parent is not blocked. An exception
cancels the blocks **of its own list** on that domain and below, not those of other lists.

**Limits.** A list is a hint about **names**. It has false positives (a harmless site that shares
a name or a host with a bad one) and false negatives (most of the web is on no list, a new site is
on none). It says nothing about the content of a page, and the filter looks at no content. Do not
present it as a guarantee that no unwanted content was read. Lists change; the copy you have is
as old as the last `refresh`.

**Lists to consider.** Names only; **check the licence and the terms of each yourself** (a
repository's licence is not always the licence of its data), and take the address and the format
from the project's own page. The tool records nothing legal.

- Hagezi DNS blocklists (categories such as adult, gambling, threat intelligence).
- StevenBlack hosts (unified hosts with extensions such as `porn` and `gambling`).
- OISD.
- AdGuard DNS filters.
- Pi-hole category lists collected by the community (adult, gambling, malware).

## Opt-out and the kill switch

- `owfscan bot exclude add example.com --note "owner asked on 2026-…"`: the domain is `blocked` with
  list `opt-out`, whatever its state; it is never scanned, no refresh lifts it. `exclude list` shows
  them, `exclude remove` lifts one.
- The stop file stops a run at the next claim, from outside: `touch bot.db.stop`. Remove it before
  the next run, or the run stops at once.
- The User-Agent can be changed in `fetch.user_agent`; keep it identifiable and with a way to reach
  you (the default carries the project address).

## What is stored

`bot.db` holds, per domain: state, how it was found, depth, rank, attempts, error class, status,
times, the **last** result (gzip JSON, schema `scan result`) and its hash, and why it is blocked.
Per host: crawl delay, robots time, backoff. The scan finds e-mail addresses and telephone numbers, and the crawler **drops them** before
saving (`contacts` is always empty). The result has the links and the technologies of every site: keep the file private, and
publish only aggregates. `bot.db` is a SQLite file in WAL mode: copy it only when no run is
active (or use `sqlite3 .backup`).

## Not done yet

- Not run on real sites; no measurement of block rates, time per domain or detection quality.
- No `bot filter add|remove` (edit the file), no command to lift a `dns` block or to re-queue
  failed domains.
- No export of results to the statistics (`owfscan stats` reads `batch.db`): the results are in
  `bot.db` and need a reader. `make tranco` still uses `batch`.
- Depth 1 only reads a few pages of the site; the browser, friends, related domains and probes are
  not used by the crawler.
