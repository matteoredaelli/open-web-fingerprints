# open-web-fingerprints

![OWF](docs/assets/owf.svg)

Open registry and toolkit for cataloguing web technologies and infrastructure
and the fingerprints used to identify them.

Status: **early development**. The local pipeline works end to end for five
sources (Enthec WebAppAnalyzer, HTTP Archive Wappalyzer, Rapid7 Recog, nuclei technology templates, OpenTechalyzer, WhatWeb): import, diff, SQLite storage, JSON export. See [AGENTS.md](AGENTS.md) for goals,
architecture and roadmap.

## Development

Requires Go 1.25+, [golangci-lint](https://golangci-lint.run) and
[lefthook](https://github.com/evilmartians/lefthook).

```sh
make hooks   # install git hooks
make check   # fmt, vet, lint, test
make build   # builds bin/owf
```

## Usage

```sh
owf init                                      # creates owf.db
owf source refresh enthec-webappanalyzer --dry-run   # fetch the branch tip, show the diff
owf source refresh enthec-webappanalyzer             # fetch and import
owf source refresh --all                             # every source, one after the other
owf source refresh enthec-webappanalyzer --revision <40-char sha>   # pin a commit

# or import a checkout you made yourself
owf import enthec-webappanalyzer --snapshot /path/to/clone --revision <sha>
owf stats
owf technology show wordpress
owf vendor list --uncurated                  # vendor names that are still guesses
owf vendor set php --name "The PHP Group" --website https://www.php.net
owf fingerprint list --technology nginx
owf fingerprint validate
owf fingerprint correct fp_... --field target --value connect.sid --reason "..."   # a reviewed fix of a rule the source got wrong
owf conflict list --state open               # candidates from other sources
owf conflict resolve --all --websites same_domain --merge --dry-run
owf fingerprint test validation/cases --apply   # store test evidence (see docs/validation.md)
owf fingerprint lint                          # rules likely to match too much
owf source review <source> --redistributable yes --note "who, what was checked"
owf export -o registry.json                   # validated against schemas/; refuses unreviewed sources
```

Exports only contain data from sources reviewed for redistribution
(see [docs/redistribution.md](docs/redistribution.md)); `--include-unreviewed`
lets you export for internal use, and says so in the file.

`--db` or `OWF_DB` selects the database file. `refresh` needs `git` and
downloads one commit of one branch, only the directories the extractor uses
(about 5 MB for Enthec), into `~/.cache/owf/snapshots` (`--cache` or
`OWF_CACHE`). A cached copy that is unmodified is reused without network
access. Imported data is unreviewed: check `owf source info` for
the license status before redistributing an export.

See [docs/domain-model.md](docs/domain-model.md),
[docs/sources.md](docs/sources.md), [docs/validation.md](docs/validation.md) and
[docs/redistribution.md](docs/redistribution.md).

## Scanning a site: `owfscan`

A second program, `owfscan`, looks at a web site and returns the technologies it
finds (applying the rules of an export, with the evidence for each), its links, the
domains they point to, the social profiles and the contact details it publishes. It
has no database and makes only GET requests.

```sh
make build
owf export --include-unreviewed -o registry.json     # the rules (internal use)
bin/owfscan scan   mr70.eu --registry registry.json -e   # technologies + evidence + the rest
bin/owfscan links  mr70.eu            # links and linked domains
bin/owfscan social mr70.eu            # profiles, emails, telephone numbers
bin/owfscan observe mr70.eu # what the rules read: headers, cookies, favicon hashes, DNS, TLS
bin/owfscan extract --url https://example.org/ page.html   # the same on saved HTML, offline
```

Scan only sites you are allowed to scan. User guide: [docs/owfscan.md](docs/owfscan.md);
design and decisions: [docs/scan.md](docs/scan.md).

## As a Go module

The module is `github.com/matteoredaelli/open-web-fingerprints`. Two packages are meant to
be imported (everything under `internal/` is not):

- [`scan`](scan): the Go types of a scan result (`owfscan scan --json`);
- [`schemas`](schemas): the embedded JSON Schemas and functions that validate a registry
  export, a scan result or a file of validation cases.

```go
import (
	"github.com/matteoredaelli/open-web-fingerprints/scan"
	"github.com/matteoredaelli/open-web-fingerprints/schemas"
)
```

The programs install with `go install github.com/matteoredaelli/open-web-fingerprints/cmd/owf@latest`
(and `.../cmd/owfscan@latest`). There is no tagged release yet: the formats are drafts (0.x)
and may change.

## License

GPL-3.0-or-later (see [LICENSE](LICENSE)) for everything the project writes: the
programs, the Go packages (`scan` and `schemas` included: a program that imports them
is subject to the GPL when distributed), the JSON Schemas, the documentation and the
validation cases. This is the maintainer's decision, one licence for code and data.

Third-party fingerprint data keeps its original license; provenance and licensing are
tracked per source, and the redistribution status of each source is a separate decision
(`owf source review`, see [docs/redistribution.md](docs/redistribution.md)).
