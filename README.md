# open-web-fingerprints

Open registry and toolkit for cataloguing web technologies and infrastructure
and the fingerprints used to identify them.

Status: **early development**. The local pipeline works end to end for one
source (Enthec WebAppAnalyzer): import, diff, SQLite storage, JSON export. See [AGENTS.md](AGENTS.md) for goals,
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
owf source refresh enthec-webappanalyzer --revision <40-char sha>   # pin a commit

# or import a checkout you made yourself
owf import enthec-webappanalyzer --snapshot /path/to/clone --revision <sha>
owf stats
owf technology show wordpress
owf vendor list --uncurated                  # vendor names that are still guesses
owf vendor set php --name "The PHP Group" --website https://www.php.net
owf fingerprint list --technology nginx
owf fingerprint validate
owf conflict list --state open               # candidates from other sources
owf conflict resolve --all --websites same_domain --merge --dry-run
owf fingerprint test validation/cases --apply   # store test evidence (see docs/validation.md)
owf fingerprint lint                          # rules likely to match too much
owf export -o registry.json                   # validated against schemas/
```

`--db` or `OWF_DB` selects the database file. `refresh` needs `git` and
downloads one commit of one branch, only the directories the extractor uses
(about 5 MB for Enthec), into `~/.cache/owf/snapshots` (`--cache` or
`OWF_CACHE`). A cached copy that is unmodified is reused without network
access. Imported data is unreviewed: check `owf source info` for
the license status before redistributing an export.

See [docs/domain-model.md](docs/domain-model.md) and
[docs/sources.md](docs/sources.md).

## License

GPL-3.0-or-later (see [LICENSE](LICENSE)). Third-party fingerprint data keeps
its original license; provenance and licensing are tracked per source.
