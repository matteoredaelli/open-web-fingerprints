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
git clone https://github.com/enthec/webappanalyzer /tmp/enthec
git -C /tmp/enthec rev-parse --short HEAD     # the revision to pin

owf init                                      # creates owf.db
owf import enthec-webappanalyzer --snapshot /tmp/enthec --revision <sha> --dry-run
owf import enthec-webappanalyzer --snapshot /tmp/enthec --revision <sha>
owf stats
owf technology show wordpress
owf fingerprint list --technology nginx
owf fingerprint validate
owf export -o registry.json                   # validated against schemas/
```

`--db` or `OWF_DB` selects the database file. Fetching snapshots is not
implemented yet. Imported data is unreviewed: check `owf source info` for
the license status before redistributing an export.

See [docs/domain-model.md](docs/domain-model.md) and
[docs/sources.md](docs/sources.md).

## License

GPL-3.0-or-later (see [LICENSE](LICENSE)). Third-party fingerprint data keeps
its original license; provenance and licensing are tracked per source.
