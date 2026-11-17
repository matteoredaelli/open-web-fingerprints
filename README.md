# open-web-fingerprints

Open registry and toolkit for cataloguing web technologies and infrastructure
and the fingerprints used to identify them.

Status: **early bootstrap (Phase 0)**. See [AGENTS.md](AGENTS.md) for goals,
architecture and roadmap.

## Development

Requires Go 1.25+, [golangci-lint](https://golangci-lint.run) and
[lefthook](https://github.com/evilmartians/lefthook).

```sh
make hooks   # install git hooks
make check   # fmt, vet, lint, test
make build   # builds bin/owf
```

## License

GPL-3.0-or-later (see [LICENSE](LICENSE)). Third-party fingerprint data keeps
its original license; provenance and licensing are tracked per source.
