# Contributing

- Open an issue before large changes; design decisions are documented in AGENTS.md.
- Run `make hooks` once, and `make check` before opening a pull request.
- Add tests for parsing, normalization, deduplication and validation. Tests must
  use pinned fixtures, never live network access.
- When adding or refreshing an upstream source, document its license and provenance.
- Active probes must be safe and non-destructive.
- Sign-off: by contributing you agree your work is licensed under GPL-3.0-or-later.
