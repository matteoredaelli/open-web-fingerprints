# OpenTechalyzer fixtures

`snapshot/src/fingerprints/` holds five of the fingerprint files and `index.ts`
of https://github.com/Houseofmvps/opentechalyzer at revision
`a3d30e479c91c06732ef88867d69b7feef8f3f35` (2026-11-20), copied unmodified.
The repository is MIT licensed (Copyright its authors); the README says the
built-in database is written for that project and is not a copy of another
dataset.

They were chosen to cover every signal the extractor maps: `analytics.ts`
(patterns with `id`, `version`, `caseSensitive`), `frameworks.ts` (headers,
cookies, js), `infrastructure.ts` (DNS), `libraries.ts` (`cssContent`) and
`selfhosted.ts` (probes, two of them intrusive). `index.ts` is code, not data,
and must be ignored.

Do not use these files to infer upstream coverage.
