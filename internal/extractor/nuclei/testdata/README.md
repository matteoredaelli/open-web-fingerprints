# nuclei fixtures

`snapshot/http/technologies/` holds real templates from
https://github.com/projectdiscovery/nuclei-templates at revision
`91be390cf10100eb3c418877a857be9a0060b1aa`, copied unmodified, except that
`favicon-detect.yaml` and `tech-detect.yaml` are cut to their first 12 and 3
matchers (the originals have 775 and 571). They were chosen to cover: base-page
and probed paths, `and`/`or` matcher conditions, word, regex, status and DSL
matchers (`contains_any`, `mmh3`), case-insensitive words, metadata with
product, vendor and CPE, a favicon table, and the templates the extractor must
skip (raw request, POST, payload list, negative matcher, flow, DSL outside the
supported subset, and the generated `tech-detect`).

nuclei-templates is under the MIT license, Copyright (c) 2025 ProjectDiscovery,
Inc. The copyright notice and license text must be kept when redistributing
these files.

Do not use these files to infer upstream coverage.
