# Enthec fixtures

`snapshot/` is a subset of real records from
https://github.com/enthec/webappanalyzer at revision
`9e52f10` (2026-11-15), license GPL-3.0. Entries were copied unmodified
(re-indented JSON) and chosen to cover each field and observation type:
headers, cookies, meta, js, dom (list and map forms), dns, scripts,
scriptSrc, url, css, text, xhr, robots, certIssuer, probe, implies,
requires, requiresCategory, excludes, cpe, `\;version:`/`\;confidence:`
modifiers, and a lookahead regex that RE2 cannot compile.

Do not use these files to infer upstream coverage. Refresh them only by
re-copying records from a newer pinned revision and updating this note.
