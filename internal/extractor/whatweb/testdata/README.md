# WhatWeb fixtures

`snapshot/plugins/` holds twelve plugins of
https://github.com/urbanadventurer/WhatWeb at revision
`d279d93042d034f3fd29d5a893d44ccc0595d3f8` (2026-04-03), copied unmodified.
The repository is licensed GPL-2.0 (`LICENSE`), and each plugin carries the
header "may be subject to redistribution and commercial restrictions"; the
maintainer has decided the licence question is settled (docs/sources-plan.md).

They were chosen to cover what the extractor reads or must refuse:
`4images`, `apache` (text, regexp, version, headers), `atutor` (`%r{}` literals),
`codeigniter` and `fortinet-firewall` (clauses that are Ruby expressions, with
`:url` probes), `content-security-policy` (a plugin that only reports a
header), `dell-kace-appliance` (any-value header rules), `magento` (a clause
that is not data, `:offset`), `1n1-hosting` (cookies), `pro-chat-rooms` (string
interpolation), `cookies` and `country` (plugins that are only code).

Do not use these files to infer upstream coverage.
