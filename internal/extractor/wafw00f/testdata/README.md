# WAFW00F fixtures

`snapshot/wafw00f/plugins/` holds real plugins from
https://github.com/EnableSecurity/wafw00f at revision
`69fbe3956bba47a172cf87e40e9037535d32a130`, copied unmodified. They cover
header and cookie rules (`cloudflare`, `sucuri`, `aesecure`), rules through
helper functions with guards (`f5firepass`) and a plugin that reads only the
response to an attack payload, which is skipped (`alertlogic`).

WAFW00F is under the BSD 3-Clause License, Copyright (c) 2009-2026, WAFW00F Developers
(`LICENSE`). The copyright notice and license text must be kept when
redistributing these files.

Do not use these files to infer upstream coverage.
