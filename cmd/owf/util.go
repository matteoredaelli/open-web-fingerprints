// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"os"
	"time"
)

// nowFunc is replaced in tests for deterministic output.
var nowFunc = time.Now

func writeFile(path string, b []byte) error {
	return os.WriteFile(path, b, 0o644) //nolint:gosec // exported data is public
}
