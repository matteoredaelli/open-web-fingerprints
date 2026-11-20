// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

// Command owfscan scans a web site and returns what it finds: technologies,
// links, linked domains, social profiles and contacts. It reads a registry
// export and applies its rules; it has no database.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := newRootCmd().ExecuteContext(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "owfscan:", err)
		os.Exit(1)
	}
}
