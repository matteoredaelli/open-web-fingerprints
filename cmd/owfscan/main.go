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
	"syscall"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	cfg, cfgPath, cfgErr = loadConfig(os.Args[1:])
	if err := newRootCmd().ExecuteContext(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "owfscan:", err)
		os.Exit(1)
	}
}
