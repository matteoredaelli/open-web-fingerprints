// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/config"
)

// cfg is the configuration in force: the file if there is one, else the built-in
// values. The flags take their defaults from it, so a flag on the command line wins.
// main fills it before the commands are built.
var (
	cfg     = config.Default()
	cfgPath string // the file it was read from, "" for the built-in values
	cfgErr  error  // a file that exists but cannot be used; reported by every command but `config`
)

// configArg finds --config in the arguments, before the flags are parsed, because the
// flag defaults depend on it. The environment variable OWFSCAN_CONFIG comes second.
func configArg(args []string) string {
	for i, a := range args {
		switch {
		case a == "--":
			return os.Getenv("OWFSCAN_CONFIG")
		case a == "--config" && i+1 < len(args):
			return args[i+1]
		case strings.HasPrefix(a, "--config="):
			return strings.TrimPrefix(a, "--config=")
		}
	}
	return os.Getenv("OWFSCAN_CONFIG")
}

func loadConfig(args []string) (config.Config, string, error) {
	c, p, err := config.Resolve(configArg(args))
	if err != nil {
		return config.Default(), "", err
	}
	return c, p, nil
}

// envOr returns the environment variable if it is set, else the fallback.
func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "owfscan",
		Short:         "Scan a web site: technologies, links, domains, social profiles and contacts",
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			// A broken file is an error, never silently ignored; `config` can still run to fix it.
			for c := cmd; c != nil; c = c.Parent() {
				if c.Name() == "config" {
					return nil
				}
			}
			return cfgErr
		},
	}
	root.PersistentFlags().String("config", "", "configuration file (env OWFSCAN_CONFIG; default "+defaultConfigHint()+")")
	root.AddCommand(newScanCmd(), newExtractCmd(), newLinksCmd(), newSocialCmd(), newFriendsCmd(), newRelatedCmd(), newObserveCmd(), newReportCmd(), newBatchCmd(), newStatsCmd(), newBotCmd(), newConfigCmd())
	return root
}
