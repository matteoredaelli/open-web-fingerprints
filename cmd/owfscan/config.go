// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/config"
)

func defaultConfigHint() string {
	if p, err := config.DefaultPath(); err == nil {
		return p
	}
	return "$HOME/.config/owf/" + config.FileName
}

func newConfigCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "config",
		Short: "Create, show and locate the configuration file (limits and default lists)",
		Long: "The configuration file sets the limits and lists owfscan uses: timeouts, the most\n" +
			"pages, friends, related domains and probes, the browser's limits, the TLDs to try. It\n" +
			"is TOML, by default " + defaultConfigHint() + " ($XDG_CONFIG_HOME/owf when that is set).\n" +
			"Flags override it; it overrides the built-in values.\n\n" +
			"It does not turn on --browser, --friends, --related or --active, and it cannot lift\n" +
			"--allow-private, --insecure or --ignore-robots: those are asked for in each run.",
	}
	c.AddCommand(newConfigInitCmd(), newConfigShowCmd(), newConfigPathCmd())
	return c
}

func newConfigInitCmd() *cobra.Command {
	var out string
	var force, stdout bool
	c := &cobra.Command{
		Use:   "init",
		Short: "Write a configuration file with every default and a comment for each value",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if stdout {
				return config.Write(cmd.OutOrStdout(), config.Default())
			}
			path := out
			if path == "" {
				p, err := config.DefaultPath()
				if err != nil {
					return err
				}
				path = p
			}
			flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL
			if force {
				flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
			}
			if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
				return err
			}
			f, err := os.OpenFile(path, flags, 0o600) //nolint:gosec // the user names the file
			if err != nil {
				if os.IsExist(err) {
					return fmt.Errorf("%s exists; use --force to overwrite it, or --stdout to print the defaults", path)
				}
				return err
			}
			if err := config.Write(f, config.Default()); err != nil {
				_ = f.Close()
				return err
			}
			if err := f.Close(); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "wrote %s\n", path)
			return nil
		},
	}
	c.Flags().StringVarP(&out, "output", "o", "", "where to write it (default "+defaultConfigHint()+")")
	c.Flags().BoolVar(&force, "force", false, "overwrite an existing file")
	c.Flags().BoolVar(&stdout, "stdout", false, "print the defaults instead of writing a file")
	return c
}

func newConfigShowCmd() *cobra.Command {
	var ceilings bool
	c := &cobra.Command{
		Use:   "show",
		Short: "Show the configuration in force and where it comes from",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if cfgErr != nil {
				return cfgErr
			}
			out := cmd.OutOrStdout()
			if cfgPath == "" {
				fmt.Fprintln(out, "# built-in values (no configuration file; `owfscan config init` writes one)")
			} else {
				fmt.Fprintf(out, "# read from %s\n", cfgPath)
			}
			if err := config.Write(out, cfg); err != nil {
				return err
			}
			if ceilings {
				fmt.Fprintln(out, "\n# the largest value each setting may have")
				for _, c := range config.Ceilings() {
					fmt.Fprintf(out, "#   %-38s %s\n", c[0], c[1])
				}
			}
			return nil
		},
	}
	c.Flags().BoolVar(&ceilings, "ceilings", false, "also list the largest value each setting may have")
	return c
}

func newConfigPathCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "path",
		Short: "Print the configuration file in use, or the one that would be",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if cfgPath != "" {
				fmt.Fprintln(cmd.OutOrStdout(), cfgPath)
				return nil
			}
			if p, _ := cmd.Flags().GetString("config"); p != "" {
				fmt.Fprintln(cmd.OutOrStdout(), p)
				return nil
			}
			if p := configArg(os.Args[1:]); p != "" {
				fmt.Fprintln(cmd.OutOrStdout(), p)
				return nil
			}
			p, err := config.DefaultPath()
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s (does not exist: built-in values are used)\n", p)
			return nil
		},
	}
}
