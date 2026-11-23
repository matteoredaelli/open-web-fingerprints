// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"fmt"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/bot"
)

func newBotCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "bot",
		Short: "The crawler: a frontier of domains kept in SQLite, with a block-list filter",
		Long: "bot is the crawler (work in progress: see TODO.md): `seed` fills the frontier, `run` scans it,\n" +
			"`status` shows it, `exclude` leaves a domain out, `filter` manages the block lists.\n" +
			"It reads home pages only (depth 0 or 1), makes only\n" +
			"GETs and honours robots.txt; none of that is a setting.",
	}
	c.AddCommand(newBotRunCmd(), newBotStatusCmd(), newBotSeedCmd(), newBotExcludeCmd(), newBotFilterCmd())
	return c
}

func newBotFilterCmd() *cobra.Command {
	var dir string
	c := &cobra.Command{
		Use:   "filter",
		Short: "Download, list and check the block lists",
		Long: "Block lists are chosen by you in the configuration ([[bot.filter.list]]); none is shipped,\n" +
			"because their licences differ: check each one. A list is a hint about names: it has false\n" +
			"positives and negatives and is no guarantee about the content of a site.",
	}
	c.PersistentFlags().StringVar(&dir, "dir", "", "directory of the downloaded lists (default: bot.filter.dir)")
	filterDir := func() string {
		if dir != "" {
			return dir
		}
		return cfg.Bot.Filter.Dir
	}

	refresh := &cobra.Command{
		Use:   "refresh",
		Short: "Download the enabled lists (needs the network); fails when no list is enabled",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			res, err := bot.Refresh(cmd.Context(), filterDir(), cfg.Bot.Filter.EnabledLists(), nil, nil)
			if err != nil {
				return err
			}
			failed := 0
			for _, r := range res {
				if r.Err != nil {
					failed++
					fmt.Fprintf(cmd.ErrOrStderr(), "%s: FAILED: %v\n", r.Name, r.Err)
					continue
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%s: %d blocked, %d exceptions, %d bytes%s\n", r.Name,
					r.Note.Blocked, r.Note.Allowed, r.Note.Bytes, skippedText(r.Note.Skipped))
			}
			if failed > 0 {
				return fmt.Errorf("%d of %d lists failed (a failed list keeps its previous copy)", failed, len(res))
			}
			return nil
		},
	}

	list := &cobra.Command{
		Use:   "list",
		Short: "Show the configured lists and their downloaded copies",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "NAME\tCATEGORY\tFORMAT\tENABLED\tBLOCKED\tFETCHED\tBLOCKS")
			for _, l := range cfg.Bot.Filter.Lists {
				one := cfg.Bot.Filter
				one.Lists = nil
				one.Lists = append(one.Lists, l)
				one.Lists[0].Enabled = true
				_, loaded, err := bot.Load(filterDir(), one)
				blocked, fetched := "-", "no copy"
				if err == nil && len(loaded) == 1 {
					blocked, fetched = fmt.Sprint(loaded[0].Note.Blocked), loaded[0].Note.FetchedAt.Format("2006-01-02")
				}
				acts := "no"
				for _, c := range cfg.Bot.Filter.ExcludeCategories {
					if c == l.Category {
						acts = "yes"
					}
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%v\t%s\t%s\t%s\n", l.Name, l.Category, l.Format, l.Enabled, blocked, fetched, acts)
			}
			return tw.Flush()
		},
	}

	check := &cobra.Command{
		Use:   "check DOMAIN...",
		Short: "Say whether domains are blocked, and by which list",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			flt, loaded, err := bot.Load(filterDir(), cfg.Bot.Filter)
			if err != nil {
				return err
			}
			if len(loaded) == 0 {
				return fmt.Errorf("no filter list is enabled (see [[bot.filter.list]] in the configuration)")
			}
			for _, d := range args {
				v := flt.Check(d)
				if v.Blocked {
					fmt.Fprintf(cmd.OutOrStdout(), "blocked  %s  list=%s category=%s entry=%s\n", d, v.List, v.Category, v.Entry)
				} else {
					fmt.Fprintf(cmd.OutOrStdout(), "allowed  %s\n", d)
				}
			}
			return nil
		},
	}
	c.AddCommand(refresh, list, check)
	return c
}

func skippedText(m map[string]int) string {
	if len(m) == 0 {
		return ""
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = fmt.Sprintf("%s %d", k, m[k])
	}
	return "; skipped: " + strings.Join(parts, ", ")
}
