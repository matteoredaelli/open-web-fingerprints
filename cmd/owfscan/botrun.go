// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/batch"
	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/bot"
	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/bot/blocklist"
	"github.com/matteoredaelli/open-web-fingerprints/scan"
	"github.com/matteoredaelli/open-web-fingerprints/scan/client"
)

const maxBotPages = 10 // with --depth 1, as in `batch`

func openBot(cmd *cobra.Command, db string, mustExist bool) (*bot.Store, error) {
	if mustExist {
		if _, err := os.Stat(db); err != nil {
			return nil, err
		}
	}
	return bot.Open(cmd.Context(), db, nil)
}

// loadFilter builds the filter from the downloaded lists. It returns nil when no list is
// enabled; the caller decides whether that is allowed.
func loadFilter(dir string) (*blocklist.Filter, []bot.LoadedList, error) {
	if len(cfg.Bot.Filter.EnabledLists()) == 0 {
		return nil, nil, nil
	}
	return bot.Load(dir, cfg.Bot.Filter)
}

func newBotRunCmd() *cobra.Command {
	var registry, verifyCache, stopFile, filterDir string
	var noFilter, quiet bool
	b := cfg.Bot
	c := &cobra.Command{
		Use:   "run",
		Short: "Scan the frontier: claim domains, scan their home page, add the domains found",
		Long: "run takes the domains that are due, scans each one's home page (--depth 1: also a few linked\n" +
			"pages) and adds the other domains it links to, until nothing is due, the budget or time is\n" +
			"spent, the stop file appears or you press Ctrl-C. It can be stopped at any moment, even with\n" +
			"kill -9, and run again: nothing is lost or scanned twice (a killed run frees its domains when\n" +
			"their lease ends). Domains in flight at a clean stop are given back and done first next time.\n\n" +
			"It makes only GET requests, honours robots.txt (always), waits between requests to one host\n" +
			"(--per-host-delay, or a longer Crawl-delay), limits the total rate, and backs off on 429 and 5xx.\n" +
			"It never sends probes (--active) and stores no contact details. Domains of the block lists are\n" +
			"kept as blocked and never scanned; with no list enabled it refuses to start unless --no-filter.\n" +
			"Every flag is also a key of [bot] in the configuration; a flag wins.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// Flags are checked with the same ceilings as the file.
			eff := cfg
			eff.Bot = b
			if err := eff.Validate(); err != nil {
				return err
			}
			if registry == "" {
				return fmt.Errorf("--registry is required (or env OWFSCAN_REGISTRY)")
			}
			fdir := eff.Bot.Filter.Dir
			if filterDir != "" {
				fdir = filterDir
			}
			flt, lists, err := loadFilter(fdir)
			if err != nil {
				return err
			}
			if flt == nil && !noFilter && eff.Bot.Filter.Require {
				return fmt.Errorf("no block list is enabled, and bot.filter.require is true: enable a [[bot.filter.list]] " +
					"and run `owfscan bot filter refresh`, or pass --no-filter to crawl with no filter")
			}
			ctx := cmd.Context()
			reg, err := client.LoadRegistryCached(registry, stampDir(verifyCache))
			if err != nil {
				return err
			}
			st, err := openBot(cmd, eff.Bot.DB, false)
			if err != nil {
				return err
			}
			defer func() { _ = st.Close() }()
			errw := cmd.ErrOrStderr()
			for _, l := range lists {
				if age := time.Since(l.Note.FetchedAt); !l.Note.FetchedAt.IsZero() && age > eff.Bot.Filter.RefreshEvery.D() {
					fmt.Fprintf(errw, "warning: list %s was downloaded %s ago (bot.filter.refresh_every is %s): run `owfscan bot filter refresh`\n",
						l.Name, age.Round(time.Hour), eff.Bot.Filter.RefreshEvery.D())
				}
			}
			if flt != nil {
				n, err := st.ReapplyFilter(ctx, func(d string) (string, string, bool) {
					v := flt.Check(d)
					return v.List, v.Category, v.Blocked
				})
				if err != nil {
					return err
				}
				if n > 0 {
					fmt.Fprintf(errw, "%d domains are no longer blocked by the lists and go back to the frontier\n", n)
				}
			} else {
				fmt.Fprintln(errw, "warning: running with no filter")
			}

			pool := bot.NewPool(bot.PoolOptions{
				Store: st, Timeout: eff.Fetch.Timeout.D(), UserAgent: eff.Fetch.UserAgent,
				Rate: eff.Bot.Rate, PerHostDelay: eff.Bot.PerHostDelay.D(), MaxCrawlDelay: eff.Crawl.MaxDelay.D(),
			})
			var opt client.Options
			eff.Apply(&opt)
			opt.Version = version()
			opt.Depth, opt.MaxPages = eff.Bot.Depth, min(eff.Crawl.MaxPages, maxBotPages)
			opt.DropHeaders = dropList(false)
			opt.Transport = pool.RoundTripper()
			scanFn := func(ctx context.Context, target string) (*scan.Result, error) {
				res, err := client.Scan(ctx, reg, opt, target)
				if err != nil {
					return nil, err
				}
				if err := client.Validate(res); err != nil {
					return nil, fmt.Errorf("result: %w", err)
				}
				return res, nil
			}
			if stopFile == "" {
				stopFile = eff.Bot.DB + ".stop"
			}
			ro := bot.RunOptions{
				Workers: eff.Bot.Workers, LeaseTTL: eff.Bot.LeaseTTL.D(), Timeout: 2 * eff.Fetch.Timeout.D(),
				Budget: eff.Bot.Budget, Until: eff.Bot.Until.D(),
				MaxNewPerSite: eff.Bot.MaxNewPerSite, MaxDepth: eff.Bot.MaxDepth,
				Revisit: eff.Bot.Revisit.D(), RevisitMax: eff.Bot.RevisitMax.D(), DNSFailures: eff.Bot.DNSFailures, Filter: flt, Scan: scanFn,
				ShouldStop: func() bool { _, err := os.Stat(stopFile); return err == nil },
			}
			if !quiet {
				ro.Progress = func(d, outcome string) { fmt.Fprintf(errw, "%s %s\n", outcome, d) }
			}
			sum, err := bot.Run(ctx, st, ro)
			fmt.Fprintf(errw, "scanned %d, failed %d, blocked %d, given back %d, %d domains found; stopped: %s\n",
				sum.Scanned, sum.Failed, sum.Blocked, sum.Released, sum.Discovered, sum.StopReason)
			return err
		},
	}
	f := c.Flags()
	f.StringVar(&b.DB, "db", b.DB, "SQLite file of the crawl (bot.db)")
	f.StringVar(&registry, "registry", os.Getenv("OWFSCAN_REGISTRY"), "registry export to apply (env OWFSCAN_REGISTRY)")
	f.StringVar(&verifyCache, "verify-cache", "", "where to remember that a registry file was verified (\"off\" verifies every time)")
	f.IntVar(&b.Workers, "workers", b.Workers, "domains scanned at once (bot.workers)")
	f.Float64Var(&b.Rate, "rate", b.Rate, "most requests per second over all hosts (bot.rate)")
	f.DurationVar((*time.Duration)(&b.PerHostDelay), "per-host-delay", b.PerHostDelay.D(), "pause between two requests to one host (bot.per_host_delay)")
	f.IntVar(&b.Budget, "budget", b.Budget, "most domains scanned in this run, 0 for no limit (bot.budget)")
	f.DurationVar((*time.Duration)(&b.Until), "until", b.Until.D(), "stop the run after this long, 0 for no limit (bot.until)")
	f.IntVar(&b.Depth, "depth", b.Depth, "0: home page only; 1: also a few linked pages (bot.depth)")
	f.IntVar(&b.MaxNewPerSite, "max-new-per-site", b.MaxNewPerSite, "most new domains one site adds (bot.max_new_per_site)")
	f.IntVar(&b.MaxDepth, "max-depth", b.MaxDepth, "most hops from a seed (bot.max_depth)")
	f.DurationVar((*time.Duration)(&b.LeaseTTL), "lease-ttl", b.LeaseTTL.D(), "how long a worker keeps a domain (bot.lease_ttl)")
	f.DurationVar((*time.Duration)(&b.Revisit), "revisit", b.Revisit.D(), "time before a domain is scanned again (bot.revisit)")
	f.DurationVar((*time.Duration)(&b.RevisitMax), "revisit-max", b.RevisitMax.D(), "longest time before a domain that does not change is scanned again (bot.revisit_max)")
	f.IntVar(&b.DNSFailures, "dns-failures", b.DNSFailures, "block a domain for good after this many DNS failures in a row, 0 never (bot.dns_failures)")
	f.StringVar(&filterDir, "filter-dir", "", "directory of the downloaded block lists (bot.filter.dir)")
	f.BoolVar(&noFilter, "no-filter", false, "crawl with no block list (explicit: the default is to refuse)")
	f.StringVar(&stopFile, "stop-file", "", "the run stops when this file exists (default: <db>.stop)")
	f.BoolVar(&quiet, "quiet", false, "do not print each domain")
	return c
}

func newBotStatusCmd() *cobra.Command {
	var db string
	var asJSON bool
	b := cfg.Bot
	c := &cobra.Command{
		Use:   "status",
		Short: "Show the frontier: domains per state, what is due, what is blocked, who is running",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			st, err := openBot(cmd, db, true)
			if err != nil {
				return err
			}
			defer func() { _ = st.Close() }()
			s, err := st.Status(cmd.Context())
			if err != nil {
				return err
			}
			if asJSON {
				return printJSON(cmd, s)
			}
			out := cmd.OutOrStdout()
			total := 0
			for _, n := range s.ByState {
				total += n
			}
			fmt.Fprintf(out, "%d domains: %d done, %d pending, %d failed, %d blocked, %d in flight\n", total,
				s.ByState[bot.StateDone], s.ByState[bot.StatePending], s.ByState[bot.StateFailed], s.ByState[bot.StateBlocked], s.ByState[bot.StateLeased])
			fmt.Fprintf(out, "due now: %d", s.Due)
			if !s.NextDue.IsZero() {
				fmt.Fprintf(out, "; next visit: %s", s.NextDue.Format(time.RFC3339))
			}
			fmt.Fprintf(out, "\nhosts in backoff: %d\n", s.InBackoff)
			if len(s.BlockedBy) > 0 {
				keys := make([]string, 0, len(s.BlockedBy))
				for k := range s.BlockedBy {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				fmt.Fprintln(out, "blocked by:")
				for _, k := range keys {
					fmt.Fprintf(out, "  %-20s %d\n", k, s.BlockedBy[k])
				}
			}
			if s.RunLockedBy != "" {
				fmt.Fprintf(out, "running: %s\n", s.RunLockedBy)
			}
			return nil
		},
	}
	c.Flags().StringVar(&db, "db", b.DB, "SQLite file of the crawl (bot.db)")
	c.Flags().BoolVar(&asJSON, "json", false, "write JSON")
	return c
}

func newBotSeedCmd() *cobra.Command {
	var db, source, filterDir string
	b := cfg.Bot
	c := &cobra.Command{
		Use:   "seed <list>",
		Short: "Add the domains of a list to the frontier (one per line, or \"rank,domain\" as Tranco)",
		Long: "Domains already known are left as they are. Domains on a block list are added as blocked.\n" +
			"With no list enabled they are all added: run is where the filter is required.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			f, err := os.Open(args[0]) //nolint:gosec // the user names the file
			if err != nil {
				return err
			}
			sites, skipped, err := batch.ParseList(f)
			_ = f.Close()
			if err != nil {
				return err
			}
			fdir := cfg.Bot.Filter.Dir
			if filterDir != "" {
				fdir = filterDir
			}
			flt, _, err := loadFilter(fdir)
			if err != nil {
				return err
			}
			if source == "" {
				source = "seed:" + filepath.Base(args[0])
			}
			seeds := make([]bot.Seed, 0, len(sites))
			blocked := 0
			for _, s := range sites {
				sd := bot.Seed{Host: s.Domain, Source: source, Rank: s.Rank}
				if flt != nil {
					if v := flt.Check(s.Domain); v.Blocked {
						sd.BlockedList, sd.BlockedReason = v.List, "category "+v.Category
						blocked++
					}
				}
				seeds = append(seeds, sd)
			}
			st, err := openBot(cmd, db, false)
			if err != nil {
				return err
			}
			defer func() { _ = st.Close() }()
			added, err := st.Add(cmd.Context(), seeds)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%d in the list (%d skipped as not host names, %d blocked by the lists): %d new\n", len(sites), skipped, blocked, added)
			return nil
		},
	}
	c.Flags().StringVar(&db, "db", b.DB, "SQLite file of the crawl (bot.db)")
	c.Flags().StringVar(&source, "source", "", "label recorded for these domains (default seed:<file>)")
	c.Flags().StringVar(&filterDir, "filter-dir", "", "directory of the downloaded block lists (bot.filter.dir)")
	return c
}

func newBotExcludeCmd() *cobra.Command {
	var db, note string
	b := cfg.Bot
	c := &cobra.Command{
		Use:   "exclude",
		Short: "Leave domains out on request (their owners asked, or you decided); no refresh lifts it",
	}
	c.PersistentFlags().StringVar(&db, "db", b.DB, "SQLite file of the crawl (bot.db)")
	add := &cobra.Command{
		Use:   "add DOMAIN...",
		Short: "Never scan these domains (a subdomain is reduced to its registrable domain)",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := openBot(cmd, db, false)
			if err != nil {
				return err
			}
			defer func() { _ = st.Close() }()
			for _, d := range args {
				if err := st.Exclude(cmd.Context(), d, note); err != nil {
					return fmt.Errorf("%s: %w", d, err)
				}
				fmt.Fprintf(cmd.OutOrStdout(), "excluded %s\n", d)
			}
			return nil
		},
	}
	add.Flags().StringVar(&note, "note", "", "why (kept with the exclusion)")
	list := &cobra.Command{
		Use: "list", Short: "Show the excluded domains", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			st, err := openBot(cmd, db, true)
			if err != nil {
				return err
			}
			defer func() { _ = st.Close() }()
			ex, err := st.Excluded(cmd.Context())
			if err != nil {
				return err
			}
			for _, e := range ex {
				fmt.Fprintf(cmd.OutOrStdout(), "%s\t%s\t%s\n", e.Domain, e.At.Format("2006-01-02"), strings.TrimSpace(e.Reason))
			}
			return nil
		},
	}
	remove := &cobra.Command{
		Use: "remove DOMAIN...", Short: "Lift an exclusion", Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := openBot(cmd, db, true)
			if err != nil {
				return err
			}
			defer func() { _ = st.Close() }()
			for _, d := range args {
				ok, err := st.Unexclude(cmd.Context(), d)
				if err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%s: %s\n", d, map[bool]string{true: "no longer excluded", false: "was not excluded"}[ok])
			}
			return nil
		},
	}
	c.AddCommand(add, list, remove)
	return c
}
