// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/spf13/cobra"

	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/batch"
	"github.com/matteoredaelli/open-web-fingerprints/scan"
	"github.com/matteoredaelli/open-web-fingerprints/scan/client"
)

const (
	maxBatchWorkers = 32
	maxBatchRate    = 20.0
	maxBatchDepth   = 1
	maxBatchPages   = 10
)

func newBatchCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "batch",
		Short: "Scan a list of sites (home page; with --depth 1 also a few internal pages) into a SQLite file that can be resumed",
		Long: "batch scans the home page of each site of a list and keeps the results in a SQLite file.\n" +
			"It does what `scan` does without extras: --depth is at most 1, and no --friends, --related, --active or\n" +
			"--browser, and the headers that change on every call are left out. A run can be stopped\n" +
			"(Ctrl-C) and resumed: finished sites are not scanned again.",
	}
	c.AddCommand(newBatchRunCmd(), newBatchStatusCmd())
	return c
}

func newBatchRunCmd() *cobra.Command {
	var db, registry, verifyCache string
	var workers, limit, depth, maxPages int
	var rate float64
	var timeout time.Duration
	var retry, noDNS, noFavicon, quiet bool
	c := &cobra.Command{
		Use:   "run <list>",
		Short: "Add the sites of a list to the file and scan those not yet done",
		Long: "The list has one domain per line, or \"rank,domain\" as the Tranco list is written;\n" +
			"blank lines and # comments are ignored. A site is tried as https://domain and, when the\n" +
			"name does not exist, as https://www.domain. Sites are scanned in rank order.\n\n" +
			"Requests go to sites you did not name one by one, so be polite: --rate is the most scans\n" +
			"started per second (at most 20), --workers the most at once (at most 32), and the\n" +
			"scanner identifies itself with its user agent and honours the guards of `scan`. Scan only\n" +
			"what you may scan. The file holds full results, personal contact details found on the\n" +
			"pages included: keep it private; statistics should use aggregates only.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if registry == "" {
				return fmt.Errorf("--registry is required (or env OWFSCAN_REGISTRY)")
			}
			if depth < 0 || depth > maxBatchDepth || maxPages < 1 || maxPages > maxBatchPages {
				return fmt.Errorf("--depth must be 0 to %d and --max-pages 1 to %d", maxBatchDepth, maxBatchPages)
			}
			if workers < 1 || workers > maxBatchWorkers || rate <= 0 || rate > maxBatchRate {
				return fmt.Errorf("--workers must be 1 to %d and --rate above 0 and at most %.0f", maxBatchWorkers, maxBatchRate)
			}
			reg, err := client.LoadRegistryCached(registry, stampDir(verifyCache))
			if err != nil {
				return err
			}
			f, err := os.Open(args[0]) //nolint:gosec // the user names the file
			if err != nil {
				return err
			}
			sites, skipped, err := batch.ParseList(f)
			_ = f.Close()
			if err != nil {
				return err
			}
			ctx := cmd.Context()
			st, err := batch.Open(ctx, db)
			if err != nil {
				return err
			}
			defer func() { _ = st.Close() }()
			added, err := st.Add(ctx, sites)
			if err != nil {
				return err
			}
			for k, v := range map[string]string{"list": args[0], "registry_sha256": reg.Ref().ContentSHA256, "scanner": "owfscan " + version(), "updated": time.Now().UTC().Format(time.RFC3339)} {
				if err := st.SetMeta(ctx, k, v); err != nil {
					return err
				}
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "%d sites in the list (%d new, %d skipped as not host names)\n", len(sites), added, skipped)

			var opt client.Options
			cfg.Apply(&opt)
			opt.Version = version()
			opt.NoFavicon = noFavicon
			opt.Depth, opt.MaxPages = depth, maxPages
			opt.DropHeaders = dropList(false)
			(&netFlags{timeout: cfg.Fetch.Timeout.D(), maxAge: cfg.Fetch.MaxAge.D(), cacheDir: cfg.Fetch.CacheDir}).applyTo(&opt)
			opt.DNS = !noDNS
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
			ropt := batch.Options{Workers: workers, Rate: rate, Timeout: timeout, Limit: limit, RetryFailed: retry}
			if !quiet {
				ropt.Progress = func(done, total int, d, outcome string) {
					fmt.Fprintf(cmd.ErrOrStderr(), "[%d/%d] %s %s\n", done, total, d, outcome)
				}
			}
			sum, err := batch.Run(ctx, st, scanFn, ropt)
			fmt.Fprintf(cmd.ErrOrStderr(), "scanned %d, failed %d, left %d%s\n", sum.Scanned, sum.Failed, sum.Remaining, map[bool]string{true: " (interrupted: run again to resume)"}[sum.Interrupted])
			return err
		},
	}
	c.Flags().StringVar(&db, "db", "batch.db", "SQLite file of the batch")
	c.Flags().StringVar(&registry, "registry", os.Getenv("OWFSCAN_REGISTRY"), "registry export to apply (env OWFSCAN_REGISTRY)")
	c.Flags().StringVar(&verifyCache, "verify-cache", "", "where to remember that a registry file was verified (\"off\" verifies every time)")
	c.Flags().IntVar(&workers, "workers", 4, "sites scanned at once")
	c.Flags().Float64Var(&rate, "rate", 2, "most scans started per second")
	c.Flags().DurationVar(&timeout, "timeout", 60*time.Second, "time allowed to one site, the www. retry included")
	c.Flags().IntVar(&depth, "depth", 0, "0: home page only; 1: also internal pages linked from it (robots.txt honoured)")
	c.Flags().IntVar(&maxPages, "max-pages", 5, "with --depth 1, most pages fetched per site, the home page included (at most 10)")
	c.Flags().IntVar(&limit, "limit", 0, "scan at most this many sites in this run (0: all)")
	c.Flags().BoolVar(&retry, "retry-failed", false, "scan again the sites that failed")
	c.Flags().BoolVar(&noDNS, "no-dns", false, "do not look up DNS records")
	c.Flags().BoolVar(&noFavicon, "no-favicon", false, "do not fetch the favicon")
	c.Flags().BoolVar(&quiet, "quiet", false, "do not print each site")
	return c
}

func newBatchStatusCmd() *cobra.Command {
	var db string
	c := &cobra.Command{
		Use:   "status",
		Short: "Show how far a batch is, with the reasons of the failures",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, err := os.Stat(db); err != nil {
				return err
			}
			st, err := batch.Open(cmd.Context(), db)
			if err != nil {
				return err
			}
			defer func() { _ = st.Close() }()
			c, err := st.Counts(cmd.Context())
			if err != nil {
				return err
			}
			meta, _ := st.Meta(cmd.Context())
			out := cmd.OutOrStdout()
			fmt.Fprintln(out, c.Describe())
			for _, k := range []string{"list", "registry_sha256", "scanner", "updated"} {
				if meta[k] != "" {
					fmt.Fprintf(out, "  %s: %s\n", k, meta[k])
				}
			}
			if len(c.ByStatus) > 0 {
				fmt.Fprintln(out, "HTTP status of the sites scanned:")
				keys := make([]int, 0, len(c.ByStatus))
				for k := range c.ByStatus {
					keys = append(keys, k)
				}
				sort.Ints(keys)
				for _, k := range keys {
					fmt.Fprintf(out, "  %d  %d\n", k, c.ByStatus[k])
				}
			}
			if len(c.ByError) > 0 {
				fmt.Fprintln(out, "Failures:")
				keys := make([]string, 0, len(c.ByError))
				for k := range c.ByError {
					keys = append(keys, k)
				}
				sort.Slice(keys, func(i, j int) bool { return c.ByError[keys[i]] > c.ByError[keys[j]] })
				for _, k := range keys {
					fmt.Fprintf(out, "  %3d  %s\n", c.ByError[k], k)
				}
			}
			return nil
		},
	}
	c.Flags().StringVar(&db, "db", "batch.db", "SQLite file of the batch")
	return c
}
