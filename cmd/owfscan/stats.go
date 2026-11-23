// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/batch"
	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/stats"
	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/statspage"
	"github.com/matteoredaelli/open-web-fingerprints/scan"
	"github.com/matteoredaelli/open-web-fingerprints/schemas"
)

func newStatsCmd() *cobra.Command {
	var db, out, exclude, htmlOut, title string
	var includeGeneric bool
	var minConf float64
	var minSites, top int
	var asJSON bool
	c := &cobra.Command{
		Use:   "stats",
		Short: "Aggregate a batch into statistics (no site-level data)",
		Long: "stats reads the SQLite file of `owfscan batch run` and writes aggregates: how many sites\n" +
			"show each technology, category and header, certificate lifetimes, pairs of technologies\n" +
			"seen together. Shares are of the sites reached (home page answered 2xx) and mean\n" +
			"\"detected on the home page\". Technologies seen only in DNS records are listed apart as\n" +
			"domain signals. Anything seen on fewer than --min-sites sites is counted, not named.\n" +
			"No address, handle or contact of a site is in the output, which follows the stats schema.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, err := os.Stat(db); err != nil {
				return err
			}
			if minConf < 0 || minConf > 1 || minSites < 1 || top < 1 {
				return fmt.Errorf("--min-confidence is 0 to 1, --min-sites and --top at least 1")
			}
			st, err := batch.Open(cmd.Context(), db)
			if err != nil {
				return err
			}
			defer func() { _ = st.Close() }()
			var ex []string
			for _, e := range strings.Split(exclude, ",") {
				if e = strings.TrimSpace(e); e != "" {
					ex = append(ex, e)
				}
			}
			s, err := stats.Compute(cmd.Context(), st, stats.Options{MinConfidence: minConf, MinSites: minSites, Exclude: ex, IncludeGeneric: includeGeneric, Top: top})
			if err != nil {
				return err
			}
			b, err := json.MarshalIndent(s, "", "  ")
			if err != nil {
				return err
			}
			if err := schemas.ValidateStats(b); err != nil {
				return fmt.Errorf("internal error: the statistics do not satisfy their schema: %w", err)
			}
			if out != "" {
				if err := os.WriteFile(out, append(b, '\n'), 0o644); err != nil { //nolint:gosec // aggregates are meant to be shared
					return err
				}
				fmt.Fprintf(cmd.ErrOrStderr(), "wrote %s\n", out)
			}
			if htmlOut != "" {
				var buf bytes.Buffer
				if err := statspage.Render(&buf, s, statspage.Options{Title: title}); err != nil {
					return err
				}
				if err := os.WriteFile(htmlOut, buf.Bytes(), 0o644); err != nil { //nolint:gosec // a page is meant to be shared
					return err
				}
				fmt.Fprintf(cmd.ErrOrStderr(), "wrote %s\n", htmlOut)
			}
			if asJSON {
				_, err := fmt.Fprintln(cmd.OutOrStdout(), string(b))
				return err
			}
			printStats(cmd, s)
			return nil
		},
	}
	c.Flags().StringVar(&db, "db", "batch.db", "SQLite file of the batch")
	c.Flags().StringVarP(&out, "output", "o", "", "also write the statistics (JSON) to this file")
	c.Flags().Float64Var(&minConf, "min-confidence", 0, "leave out technologies whose confidence is lower")
	c.Flags().IntVar(&minSites, "min-sites", 3, "name a technology only when at least this many sites show it")
	c.Flags().BoolVar(&includeGeneric, "include-generic", false, "also count technologies the registry marks as generic signals (left out by default)")
	c.Flags().StringVar(&exclude, "exclude", "", "comma-separated technology names to leave out (rules known to be unreliable)")
	c.Flags().IntVar(&top, "top", 30, "length of the lists")
	c.Flags().StringVar(&htmlOut, "html", "", "also write a static HTML summary page (no script, aggregates only) to this file")
	c.Flags().StringVar(&title, "title", "", "title of the HTML page")
	c.Flags().BoolVar(&asJSON, "json", false, "print the JSON instead of the summary")
	return c
}

func pct(f float64) string { return fmt.Sprintf("%5.1f%%", f*100) }

func printStats(cmd *cobra.Command, s *scan.Stats) {
	o := cmd.OutOrStdout()
	fmt.Fprintf(o, "%d listed, %d scanned, %d reached (2xx), %d failed, %d pending\n", s.Sites.Listed, s.Sites.Scanned, s.Sites.Reached, s.Sites.Failed, s.Sites.Pending)
	fmt.Fprintf(o, "technologies per site: median %d, mean %.1f, none on %d; rules applied %.1f%% on average\n\n", s.Coverage.MedianTechs, s.Coverage.MeanTechs, s.Coverage.SitesWithNone, s.Coverage.MeanPercent)
	w := tabwriter.NewWriter(o, 0, 4, 2, ' ', 0)
	section := func(title string, l []scan.StatCount, n int) {
		fmt.Fprintf(w, "%s\tSITES\tSHARE\n", title)
		for i, c := range l {
			if i == n {
				break
			}
			fmt.Fprintf(w, "  %s\t%d\t%s\n", c.Name, c.Sites, pct(c.Share))
		}
		fmt.Fprintln(w)
	}
	var tl []scan.StatCount
	for _, t := range s.Technologies {
		tl = append(tl, scan.StatCount{Name: t.Name, Sites: t.Sites, Share: t.Share})
	}
	section("WEB TECHNOLOGIES", tl, 15)
	var dl []scan.StatCount
	for _, t := range s.DomainSignals {
		dl = append(dl, scan.StatCount{Name: t.Name, Sites: t.Sites, Share: t.Share})
	}
	section("DOMAIN SIGNALS (DNS only)", dl, 8)
	section("CATEGORIES", s.Categories, 10)
	section("HEADERS ON THE HOME PAGE", s.Headers, 6)
	section("CERTIFICATE TIME LEFT", s.TLS.DaysLeft, 5)
	_ = w.Flush()
	fmt.Fprintf(o, "%d technologies seen on fewer than %d sites are not named\n", s.Other.TechnologiesHidden, s.Filters.MinSites)
}
