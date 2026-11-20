// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"fmt"
	"os"
	"runtime/debug"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/engine"
	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/fetch"
	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/observe"
	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/scanner"
	"github.com/matteoredaelli/open-web-fingerprints/scan"
)

func version() string {
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			if s.Key == "vcs.revision" && len(s.Value) >= 12 {
				return s.Value[:12]
			}
		}
	}
	return "dev"
}

func newScanCmd() *cobra.Command {
	n := &netFlags{}
	var registry, minHealth string
	var noDNS, noFavicon, verbose bool
	c := &cobra.Command{
		Use:   "scan <url>",
		Short: "Scan a site: technologies with their evidence, links, domains, social profiles, contacts",
		Long: "scan fetches a page and applies the rules of a registry export (written by\n" +
			"`owf export`) to it, and also lists its links, linked domains, social profiles and\n" +
			"contact details. Each technology comes with the rules that matched, the health of\n" +
			"each rule (most are 'unknown': they have no tests) and their sources. The result also\n" +
			"says how many rules could not be applied and why (a browser would be needed, probes\n" +
			"are not run, ...). Nothing is executed: only what a plain request shows is seen.\n\n" +
			"The export is checked against its manifest before use. If it contains data whose\n" +
			"redistribution is unreviewed, the result repeats the export's notice." + netNotice,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if registry == "" {
				return fmt.Errorf("--registry is required: the export written by `owf export` (or env OWFSCAN_REGISTRY)")
			}
			if minHealth != "" && !engine.ValidHealth(minHealth) {
				return fmt.Errorf("--min-health must be broken, degraded, unknown or ok")
			}
			reg, err := scanner.LoadRegistry(registry)
			if err != nil {
				return err
			}
			opt := scanner.Options{
				Registry: reg, NoFavicon: noFavicon, MinHealth: minHealth, Version: version(),
				Fetch: fetch.Options{Timeout: n.timeout, AllowPrivate: n.allowPrivate, Insecure: n.insecure, CacheDir: n.cacheDir, MaxAge: n.maxAge},
			}
			if !noDNS {
				opt.Resolver = observe.SystemResolver{}
			}
			res, err := scanner.Scan(cmd.Context(), opt, args[0])
			if err != nil {
				return err
			}
			if err := scanner.Validate(res); err != nil {
				return fmt.Errorf("internal error: the result does not satisfy its schema: %w", err)
			}
			if n.asJSON {
				return printJSON(cmd, res)
			}
			printScan(cmd, res, verbose)
			return nil
		},
	}
	n.add(c)
	c.Flags().StringVar(&registry, "registry", os.Getenv("OWFSCAN_REGISTRY"), "registry export to apply (env OWFSCAN_REGISTRY)")
	c.Flags().StringVar(&minHealth, "min-health", "", "use only rules at least this healthy: broken (all, default), degraded, unknown, ok")
	c.Flags().BoolVar(&noDNS, "no-dns", false, "do not look up DNS records")
	c.Flags().BoolVar(&noFavicon, "no-favicon", false, "do not fetch the favicon")
	c.Flags().BoolVarP(&verbose, "evidence", "e", false, "list the matching rules of each technology")
	return c
}

var healthOrder = map[string]int{"broken": 0, "degraded": 1, "unknown": 2, "ok": 3}

func printScan(cmd *cobra.Command, r *scan.Result, verbose bool) {
	out := cmd.OutOrStdout()
	p := r.Pages[0]
	fmt.Fprintf(out, "%s  (%d, %d ms%s)\n", r.Target.URL, p.Status, p.DurationMS, map[bool]string{true: ", cached"}[p.Cached])
	short := r.Registry.ContentSHA256
	if len(short) > 19 {
		short = short[:19]
	}
	fmt.Fprintf(out, "registry %s: %s\n", short, strings.Join(r.Registry.Sources, ", "))
	if r.Registry.Notice != "" {
		fmt.Fprintf(out, "NOTICE: %s\n", r.Registry.Notice)
	}

	fmt.Fprintf(out, "\nTECHNOLOGIES (%d)\n", len(r.Technologies))
	w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tVERSION\tCONFIDENCE\tBEST HEALTH\tRULES\tSOURCES")
	for _, t := range r.Technologies {
		best := "broken"
		for _, e := range t.Evidence {
			if healthOrder[e.Health] >= healthOrder[best] {
				best = e.Health
			}
		}
		fmt.Fprintf(w, "%s\t%s\t%.2f\t%s\t%d\t%s\n", t.Name, t.Version, t.Confidence, best, len(t.Evidence), strings.Join(t.Sources, ","))
		if verbose {
			for _, e := range t.Evidence {
				g := ""
				if e.Group != "" {
					g = " [group]"
				}
				fmt.Fprintf(w, "  %s %s\t%s\t\t%s\t\t%q%s\n", e.Observation, e.Target, e.Version, e.Health, e.Matched, g)
			}
		}
	}
	_ = w.Flush()

	fmt.Fprintf(out, "\nLINKS: %d to %d domains", len(r.Links), len(r.Domains))
	for i, d := range r.Domains {
		if i == 0 {
			fmt.Fprint(out, " (")
		}
		if i >= 6 {
			fmt.Fprintf(out, ", ... %d more", len(r.Domains)-6)
			break
		}
		if i > 0 {
			fmt.Fprint(out, ", ")
		}
		fmt.Fprintf(out, "%s %d", d.Domain, d.Links)
	}
	if len(r.Domains) > 0 {
		fmt.Fprint(out, ")")
	}
	fmt.Fprintln(out)
	w = tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "\nSOCIAL\tKIND\tHANDLE")
	for _, s := range r.Socials {
		fmt.Fprintf(w, "%s\t%s\t%s\n", s.Platform, s.Kind, s.Handle)
	}
	fmt.Fprintln(w, "\nCONTACT\tVALUE")
	for _, c := range r.Contacts {
		fmt.Fprintf(w, "%s\t%s\n", c.Kind, c.Value)
	}
	_ = w.Flush()

	c := r.Coverage
	fmt.Fprintf(out, "\nCOVERAGE: %d of %d rules evaluated, %d could not be", c.RulesEvaluated, c.RulesTotal, c.RulesUnsupported)
	keys := make([]string, 0, len(c.Skipped))
	for k := range c.Skipped {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return c.Skipped[keys[i]] > c.Skipped[keys[j]] })
	for i, k := range keys {
		sep := ": "
		if i > 0 {
			sep = ", "
		}
		fmt.Fprintf(out, "%s%s %d", sep, k, c.Skipped[k])
	}
	fmt.Fprintln(out)
	printWarnings(cmd, r.Warnings)
}
