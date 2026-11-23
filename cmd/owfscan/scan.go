// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/matteoredaelli/open-web-fingerprints/scan"
	"github.com/matteoredaelli/open-web-fingerprints/scan/client"
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
	var registry, minHealth, verifyCache string
	var friends, related, useBrowser, active bool
	var tf tldFlags
	var activeMax, relatedMax int
	var chrome string
	var browserTimeout time.Duration
	var friendsMax int
	var noDNS, noFavicon, verbose, allHeaders bool
	var htmlOut string
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
			if minHealth != "" && !client.ValidHealth(minHealth) {
				return fmt.Errorf("--min-health must be broken, degraded, unknown or ok")
			}
			reg, err := client.LoadRegistryCached(registry, stampDir(verifyCache))
			if err != nil {
				return err
			}
			var opt client.Options
			cfg.Apply(&opt) // the limits without a flag; the flags below override the rest
			opt.NoFavicon, opt.MinHealth, opt.Version = noFavicon, minHealth, version()
			opt.Depth, opt.MaxPages, opt.Delay, opt.IgnoreRobots = n.depth, n.maxPages, n.delay, n.ignoreRobots
			opt.Friends, opt.FriendsMax = friends, friendsMax
			tlds, err := tf.tlds()
			if err != nil {
				return err
			}
			opt.Related, opt.RelatedMax, opt.RelatedTLDs = related, relatedMax, tlds
			opt.Active, opt.ActiveMax = active, activeMax
			opt.Browser, opt.BrowserPath, opt.BrowserTimeout = useBrowser, chrome, browserTimeout
			n.applyTo(&opt)
			opt.DropHeaders = dropList(allHeaders)
			opt.DNS = !noDNS
			if len(tlds) > 0 && !related {
				return fmt.Errorf("--related-tlds needs --related")
			}
			if len(tlds) > 0 && noDNS {
				return fmt.Errorf("--related-tlds looks names up in DNS: it cannot be used with --no-dns")
			}
			res, err := client.Scan(cmd.Context(), reg, opt, args[0])
			if err != nil {
				return err
			}
			if err := client.Validate(res); err != nil {
				return fmt.Errorf("internal error: the result does not satisfy its schema: %w", err)
			}
			if htmlOut == "-" {
				return fmt.Errorf("--html needs a file name; use `owfscan report result.json -o -` to print the page")
			}
			if htmlOut != "" {
				if err := writeReport(cmd, res, htmlOut, ""); err != nil {
					return err
				}
			}
			if n.asJSON {
				return printJSON(cmd, res)
			}
			printScan(cmd, res, verbose)
			return nil
		},
	}
	n.add(c)
	n.addCrawl(c)
	c.Flags().BoolVar(&friends, "friends", false, "also look for friend domains: linked from the home page and linking back to it (contacts other sites; see `owfscan friends --help`)")
	c.Flags().BoolVar(&related, "related", false, "also look for domains that may belong to the same owner, with the evidence (contacts other sites; see `owfscan related --help`)")
	tf.add(c)
	c.Flags().IntVar(&relatedMax, "related-max", cfg.Related.Max, "most candidate domains to read with --related")
	c.Flags().BoolVar(&active, "active", false, "also send the probes a reviewer approved (GET to fixed paths of the site, robots.txt honoured; see `owf probe --help`)")
	c.Flags().IntVar(&activeMax, "active-max", cfg.Active.Max, "most probe requests to send with --active")
	c.Flags().BoolVar(&useBrowser, "browser", false, "also open the first page in headless Chrome, to see global variables, XHR calls and the DOM after scripts ran (runs the page's JavaScript; see docs/owfscan.md)")
	c.Flags().StringVar(&chrome, "chrome", envOr("OWFSCAN_CHROME", cfg.Browser.ChromePath), "Chrome or Chromium executable for --browser (env OWFSCAN_CHROME; default: the usual places)")
	c.Flags().DurationVar(&browserTimeout, "browser-timeout", cfg.Browser.Timeout.D(), "time allowed to the browser for the page")
	c.Flags().IntVar(&friendsMax, "friends-max", cfg.Friends.Max, "most candidate domains to look at with --friends")
	c.Flags().StringVar(&verifyCache, "verify-cache", "", "where to remember that a registry file was verified (default: the user cache directory; \"off\" verifies every time)")
	c.Flags().StringVar(&registry, "registry", os.Getenv("OWFSCAN_REGISTRY"), "registry export to apply (env OWFSCAN_REGISTRY)")
	c.Flags().StringVar(&minHealth, "min-health", "", "use only rules at least this healthy: broken (all, default), degraded, unknown, ok")
	c.Flags().BoolVar(&noDNS, "no-dns", false, "do not look up DNS records")
	c.Flags().BoolVar(&noFavicon, "no-favicon", false, "do not fetch the favicon")
	c.Flags().StringVar(&htmlOut, "html", "", "also write an HTML report to this file (\"-\" is not allowed here; see `owfscan report`)")
	c.Flags().BoolVar(&allHeaders, "all-headers", false, "keep the response headers that change on every call (date, request ids, cache state, ...) in the pages of the result")
	c.Flags().BoolVarP(&verbose, "evidence", "e", false, "list the matching rules of each technology")
	return c
}

var healthOrder = map[string]int{"broken": 0, "degraded": 1, "unknown": 2, "ok": 3}

func printScan(cmd *cobra.Command, r *scan.Result, verbose bool) {
	out := cmd.OutOrStdout()
	p := r.Pages[0]
	fmt.Fprintf(out, "%s  (%d, %d ms%s)", r.Target.URL, p.Status, p.DurationMS, map[bool]string{true: ", cached"}[p.Cached])
	if len(r.Pages) > 1 {
		fmt.Fprintf(out, " + %d more page(s)", len(r.Pages)-1)
	}
	fmt.Fprintln(out)
	short := r.Registry.ContentSHA256
	if len(short) > 19 {
		short = short[:19]
	}
	fmt.Fprintf(out, "registry %s: %s\n", short, strings.Join(r.Registry.Sources, ", "))
	if r.Registry.Notice != "" {
		fmt.Fprintf(out, "NOTICE: %s\n", r.Registry.Notice)
	}

	if len(r.Pages) > 1 {
		fmt.Fprintln(out, "pages read:")
		for _, pg := range r.Pages {
			fmt.Fprintf(out, "  %d  %s\n", pg.Status, pg.FinalURL)
		}
	}
	if len(r.DomainSignals) > 0 {
		names := make([]string, len(r.DomainSignals))
		for i, t := range r.DomainSignals {
			names[i] = t.Name
		}
		fmt.Fprintf(out, "\nDOMAIN SIGNALS (%d, DNS records only): %s\n", len(names), strings.Join(names, ", "))
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
	if len(r.Implied) > 0 {
		fmt.Fprintf(out, "\nIMPLIED (%d): not matched on this site, but they follow from what was found\n", len(r.Implied))
		for _, im := range r.Implied {
			fmt.Fprintf(out, "  %s (confidence %.2f): implied by %s\n", im.Name, im.Confidence, strings.Join(im.ImpliedBy, ", "))
		}
	}
	if len(r.Suppressed) > 0 {
		fmt.Fprintf(out, "\nNOT REPORTED (%d): matched, but the registry says otherwise\n", len(r.Suppressed))
		for _, s := range r.Suppressed {
			why := "excluded by "
			if s.Reason == scan.SuppressedRequirement {
				why = "needs one of "
			}
			fmt.Fprintf(out, "  %s (confidence %.2f): %s%s\n", s.Name, s.Confidence, why, strings.Join(s.By, ", "))
		}
	}
	if r.Related != nil {
		printRelated(cmd, r.Related)
	}
	if a := r.Active; a != nil {
		fmt.Fprintf(out, "\nPROBES: %d approved, %d sent, %d failed, %d not sent (%d disallowed by robots.txt, %d refused)\n", a.Approved, a.Sent, a.Failed, a.NotSent, a.Disallowed, a.Refused)
	}
	if r.Browser != nil {
		b := r.Browser
		fmt.Fprintf(out, "\nBROWSER: %s, %d requests (%d refused), %d global variables found%s\n", b.Version, b.Requests, b.Blocked, b.Globals, map[bool]string{true: ", timed out"}[b.TimedOut])
	}
	if r.Friends != nil {
		printFriends(cmd, r.Friends)
	}

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

// stampDir is where verification stamps go: the flag, else the user cache directory.
func stampDir(flag string) string {
	switch flag {
	case "off":
		return ""
	case "":
		d, err := os.UserCacheDir()
		if err != nil {
			return ""
		}
		return filepath.Join(d, "owfscan", "verified")
	}
	return flag
}
