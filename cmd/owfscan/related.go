// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"fmt"
	"net/url"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/scanner"
	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/web"
	"github.com/matteoredaelli/open-web-fingerprints/scan"
)

const relatedNotice = "\nA related domain is one that the home page links to, declares as another-language version\n" +
	"(hreflang) or names in its TLS certificate. Each is then compared with the target: the\n" +
	"organization in the certificate, ownership tokens in meta tags (Google, Bing, Facebook ...), Tag\n" +
	"Manager and Analytics identifiers, and links or alternates pointing back. At least one of the\n" +
	"strong signals makes it \"probable\". It says what two sites have in common, never who owns them.\n" +
	"Each candidate costs one request (plus robots.txt) to a site you did not name: robots.txt is\n" +
	"always honoured, there is a pause between requests (--delay) and at most --related-max sites\n" +
	"are contacted. Social platforms are not candidates."

func newRelatedCmd() *cobra.Command {
	n := &netFlags{}
	var max int
	c := &cobra.Command{
		Use:   "related <url>",
		Short: "Find domains that may belong to the same owner, with the evidence for each",
		Long:  "related reads a home page and looks for domains that may belong to the same owner." + relatedNotice + netNotice,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			n.depth = 0
			o := n.crawlOptions(true, false)
			cr, err := scanner.Crawl(cmd.Context(), o, args[0])
			if err != nil {
				return err
			}
			u, err := url.Parse(cr.Main.Page.FinalURL)
			if err != nil {
				return err
			}
			ex := web.Extract([]web.Page{{URL: cr.Main.Page.FinalURL, Body: cr.Main.HTML}}, u.Hostname())
			r := scanner.FindRelated(cmd.Context(), scanner.RelatedOptions{Fetch: o.Fetch, Max: max, Delay: n.delay}, scanner.HomeInfo{
				Domain: web.RegistrableDomain(u.Hostname()), URL: cr.Main.Page.FinalURL, HTML: cr.Main.HTML, Links: ex.Links, TLS: cr.Main.Host.TLS,
			})
			if n.asJSON {
				return printJSON(cmd, map[string]any{"target": cr.Main.Page.FinalURL, "related": r})
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s\n", cr.Main.Page.FinalURL)
			printRelated(cmd, r)
			return nil
		},
	}
	n.add(c)
	c.Flags().DurationVar(&n.delay, "delay", scanner.DefaultDelay, "pause before each request to another site")
	c.Flags().IntVar(&max, "related-max", scanner.DefaultMaxRelated, "most candidate domains to read")
	return c
}

func printRelated(cmd *cobra.Command, r *scan.Related) {
	out := cmd.OutOrStdout()
	var probable int
	for _, d := range r.Domains {
		if d.Level == scan.RelatedProbable {
			probable++
		}
	}
	fmt.Fprintf(out, "\nRELATED DOMAINS (%d probable of %d candidates, %d read)\n", probable, r.Candidates, r.Checked)
	if len(r.Domains) == 0 {
		fmt.Fprintln(out, "  none found")
		return
	}
	w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "DOMAIN\tLEVEL\tSTATUS\tEVIDENCE")
	for _, d := range r.Domains {
		var ev []string
		for _, e := range d.Evidence {
			s := e.Kind
			if e.Strength == "strong" {
				s += "*"
			}
			ev = append(ev, s)
		}
		note := strings.Join(ev, ", ")
		if d.Detail != "" {
			note += " (" + d.Detail + ")"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", d.Domain, d.Level, d.Status, note)
	}
	_ = w.Flush()
	fmt.Fprintln(out, "  * strong signal")
}
