// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"fmt"
	"net/url"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/observe"
	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/scanner"
	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/web"
	"github.com/matteoredaelli/open-web-fingerprints/scan"
)

const relatedNotice = "\nA related domain is one that the home page links to, declares as another-language version\n" +
	"(hreflang) or names in its TLS certificate. Each is then compared with the target: the\n" +
	"organization in the certificate, ownership tokens in meta tags (Google, Bing, Facebook ...), Tag\n" +
	"Manager and Analytics identifiers, and links or alternates pointing back. At least one of the\n" +
	"strong signals makes it \"probable\". It says what two sites have in common, never who owns them.\n" +
	"With --related-tlds the target's name is also tried under other TLDs (michelin.com -> michelin.it ...): a DNS\n" +
	"lookup for each, and a read of the home page of those that exist. Nobody pointed to those names, so it is an\n" +
	"option. Each candidate costs one request (plus robots.txt) to a site you did not name: robots.txt is\n" +
	"always honoured, there is a pause between requests (--delay) and at most --related-max sites\n" +
	"are contacted. Social platforms are not candidates."

// tldFlags are the options that make the search try the target's name under other TLDs.
type tldFlags struct {
	on   bool
	list string
}

func (t *tldFlags) add(c *cobra.Command) {
	c.Flags().BoolVar(&t.on, "related-tlds", false, "also try the target's name under other TLDs ("+strings.Join(scanner.DefaultRelatedTLDs, ", ")+"): looks the names up in DNS and reads the home page of those that exist")
	c.Flags().StringVar(&t.list, "related-tlds-list", "", "comma-separated TLDs to try instead of the default list (implies --related-tlds)")
}

// tlds returns the TLDs to try, nil when the option is off.
func (t *tldFlags) tlds() []string {
	if t.list != "" {
		var out []string
		for _, s := range strings.Split(t.list, ",") {
			if s = strings.TrimSpace(s); s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	if t.on {
		return scanner.DefaultRelatedTLDs
	}
	return nil
}

func newRelatedCmd() *cobra.Command {
	n := &netFlags{}
	var tf tldFlags
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
			r := scanner.FindRelated(cmd.Context(), scanner.RelatedOptions{Fetch: o.Fetch, Max: max, Delay: n.delay, TLDs: tf.tlds(), Resolver: observe.SystemResolver{}}, scanner.HomeInfo{
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
	tf.add(c)
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
	if r.VariantsTried > 0 {
		fmt.Fprintf(out, "  %d names tried under other TLDs, %d exist in DNS\n", r.VariantsTried, r.VariantsResolved)
	}
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
