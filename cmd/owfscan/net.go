// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"encoding/json"
	"fmt"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/matteoredaelli/open-web-fingerprints/scan"
	"github.com/matteoredaelli/open-web-fingerprints/scan/client"
)

// netFlags are shared by the commands that make requests.
type netFlags struct {
	cacheDir     string
	maxAge       time.Duration
	timeout      time.Duration
	allowPrivate bool
	insecure     bool
	asJSON       bool
	// Crawling: pages beyond the one asked for.
	depth, maxPages int
	delay           time.Duration
	ignoreRobots    bool
}

func (n *netFlags) add(c *cobra.Command) {
	c.Flags().StringVar(&n.cacheDir, "cache-dir", envOr("OWFSCAN_CACHE", cfg.Fetch.CacheDir), "cache responses on disk here (env OWFSCAN_CACHE, or fetch.cache_dir of the config file)")
	c.Flags().DurationVar(&n.maxAge, "max-age", cfg.Fetch.MaxAge.D(), "how long a cached response is reused")
	c.Flags().DurationVar(&n.timeout, "timeout", cfg.Fetch.Timeout.D(), "timeout of each request")
	c.Flags().BoolVar(&n.allowPrivate, "allow-private", false, "allow private and local addresses (your own network)")
	c.Flags().BoolVar(&n.insecure, "insecure", false, "accept invalid TLS certificates")
	c.Flags().BoolVar(&n.asJSON, "json", false, "output JSON")
}

// addCrawl adds the flags that make a command follow links to other pages.
func (n *netFlags) addCrawl(c *cobra.Command) {
	c.Flags().IntVar(&n.depth, "depth", 0, "follow links this many levels to pages likely to list contacts and profiles (contact, about, press, legal, ...); 0 reads only the page given")
	c.Flags().IntVar(&n.maxPages, "max-pages", cfg.Crawl.MaxPages, "most pages fetched in total, the first included")
	c.Flags().DurationVar(&n.delay, "delay", cfg.Crawl.Delay.D(), "pause before each further page (a larger Crawl-delay in robots.txt wins)")
	c.Flags().BoolVar(&n.ignoreRobots, "ignore-robots", false, "fetch pages that robots.txt asks crawlers to avoid (the page given is always fetched)")
}

// applyTo sets the network limits of a scan from the flags and the configuration.
func (n *netFlags) applyTo(o *client.Options) {
	o.Timeout, o.MaxBody, o.MaxRedirects, o.UserAgent = n.timeout, cfg.Fetch.MaxBodyBytes, cfg.Fetch.MaxRedirects, cfg.Fetch.UserAgent
	o.AllowPrivate, o.Insecure, o.CacheDir, o.MaxAge = n.allowPrivate, n.insecure, n.cacheDir, n.maxAge
}

// options is what the flags and the configuration say, for the commands that are not `scan`.
func (n *netFlags) options() client.Options {
	var o client.Options
	cfg.Apply(&o)
	n.applyTo(&o)
	o.Depth, o.MaxPages, o.Delay, o.IgnoreRobots = n.depth, n.maxPages, n.delay, n.ignoreRobots
	return o
}

const netNotice = "\nIt makes one request to the page (plus the favicon with `observe` and `scan`) and\n" +
	"follows its redirects. With --depth it also reads a few pages of the same site (contact,\n" +
	"about, press, legal, ...), honouring robots.txt, pausing between requests and stopping at\n" +
	"--max-pages. Private and local addresses are refused unless --allow-private is given.\n" +
	"Scan only sites you are allowed to scan."

func newLinksCmd() *cobra.Command {
	n := &netFlags{}
	c := &cobra.Command{
		Use:   "links <url>",
		Short: "List the links of a page and the domains they point to",
		Long:  "links fetches a page and lists its links, with the registrable domains they\npoint to." + netNotice,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			site, err := client.ReadSite(cmd.Context(), n.options(), args[0])
			if err != nil {
				return err
			}
			final, ex := site.URL, site.Extraction
			if n.asJSON {
				return printJSON(cmd, map[string]any{"target": final, "pages": site.Pages, "links": ex.Links, "domains": ex.Domains, "warnings": ex.Warnings})
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "%s: %d links, %d domains, %d page(s) read\n\n", final, len(ex.Links), len(ex.Domains), len(site.Pages))
			w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "DOMAIN\tLINKS\tINTERNAL\tEXAMPLE")
			for _, d := range ex.Domains {
				fmt.Fprintf(w, "%s\t%d\t%v\t%s\n", d.Domain, d.Links, d.Internal, d.Examples[0])
			}
			if err := w.Flush(); err != nil {
				return err
			}
			printWarnings(cmd, ex.Warnings)
			return nil
		},
	}
	n.add(c)
	n.addCrawl(c)
	return c
}

func newSocialCmd() *cobra.Command {
	n := &netFlags{}
	c := &cobra.Command{
		Use:   "social <url>",
		Short: "List the social profiles and contact details a page publishes",
		Long:  "social fetches a page and lists the social profiles and the email addresses and\ntelephone numbers it publishes." + netNotice,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			site, err := client.ReadSite(cmd.Context(), n.options(), args[0])
			if err != nil {
				return err
			}
			ex := site.Extraction
			if n.asJSON {
				return printJSON(cmd, map[string]any{"target": site.URL, "pages": site.Pages, "socials": ex.Socials, "contacts": ex.Contacts, "warnings": ex.Warnings})
			}
			printSocial(cmd, ex)
			printWarnings(cmd, ex.Warnings)
			return nil
		},
	}
	n.add(c)
	n.addCrawl(c)
	return c
}

func newObserveCmd() *cobra.Command {
	n := &netFlags{}
	var noDNS, noFavicon, withHTML, allHeaders bool
	c := &cobra.Command{
		Use:   "observe <url>",
		Short: "Fetch a page and print the observation the rules read (JSON)",
		Long: "observe fetches a page, its favicon and the DNS records and certificate of its host,\n" +
			"and prints what the rules are applied to: headers, cookies, favicon hashes, DNS, TLS.\n" +
			"The page body is left out unless --html is given. Headers that change on every call\n" +
			"(date, request ids, cache hits, cookies: `owfscan config show`, section output) are left\n" +
			"out too, so two calls in a row give the same output; --all-headers keeps them. The output\n" +
			"can be saved and used as the input of a validation case: for that, give --html and\n" +
			"--all-headers, since the rules read both." + netNotice,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			o := n.options()
			o.DNS, o.NoFavicon, o.KeepHTML = !noDNS, noFavicon, withHTML
			o.DropHeaders = dropList(allHeaders)
			ob, err := client.Observe(cmd.Context(), o, args[0])
			if err != nil {
				return err
			}
			page, obs := ob.Page, ob.Observation
			return printJSON(cmd, map[string]any{"page": page, "host": ob.Host, "observation": obs, "warnings": ob.Warnings})
		},
	}
	n.add(c)
	c.Flags().BoolVar(&noDNS, "no-dns", false, "do not look up DNS records")
	c.Flags().BoolVar(&noFavicon, "no-favicon", false, "do not fetch the favicon")
	c.Flags().BoolVar(&withHTML, "html", false, "include the page body in the output (left out by default)")
	c.Flags().BoolVar(&allHeaders, "all-headers", false, "keep the headers and cookie values that change on every call")
	return c
}

// dropList is the headers to leave out of the output: none with --all-headers.
func dropList(all bool) []string {
	if all {
		return nil
	}
	return cfg.Output.DropHeaders
}

func printJSON(cmd *cobra.Command, v any) error {
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func printWarnings(cmd *cobra.Command, ws []scan.Warning) {
	for _, w := range ws {
		fmt.Fprintf(cmd.ErrOrStderr(), "warning: %s: %s (%s)\n", w.Code, w.Message, w.Ref)
	}
}

func printSocial(cmd *cobra.Command, ex client.Extraction) {
	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "PLATFORM\tKIND\tHANDLE\tFOUND VIA")
	for _, s := range ex.Socials {
		via := ""
		for i, f := range s.Found {
			if i > 0 {
				via += ","
			}
			via += f.Via
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", s.Platform, s.Kind, s.Handle, via)
	}
	fmt.Fprintln(w, "\nCONTACT\tVALUE")
	for _, c := range ex.Contacts {
		fmt.Fprintf(w, "%s\t%s\n", c.Kind, c.Value)
	}
	_ = w.Flush()
}

func printExtraction(cmd *cobra.Command, ex client.Extraction, asJSON, _ bool) error {
	if asJSON {
		return printJSON(cmd, map[string]any{
			"links": ex.Links, "domains": ex.Domains, "socials": ex.Socials, "contacts": ex.Contacts, "warnings": ex.Warnings,
		})
	}
	out := cmd.OutOrStdout()
	fmt.Fprintln(out, ex.String())
	w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "\nDOMAIN\tLINKS\tINTERNAL")
	for _, d := range ex.Domains {
		fmt.Fprintf(w, "%s\t%d\t%v\n", d.Domain, d.Links, d.Internal)
	}
	_ = w.Flush()
	fmt.Fprintln(out)
	printSocial(cmd, ex)
	printWarnings(cmd, ex.Warnings)
	return nil
}
