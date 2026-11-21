// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/fetch"
	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/observe"
	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/scanner"
	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/web"
	"github.com/matteoredaelli/open-web-fingerprints/scan"
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

func (n *netFlags) crawlOptions(dns, favicon bool) scanner.CrawlOptions {
	o := scanner.CrawlOptions{
		Fetch:     n.fetchOptions(),
		NoFavicon: !favicon, Depth: n.depth, MaxPages: n.maxPages, Delay: n.delay, IgnoreRobots: n.ignoreRobots,
		MaxDelay: cfg.Crawl.MaxDelay.D(),
	}
	if dns {
		o.Resolver = observe.SystemResolver{}
	}
	return o
}

// fetchOptions combines the flags with the limits of the configuration that have no flag.
func (n *netFlags) fetchOptions() fetch.Options {
	return fetch.Options{
		Timeout: n.timeout, AllowPrivate: n.allowPrivate, Insecure: n.insecure,
		CacheDir: n.cacheDir, MaxAge: n.maxAge,
		MaxBody: cfg.Fetch.MaxBodyBytes, MaxRedirects: cfg.Fetch.MaxRedirects, UserAgent: cfg.Fetch.UserAgent,
	}
}

func (n *netFlags) fetcher() *fetch.Fetcher { return fetch.New(n.fetchOptions()) }

const netNotice = "\nIt makes one request to the page (plus the favicon with `observe` and `scan`) and\n" +
	"follows its redirects. With --depth it also reads a few pages of the same site (contact,\n" +
	"about, press, legal, ...), honouring robots.txt, pausing between requests and stopping at\n" +
	"--max-pages. Private and local addresses are refused unless --allow-private is given.\n" +
	"Scan only sites you are allowed to scan."

func observeURL(ctx context.Context, n *netFlags, target string, dns, favicon bool) (*observe.Observed, error) {
	o := observe.Options{Fetcher: n.fetcher(), NoFavicon: !favicon}
	if dns {
		o.Resolver = observe.SystemResolver{}
	}
	return observe.Observe(ctx, o, target)
}

// crawlFor reads the page (and, with --depth, the pages it leads to) and extracts
// links, domains, social profiles and contacts from all of them.
func crawlFor(cmd *cobra.Command, n *netFlags, target string) (*scanner.Crawled, web.Extraction, error) {
	c, err := scanner.Crawl(cmd.Context(), n.crawlOptions(false, false), target)
	if err != nil {
		return nil, web.Extraction{}, err
	}
	var pages []web.Page
	for _, p := range c.Pages {
		if len(p.HTML) > 0 {
			pages = append(pages, web.Page{URL: p.Page.FinalURL, Body: p.HTML})
		}
	}
	u, _ := url.Parse(c.Main.Page.FinalURL)
	host := ""
	if u != nil {
		host = u.Hostname()
	}
	ex := web.Extract(pages, host)
	ex.Warnings = append(append([]scan.Warning{}, c.Warnings...), ex.Warnings...)
	return c, ex, nil
}

func newLinksCmd() *cobra.Command {
	n := &netFlags{}
	c := &cobra.Command{
		Use:   "links <url>",
		Short: "List the links of a page and the domains they point to",
		Long:  "links fetches a page and lists its links, with the registrable domains they\npoint to." + netNotice,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, ex, err := crawlFor(cmd, n, args[0])
			if err != nil {
				return err
			}
			final := c.Main.Page.FinalURL
			if n.asJSON {
				return printJSON(cmd, map[string]any{"target": final, "pages": pageURLs(c), "links": ex.Links, "domains": ex.Domains, "warnings": ex.Warnings})
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "%s: %d links, %d domains, %d page(s) read\n\n", final, len(ex.Links), len(ex.Domains), len(c.Pages))
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

func pageURLs(c *scanner.Crawled) []string {
	out := make([]string, 0, len(c.Pages))
	for _, p := range c.Pages {
		out = append(out, p.Page.FinalURL)
	}
	return out
}

func newSocialCmd() *cobra.Command {
	n := &netFlags{}
	c := &cobra.Command{
		Use:   "social <url>",
		Short: "List the social profiles and contact details a page publishes",
		Long:  "social fetches a page and lists the social profiles and the email addresses and\ntelephone numbers it publishes." + netNotice,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, ex, err := crawlFor(cmd, n, args[0])
			if err != nil {
				return err
			}
			if n.asJSON {
				return printJSON(cmd, map[string]any{"target": c.Main.Page.FinalURL, "pages": pageURLs(c), "socials": ex.Socials, "contacts": ex.Contacts, "warnings": ex.Warnings})
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
			ob, err := observeURL(cmd.Context(), n, args[0], !noDNS, !noFavicon)
			if err != nil {
				return err
			}
			obs := ob.Observation
			if !withHTML {
				obs.HTML = ""
			}
			page := ob.Page
			if drop := dropList(allHeaders); len(drop) > 0 {
				page.Headers, page.HeadersFiltered = observe.FilterHeaders(page.Headers, drop), true
				obs.Headers = observe.FilterHeaders(obs.Headers, drop)
				if observe.Dropped("set-cookie", drop) {
					// The cookie names stay (they are what rules look for); the values and
					// the raw lines are what changes.
					obs.SetCookies = nil
					names := make(map[string]string, len(obs.Cookies))
					for k := range obs.Cookies {
						names[k] = ""
					}
					obs.Cookies = names
				}
			}
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

func printSocial(cmd *cobra.Command, ex web.Extraction) {
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

func printExtraction(cmd *cobra.Command, ex web.Extraction, asJSON, _ bool) error {
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
