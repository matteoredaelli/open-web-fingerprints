// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/fetch"
	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/observe"
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
}

func (n *netFlags) add(c *cobra.Command) {
	c.Flags().StringVar(&n.cacheDir, "cache-dir", os.Getenv("OWFSCAN_CACHE"), "cache responses on disk here (env OWFSCAN_CACHE)")
	c.Flags().DurationVar(&n.maxAge, "max-age", fetch.DefaultMaxAge, "how long a cached response is reused")
	c.Flags().DurationVar(&n.timeout, "timeout", fetch.DefaultTimeout, "timeout of each request")
	c.Flags().BoolVar(&n.allowPrivate, "allow-private", false, "allow private and local addresses (your own network)")
	c.Flags().BoolVar(&n.insecure, "insecure", false, "accept invalid TLS certificates")
	c.Flags().BoolVar(&n.asJSON, "json", false, "output JSON")
}

func (n *netFlags) fetcher() *fetch.Fetcher {
	return fetch.New(fetch.Options{
		Timeout: n.timeout, AllowPrivate: n.allowPrivate, Insecure: n.insecure,
		CacheDir: n.cacheDir, MaxAge: n.maxAge,
	})
}

const netNotice = "\nIt makes one request to the page (plus the favicon with `observe`) and follows its\n" +
	"redirects. Private and local addresses are refused unless --allow-private is given.\n" +
	"Scan only sites you are allowed to scan."

func observeURL(ctx context.Context, n *netFlags, target string, dns, favicon bool) (*observe.Observed, error) {
	o := observe.Options{Fetcher: n.fetcher(), NoFavicon: !favicon}
	if dns {
		o.Resolver = observe.SystemResolver{}
	}
	return observe.Observe(ctx, o, target)
}

func extractFrom(ob *observe.Observed) web.Extraction {
	u, _ := url.Parse(ob.Page.FinalURL)
	host := ""
	if u != nil {
		host = u.Hostname()
	}
	ex := web.Extract([]web.Page{{URL: ob.Page.FinalURL, Body: ob.HTML}}, host)
	ex.Warnings = append(append([]scan.Warning{}, ob.Warnings...), ex.Warnings...)
	return ex
}

func newLinksCmd() *cobra.Command {
	n := &netFlags{}
	c := &cobra.Command{
		Use:   "links <url>",
		Short: "List the links of a page and the domains they point to",
		Long:  "links fetches a page and lists its links, with the registrable domains they\npoint to." + netNotice,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ob, err := observeURL(cmd.Context(), n, args[0], false, false)
			if err != nil {
				return err
			}
			ex := extractFrom(ob)
			if n.asJSON {
				return printJSON(cmd, map[string]any{"target": ob.Page.FinalURL, "links": ex.Links, "domains": ex.Domains, "warnings": ex.Warnings})
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "%s: %d links, %d domains\n\n", ob.Page.FinalURL, len(ex.Links), len(ex.Domains))
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
			ob, err := observeURL(cmd.Context(), n, args[0], false, false)
			if err != nil {
				return err
			}
			ex := extractFrom(ob)
			if n.asJSON {
				return printJSON(cmd, map[string]any{"target": ob.Page.FinalURL, "socials": ex.Socials, "contacts": ex.Contacts, "warnings": ex.Warnings})
			}
			printSocial(cmd, ex)
			printWarnings(cmd, ex.Warnings)
			return nil
		},
	}
	n.add(c)
	return c
}

func newObserveCmd() *cobra.Command {
	n := &netFlags{}
	var noDNS, noFavicon, noHTML bool
	c := &cobra.Command{
		Use:   "observe <url>",
		Short: "Fetch a page and print the observation the rules read (JSON)",
		Long: "observe fetches a page, its favicon and the DNS records and certificate of its host,\n" +
			"and prints what the rules are applied to: headers, cookies, HTML, favicon hashes, DNS,\n" +
			"TLS. The output can be saved and used as the input of a validation case." + netNotice,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ob, err := observeURL(cmd.Context(), n, args[0], !noDNS, !noFavicon)
			if err != nil {
				return err
			}
			obs := ob.Observation
			if noHTML {
				obs.HTML = ""
			}
			return printJSON(cmd, map[string]any{"page": ob.Page, "host": ob.Host, "observation": obs, "warnings": ob.Warnings})
		},
	}
	n.add(c)
	c.Flags().BoolVar(&noDNS, "no-dns", false, "do not look up DNS records")
	c.Flags().BoolVar(&noFavicon, "no-favicon", false, "do not fetch the favicon")
	c.Flags().BoolVar(&noHTML, "no-html", false, "leave the page body out of the output")
	return c
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
