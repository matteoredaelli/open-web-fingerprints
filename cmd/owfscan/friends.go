// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"fmt"
	"net/url"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/scanner"
	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/web"
	"github.com/matteoredaelli/open-web-fingerprints/scan"
)

const friendsNotice = "\nA friend is a domain that the home page links to and whose own home page links\n" +
	"back. It says what two home pages link to, nothing more. Each candidate costs one request\n" +
	"(plus its robots.txt) to a site you did not name: robots.txt is always honoured, there is a\n" +
	"pause between requests (--delay) and at most --friends-max sites are contacted. Social\n" +
	"platforms are not candidates."

func newFriendsCmd() *cobra.Command {
	n := &netFlags{}
	var max int
	c := &cobra.Command{
		Use:   "friends <url>",
		Short: "Find friend domains: linked from the home page and linking back to it",
		Long: "friends reads a home page, takes the other domains it links to and checks each one's\n" +
			"home page for a link back to the first." + friendsNotice + netNotice,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			n.depth = 0 // the definition is about the home page
			o := n.crawlOptions(false, false)
			ob, err := scanner.Crawl(cmd.Context(), o, args[0])
			if err != nil {
				return err
			}
			u, err := url.Parse(ob.Main.Page.FinalURL)
			if err != nil {
				return err
			}
			ex := web.Extract([]web.Page{{URL: ob.Main.Page.FinalURL, Body: ob.Main.HTML}}, u.Hostname())
			fr := scanner.FindFriends(cmd.Context(), scanner.FriendsOptions{Fetch: o.Fetch, Max: max, Delay: n.delay},
				scanner.Home{Domain: web.RegistrableDomain(u.Hostname()), Links: ex.Links})
			if n.asJSON {
				return printJSON(cmd, map[string]any{"target": ob.Main.Page.FinalURL, "friends": fr})
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s\n", ob.Main.Page.FinalURL)
			printFriends(cmd, fr)
			return nil
		},
	}
	n.add(c)
	c.Flags().DurationVar(&n.delay, "delay", cfg.Crawl.Delay.D(), "pause before each request to another site")
	c.Flags().IntVar(&max, "friends-max", cfg.Friends.Max, "most candidate domains to look at")
	return c
}

func printFriends(cmd *cobra.Command, f *scan.Friends) {
	out := cmd.OutOrStdout()
	var friends int
	for _, d := range f.Domains {
		if d.Status == scan.FriendYes {
			friends++
		}
	}
	fmt.Fprintf(out, "\nFRIENDS (%d of %d checked, %d candidates)\n", friends, f.Checked, f.Candidates)
	if len(f.Domains) == 0 {
		fmt.Fprintln(out, "  none: the home page links to no other domain")
		return
	}
	w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "DOMAIN\tSTATUS\tLINKS BACK")
	for _, d := range f.Domains {
		back := ""
		if len(d.LinksBack) > 0 {
			back = d.LinksBack[0]
		} else if d.Detail != "" {
			back = "(" + d.Detail + ")"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\n", d.Domain, d.Status, back)
	}
	_ = w.Flush()
}
