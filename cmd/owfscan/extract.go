// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/web"
)

func newExtractCmd() *cobra.Command {
	var pageURL string
	var asJSON bool
	c := &cobra.Command{
		Use:   "extract <file.html | ->",
		Short: "Extract links, domains, social profiles and contacts from saved HTML",
		Long: "extract reads an HTML file (or standard input) and prints the links, the domains\n" +
			"they point to, the social profiles and the contact details it contains. --url is\n" +
			"the address the page was fetched from: relative links are resolved against it and\n" +
			"links to the same registrable domain are internal. It makes no network requests.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			u, err := url.Parse(pageURL)
			if err != nil || u.Hostname() == "" {
				return fmt.Errorf("--url must be the http(s) address of the page")
			}
			var body []byte
			if args[0] == "-" {
				body, err = io.ReadAll(cmd.InOrStdin())
			} else {
				body, err = os.ReadFile(args[0])
			}
			if err != nil {
				return err
			}
			ex := web.Extract([]web.Page{{URL: pageURL, Body: body}}, u.Hostname())
			out := cmd.OutOrStdout()
			if asJSON {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(map[string]any{
					"links": ex.Links, "domains": ex.Domains, "socials": ex.Socials,
					"contacts": ex.Contacts, "warnings": ex.Warnings,
				})
			}
			fmt.Fprintln(out, ex.String())
			w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "\nDOMAIN\tLINKS\tINTERNAL")
			for _, d := range ex.Domains {
				fmt.Fprintf(w, "%s\t%d\t%v\n", d.Domain, d.Links, d.Internal)
			}
			fmt.Fprintln(w, "\nPLATFORM\tKIND\tHANDLE\tFOUND VIA")
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
			if err := w.Flush(); err != nil {
				return err
			}
			for _, wn := range ex.Warnings {
				fmt.Fprintf(cmd.ErrOrStderr(), "warning: %s: %s (%s)\n", wn.Code, wn.Message, wn.Ref)
			}
			return nil
		},
	}
	c.Flags().StringVar(&pageURL, "url", "", "address the page was fetched from (required)")
	c.Flags().BoolVar(&asJSON, "json", false, "output JSON")
	_ = c.MarkFlagRequired("url")
	return c
}
