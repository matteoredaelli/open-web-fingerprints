// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/matteoredaelli/open-web-fingerprints/scan/client"
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
			var err error
			var body []byte
			if args[0] == "-" {
				body, err = io.ReadAll(cmd.InOrStdin())
			} else {
				body, err = os.ReadFile(args[0])
			}
			if err != nil {
				return err
			}
			ex, err := client.Extract(body, pageURL)
			if err != nil {
				return fmt.Errorf("--url must be the http(s) address of the page")
			}
			return printExtraction(cmd, ex, asJSON, true)
		},
	}
	c.Flags().StringVar(&pageURL, "url", "", "address the page was fetched from (required)")
	c.Flags().BoolVar(&asJSON, "json", false, "output JSON")
	_ = c.MarkFlagRequired("url")
	return c
}
