// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/matteoredaelli/open-web-fingerprints/scan"
	"github.com/matteoredaelli/open-web-fingerprints/scan/client"
	"github.com/matteoredaelli/open-web-fingerprints/schemas"
)

func newReportCmd() *cobra.Command {
	var out, title string
	c := &cobra.Command{
		Use:   "report <result.json | ->",
		Short: "Write an HTML report from a scan result (owfscan scan --json)",
		Long: "report turns a scan result into one self-contained HTML page: the stack by category with\n" +
			"its evidence, the infrastructure, the profiles and contacts found, the connected domains\n" +
			"and what the scan did not see. The page has no script, loads nothing from the network and\n" +
			"uses system fonts, so it opens offline. It is made from the file alone: nothing is\n" +
			"fetched. The result is checked against its schema first.\n\n" +
			"  owfscan scan example.com --registry registry.json --json > example.json\n" +
			"  owfscan report example.json -o example.html\n\n" +
			"Without -o the page is written to <domain>.html in the current directory; -o - prints it.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			in := io.Reader(cmd.InOrStdin())
			if args[0] != "-" {
				f, err := os.Open(args[0]) //nolint:gosec // the user names the file
				if err != nil {
					return err
				}
				defer func() { _ = f.Close() }()
				in = f
			}
			b, err := io.ReadAll(io.LimitReader(in, 64<<20))
			if err != nil {
				return err
			}
			if err := schemas.ValidateScanResult(b); err != nil {
				return fmt.Errorf("%s is not a scan result: %w", args[0], err)
			}
			var res scan.Result
			if err := json.Unmarshal(b, &res); err != nil {
				return err
			}
			return writeReport(cmd, &res, out, title)
		},
	}
	c.Flags().StringVarP(&out, "output", "o", "", "file to write (default <domain>.html; - for the standard output)")
	c.Flags().StringVar(&title, "title", "", "title of the page (default: the domain)")
	return c
}

// writeReport renders the page to a file, or to the standard output for "-".
func writeReport(cmd *cobra.Command, res *scan.Result, out, title string) error {
	var buf bytes.Buffer
	if err := client.RenderReport(&buf, res, title); err != nil {
		return err
	}
	if out == "-" {
		_, err := cmd.OutOrStdout().Write(buf.Bytes())
		return err
	}
	if out == "" {
		out = reportName(res)
	}
	if err := os.WriteFile(out, buf.Bytes(), 0o644); err != nil { //nolint:gosec // a report is meant to be shared
		return err
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "wrote %s\n", out)
	return nil
}

// reportName is a file name made from the domain, never a path.
func reportName(res *scan.Result) string {
	d := res.Target.RegistrableDomain
	if d == "" {
		d = res.Target.Host
	}
	d = strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-' {
			return r
		}
		return '-'
	}, d)
	if d == "" || strings.Trim(d, ".-") == "" {
		d = "report"
	}
	return filepath.Base(d) + ".html"
}
