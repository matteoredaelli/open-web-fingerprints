// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"fmt"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/matteoredaelli/open-web-fingerprints/internal/builtin"
	"github.com/matteoredaelli/open-web-fingerprints/internal/domain"
	"github.com/matteoredaelli/open-web-fingerprints/internal/extractor"
)

func newSourceCmd(o *options) *cobra.Command {
	c := &cobra.Command{Use: "source", Short: "Inspect upstream sources"}
	c.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List known sources and whether they were imported",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			imported := map[string]int{}
			if r, err := o.open(cmd.Context()); err == nil {
				defer func() { _ = r.Close() }()
				srcs, err := r.Sources(cmd.Context())
				if err != nil {
					return err
				}
				for _, s := range srcs {
					snaps, err := r.Snapshots(cmd.Context(), s.ID)
					if err != nil {
						return err
					}
					imported[s.Slug] = len(snaps)
				}
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "SOURCE\tLICENSE\tREDISTRIBUTABLE\tSNAPSHOTS")
			for _, e := range builtin.Sources() {
				fmt.Fprintf(w, "%s\t%s\t%s\t%d\n", e.Source.Slug, e.Source.License, e.Source.Redistributable, imported[e.Source.Slug])
			}
			return w.Flush()
		},
	})
	c.AddCommand(&cobra.Command{
		Use:   "info <source>",
		Short: "Show details of a source",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			e, ok := builtin.Find(args[0])
			if !ok {
				return fmt.Errorf("unknown source %q (see `owf source list`)", args[0])
			}
			out := cmd.OutOrStdout()
			s := e.Source
			fmt.Fprintf(out, "Slug:            %s\nName:            %s\nURL:             %s\nLicense:         %s\nRedistributable: %s\nExtractor:       %s\n",
				s.Slug, s.Name, s.URL, s.License, s.Redistributable, s.ExtractorID)
			if x, err := builtin.Extractors().Get(s.ExtractorID); err == nil {
				if cr, ok := x.(extractor.CapabilityReporter); ok {
					fmt.Fprint(out, "Capabilities:   ")
					for _, c := range cr.Capabilities() {
						fmt.Fprintf(out, " %s", c)
					}
					fmt.Fprintln(out)
				}
			}
			if s.Notes != "" {
				fmt.Fprintf(out, "Notes:           %s\n", s.Notes)
			}
			if r, err := o.open(cmd.Context()); err == nil {
				defer func() { _ = r.Close() }()
				if stored, ok, err := r.GetSourceBySlug(cmd.Context(), s.Slug); err == nil && ok {
					snaps, err := r.Snapshots(cmd.Context(), stored.ID)
					if err != nil {
						return err
					}
					printSnapshots(cmd, snaps)
				}
			}
			return nil
		},
	})
	return c
}

func printSnapshots(cmd *cobra.Command, snaps []domain.Snapshot) {
	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "Snapshots:       %d\n", len(snaps))
	for _, s := range snaps {
		fmt.Fprintf(out, "  %s  %s  %s  (%d files)\n", s.Revision, s.RetrievedAt.Format("2006-01-02 15:04"), s.Checksum[:19], len(s.Files))
	}
}
