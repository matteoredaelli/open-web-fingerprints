// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"fmt"
	"strings"
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
			decision := map[string]string{}
			if r, err := o.open(cmd.Context()); err == nil {
				defer func() { _ = r.Close() }()
				srcs, err := r.Sources(cmd.Context())
				if err != nil {
					return err
				}
				for _, s := range srcs {
					decision[s.Slug] = s.Redistributable
					snaps, err := r.Snapshots(cmd.Context(), s.ID)
					if err != nil {
						return err
					}
					imported[s.Slug] = len(snaps)
				}
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "SOURCE\tLICENSE\tREDISTRIBUTABLE\tSNAPSHOTS")
			for _, e := range o.entries {
				red := e.Source.Redistributable
				if d, ok := decision[e.Source.Slug]; ok {
					red = d
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%d\n", e.Source.Slug, e.Source.License, red, imported[e.Source.Slug])
			}
			return w.Flush()
		},
	})
	c.AddCommand(&cobra.Command{
		Use:   "info <source>",
		Short: "Show details of a source",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			e, ok := o.find(args[0])
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
					fmt.Fprintf(out, "Decision:        %s", stored.Redistributable)
					if stored.ReviewedAt != nil {
						fmt.Fprintf(out, " (reviewed %s: %s)", stored.ReviewedAt.Format("2006-01-02"), stored.ReviewNote)
					}
					fmt.Fprintln(out)
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
	c.AddCommand(newRefreshCmd(o), newSourceReviewCmd(o))
	return c
}

func printSnapshots(cmd *cobra.Command, snaps []domain.Snapshot) {
	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "Snapshots:       %d\n", len(snaps))
	for _, s := range snaps {
		fmt.Fprintf(out, "  %s  %s  %s  (%d files)\n", s.Revision, s.RetrievedAt.Format("2006-01-02 15:04"), s.Checksum[:19], len(s.Files))
	}
}

func newSourceReviewCmd(o *options) *cobra.Command {
	var decision, note string
	c := &cobra.Command{
		Use:   "review <source>",
		Short: "Record whether a source's data may be redistributed",
		Long: "review records the outcome of the license review of a source: yes, no, or\n" +
			"unreviewed (to withdraw a decision). A yes or no decision needs a --note naming\n" +
			"its basis (who decided, what was checked). The decision is kept by later imports\n" +
			"and decides what `owf export` may contain. This is not legal advice: the tool\n" +
			"records the decision, it does not make it.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			switch decision {
			case "yes", "no", "unreviewed":
			default:
				return fmt.Errorf("--redistributable must be yes, no or unreviewed")
			}
			note = strings.TrimSpace(note)
			if decision != "unreviewed" && note == "" {
				return fmt.Errorf("a %q decision needs a --note saying who decided it and on what basis", decision)
			}
			r, err := o.open(cmd.Context())
			if err != nil {
				return err
			}
			defer func() { _ = r.Close() }()
			s, ok, err := r.GetSourceBySlug(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			if !ok {
				return fmt.Errorf("source %q is not in the registry yet; import it first", args[0])
			}
			s.Redistributable = decision
			if decision == "unreviewed" {
				s.ReviewNote, s.ReviewedAt = "", nil
			} else {
				t := nowFunc().UTC()
				s.ReviewNote, s.ReviewedAt = note, &t
			}
			if err := r.UpsertSource(cmd.Context(), s); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s: redistributable=%s\n", s.Slug, s.Redistributable)
			return nil
		},
	}
	c.Flags().StringVar(&decision, "redistributable", "", "yes, no or unreviewed")
	c.Flags().StringVar(&note, "note", "", "basis of the decision (required for yes and no)")
	_ = c.MarkFlagRequired("redistributable")
	return c
}
