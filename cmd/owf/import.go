// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"fmt"
	"os"
	"sort"

	"github.com/spf13/cobra"

	"github.com/matteoredaelli/open-web-fingerprints/internal/builtin"
	"github.com/matteoredaelli/open-web-fingerprints/internal/pipeline"
)

func newImportCmd(o *options) *cobra.Command {
	var snapshot, revision string
	var dryRun bool
	c := &cobra.Command{
		Use:   "import <source>",
		Short: "Import a local snapshot of a source",
		Long: "Import runs the pipeline on a local checkout of the source: checksum, extract,\n" +
			"normalize, validate, diff and store. Fetching snapshots is not implemented yet;\n" +
			"clone the upstream repository and pin the revision you pass with --revision.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			e, ok := builtin.Find(args[0])
			if !ok {
				return fmt.Errorf("unknown source %q (see `owf source list`)", args[0])
			}
			if snapshot == "" || revision == "" {
				return fmt.Errorf("--snapshot and --revision are required")
			}
			if st, err := os.Stat(snapshot); err != nil || !st.IsDir() {
				return fmt.Errorf("snapshot %q is not a directory", snapshot)
			}
			r, err := o.open(cmd.Context())
			if err != nil {
				return err
			}
			defer func() { _ = r.Close() }()

			p := pipeline.New(builtin.Extractors(), r)
			rep, err := p.Run(cmd.Context(), pipeline.Request{
				Source: e.Source, Revision: revision, FS: os.DirFS(snapshot),
				IncludeFile: e.IncludeFile, DryRun: dryRun,
			})
			if rep != nil {
				printReport(cmd, rep, dryRun)
			}
			return err
		},
	}
	c.Flags().StringVar(&snapshot, "snapshot", "", "directory with the local snapshot")
	c.Flags().StringVar(&revision, "revision", "", "pinned revision of the snapshot (commit SHA or version)")
	c.Flags().BoolVar(&dryRun, "dry-run", false, "compute the diff without storing anything")
	return c
}

func printReport(cmd *cobra.Command, rep *pipeline.Report, dry bool) {
	out := cmd.OutOrStdout()
	state := "applied"
	switch {
	case dry:
		state = "dry run, nothing stored"
	case !rep.Applied:
		state = "NOT applied"
	}
	fmt.Fprintf(out, "%s @ %s: %s\n", rep.Source.Slug, rep.Snapshot.Revision, state)
	fmt.Fprintf(out, "  snapshot  %s (%d files)\n", rep.Snapshot.Checksum, len(rep.Snapshot.Files))
	fmt.Fprintf(out, "  extracted %d categories, %d technologies, %d fingerprints, %d relationships\n",
		rep.Counts.Categories, rep.Counts.Technologies, rep.Counts.Fingerprints, rep.Counts.Relationships)
	row := func(name string, c pipeline.Change) {
		fmt.Fprintf(out, "  %-14s +%d ~%d -%d\n", name, len(c.Added), len(c.Modified), len(c.Removed))
	}
	row("categories", rep.Diff.Categories)
	row("technologies", rep.Diff.Technologies)
	row("fingerprints", rep.Diff.Fingerprints)
	row("relationships", rep.Diff.Relationships)
	if rep.Diff.IsEmpty() {
		fmt.Fprintln(out, "  no changes")
	}
	if len(rep.Warnings) > 0 {
		counts := map[string]int{}
		for _, w := range rep.Warnings {
			counts[w.Code]++
		}
		codes := make([]string, 0, len(counts))
		for c := range counts {
			codes = append(codes, c)
		}
		sort.Strings(codes)
		fmt.Fprintf(out, "  warnings (%d):", len(rep.Warnings))
		for _, c := range codes {
			fmt.Fprintf(out, " %s=%d", c, counts[c])
		}
		fmt.Fprintln(out)
	}
	for _, i := range rep.Issues {
		fmt.Fprintf(out, "  %s %s %s: %s\n", i.Severity, i.Code, i.Ref, i.Message)
	}
}
