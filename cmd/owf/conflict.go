// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"fmt"
	"sort"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/matteoredaelli/open-web-fingerprints/internal/domain"
	"github.com/matteoredaelli/open-web-fingerprints/internal/merge"
	"github.com/matteoredaelli/open-web-fingerprints/internal/review"
)

func newConflictCmd(o *options) *cobra.Command {
	c := &cobra.Command{Use: "conflict", Short: "Review items found while reconciling sources"}
	var kind, state, websites string
	var asJSON bool
	list := &cobra.Command{
		Use:   "list",
		Short: "List conflicts (nothing is merged until a reviewer approves it)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			r, err := o.open(cmd.Context())
			if err != nil {
				return err
			}
			defer func() { _ = r.Close() }()
			all, err := r.Conflicts(cmd.Context())
			if err != nil {
				return err
			}
			var out []domain.Conflict
			for _, x := range all {
				if (kind == "" || x.Kind == kind) && (state == "" || x.State == state) &&
					(websites == "" || x.Detail["websites"] == websites) {
					out = append(out, x)
				}
			}
			sort.SliceStable(out, func(i, j int) bool {
				if out[i].Kind != out[j].Kind {
					return out[i].Kind < out[j].Kind
				}
				return out[i].Detail["identity"] < out[j].Detail["identity"]
			})
			if asJSON {
				return printJSON(cmd, out)
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tKIND\tSTATE\tIDENTITY\tWEBSITES")
			for _, x := range out {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", x.ID, x.Kind, x.State, x.Detail["identity"], x.Detail["websites"])
			}
			if err := w.Flush(); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%d conflicts\n", len(out))
			return nil
		},
	}
	list.Flags().StringVar(&kind, "kind", "", "filter by kind (identity_candidate, category_candidate)")
	list.Flags().StringVar(&state, "state", "", "filter by state (open, resolved, ignored)")
	list.Flags().StringVar(&websites, "websites", "", "filter by website relation (same_domain, different, unknown)")
	list.Flags().BoolVar(&asJSON, "json", false, "output JSON")
	c.AddCommand(list, newConflictShowCmd(o), newConflictResolveCmd(o))
	return c
}

func newConflictShowCmd(o *options) *cobra.Command {
	return &cobra.Command{
		Use:   "show <id>",
		Short: "Show a conflict with the records involved",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			r, err := o.open(cmd.Context())
			if err != nil {
				return err
			}
			defer func() { _ = r.Close() }()
			cs, err := r.Conflicts(cmd.Context())
			if err != nil {
				return err
			}
			var c *domain.Conflict
			for i := range cs {
				if string(cs[i].ID) == args[0] {
					c = &cs[i]
				}
			}
			if c == nil {
				return fmt.Errorf("conflict %q not found", args[0])
			}
			all, err := r.AllRecords(cmd.Context())
			if err != nil {
				return err
			}
			srcs, err := r.Sources(cmd.Context())
			if err != nil {
				return err
			}
			slug := map[domain.SourceID]string{}
			for _, s := range srcs {
				slug[s.ID] = s.Slug
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "%s\n  kind:  %s\n  state: %s\n", c.ID, c.Kind, c.State)
			if c.Resolution != "" {
				fmt.Fprintf(out, "  resolution: %s\n", c.Resolution)
			}
			keys := make([]string, 0, len(c.Detail))
			for k := range c.Detail {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				fmt.Fprintf(out, "  %s: %s\n", k, c.Detail[k])
			}
			for _, id := range c.RecordIDs {
				fmt.Fprintf(out, "record %s\n", id)
				for _, t := range all.Technologies {
					if string(t.ID) == id {
						n := 0
						for _, f := range all.Fingerprints {
							if f.TechnologyID == t.ID {
								n++
							}
						}
						fmt.Fprintf(out, "  technology %q (%s) %s, %d fingerprints\n", t.Name, t.Slug, t.Website, n)
						for _, p := range t.Provenance {
							fmt.Fprintf(out, "  from %s @ %s\n", slug[p.SourceID], p.SnapshotRevision)
						}
					}
				}
				for _, cat := range all.Categories {
					if string(cat.ID) == id {
						fmt.Fprintf(out, "  category %q (%s)\n", cat.Name, cat.Slug)
					}
				}
			}
			return nil
		},
	}
}

func newConflictResolveCmd(o *options) *cobra.Command {
	var doMerge, keep, all, dryRun bool
	var kind, state, websites, note string
	c := &cobra.Command{
		Use:   "resolve [id...]",
		Short: "Merge records or keep them separate",
		Long: "resolve applies a reviewer decision to conflicts.\n" +
			"  --merge          merge the two records; the older one survives and the other\n" +
			"                   becomes an alias so future imports map onto it\n" +
			"  --keep-separate  record that they are different (state: ignored)\n" +
			"Name conflicts by ID, or use --all with --kind and/or --websites for a bulk\n" +
			"decision. Use --dry-run first: a bulk merge touches many records.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if doMerge == keep {
				return fmt.Errorf("choose exactly one of --merge and --keep-separate")
			}
			if len(args) == 0 && !all {
				return fmt.Errorf("name conflict IDs, or use --all with a filter")
			}
			if len(args) > 0 && all {
				return fmt.Errorf("use either conflict IDs or --all")
			}
			if all && kind == "" && websites == "" {
				return fmt.Errorf("--all needs --kind and/or --websites")
			}
			dec := merge.Merge
			if keep {
				dec = merge.KeepSeparate
			}
			ids := make([]domain.ConflictID, len(args))
			for i, a := range args {
				ids[i] = domain.ConflictID(a)
			}
			r, err := o.open(cmd.Context())
			if err != nil {
				return err
			}
			defer func() { _ = r.Close() }()
			res, err := review.Resolve(cmd.Context(), r, review.Request{
				IDs: ids, Bulk: all, Kind: kind, Websites: websites, State: state,
				Decision: dec, Note: note, DryRun: dryRun,
			})
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			verb := "applied"
			if dryRun {
				verb = "dry run, nothing stored"
			}
			fmt.Fprintf(out, "%s: %d selected, %d merged, %d kept separate, %d skipped\n",
				verb, res.Selected, res.Merged, res.KeptSeparate, res.Skipped)
			if res.Merged > 0 {
				fmt.Fprintf(out, "  absorbed: %d technologies, %d categories, %d fingerprints, %d relationships (%d aliases)\n",
					len(res.Delete.Technologies), len(res.Delete.Categories), len(res.Delete.Fingerprints),
					len(res.Delete.Relationships), res.Aliases)
				if res.SelfRelations > 0 {
					fmt.Fprintf(out, "  %d relationships became self references and were dropped\n", res.SelfRelations)
				}
			}
			return nil
		},
	}
	c.Flags().BoolVar(&doMerge, "merge", false, "merge the records")
	c.Flags().BoolVar(&keep, "keep-separate", false, "keep the records separate")
	c.Flags().BoolVar(&all, "all", false, "apply to every conflict matching the filters")
	c.Flags().BoolVar(&dryRun, "dry-run", false, "show the effect without storing anything")
	c.Flags().StringVar(&kind, "kind", "", "filter by kind")
	c.Flags().StringVar(&state, "state", "", "filter by state (default open)")
	c.Flags().StringVar(&websites, "websites", "", "filter by website relation")
	c.Flags().StringVar(&note, "note", "", "reason, stored with the resolution")
	return c
}
