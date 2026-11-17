// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/matteoredaelli/open-web-fingerprints/internal/domain"
	"github.com/matteoredaelli/open-web-fingerprints/internal/export"
	"github.com/matteoredaelli/open-web-fingerprints/internal/validator"
)

func printJSON(cmd *cobra.Command, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	fmt.Fprintln(cmd.OutOrStdout(), string(b))
	return nil
}

func newTechnologyCmd(o *options) *cobra.Command {
	c := &cobra.Command{Use: "technology", Aliases: []string{"tech"}, Short: "Browse technologies"}
	var asJSON bool
	var category string
	list := &cobra.Command{
		Use:   "list",
		Short: "List technologies",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			r, err := o.open(cmd.Context())
			if err != nil {
				return err
			}
			defer func() { _ = r.Close() }()
			all, err := r.AllRecords(cmd.Context())
			if err != nil {
				return err
			}
			var catID domain.CategoryID
			if category != "" {
				for _, c := range all.Categories {
					if c.Slug == category {
						catID = c.ID
					}
				}
				if catID == "" {
					return fmt.Errorf("unknown category %q", category)
				}
			}
			var out []domain.Technology
			for _, t := range all.Technologies {
				if catID != "" && !hasCategory(t, catID) {
					continue
				}
				out = append(out, t)
			}
			sort.Slice(out, func(i, j int) bool { return out[i].Slug < out[j].Slug })
			if asJSON {
				return printJSON(cmd, out)
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "SLUG\tNAME\tSTATUS\tWEBSITE")
			for _, t := range out {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", t.Slug, t.Name, t.Status, t.Website)
			}
			return w.Flush()
		},
	}
	list.Flags().BoolVar(&asJSON, "json", false, "output JSON")
	list.Flags().StringVar(&category, "category", "", "filter by category slug")

	show := &cobra.Command{
		Use:   "show <slug>",
		Short: "Show a technology with its fingerprints and relationships",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			r, err := o.open(cmd.Context())
			if err != nil {
				return err
			}
			defer func() { _ = r.Close() }()
			all, err := r.AllRecords(cmd.Context())
			if err != nil {
				return err
			}
			srcs, err := r.Sources(cmd.Context())
			if err != nil {
				return err
			}
			slugs := map[domain.SourceID]string{}
			for _, s := range srcs {
				slugs[s.ID] = s.Slug
			}
			var t *domain.Technology
			names := map[domain.TechnologyID]string{}
			for i := range all.Technologies {
				names[all.Technologies[i].ID] = all.Technologies[i].Name
				if all.Technologies[i].Slug == args[0] {
					t = &all.Technologies[i]
				}
			}
			if t == nil {
				return fmt.Errorf("technology %q not found", args[0])
			}
			var fps []domain.Fingerprint
			for _, f := range all.Fingerprints {
				if f.TechnologyID == t.ID {
					fps = append(fps, f)
				}
			}
			var rels []domain.Relationship
			for _, x := range all.Relationships {
				if x.FromTechnologyID == t.ID {
					rels = append(rels, x)
				}
			}
			if asJSON {
				return printJSON(cmd, map[string]any{"technology": t, "fingerprints": fps, "relationships": rels})
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "%s (%s)\n  id:       %s\n  status:   %s\n  website:  %s\n", t.Name, t.Slug, t.ID, t.Status, t.Website)
			if t.Description != "" {
				fmt.Fprintf(out, "  about:    %s\n", t.Description)
			}
			for _, v := range all.Vendors {
				if v.ID == t.VendorID {
					fmt.Fprintf(out, "  vendor:   %s (cpe: %s)\n", v.Name, v.CPEVendor)
				}
			}
			for _, cid := range t.CategoryIDs {
				for _, c := range all.Categories {
					if c.ID == cid {
						fmt.Fprintf(out, "  category: %s\n", c.Name)
					}
				}
			}
			for _, p := range t.Provenance {
				fmt.Fprintf(out, "  from:     %s @ %s (%s, %s)\n", slugs[p.SourceID], p.SnapshotRevision, p.OriginalID, p.State)
			}
			fmt.Fprintf(out, "Fingerprints (%d):\n", len(fps))
			printFingerprints(cmd, fps)
			fmt.Fprintf(out, "Relationships (%d):\n", len(rels))
			for _, x := range rels {
				target := names[x.ToTechnologyID]
				if x.ToCategoryID != "" {
					target = "category " + string(x.ToCategoryID)
				}
				fmt.Fprintf(out, "  %s %s\n", x.Type, target)
			}
			return nil
		},
	}
	show.Flags().BoolVar(&asJSON, "json", false, "output JSON")
	c.AddCommand(list, show)
	return c
}

func hasCategory(t domain.Technology, id domain.CategoryID) bool {
	for _, c := range t.CategoryIDs {
		if c == id {
			return true
		}
	}
	return false
}

func printFingerprints(cmd *cobra.Command, fps []domain.Fingerprint) {
	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "  OBSERVATION\tTARGET\tOPERATOR\tPATTERN\tCONF\tSTATUS")
	for _, f := range fps {
		pat := f.Pattern
		if len(pat) > 48 {
			pat = pat[:45] + "..."
		}
		fmt.Fprintf(w, "  %s\t%s\t%s\t%s\t%.2f\t%s\n", f.Observation, f.Target, f.Operator, pat, f.Confidence, f.Status)
	}
	_ = w.Flush()
}

func newVendorCmd(o *options) *cobra.Command {
	c := &cobra.Command{Use: "vendor", Short: "Browse vendors"}
	var asJSON bool
	list := &cobra.Command{
		Use:   "list",
		Short: "List vendors with the number of technologies they have",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			r, err := o.open(cmd.Context())
			if err != nil {
				return err
			}
			defer func() { _ = r.Close() }()
			all, err := r.AllRecords(cmd.Context())
			if err != nil {
				return err
			}
			n := map[domain.VendorID]int{}
			for _, t := range all.Technologies {
				if t.VendorID != "" {
					n[t.VendorID]++
				}
			}
			out := all.Vendors
			sort.Slice(out, func(i, j int) bool { return out[i].Slug < out[j].Slug })
			if asJSON {
				return printJSON(cmd, out)
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "SLUG\tNAME\tCPE VENDOR\tTECHNOLOGIES")
			for _, v := range out {
				fmt.Fprintf(w, "%s\t%s\t%s\t%d\n", v.Slug, v.Name, v.CPEVendor, n[v.ID])
			}
			return w.Flush()
		},
	}
	list.Flags().BoolVar(&asJSON, "json", false, "output JSON")
	c.AddCommand(list)
	return c
}

func newFingerprintCmd(o *options) *cobra.Command {
	c := &cobra.Command{Use: "fingerprint", Aliases: []string{"fp"}, Short: "Browse and validate fingerprints"}
	var tech, observation string
	var asJSON bool
	list := &cobra.Command{
		Use:   "list",
		Short: "List fingerprints",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			r, err := o.open(cmd.Context())
			if err != nil {
				return err
			}
			defer func() { _ = r.Close() }()
			all, err := r.AllRecords(cmd.Context())
			if err != nil {
				return err
			}
			var techID domain.TechnologyID
			if tech != "" {
				for _, t := range all.Technologies {
					if t.Slug == tech {
						techID = t.ID
					}
				}
				if techID == "" {
					return fmt.Errorf("technology %q not found", tech)
				}
			}
			var out []domain.Fingerprint
			for _, f := range all.Fingerprints {
				if (techID == "" || f.TechnologyID == techID) &&
					(observation == "" || string(f.Observation) == observation) {
					out = append(out, f)
				}
			}
			if asJSON {
				return printJSON(cmd, out)
			}
			printFingerprints(cmd, out)
			fmt.Fprintf(cmd.OutOrStdout(), "%d fingerprints\n", len(out))
			return nil
		},
	}
	list.Flags().StringVar(&tech, "technology", "", "filter by technology slug")
	list.Flags().StringVar(&observation, "observation", "", "filter by observation type")
	list.Flags().BoolVar(&asJSON, "json", false, "output JSON")

	validate := &cobra.Command{
		Use:   "validate",
		Short: "Check semantic constraints on all stored records",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			r, err := o.open(cmd.Context())
			if err != nil {
				return err
			}
			defer func() { _ = r.Close() }()
			all, err := r.AllRecords(cmd.Context())
			if err != nil {
				return err
			}
			issues := validator.Validate(all)
			for _, i := range issues {
				fmt.Fprintf(cmd.OutOrStdout(), "%s %s %s: %s\n", i.Severity, i.Code, i.Ref, i.Message)
			}
			if validator.HasErrors(issues) {
				return fmt.Errorf("%d validation issues", len(issues))
			}
			fmt.Fprintf(cmd.OutOrStdout(), "ok: %d technologies, %d fingerprints, %d relationships\n",
				len(all.Technologies), len(all.Fingerprints), len(all.Relationships))
			return nil
		},
	}
	c.AddCommand(list, validate, newFingerprintTestCmd(o), newFingerprintLintCmd(o))
	return c
}

func newExportCmd(o *options) *cobra.Command {
	var format, outPath string
	c := &cobra.Command{
		Use:   "export",
		Short: "Export the registry as schema-validated JSON",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if format != "json" {
				return fmt.Errorf("unsupported format %q (only json)", format)
			}
			r, err := o.open(cmd.Context())
			if err != nil {
				return err
			}
			defer func() { _ = r.Close() }()
			reg, err := export.Build(cmd.Context(), r, nowFunc())
			if err != nil {
				return err
			}
			b, err := export.JSON(reg)
			if err != nil {
				return err
			}
			if outPath == "" || outPath == "-" {
				_, err = cmd.OutOrStdout().Write(b)
				return err
			}
			if err := writeFile(outPath, b); err != nil {
				return err
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "wrote %s (%d bytes)\n", outPath, len(b))
			return nil
		},
	}
	c.Flags().StringVar(&format, "format", "json", "export format")
	c.Flags().StringVarP(&outPath, "output", "o", "", "output file (default stdout)")
	return c
}

func newStatsCmd(o *options) *cobra.Command {
	return &cobra.Command{
		Use:   "stats",
		Short: "Show registry statistics",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			r, err := o.open(cmd.Context())
			if err != nil {
				return err
			}
			defer func() { _ = r.Close() }()
			all, err := r.AllRecords(cmd.Context())
			if err != nil {
				return err
			}
			srcs, err := r.Sources(cmd.Context())
			if err != nil {
				return err
			}
			conflicts, err := r.Conflicts(cmd.Context())
			if err != nil {
				return err
			}
			open := 0
			for _, c := range conflicts {
				if c.State == domain.ConflictOpen {
					open++
				}
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "open conflicts  %d\n", open)
			fmt.Fprintf(out, "vendors         %d\n", len(all.Vendors))
			fmt.Fprintf(out, "sources         %d\ncategories      %d\ntechnologies    %d\nfingerprints    %d\nrelationships   %d\n",
				len(srcs), len(all.Categories), len(all.Technologies), len(all.Fingerprints), len(all.Relationships))
			byObs := map[domain.Observation]int{}
			byStatus := map[domain.Status]int{}
			var removed int
			for _, f := range all.Fingerprints {
				byObs[f.Observation]++
				byStatus[f.Status]++
				for _, p := range f.Provenance {
					if p.State == "removed_upstream" {
						removed++
					}
				}
			}
			fmt.Fprintln(out, "fingerprints by observation:")
			keys := make([]string, 0, len(byObs))
			for k := range byObs {
				keys = append(keys, string(k))
			}
			sort.Strings(keys)
			for _, k := range keys {
				fmt.Fprintf(out, "  %-16s %d\n", k, byObs[domain.Observation(k)])
			}
			health := map[string]int{}
			for _, f := range all.Fingerprints {
				h := "unknown"
				if f.Validation != nil && f.Validation.Health != "" {
					h = f.Validation.Health
				}
				health[h]++
			}
			fmt.Fprintln(out, "fingerprints by health (ok needs positive and negative test evidence):")
			for _, h := range []string{"ok", "degraded", "broken", "unknown"} {
				if health[h] > 0 {
					fmt.Fprintf(out, "  %-16s %d\n", h, health[h])
				}
			}
			fmt.Fprintln(out, "fingerprints by status:")
			for _, s := range []domain.Status{domain.StatusActive, domain.StatusExperimental, domain.StatusDraft, domain.StatusDeprecated} {
				if byStatus[s] > 0 {
					fmt.Fprintf(out, "  %-16s %d\n", s, byStatus[s])
				}
			}
			if removed > 0 {
				fmt.Fprintf(out, "fingerprints removed upstream (to review): %d\n", removed)
			}
			return nil
		},
	}
}
