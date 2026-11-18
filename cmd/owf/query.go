// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/matteoredaelli/open-web-fingerprints/internal/curate"
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
	var asJSON, uncurated bool
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
			var out []domain.Vendor
			for _, v := range all.Vendors {
				if !uncurated || !v.Curated {
					out = append(out, v)
				}
			}
			sort.Slice(out, func(i, j int) bool { return out[i].Slug < out[j].Slug })
			if asJSON {
				return printJSON(cmd, out)
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "SLUG\tNAME\tCPE VENDOR\tTECHNOLOGIES\tCURATED")
			for _, v := range out {
				fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%v\n", v.Slug, v.Name, v.CPEVendor, n[v.ID], v.Curated)
			}
			return w.Flush()
		},
	}
	list.Flags().BoolVar(&asJSON, "json", false, "output JSON")
	list.Flags().BoolVar(&uncurated, "uncurated", false, "only vendors nobody has reviewed (their names are guesses)")
	c.AddCommand(list, newVendorShowCmd(o), newVendorSetCmd(o))
	return c
}

func newVendorShowCmd(o *options) *cobra.Command {
	return &cobra.Command{
		Use:   "show <slug>",
		Short: "Show a vendor and its technologies",
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
			var v *domain.Vendor
			for i := range all.Vendors {
				if all.Vendors[i].Slug == args[0] {
					v = &all.Vendors[i]
				}
			}
			if v == nil {
				return fmt.Errorf("vendor %q not found", args[0])
			}
			out := cmd.OutOrStdout()
			state := "uncurated (the name is a guess)"
			if v.Curated {
				state = "curated"
			}
			fmt.Fprintf(out, "%s (%s)\n  id:       %s\n  cpe:      %s\n  website:  %s\n  aliases:  %s\n  state:    %s\n",
				v.Name, v.Slug, v.ID, v.CPEVendor, v.Website, strings.Join(v.Aliases, ", "), state)
			var techs []string
			for _, t := range all.Technologies {
				if t.VendorID == v.ID {
					techs = append(techs, t.Slug)
				}
			}
			sort.Strings(techs)
			fmt.Fprintf(out, "Technologies (%d): %s\n", len(techs), strings.Join(techs, ", "))
			return nil
		},
	}
}

func newVendorSetCmd(o *options) *cobra.Command {
	var name, website string
	var add, remove []string
	var clearWebsite bool
	c := &cobra.Command{
		Use:   "set <slug>",
		Short: "Correct a vendor's name, website or aliases",
		Long: "set edits a vendor and marks it curated. Refreshes never overwrite curated\n" +
			"content. The slug and the CPE identifier do not change. Do not run it while\n" +
			"an import is running.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			p := curate.VendorPatch{AddAliases: add, RemoveAliases: remove}
			if cmd.Flags().Changed("name") {
				p.Name = &name
			}
			if cmd.Flags().Changed("website") {
				if clearWebsite {
					return fmt.Errorf("use either --website or --clear-website")
				}
				p.Website = &website
			}
			if clearWebsite {
				empty := ""
				p.Website = &empty
			}
			r, err := o.open(cmd.Context())
			if err != nil {
				return err
			}
			defer func() { _ = r.Close() }()
			v, err := curate.Vendor(cmd.Context(), r, args[0], p)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s: name %q, website %q, aliases [%s], curated\n",
				v.Slug, v.Name, v.Website, strings.Join(v.Aliases, ", "))
			return nil
		},
	}
	c.Flags().StringVar(&name, "name", "", "display name")
	c.Flags().StringVar(&website, "website", "", "website (http or https URL)")
	c.Flags().BoolVar(&clearWebsite, "clear-website", false, "remove the website")
	c.Flags().StringArrayVar(&add, "alias", nil, "add an alias (repeatable)")
	c.Flags().StringArrayVar(&remove, "remove-alias", nil, "remove an alias (repeatable)")
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
	var includeUnreviewed bool
	c := &cobra.Command{
		Use:   "export",
		Short: "Export the registry as schema-validated JSON",
		Long: "export writes the registry as JSON validated against the published schema.\n" +
			"Only data from sources whose redistribution has been reviewed as \"yes\" is\n" +
			"exported. If some source is still unreviewed the command refuses; record the\n" +
			"decision with `owf source review`, or pass --include-unreviewed for internal use\n" +
			"(the file then says so in its `export` section). Sources marked \"no\" are never\n" +
			"exported.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if format != "json" {
				return fmt.Errorf("unsupported format %q (only json)", format)
			}
			r, err := o.open(cmd.Context())
			if err != nil {
				return err
			}
			defer func() { _ = r.Close() }()
			reg, err := export.Build(cmd.Context(), r, nowFunc(), export.Options{IncludeUnreviewed: includeUnreviewed})
			if err != nil {
				return err
			}
			if reg.Export != nil && len(reg.Export.UnreviewedSources) > 0 {
				fmt.Fprintf(cmd.ErrOrStderr(), "warning: includes unreviewed sources (%s): %s\n",
					strings.Join(reg.Export.UnreviewedSources, ", "), "internal use only, do not redistribute")
			}
			if reg.Export != nil && (reg.Export.ExcludedRecords > 0 || len(reg.Export.ExcludedSources) > 0) {
				fmt.Fprintf(cmd.ErrOrStderr(), "note: left out %d records; excluded sources: %s\n",
					reg.Export.ExcludedRecords, strings.Join(reg.Export.ExcludedSources, ", "))
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
	c.Flags().BoolVar(&includeUnreviewed, "include-unreviewed", false, "include sources whose redistribution is unreviewed (internal use only)")
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
			var okUpstreamOnly int
			for _, f := range all.Fingerprints {
				h := "unknown"
				if f.Validation != nil && f.Validation.Health != "" {
					h = f.Validation.Health
				}
				health[h]++
				if h == "ok" {
					own := false
					for _, tr := range f.Validation.TestRuns {
						if tr.Origin == "" {
							own = true
						}
					}
					if !own {
						okUpstreamOnly++
					}
				}
			}
			fmt.Fprintln(out, "fingerprints by health (ok needs positive and negative test evidence):")
			for _, h := range []string{"ok", "degraded", "broken", "unknown"} {
				if health[h] > 0 {
					fmt.Fprintf(out, "  %-16s %d", h, health[h])
					if h == "ok" && okUpstreamOnly > 0 {
						fmt.Fprintf(out, " (%d only from upstream examples)", okUpstreamOnly)
					}
					fmt.Fprintln(out)
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
