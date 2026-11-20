// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"fmt"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/matteoredaelli/open-web-fingerprints/internal/curate"
	"github.com/matteoredaelli/open-web-fingerprints/internal/domain"
)

func newProbeCmd(o *options) *cobra.Command {
	c := &cobra.Command{
		Use:   "probe",
		Short: "Review the active probes that some rules need (safety review)",
		Long: "Some rules need the answer to a request to a path of the site (/robots.txt, /admin, an API\n" +
			"index). They are imported as drafts with a pending safety review and the scanner does not send\n" +
			"them. A reviewer approves a path (every rule that probes it is then active) or rejects it. The\n" +
			"scanner sends only approved probes, only with --active, only GET, and honours robots.txt.\n" +
			"Rules that share a path share one request, so the review is per path.",
	}
	c.AddCommand(newProbeListCmd(o), newProbeReviewCmd(o))
	return c
}

type probeRow struct {
	Path         string   `json:"path"`
	Method       string   `json:"method"`
	Rules        int      `json:"rules"`
	Technologies int      `json:"technologies"`
	Examples     []string `json:"examples"`
	State        string   `json:"state"` // pending, approved, rejected or mixed
	Note         string   `json:"note,omitempty"`
	Concerns     []string `json:"concerns,omitempty"`
}

func newProbeListCmd(o *options) *cobra.Command {
	var state string
	var asJSON bool
	var limit int
	c := &cobra.Command{
		Use:   "list",
		Short: "List the probe paths with how many rules need each, most used first",
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
			names := map[domain.TechnologyID]string{}
			for _, t := range all.Technologies {
				names[t.ID] = t.Name
			}
			type acc struct {
				row   probeRow
				techs map[string]bool
				state map[string]bool
			}
			by := map[string]*acc{}
			for _, f := range all.Fingerprints {
				if f.Probe == nil || f.Status == domain.StatusDeprecated {
					continue
				}
				a := by[f.Probe.Path]
				if a == nil {
					a = &acc{row: probeRow{Path: f.Probe.Path, Method: f.Probe.Method}, techs: map[string]bool{}, state: map[string]bool{}}
					by[f.Probe.Path] = a
				}
				a.row.Rules++
				a.techs[names[f.TechnologyID]] = true
				a.state[f.Probe.SafetyReview] = true
				if f.Probe.ReviewNote != "" {
					a.row.Note = f.Probe.ReviewNote
				}
			}
			var rows []probeRow
			for _, a := range by {
				a.row.Technologies = len(a.techs)
				for n := range a.techs {
					a.row.Examples = append(a.row.Examples, n)
				}
				sort.Strings(a.row.Examples)
				if len(a.row.Examples) > 3 {
					a.row.Examples = a.row.Examples[:3]
				}
				switch {
				case len(a.state) == 1:
					for s := range a.state {
						a.row.State = s
					}
				default:
					a.row.State = "mixed"
				}
				if err := curate.SafePath(a.row.Path); err != nil {
					a.row.Concerns = append(a.row.Concerns, err.Error())
				}
				if strings.Contains(a.row.Path, "?") {
					a.row.Concerns = append(a.row.Concerns, "has a query string")
				}
				if a.row.Method != "GET" {
					a.row.Concerns = append(a.row.Concerns, "method "+a.row.Method+" is not sent by the scanner")
				}
				if state == "" || a.row.State == state {
					rows = append(rows, a.row)
				}
			}
			sort.Slice(rows, func(i, j int) bool {
				if rows[i].Rules != rows[j].Rules {
					return rows[i].Rules > rows[j].Rules
				}
				return rows[i].Path < rows[j].Path
			})
			if limit > 0 && len(rows) > limit {
				rows = rows[:limit]
			}
			if asJSON {
				return printJSON(cmd, rows)
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "PATH\tRULES\tTECHS\tSTATE\tEXAMPLES\tCONCERNS")
			for _, x := range rows {
				fmt.Fprintf(w, "%s\t%d\t%d\t%s\t%s\t%s\n", x.Path, x.Rules, x.Technologies, x.State, strings.Join(x.Examples, ", "), strings.Join(x.Concerns, "; "))
			}
			_ = w.Flush()
			fmt.Fprintf(cmd.OutOrStdout(), "%d paths\n", len(rows))
			return nil
		},
	}
	c.Flags().StringVar(&state, "state", "", "only paths in this state: pending, approved, rejected, mixed")
	c.Flags().IntVar(&limit, "limit", 0, "show at most this many (0: all)")
	c.Flags().BoolVar(&asJSON, "json", false, "output JSON")
	return c
}

func newProbeReviewCmd(o *options) *cobra.Command {
	var decision, note string
	var all, dryRun bool
	c := &cobra.Command{
		Use:   "review <path>...",
		Short: "Approve, reject or reset the probes of one or more paths",
		Long: "review records your decision on the probes that request the given paths. Approving makes\n" +
			"every rule that probes the path active, so the scanner can send the request with --active:\n" +
			"a GET to that path of the site being scanned. Approve only a request you are willing to see\n" +
			"sent to any site anyone scans with this registry: a static file, an API index, a login page\n" +
			"that is only fetched. Never approve a path that changes state, even if it is a GET.\n" +
			"A note naming your basis is required. Only absolute paths, only GET. --all-pending applies\n" +
			"the decision to every path still pending (use --dry-run first).",
		Example: "  owf probe list --limit 30\n" +
			"  owf probe review /robots.txt /sitemap.xml /favicon.ico --decision approved --note \"static files, read-only\"",
		RunE: func(cmd *cobra.Command, args []string) error {
			if all == (len(args) > 0) {
				return fmt.Errorf("give paths, or --all-pending")
			}
			r, err := o.open(cmd.Context())
			if err != nil {
				return err
			}
			defer func() { _ = r.Close() }()
			paths := args
			if all {
				recs, err := r.AllRecords(cmd.Context())
				if err != nil {
					return err
				}
				seen := map[string]bool{}
				for _, f := range recs.Fingerprints {
					if f.Probe != nil && f.Probe.SafetyReview == curate.ProbePending && f.Probe.Method == "GET" && !seen[f.Probe.Path] && curate.SafePath(f.Probe.Path) == nil {
						seen[f.Probe.Path] = true
						paths = append(paths, f.Probe.Path)
					}
				}
				sort.Strings(paths)
			}
			out := cmd.OutOrStdout()
			if dryRun {
				fmt.Fprintf(out, "dry run, nothing stored: %q would be recorded for %d path(s)\n", decision, len(paths))
				for _, p := range paths {
					fmt.Fprintf(out, "  %s\n", p)
				}
				return nil
			}
			res, err := curate.ReviewProbes(cmd.Context(), r, curate.ProbeReview{Paths: paths, Decision: decision, Note: note}, time.Now())
			if err != nil {
				return err
			}
			fmt.Fprintf(out, "%s: %d rule(s) on %d path(s) changed\n", decision, res.Rules, len(res.Paths))
			return nil
		},
	}
	c.Flags().StringVar(&decision, "decision", "", "approved, rejected or pending (pending withdraws a decision)")
	c.Flags().StringVar(&note, "note", "", "the basis of the decision (required for approved and rejected)")
	c.Flags().BoolVar(&all, "all-pending", false, "apply to every path that is still pending")
	c.Flags().BoolVar(&dryRun, "dry-run", false, "list the paths without storing anything")
	_ = c.MarkFlagRequired("decision")
	return c
}
