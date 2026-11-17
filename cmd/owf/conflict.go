// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"fmt"
	"sort"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/matteoredaelli/open-web-fingerprints/internal/domain"
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
	c.AddCommand(list)
	return c
}
