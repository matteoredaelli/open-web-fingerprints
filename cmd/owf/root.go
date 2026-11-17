// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/matteoredaelli/open-web-fingerprints/internal/builtin"
	"github.com/matteoredaelli/open-web-fingerprints/internal/fetch"
	"github.com/matteoredaelli/open-web-fingerprints/internal/repository/sqlite"
)

// options are shared by all commands.
type options struct {
	db      string
	entries []builtin.Entry
	git     *fetch.Git
}

// find returns the known source with the given slug.
func (o *options) find(slug string) (builtin.Entry, bool) {
	for _, e := range o.entries {
		if e.Source.Slug == slug {
			return e, true
		}
	}
	return builtin.Entry{}, false
}

func newRootCmd() *cobra.Command {
	return newRootCmdWith(&options{entries: builtin.Sources(), git: fetch.New()})
}

// newRootCmdWith builds the command tree on the given dependencies; tests
// replace the source catalogue and the fetcher.
func newRootCmdWith(o *options) *cobra.Command {
	root := &cobra.Command{
		Use:           "owf",
		Short:         "Open Web Fingerprints registry toolkit",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	def := os.Getenv("OWF_DB")
	if def == "" {
		def = "owf.db"
	}
	root.PersistentFlags().StringVar(&o.db, "db", def, "path to the SQLite registry (env OWF_DB)")
	root.AddCommand(
		newInitCmd(o), newSourceCmd(o), newImportCmd(o), newTechnologyCmd(o),
		newFingerprintCmd(o), newVendorCmd(o), newConflictCmd(o), newExportCmd(o), newStatsCmd(o),
	)
	return root
}

// open opens an existing registry; it does not create one.
func (o *options) open(ctx context.Context) (*sqlite.Repo, error) {
	if _, err := os.Stat(o.db); err != nil {
		return nil, fmt.Errorf("registry %q not found; run `owf init` first", o.db)
	}
	return sqlite.Open(ctx, o.db)
}
