// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/matteoredaelli/open-web-fingerprints/internal/repository/sqlite"
)

// options are shared by all commands.
type options struct {
	db string
}

func newRootCmd() *cobra.Command {
	o := &options{}
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
		newFingerprintCmd(o), newExportCmd(o), newStatsCmd(o),
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
