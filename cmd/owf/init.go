// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/matteoredaelli/open-web-fingerprints/internal/repository/sqlite"
)

func newInitCmd(o *options) *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Create the registry database and apply migrations",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			r, err := sqlite.Open(cmd.Context(), o.db)
			if err != nil {
				return err
			}
			defer func() { _ = r.Close() }()
			v, err := r.SchemaVersion(cmd.Context())
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "registry %s ready (schema version %d)\n", o.db, v)
			return nil
		},
	}
}
