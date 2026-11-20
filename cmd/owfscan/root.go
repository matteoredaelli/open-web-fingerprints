// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import "github.com/spf13/cobra"

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "owfscan",
		Short:         "Scan a web site: technologies, links, domains, social profiles and contacts",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(newExtractCmd(), newLinksCmd(), newSocialCmd(), newObserveCmd())
	return root
}
