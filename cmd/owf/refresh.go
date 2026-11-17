// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/matteoredaelli/open-web-fingerprints/internal/fetch"
)

func defaultCache() string {
	if d := os.Getenv("OWF_CACHE"); d != "" {
		return d
	}
	if d, err := os.UserCacheDir(); err == nil {
		return filepath.Join(d, "owf", "snapshots")
	}
	return filepath.Join(os.TempDir(), "owf-snapshots")
}

func newRefreshCmd(o *options) *cobra.Command {
	var revision, branch, cache string
	var dryRun, fetchOnly bool
	c := &cobra.Command{
		Use:   "refresh <source>",
		Short: "Fetch the latest snapshot of a source and import it",
		Long: "refresh resolves the tip of the source's branch (or uses --revision), downloads\n" +
			"only that commit and only the directories the extractor needs, and runs the\n" +
			"import pipeline. Changes are stored as reviewable records and conflicts; nothing\n" +
			"is published. Use --dry-run to see the diff first.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			e, ok := o.find(args[0])
			if !ok {
				return fmt.Errorf("unknown source %q (see `owf source list`)", args[0])
			}
			if revision != "" && !fetch.ValidSHA(revision) {
				return fmt.Errorf("--revision must be a full 40-character commit ID")
			}
			if branch == "" {
				branch = e.Branch
			}
			if e.Source.URL == "" || branch == "" {
				return fmt.Errorf("source %q has no fetchable repository", e.Source.Slug)
			}
			out := cmd.OutOrStdout()
			sha := revision
			if sha == "" {
				var err error
				if sha, err = o.git.ResolveBranch(cmd.Context(), e.Source.URL, branch); err != nil {
					return err
				}
				fmt.Fprintf(out, "%s: branch %s is at %s\n", e.Source.Slug, branch, sha)
			}
			dest := filepath.Join(cache, e.Source.Slug, sha)
			res, err := o.git.Fetch(cmd.Context(), fetch.Request{
				URL: e.Source.URL, SHA: sha, Root: cache, Dest: dest, Sparse: e.SparsePaths,
			})
			if err != nil {
				return err
			}
			how := "downloaded"
			if res.Reused {
				how = "reused from cache"
			}
			fmt.Fprintf(out, "snapshot %s %s: %s\n", sha[:12], how, res.Path)
			if fetchOnly {
				return nil
			}
			return runImport(cmd, o, e, res.Path, sha, dryRun)
		},
	}
	c.Flags().StringVar(&revision, "revision", "", "pin a full commit ID instead of the branch tip")
	c.Flags().StringVar(&branch, "branch", "", "branch to follow (default: the source's branch)")
	c.Flags().StringVar(&cache, "cache", defaultCache(), "snapshot cache directory (env OWF_CACHE)")
	c.Flags().BoolVar(&dryRun, "dry-run", false, "compute the diff without storing anything")
	c.Flags().BoolVar(&fetchOnly, "fetch-only", false, "download the snapshot but do not import it")
	return c
}
