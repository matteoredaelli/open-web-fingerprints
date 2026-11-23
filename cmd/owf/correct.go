// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/matteoredaelli/open-web-fingerprints/internal/curate"
	"github.com/matteoredaelli/open-web-fingerprints/internal/domain"
	"github.com/matteoredaelli/open-web-fingerprints/internal/validation"
)

func newFingerprintCorrectCmd(o *options) *cobra.Command {
	var field, value, reason string
	var revert bool
	c := &cobra.Command{
		Use:   "correct <fingerprint-id>",
		Short: "Correct one field of a rule that the source got wrong (a reviewer decision)",
		Long: "correct changes the target, the pattern or the version_extract of one rule and records the value the\n" +
			"source gave, the new value, your reason and the time. The importer never does this\n" +
			"by itself. A refresh keeps the correction. If the source later changes the value you\n" +
			"corrected, that is a new rule without your correction (and yours stays as removed\n" +
			"upstream), so you look again. The rule's test evidence is cleared (it was gathered\n" +
			"on the old rule). Use --revert to put the source's value back. The ID is in\n" +
			"`owf fingerprint lint`. Do not run it while an import is running.",
		Example: "  owf fingerprint lint     # finds inert_cookie_name findings with the rule IDs\n" +
			"  owf fingerprint correct fp_... --field target --value connect.sid \\\n" +
			"      --reason 'the name was written as a regex but cookie names are literal'",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			r, err := o.open(cmd.Context())
			if err != nil {
				return err
			}
			defer func() { _ = r.Close() }()
			id := domain.FingerprintID(args[0])
			var f domain.Fingerprint
			if revert {
				if cmd.Flags().Changed("field") || cmd.Flags().Changed("value") || cmd.Flags().Changed("reason") {
					return fmt.Errorf("--revert takes no --field, --value or --reason")
				}
				f, err = curate.RevertFingerprint(cmd.Context(), r, id)
				if err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%s: back to the source's value; health unknown\n", f.ID)
			} else {
				if field == "version_extract" && !cmd.Flags().Changed("value") {
					return fmt.Errorf("--field version_extract needs --value (use --value \"\" to read no version)")
				}
				f, err = curate.CorrectFingerprint(cmd.Context(), r, id, curate.Correction{Field: field, Value: value, Reason: reason}, time.Now())
				if err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%s: %s %q -> %q; health unknown\n", f.ID, f.Correction.Field, f.Correction.Original, f.Correction.Value)
			}
			// Show what the linter says about the rule now.
			for _, fi := range validation.Lint(f) {
				fmt.Fprintf(cmd.OutOrStdout(), "  lint: %s: %s\n", fi.Code, fi.Message)
			}
			return nil
		},
	}
	c.Flags().StringVar(&field, "field", "target", "field to correct: target, pattern or version_extract")
	c.Flags().StringVar(&value, "value", "", "the new value")
	c.Flags().StringVar(&reason, "reason", "", "why (required)")
	c.Flags().BoolVar(&revert, "revert", false, "remove the correction and put the source's value back")
	return c
}
