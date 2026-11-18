// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"fmt"
	"sort"

	"github.com/spf13/cobra"

	"github.com/matteoredaelli/open-web-fingerprints/internal/domain"
	"github.com/matteoredaelli/open-web-fingerprints/internal/repository"
	"github.com/matteoredaelli/open-web-fingerprints/internal/validation"
)

func newFingerprintTestCmd(o *options) *cobra.Command {
	var apply, asJSON, verbose, upstream bool
	c := &cobra.Command{
		Use:   "test [file-or-dir]",
		Short: "Run validation cases against the stored fingerprints",
		Long: "test evaluates recorded observations (JSON case files) against the rules they\n" +
			"select. Nothing is requested from the network. A case that fails makes the command\n" +
			"exit with an error. With --apply the results are stored as test evidence:\n" +
			"a rule becomes healthy only with a passing positive and a passing negative case,\n" +
			"and broken when any case fails.\n\n" +
			"--upstream-examples also generates cases from the examples that some sources ship\n" +
			"with their rules (Recog): positives from a rule's own examples, negatives from\n" +
			"examples of other products later in the same database. Their evidence is marked\n" +
			"as coming from upstream examples.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 && !upstream {
				return fmt.Errorf("give a case file or directory, or --upstream-examples")
			}
			var cases []validation.Loaded
			if len(args) == 1 {
				var err error
				if cases, err = validation.Load(args[0]); err != nil {
					return err
				}
			}
			r, err := o.open(cmd.Context())
			if err != nil {
				return err
			}
			defer func() { _ = r.Close() }()
			all, err := r.AllRecords(cmd.Context())
			if err != nil {
				return err
			}
			var gen validation.UpstreamStats
			if upstream {
				var g []validation.Loaded
				g, gen = validation.FromUpstreamExamples(all)
				cases = append(cases, g...)
			}
			results := validation.Run(cases, all)
			sum := validation.Summarize(results)
			stored := 0
			if apply {
				updated := validation.Apply(results, all, nowFunc())
				if len(updated) > 0 {
					if err := r.Apply(cmd.Context(), repository.ChangeSet{Upsert: domain.Records{Fingerprints: updated}}); err != nil {
						return err
					}
				}
				stored = len(updated)
			}
			if asJSON {
				type row struct {
					Ref, Status, Message string
				}
				rows := make([]row, len(results))
				for i, x := range results {
					rows[i] = row{x.Ref(), string(x.Status), x.Message}
				}
				if err := printJSON(cmd, rows); err != nil {
					return err
				}
			} else {
				out := cmd.OutOrStdout()
				for _, x := range results {
					if x.Status != validation.Pass || verbose {
						fmt.Fprintf(out, "%-11s %s %s\n", x.Status, x.Ref(), x.Message)
					}
				}
				fmt.Fprintf(out, "%d cases: %d pass, %d fail, %d error, %d unsupported\n",
					len(results), sum[validation.Pass], sum[validation.Fail], sum[validation.Error], sum[validation.Unsupported])
				if upstream {
					fmt.Fprintf(out, "upstream examples: %d rules, %d positive and %d negative cases (%d negatives checked)",
						gen.Rules, gen.Positive, gen.Negative, gen.NegativeChecks)
					for _, why := range sortedKeys(gen.Skipped) {
						fmt.Fprintf(out, "; %d rules skipped: %s", gen.Skipped[why], why)
					}
					fmt.Fprintln(out)
				}
				if apply {
					fmt.Fprintf(out, "evidence stored on %d fingerprints\n", stored)
				}
			}
			if sum[validation.Fail]+sum[validation.Error] > 0 {
				return fmt.Errorf("%d cases failed or do not fit the registry", sum[validation.Fail]+sum[validation.Error])
			}
			return nil
		},
	}
	c.Flags().BoolVar(&upstream, "upstream-examples", false, "also test rules with the examples their source ships")
	c.Flags().BoolVar(&apply, "apply", false, "store the results as test evidence on the fingerprints")
	c.Flags().BoolVar(&asJSON, "json", false, "output JSON")
	c.Flags().BoolVarP(&verbose, "verbose", "v", false, "list passing cases too")
	return c
}

func newFingerprintLintCmd(o *options) *cobra.Command {
	var asJSON bool
	var limit int
	c := &cobra.Command{
		Use:   "lint",
		Short: "Report rules that are likely to produce false positives (static, no fixtures)",
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
			findings := validation.LintAll(all)
			if asJSON {
				return printJSON(cmd, findings)
			}
			name := map[domain.TechnologyID]string{}
			for _, t := range all.Technologies {
				name[t.ID] = t.Name
			}
			rules := map[domain.FingerprintID]domain.Fingerprint{}
			for _, f := range all.Fingerprints {
				rules[f.ID] = f
			}
			byCode := map[string][]validation.Finding{}
			for _, f := range findings {
				byCode[f.Code] = append(byCode[f.Code], f)
			}
			codes := make([]string, 0, len(byCode))
			for c := range byCode {
				codes = append(codes, c)
			}
			sort.Strings(codes)
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "%d findings on %d of %d fingerprints\n", len(findings), distinct(findings), len(all.Fingerprints))
			for _, c := range codes {
				fmt.Fprintf(out, "\n%s (%d)\n", c, len(byCode[c]))
				for i, f := range byCode[c] {
					if i == limit {
						fmt.Fprintf(out, "  ... %d more (use --json)\n", len(byCode[c])-limit)
						break
					}
					ru := rules[f.RuleID]
					where := ""
					if ru.Probe != nil {
						where = " (" + ru.Probe.Method + " " + ru.Probe.Path + ")"
					}
					fmt.Fprintf(out, "  %s: %s %s %q%s\n", name[ru.TechnologyID], ru.Observation, ru.Target, ru.Pattern, where)
				}
			}
			return nil
		},
	}
	c.Flags().BoolVar(&asJSON, "json", false, "output JSON")
	c.Flags().IntVar(&limit, "limit", 8, "examples shown per finding code")
	return c
}

func distinct(fs []validation.Finding) int {
	seen := map[domain.FingerprintID]bool{}
	for _, f := range fs {
		seen[f.RuleID] = true
	}
	return len(seen)
}

func sortedKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
