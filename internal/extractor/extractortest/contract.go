// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

// Package extractortest provides the contract tests every extractor must pass.
package extractortest

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/matteoredaelli/open-web-fingerprints/internal/domain"
	"github.com/matteoredaelli/open-web-fingerprints/internal/extractor"
)

var validOps = map[domain.Operator]bool{
	domain.OpExists: true, domain.OpEquals: true, domain.OpContains: true,
	domain.OpRegex: true, domain.OpHashEquals: true,
}

// RunContract checks the behavior required of any extractor against a
// deterministic fixture snapshot.
func RunContract(t *testing.T, e extractor.Extractor, src extractor.Source) {
	t.Helper()

	if e.ID() == "" || e.Name() == "" {
		t.Fatal("ID and Name must be non-empty")
	}

	t.Run("deterministic", func(t *testing.T) {
		a, err := e.Extract(context.Background(), src)
		if err != nil {
			t.Fatal(err)
		}
		b, err := e.Extract(context.Background(), src)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(a, b) {
			t.Fatal("two extractions of the same snapshot differ")
		}
	})

	t.Run("cancelled context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := e.Extract(ctx, src); !errors.Is(err, context.Canceled) {
			t.Fatalf("want context.Canceled, got %v", err)
		}
	})

	t.Run("well-formed result", func(t *testing.T) {
		res, err := e.Extract(context.Background(), src)
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Technologies) == 0 {
			t.Fatal("fixture produced no technologies")
		}
		techs := map[string]bool{}
		for _, x := range res.Technologies {
			if x.Key == "" || x.Name == "" {
				t.Errorf("technology with empty key or name: %+v", x)
			}
			if techs[x.Key] {
				t.Errorf("duplicate technology key %q", x.Key)
			}
			techs[x.Key] = true
		}
		cats := map[string]bool{}
		for _, c := range res.Categories {
			cats[c.Key] = true
		}
		for _, x := range res.Technologies {
			for _, k := range x.CategoryKeys {
				if !cats[k] {
					t.Errorf("technology %q references unknown category %q", x.Key, k)
				}
			}
		}
		for i, f := range res.Fingerprints {
			if !techs[f.TechnologyKey] {
				t.Errorf("fingerprint %d references unknown technology %q", i, f.TechnologyKey)
			}
			if f.Observation == "" {
				t.Errorf("fingerprint %d has no observation", i)
			}
			if !validOps[f.Operator] {
				t.Errorf("fingerprint %d has invalid operator %q", i, f.Operator)
			}
			if f.Operator == domain.OpRegex && f.RegexFlavor == "" {
				t.Errorf("fingerprint %d is a regex without flavor", i)
			}
			if f.Confidence != nil && (*f.Confidence < 0 || *f.Confidence > 1) {
				t.Errorf("fingerprint %d confidence out of range", i)
			}
			if f.Probe != nil && f.Probe.SafetyReview == "approved" {
				t.Errorf("fingerprint %d: extractors must not pre-approve probes", i)
			}
		}
		for i, r := range res.Relationships {
			if !techs[r.FromKey] {
				t.Errorf("relationship %d has unknown source technology %q", i, r.FromKey)
			}
			if (r.ToTechnologyKey == "") == (r.ToCategoryKey == "") {
				t.Errorf("relationship %d needs exactly one target", i)
			}
		}
	})
}
