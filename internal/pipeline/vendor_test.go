// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package pipeline_test

import (
	"context"
	"strings"
	"testing"

	"github.com/matteoredaelli/open-web-fingerprints/internal/domain"
	"github.com/matteoredaelli/open-web-fingerprints/internal/repository"
	"github.com/matteoredaelli/open-web-fingerprints/internal/validator"
)

func vendorsOf(t *testing.T, repo repository.Repository) map[string]domain.Vendor {
	t.Helper()
	all, err := repo.AllRecords(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]domain.Vendor{}
	for _, v := range all.Vendors {
		out[v.CPEVendor] = v
	}
	return out
}

func TestVendorsAreSharedAcrossSourcesAndIdempotent(t *testing.T) {
	eachBackend(t, func(t *testing.T) {
		p, repo := setup(t)
		ctx := context.Background()
		rep := run(t, p, mapFS(t), "r1")
		first := vendorsOf(t, repo)
		if len(first) < 3 || rep.Counts.Vendors != len(first) || len(rep.Diff.Vendors.Added) != len(first) {
			t.Fatalf("vendors = %d, counts=%+v diff=%+v", len(first), rep.Counts, rep.Diff.Vendors)
		}
		all, _ := repo.AllRecords(ctx)
		var withVendor int
		for _, x := range all.Technologies {
			if x.VendorID != "" {
				withVendor++
			}
		}
		if withVendor < len(first) {
			t.Errorf("technologies with a vendor: %d", withVendor)
		}
		if issues := validator.Validate(all); len(issues) != 0 {
			t.Fatalf("invalid: %v", issues)
		}
		if again := run(t, p, mapFS(t), "r1"); !again.Diff.IsEmpty() {
			t.Fatalf("re-import: %+v", again.Diff)
		}

		// A second source describing the same technologies reuses the vendors.
		rep2 := runAs(t, p, source2(), secondSnapshot(t, "https://aframe.example"), "r1")
		second := vendorsOf(t, repo)
		if len(second) != len(first) || len(rep2.Diff.Vendors.Added) != 0 {
			t.Fatalf("vendors must be shared: %d then %d, diff %+v", len(first), len(second), rep2.Diff.Vendors)
		}
		for tok, v := range second {
			if v.ID != first[tok].ID {
				t.Errorf("vendor %s changed ID", tok)
			}
			srcs := map[domain.SourceID]bool{}
			for _, pr := range v.Provenance {
				srcs[pr.SourceID] = true
			}
			if len(srcs) != 2 {
				t.Errorf("vendor %s has provenance from %d sources, want 2", tok, len(srcs))
			}
		}
		// Both sources' technologies point at the same vendor records.
		all, _ = repo.AllRecords(ctx)
		ids := map[domain.VendorID]bool{}
		for _, v := range all.Vendors {
			ids[v.ID] = true
		}
		for _, x := range all.Technologies {
			if x.VendorID != "" && !ids[x.VendorID] {
				t.Errorf("technology %s points at a missing vendor", x.Name)
			}
		}
		for _, imp := range []func() bool{
			func() bool { return run(t, p, mapFS(t), "r1").Diff.IsEmpty() },
			func() bool {
				return runAs(t, p, source2(), secondSnapshot(t, "https://aframe.example"), "r1").Diff.IsEmpty()
			},
		} {
			if !imp() {
				t.Error("re-import with shared vendors must change nothing")
			}
		}
	})
}

func TestCuratedVendorSurvivesRefreshes(t *testing.T) {
	eachBackend(t, func(t *testing.T) {
		p, repo := setup(t)
		ctx := context.Background()
		run(t, p, mapFS(t), "r1")
		vs := vendorsOf(t, repo)
		var v domain.Vendor
		for _, x := range vs {
			v = x
			break
		}
		v.Name, v.Website = "Curated Name Inc.", "https://curated.example"
		if err := repo.Apply(ctx, repository.ChangeSet{Upsert: domain.Records{Vendors: []domain.Vendor{v}}}); err != nil {
			t.Fatal(err)
		}
		runAs(t, p, source2(), secondSnapshot(t, "https://aframe.example"), "r1")
		rep := run(t, p, mapFS(t), "r1")
		if !rep.Diff.IsEmpty() {
			t.Fatalf("diff: %+v", rep.Diff)
		}
		got := vendorsOf(t, repo)[v.CPEVendor]
		if got.Name != "Curated Name Inc." || got.Website != "https://curated.example" {
			t.Errorf("curation overwritten: %+v", got)
		}
		if len(got.Provenance) < 2 {
			t.Errorf("provenance must still be updated: %+v", got.Provenance)
		}
	})
}

func TestVendorRemovedWhenNoTechnologyOfASourceUsesIt(t *testing.T) {
	eachBackend(t, func(t *testing.T) {
		p, repo := setup(t)
		run(t, p, mapFS(t), "r1")
		runAs(t, p, source2(), secondSnapshot(t, "https://aframe.example"), "r1")

		// Source 2 drops the CPE of every technology that has one.
		m := secondSnapshot(t, "https://aframe.example")
		for _, f := range []string{"src/technologies/a.json", "src/technologies/c.json", "src/technologies/n.json",
			"src/technologies/p.json", "src/technologies/s.json", "src/technologies/t.json"} {
			if _, ok := m[f]; !ok {
				continue
			}
			editTechFile(t, m, f, func(d map[string]map[string]any) {
				for _, tech := range d {
					delete(tech, "cpe")
				}
			})
		}
		rep := runAs(t, p, source2(), m, "r2")
		if len(rep.Diff.Vendors.Removed) == 0 {
			t.Fatalf("vendor diff: %+v", rep.Diff.Vendors)
		}
		for _, v := range vendorsOf(t, repo) {
			states := map[domain.SourceID]string{}
			for _, pr := range v.Provenance {
				states[pr.SourceID] = pr.State
			}
			var removed, present int
			for _, s := range states {
				if s == "removed_upstream" {
					removed++
				}
				if s == "present" {
					present++
				}
			}
			if removed != 1 || present != 1 {
				t.Errorf("vendor %s must be removed for source 2 only: %v", v.CPEVendor, states)
			}
			if strings.TrimSpace(v.Name) == "" {
				t.Error("vendor lost its name")
			}
		}
	})
}
