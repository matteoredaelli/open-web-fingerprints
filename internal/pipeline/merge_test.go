// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package pipeline_test

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/matteoredaelli/open-web-fingerprints/internal/domain"
	"github.com/matteoredaelli/open-web-fingerprints/internal/merge"
	"github.com/matteoredaelli/open-web-fingerprints/internal/pipeline"
	"github.com/matteoredaelli/open-web-fingerprints/internal/repository"
	"github.com/matteoredaelli/open-web-fingerprints/internal/review"
	"github.com/matteoredaelli/open-web-fingerprints/internal/validator"
)

// secondWithLowerConfidence is the second source's snapshot with a lower
// explicit confidence on one AdOcean rule.
func secondWithLowerConfidence(t *testing.T, website string) fstest.MapFS {
	m := secondSnapshot(t, website)
	editTechFile(t, m, "src/technologies/a.json", func(d map[string]map[string]any) {
		l := d["AdOcean"]["scriptSrc"].([]any)
		for i, x := range l {
			l[i] = strings.ReplaceAll(x.(string), "confidence:80", "confidence:60")
		}
	})
	return m
}

func resolve(t *testing.T, repo repository.Repository, req review.Request) *review.Result {
	t.Helper()
	res, err := review.Resolve(context.Background(), repo, req)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func mergeAllCandidates(t *testing.T, repo repository.Repository, websites string) *review.Result {
	return resolve(t, repo, review.Request{Bulk: true, Decision: merge.Merge, Websites: websites})
}

// shape describes the registry without IDs or slugs, so that registries built
// in a different import order can be compared.
func shape(t *testing.T, repo repository.Repository) []string {
	t.Helper()
	all, err := repo.AllRecords(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	name := map[domain.TechnologyID]string{}
	for _, x := range all.Technologies {
		name[x.ID] = x.Name
	}
	var out []string
	for _, x := range all.Technologies {
		out = append(out, fmt.Sprintf("T|%s|%d|%d", x.Name, len(x.Provenance), len(x.CategoryIDs)))
	}
	for _, f := range all.Fingerprints {
		out = append(out, fmt.Sprintf("F|%s|%s|%s|%s|%s|%d", name[f.TechnologyID], f.Observation,
			strings.ToLower(f.Target), f.Operator, f.Pattern, len(f.Provenance)))
	}
	for _, c := range all.Categories {
		out = append(out, fmt.Sprintf("C|%s|%d", c.Name, len(c.Provenance)))
	}
	sort.Strings(out)
	return out
}

func TestMergeCombinesRecordsAndSurvivesReimport(t *testing.T) {
	eachBackend(t, func(t *testing.T) {
		p, repo := setup(t)
		ctx := context.Background()
		run(t, p, mapFS(t), "r1")
		runAs(t, p, source2(), secondWithLowerConfidence(t, "https://aframe.example"), "r1")
		beforeRecs, _ := repo.AllRecords(ctx)
		beforeFPs := len(beforeRecs.Fingerprints)

		dry := resolve(t, repo, review.Request{Bulk: true, Decision: merge.Merge, Websites: "same_domain", DryRun: true})
		if dry.Applied || dry.Merged == 0 {
			t.Fatalf("dry run: %+v", dry)
		}
		if after, _ := repo.AllRecords(ctx); len(after.Technologies) != len(beforeRecs.Technologies) {
			t.Fatal("dry run changed the registry")
		}

		res := mergeAllCandidates(t, repo, "same_domain")
		if !res.Applied || len(res.Delete.Technologies) != 20 {
			t.Fatalf("result: %+v", res)
		}
		resolve(t, repo, review.Request{Bulk: true, Decision: merge.Merge, Kind: domain.ConflictCategoryCandidate})

		all, _ := repo.AllRecords(ctx)
		if len(all.Technologies) != 44-20 {
			t.Fatalf("technologies = %d, want 24", len(all.Technologies))
		}
		if issues := validator.Validate(all); len(issues) != 0 {
			t.Fatalf("merged registry is invalid: %v", issues[:min(3, len(issues))])
		}
		// Equivalent rules were combined: every rule key is unique per technology.
		seen := map[string]bool{}
		var twoSources int
		for _, f := range all.Fingerprints {
			if seen[f.SemanticKey()] {
				t.Fatalf("duplicate rule after merge: %+v", f)
			}
			seen[f.SemanticKey()] = true
			if len(f.Provenance) >= 2 {
				twoSources++
			}
		}
		if twoSources == 0 || len(all.Fingerprints) >= beforeFPs {
			t.Errorf("rules were not combined: %d before, %d after, %d with two sources", beforeFPs, len(all.Fingerprints), twoSources)
		}
		for _, x := range all.Technologies {
			if x.Name == "WordPress" || x.Name == "AdOcean" {
				srcs := map[domain.SourceID]bool{}
				for _, pr := range x.Provenance {
					srcs[pr.SourceID] = true
				}
				if x.Name == "AdOcean" && len(srcs) != 2 {
					t.Errorf("AdOcean sources = %d", len(srcs))
				}
			}
		}

		// Confidence: the lowest explicit value wins, and the disagreement is a conflict.
		var adocean *domain.Fingerprint
		for i := range all.Fingerprints {
			f := &all.Fingerprints[i]
			if f.Pattern == `adocean\.pl` {
				adocean = f
			}
		}
		if adocean == nil || adocean.Confidence != 0.6 || len(adocean.Provenance) != 2 {
			t.Fatalf("AdOcean rule: %+v", adocean)
		}
		var disagree int
		for _, c := range conflictsOf(t, repo) {
			if c.Kind == domain.ConflictConfidence && c.State == domain.ConflictOpen {
				disagree++
			}
		}
		if disagree != 1 {
			t.Errorf("confidence conflicts = %d", disagree)
		}
		aliases, _ := repo.Aliases(ctx)
		if len(aliases) < 20 {
			t.Errorf("aliases = %d", len(aliases))
		}

		// Re-importing either source must not undo or alter the merge.
		snapshot := shape(t, repo)
		for i, imp := range []func() *pipeline.Report{
			func() *pipeline.Report { return run(t, p, mapFS(t), "r1") },
			func() *pipeline.Report {
				return runAs(t, p, source2(), secondWithLowerConfidence(t, "https://aframe.example"), "r1")
			},
		} {
			rep := imp()
			if !rep.Diff.IsEmpty() {
				t.Fatalf("re-import %d changes a merged registry: %+v", i, rep.Diff)
			}
		}
		if got := shape(t, repo); strings.Join(got, "\n") != strings.Join(snapshot, "\n") {
			t.Error("merged registry changed after re-import")
		}
	})
}

func TestMergeDoesNotLetASecondSourceOverwriteContent(t *testing.T) {
	eachBackend(t, func(t *testing.T) {
		p, repo := setup(t)
		run(t, p, mapFS(t), "r1")
		runAs(t, p, source2(), secondSnapshot(t, "https://aframe.example"), "r1")
		mergeAllCandidates(t, repo, "same_domain")

		// Source 2 edits a merged technology; source 1 owns its content.
		m := secondSnapshot(t, "https://aframe.example")
		editTechFile(t, m, "src/technologies/t.json", func(d map[string]map[string]any) {
			d["TYPO3 CMS"]["description"] = "rewritten by the second source"
		})
		rep := runAs(t, p, source2(), m, "r2")
		if len(rep.Diff.Technologies.Modified) != 0 {
			t.Errorf("non-primary source modified content: %+v", rep.Diff.Technologies)
		}
		if got := getTech(repo, techID(t, repo, "TYPO3 CMS")); strings.Contains(got.Description, "rewritten") {
			t.Errorf("description overwritten: %q", got.Description)
		}

		// The owner can update it.
		m1 := mapFS(t)
		editTechFile(t, m1, "src/technologies/t.json", func(d map[string]map[string]any) {
			d["TYPO3 CMS"]["description"] = "updated by the first source"
		})
		rep = run(t, p, m1, "r2")
		if len(rep.Diff.Technologies.Modified) != 1 {
			t.Fatalf("owner update: %+v", rep.Diff.Technologies)
		}
		got := getTech(repo, techID(t, repo, "TYPO3 CMS"))
		if got.Description != "updated by the first source" || len(got.Provenance) != 2 {
			t.Errorf("after owner update: %q, %d provenance entries", got.Description, len(got.Provenance))
		}
	})
}

func TestRemovalFromOneSourceKeepsTheOther(t *testing.T) {
	eachBackend(t, func(t *testing.T) {
		p, repo := setup(t)
		run(t, p, mapFS(t), "r1")
		runAs(t, p, source2(), secondSnapshot(t, "https://aframe.example"), "r1")
		mergeAllCandidates(t, repo, "same_domain")

		m := secondSnapshot(t, "https://aframe.example")
		editTechFile(t, m, "src/technologies/t.json", func(d map[string]map[string]any) { delete(d, "TYPO3 CMS") })
		rep := runAs(t, p, source2(), m, "r2")
		if len(rep.Diff.Technologies.Removed) != 1 {
			t.Fatalf("removed: %+v", rep.Diff.Technologies)
		}
		got := getTech(repo, techID(t, repo, "TYPO3 CMS"))
		states := map[domain.SourceID]string{}
		for _, pr := range got.Provenance {
			states[pr.SourceID] = pr.State
		}
		var present, removed int
		for _, s := range states {
			if s == "present" {
				present++
			}
			if s == "removed_upstream" {
				removed++
			}
		}
		if present != 1 || removed != 1 {
			t.Errorf("provenance states: %v", states)
		}
	})
}

func TestMergeIsIndependentOfImportOrder(t *testing.T) {
	eachBackend(t, func(t *testing.T) {
		build := func(firstIsA bool) []string {
			p, repo := setup(t)
			a := func() { run(t, p, mapFS(t), "r1") }
			b := func() { runAs(t, p, source2(), secondWithLowerConfidence(t, "https://aframe.example"), "r1") }
			if firstIsA {
				a()
				b()
			} else {
				b()
				a()
			}
			mergeAllCandidates(t, repo, "same_domain")
			resolve(t, repo, review.Request{Bulk: true, Decision: merge.Merge, Kind: domain.ConflictCategoryCandidate})
			return shape(t, repo)
		}
		x, y := build(true), build(false)
		if strings.Join(x, "\n") != strings.Join(y, "\n") {
			t.Errorf("merged registry depends on import order")
			for i := 0; i < len(x) && i < len(y); i++ {
				if x[i] != y[i] {
					t.Logf("first difference:\n  %s\n  %s", x[i], y[i])
					break
				}
			}
		}
	})
}

func TestManualDecisions(t *testing.T) {
	eachBackend(t, func(t *testing.T) {
		p, repo := setup(t)
		ctx := context.Background()
		run(t, p, mapFS(t), "r1")
		runAs(t, p, source2(), secondSnapshot(t, "https://aframe.example"), "r1")

		var diff domain.Conflict
		for _, c := range conflictsOf(t, repo) {
			if c.Detail["websites"] == "different" {
				diff = c
			}
		}
		// Keep separate.
		resolve(t, repo, review.Request{IDs: []domain.ConflictID{diff.ID}, Decision: merge.KeepSeparate, Note: "different product"})
		for _, c := range conflictsOf(t, repo) {
			if c.ID == diff.ID && (c.State != domain.ConflictIgnored || !strings.Contains(c.Resolution, "different product")) {
				t.Fatalf("keep-separate: %+v", c)
			}
		}
		// A closed conflict cannot be decided again (only a merge may reverse a keep-separate).
		if _, err := review.Resolve(ctx, repo, review.Request{IDs: []domain.ConflictID{diff.ID}, Decision: merge.KeepSeparate}); err == nil {
			t.Error("deciding a closed conflict must fail")
		}
		// Bulk without filters or IDs is refused.
		if _, err := review.Resolve(ctx, repo, review.Request{Decision: merge.Merge}); err == nil {
			t.Error("a request with no selection must fail")
		}
		// Unknown ID.
		if _, err := review.Resolve(ctx, repo, review.Request{IDs: []domain.ConflictID{"cfl_nope"}, Decision: merge.Merge}); err == nil {
			t.Error("unknown conflict must fail")
		}
		// Re-importing keeps the decision.
		runAs(t, p, source2(), secondSnapshot(t, "https://aframe.example"), "r1")
		for _, c := range conflictsOf(t, repo) {
			if c.ID == diff.ID && c.State != domain.ConflictIgnored {
				t.Error("decision lost after re-import")
			}
		}

		// Merge a pair with different websites by hand: the survivor keeps its
		// website and a metadata conflict records the other one.
		resolve(t, repo, review.Request{Bulk: true, Decision: merge.KeepSeparate, Websites: "different", State: domain.ConflictIgnored})
		_ = diff
	})
}

func TestManualMergeOfDifferentWebsitesRecordsMetadataConflict(t *testing.T) {
	eachBackend(t, func(t *testing.T) {
		p, repo := setup(t)
		run(t, p, mapFS(t), "r1")
		runAs(t, p, source2(), secondSnapshot(t, "https://aframe.example"), "r1")
		var diff domain.Conflict
		for _, c := range conflictsOf(t, repo) {
			if c.Detail["websites"] == "different" {
				diff = c
			}
		}
		resolve(t, repo, review.Request{IDs: []domain.ConflictID{diff.ID}, Decision: merge.Merge, Note: "same product, new domain"})
		var meta []domain.Conflict
		for _, c := range conflictsOf(t, repo) {
			if c.Kind == domain.ConflictMetadata {
				meta = append(meta, c)
			}
		}
		if len(meta) != 1 || meta[0].Detail["field"] != "website" || meta[0].Detail["kept"] == meta[0].Detail["other"] {
			t.Fatalf("metadata conflicts: %+v", meta)
		}
		tech := getTech(repo, techID(t, repo, "A-Frame"))
		if tech.Website != "https://aframe.io" {
			t.Errorf("survivor must keep the older record's website, got %q", tech.Website)
		}
		// The merged away name is not lost: a second import still maps to the survivor.
		if rep := runAs(t, p, source2(), secondSnapshot(t, "https://aframe.example"), "r1"); !rep.Diff.IsEmpty() {
			t.Errorf("re-import after manual merge: %+v", rep.Diff)
		}
	})
}
