// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package pipeline_test

import (
	"context"
	"io/fs"
	"os"
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

func source2() domain.Source {
	s := source()
	s.Slug, s.Name = "enthec-copy", "Enthec copy"
	return s
}

func runAs(t *testing.T, p *pipeline.Pipeline, src domain.Source, fsys fs.FS, rev string) *pipeline.Report {
	t.Helper()
	rep, err := p.Run(context.Background(), pipeline.Request{Source: src, Revision: rev, FS: fsys})
	if err != nil {
		t.Fatalf("run %s %s: %v", src.Slug, rev, err)
	}
	return rep
}

// secondSnapshot is the fixture with one changed website, one removed and
// one new technology.
func secondSnapshot(t *testing.T, website string) fstest.MapFS {
	m := mapFS(t)
	editTechFile(t, m, "src/technologies/a.json", func(d map[string]map[string]any) {
		d["A-Frame"]["website"] = website
		delete(d, "a-blog cms")
		d["Zeta"] = map[string]any{"cats": []int{1}, "website": "https://zeta.example", "headers": map[string]string{"X-Zeta": ""}}
	})
	return m
}

func conflictsOf(t *testing.T, repo repository.Repository) []domain.Conflict {
	t.Helper()
	c, err := repo.Conflicts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func summarize(cs []domain.Conflict) []string {
	var out []string
	for _, c := range cs {
		out = append(out, c.Kind+"|"+c.Detail["identity"]+"|"+c.Detail["websites"])
	}
	sort.Strings(out)
	return out
}

func TestSecondSourceCreatesCandidatesNotMerges(t *testing.T) {
	eachBackend(t, func(t *testing.T) {
		p, repo := setup(t)
		run(t, p, mapFS(t), "r1")
		rep := runAs(t, p, source2(), secondSnapshot(t, "https://aframe.example"), "r1")

		all, _ := repo.AllRecords(context.Background())
		if len(all.Technologies) != 22+22 {
			t.Fatalf("technologies = %d, want 44 (no automatic merge)", len(all.Technologies))
		}
		slugs := map[string]bool{}
		for _, x := range all.Technologies {
			if slugs[x.Slug] {
				t.Fatalf("duplicate slug %s", x.Slug)
			}
			slugs[x.Slug] = true
		}
		if !slugs["a-frame"] || !slugs["a-frame-2"] {
			t.Error("the later record must get a suffixed slug")
		}

		cs := conflictsOf(t, repo)
		var ident, cat, different, same int
		for _, c := range cs {
			switch c.Kind {
			case domain.ConflictIdentityCandidate:
				ident++
				switch c.Detail["websites"] {
				case "different":
					different++
				case "same_domain":
					same++
				}
			case domain.ConflictCategoryCandidate:
				cat++
			}
			if c.State != domain.ConflictOpen || len(c.RecordIDs) != 2 || len(c.SourceIDs) != 2 {
				t.Errorf("bad conflict %+v", c)
			}
		}
		if ident != 21 || different != 1 || same < 15 {
			t.Errorf("identity candidates=%d different=%d same_domain=%d", ident, different, same)
		}
		if cat == 0 {
			t.Error("shared categories must be candidates")
		}
		if len(rep.Diff.Conflicts.Added) != len(cs) {
			t.Errorf("report lists %d new conflicts, %d stored", len(rep.Diff.Conflicts.Added), len(cs))
		}

		// Importing again changes nothing, including conflicts.
		again := runAs(t, p, source2(), secondSnapshot(t, "https://aframe.example"), "r1")
		if !again.Diff.IsEmpty() {
			t.Errorf("second import must be empty: %+v", again.Diff)
		}
		first := run(t, p, mapFS(t), "r1")
		if !first.Diff.IsEmpty() {
			t.Errorf("re-importing the first source must be empty: %+v", first.Diff)
		}
		if len(conflictsOf(t, repo)) != len(cs) {
			t.Error("conflict count changed")
		}
	})
}

func TestCandidatesDoNotDependOnImportOrder(t *testing.T) {
	eachBackend(t, func(t *testing.T) {
		pa, ra := setup(t)
		run(t, pa, mapFS(t), "r1")
		runAs(t, pa, source2(), secondSnapshot(t, "https://aframe.example"), "r1")

		pb, rb := setup(t)
		runAs(t, pb, source2(), secondSnapshot(t, "https://aframe.example"), "r1")
		run(t, pb, mapFS(t), "r1")

		a, b := summarize(conflictsOf(t, ra)), summarize(conflictsOf(t, rb))
		if strings.Join(a, "\n") != strings.Join(b, "\n") {
			t.Errorf("conflicts depend on import order:\n%v\n%v", a, b)
		}
	})
}

func TestResolvedConflictStaysResolvedUntilEvidenceChanges(t *testing.T) {
	eachBackend(t, func(t *testing.T) {
		p, repo := setup(t)
		ctx := context.Background()
		run(t, p, mapFS(t), "r1")
		runAs(t, p, source2(), secondSnapshot(t, "https://aframe.example"), "r1")

		var target domain.Conflict
		for _, c := range conflictsOf(t, repo) {
			if c.Detail["websites"] == "different" {
				target = c
			}
		}
		target.State, target.Resolution = domain.ConflictIgnored, "different products"
		if err := repo.Apply(ctx, repository.ChangeSet{Conflicts: []domain.Conflict{target}}); err != nil {
			t.Fatal(err)
		}

		// Same evidence: stays ignored.
		runAs(t, p, source2(), secondSnapshot(t, "https://aframe.example"), "r1")
		runAs(t, p, source(), mapFS(t), "r2")
		for _, c := range conflictsOf(t, repo) {
			if c.ID == target.ID && (c.State != domain.ConflictIgnored || c.Resolution == "") {
				t.Fatalf("resolution lost: %+v", c)
			}
		}

		// New evidence (the website changes): reopened, history kept.
		rep := runAs(t, p, source2(), secondSnapshot(t, "https://aframe.io"), "r2")
		if len(rep.Diff.Conflicts.Modified) != 1 {
			t.Fatalf("conflict diff: %+v", rep.Diff.Conflicts)
		}
		for _, c := range conflictsOf(t, repo) {
			if c.ID != target.ID {
				continue
			}
			if c.State != domain.ConflictOpen || c.Resolution != "" || !c.CreatedAt.Equal(target.CreatedAt) {
				t.Errorf("must be reopened keeping CreatedAt: %+v", c)
			}
			if c.Detail["websites"] != "same_domain" {
				t.Errorf("detail not refreshed: %v", c.Detail)
			}
		}
	})
}

func TestEquivalentRulesKeepOneRecordWithTwoProvenanceEntries(t *testing.T) {
	eachBackend(t, func(t *testing.T) {
		p, repo := setup(t)
		fsys := mapFS(t)
		edit := func(h map[string]string) {
			editTechFile(t, fsys, "src/technologies/a.json", func(d map[string]map[string]any) {
				d["Zeta"] = map[string]any{"cats": []int{1}, "website": "https://zeta.example", "headers": h}
			})
		}
		count := func(r *pipeline.Report) (int, int) {
			return len(r.Diff.Fingerprints.Modified), len(r.Diff.Fingerprints.Removed)
		}
		edit(map[string]string{"X-Zeta": "", "x-zeta": ""}) // header names are case-insensitive
		rep := run(t, p, fsys, "r1")
		all, _ := repo.AllRecords(context.Background())
		var zeta []domain.Fingerprint
		for _, f := range all.Fingerprints {
			if len(f.Provenance) == 2 {
				zeta = append(zeta, f)
			}
		}
		if len(zeta) != 1 || len(rep.Diff.Fingerprints.Added) != len(all.Fingerprints) {
			t.Fatalf("merged rules = %d", len(zeta))
		}
		if again := run(t, p, fsys, "r1"); !again.Diff.IsEmpty() {
			t.Fatalf("idempotency with merged rules: %+v", again.Diff)
		}

		// One upstream rule disappears: the canonical rule stays, modified.
		edit(map[string]string{"X-Zeta": ""})
		m, r := count(run(t, p, fsys, "r2"))
		if m != 1 || r != 0 {
			t.Errorf("one duplicate gone: modified=%d removed=%d", m, r)
		}
		// Both gone: now it is removed upstream, never deleted.
		edit(map[string]string{})
		m, r = count(run(t, p, fsys, "r3"))
		if r != 1 {
			t.Errorf("all gone: modified=%d removed=%d", m, r)
		}
		all, _ = repo.AllRecords(context.Background())
		var found bool
		for _, f := range all.Fingerprints {
			if f.ID == domain.FingerprintID(zeta[0].ID) {
				found = true
				if f.Provenance[0].State != "removed_upstream" {
					t.Errorf("state = %s", f.Provenance[0].State)
				}
			}
		}
		if !found {
			t.Error("record deleted")
		}
	})
}

// Opt-in: two full local clones (Enthec and HTTP Archive share a format).
func TestFullTwoSources(t *testing.T) {
	a, b := os.Getenv("OWF_ENTHEC_SNAPSHOT"), os.Getenv("OWF_HTTPARCHIVE_SNAPSHOT")
	if a == "" || b == "" {
		t.Skip("OWF_ENTHEC_SNAPSHOT and OWF_HTTPARCHIVE_SNAPSHOT not set")
	}
	backend = "sqlite"
	p, repo := setup(t)
	include := func(path string) bool {
		return path == "src/categories.json" || path == "src/groups.json" || strings.HasPrefix(path, "src/technologies/")
	}
	imp := func(src domain.Source, dir string) *pipeline.Report {
		rep, err := p.Run(context.Background(), pipeline.Request{Source: src, Revision: "full", FS: os.DirFS(dir), IncludeFile: include})
		if err != nil {
			t.Fatalf("%s: %v %v", src.Slug, err, rep.Issues)
		}
		return rep
	}
	imp(source(), a)
	hb := source2()
	hb.Slug = "httparchive"
	rep := imp(hb, b)
	cs := conflictsOf(t, repo)
	kinds := map[string]int{}
	for _, c := range cs {
		kinds[c.Kind+"/"+c.Detail["websites"]]++
	}
	all, _ := repo.AllRecords(context.Background())
	t.Logf("technologies=%d fingerprints=%d conflicts=%v", len(all.Technologies), len(all.Fingerprints), kinds)
	if again := imp(hb, b); !again.Diff.IsEmpty() {
		t.Errorf("re-import not empty: %+v", again.Diff)
	}
	_ = rep

	// Review: approve same-domain matches and shared categories in bulk.
	res, err := review.Resolve(context.Background(), repo, review.Request{Bulk: true, Decision: merge.Merge, Websites: "same_domain"})
	if err != nil {
		t.Fatal(err)
	}
	cat, err := review.Resolve(context.Background(), repo, review.Request{Bulk: true, Decision: merge.Merge, Kind: domain.ConflictCategoryCandidate})
	if err != nil {
		t.Fatal(err)
	}
	all, _ = repo.AllRecords(context.Background())
	if issues := validator.Validate(all); len(issues) != 0 {
		t.Fatalf("%d issues after merge, first: %v", len(issues), issues[0])
	}
	open := 0
	for _, c := range conflictsOf(t, repo) {
		if c.State == domain.ConflictOpen {
			open++
		}
	}
	t.Logf("merged %d technologies (%d rules combined, %d relationships absorbed, %d self refs dropped), %d categories; now technologies=%d fingerprints=%d open conflicts=%d",
		res.Merged, len(res.Delete.Fingerprints), len(res.Delete.Relationships), res.SelfRelations, cat.Merged,
		len(all.Technologies), len(all.Fingerprints), open)
	for _, src := range []struct {
		s   domain.Source
		dir string
	}{{source(), a}, {hb, b}} {
		if again := imp(src.s, src.dir); !again.Diff.IsEmpty() {
			t.Errorf("re-import of %s after merge is not empty: %+v", src.s.Slug,
				[]int{len(again.Diff.Technologies.Modified), len(again.Diff.Fingerprints.Modified), len(again.Diff.Categories.Modified), len(again.Diff.Relationships.Modified), len(again.Diff.Conflicts.Added)})
		}
	}
}
