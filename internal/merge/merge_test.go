// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package merge

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/matteoredaelli/open-web-fingerprints/internal/domain"
	"github.com/matteoredaelli/open-web-fingerprints/internal/reconciler"
	"github.com/matteoredaelli/open-web-fingerprints/internal/validator"
)

var now = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func alloc(kind domain.Kind, key string) (string, error) { return fmt.Sprintf("%s_%s", kind, key), nil }

func conf(v float64) *float64 { return &v }

func prov(src, orig string, c *float64) []domain.Provenance {
	return []domain.Provenance{{SourceID: domain.SourceID(src), OriginalID: orig, OriginalConfidence: c, State: "present"}}
}

func tech(id, name, site, src string) domain.Technology {
	return domain.Technology{ID: domain.TechnologyID(id), Slug: id, Name: name, Website: site, Status: domain.StatusActive, Provenance: prov(src, name, nil)}
}

func rule(id, tech, target string, c *float64, src string) domain.Fingerprint {
	return domain.Fingerprint{
		ID: domain.FingerprintID(id), TechnologyID: domain.TechnologyID(tech), Observation: domain.ObsHTTPHeader,
		Target: target, Operator: domain.OpExists, Confidence: 0.5, Status: domain.StatusActive,
		Provenance: prov(src, id, c),
	}
}

func fixture() (domain.Records, []domain.Conflict) {
	recs := domain.Records{
		Technologies: []domain.Technology{
			tech("tech_1", "Foo", "https://foo.com", "s1"),
			tech("tech_2", "foo", "https://www.foo.com", "s2"),
			tech("tech_3", "FOO", "https://foo.com", "s3"),
			tech("tech_9", "Other", "", "s1"),
		},
		Fingerprints: []domain.Fingerprint{
			rule("fp_a", "tech_1", "X-Foo", conf(0.8), "s1"),
			rule("fp_b", "tech_2", "x-foo", conf(0.6), "s2"), // same meaning as fp_a
			rule("fp_c", "tech_2", "X-Only-B", nil, "s2"),
		},
		Relationships: []domain.Relationship{
			{ID: "rel_1", FromTechnologyID: "tech_9", ToTechnologyID: "tech_1", Type: "implies", Provenance: prov("s1", "r1", nil)},
			{ID: "rel_2", FromTechnologyID: "tech_9", ToTechnologyID: "tech_2", Type: "implies", Provenance: prov("s2", "r2", nil)},
			{ID: "rel_3", FromTechnologyID: "tech_1", ToTechnologyID: "tech_2", Type: "implies", Provenance: prov("s1", "r3", nil)},
		},
	}
	var cs []domain.Conflict
	pair := func(a, b string) {
		x, y := techByID(recs, a), techByID(recs, b)
		id, _ := alloc(domain.KindConflict, reconciler.PairKey(domain.ConflictIdentityCandidate, a, b))
		cs = append(cs, domain.Conflict{
			ID: domain.ConflictID(id), Kind: domain.ConflictIdentityCandidate, State: domain.ConflictOpen,
			RecordIDs: []string{a, b}, Detail: reconciler.IdentityDetail(x, y),
		})
	}
	pair("tech_1", "tech_2")
	pair("tech_1", "tech_3")
	pair("tech_2", "tech_3")
	return recs, cs
}

func techByID(r domain.Records, id string) domain.Technology {
	for _, t := range r.Technologies {
		if string(t.ID) == id {
			return t
		}
	}
	return domain.Technology{}
}

func TestMergeTechnologies(t *testing.T) {
	recs, cs := fixture()
	w := NewWorkspace(recs, nil, cs, alloc, now)
	surv, err := w.MergeTechnologies("tech_2", "tech_1")
	if err != nil || surv != "tech_1" {
		t.Fatalf("survivor = %q err=%v (the older ID must survive)", surv, err)
	}
	cset := w.ChangeSet()

	if len(cset.Delete.Technologies) != 1 || cset.Delete.Technologies[0] != "tech_2" {
		t.Errorf("delete: %+v", cset.Delete)
	}
	// Equivalent rules combine: fp_b goes into fp_a, fp_c moves to the survivor.
	if len(cset.Delete.Fingerprints) != 1 || cset.Delete.Fingerprints[0] != "fp_b" {
		t.Errorf("deleted rules: %v", cset.Delete.Fingerprints)
	}
	var a, c *domain.Fingerprint
	for i := range cset.Upsert.Fingerprints {
		switch cset.Upsert.Fingerprints[i].ID {
		case "fp_a":
			a = &cset.Upsert.Fingerprints[i]
		case "fp_c":
			c = &cset.Upsert.Fingerprints[i]
		}
	}
	if a == nil || len(a.Provenance) != 2 || a.Confidence != 0.6 {
		t.Errorf("fp_a must have two provenance entries and the lowest explicit confidence: %+v", a)
	}
	if c == nil || c.TechnologyID != "tech_1" {
		t.Errorf("fp_c must move to the survivor: %+v", c)
	}
	// Relationships: rel_3 became tech_1 -> tech_1 and is dropped; rel_2 merges into rel_1.
	if len(cset.Delete.Relationships) != 2 || w.Stats().DroppedSelfRelationships != 1 {
		t.Errorf("relationships deleted=%v self=%d", cset.Delete.Relationships, w.Stats().DroppedSelfRelationships)
	}
	// Aliases and the survivor's content.
	if len(cset.Aliases) != 3 {
		t.Errorf("aliases: %+v", cset.Aliases)
	}
	s := cset.Upsert.Technologies[0]
	if s.ID != "tech_1" || len(s.Provenance) != 2 || len(s.Aliases) != 1 || s.Aliases[0] != "foo" {
		t.Errorf("survivor: %+v", s)
	}
	// The confidence disagreement is recorded for review.
	var found bool
	for _, x := range cset.Conflicts {
		if x.Kind == domain.ConflictConfidence && x.State == domain.ConflictOpen {
			found = true
		}
	}
	if !found {
		t.Error("missing confidence_disagreement conflict")
	}
	if _, err := w.MergeTechnologies("tech_1", "tech_2"); !errors.Is(err, ErrAlreadyMerged) {
		t.Errorf("second merge: %v", err)
	}
	if _, err := w.MergeTechnologies("tech_1", "tech_nope"); err == nil {
		t.Error("unknown record must fail")
	}
}

func TestDecideSupersedesAndReopensRemainingPairs(t *testing.T) {
	recs, cs := fixture()
	w := NewWorkspace(recs, nil, cs, alloc, now)
	id12, _ := alloc(domain.KindConflict, reconciler.PairKey(domain.ConflictIdentityCandidate, "tech_1", "tech_2"))
	if err := w.Decide(domain.ConflictID(id12), Merge, "same product"); err != nil {
		t.Fatal(err)
	}
	open := map[string]bool{}
	for _, c := range w.ChangeSet().Conflicts {
		if c.Kind == domain.ConflictIdentityCandidate && c.State == domain.ConflictOpen {
			open[fmt.Sprint(c.RecordIDs)] = true
		}
	}
	// (1,3) stays open; (2,3) was superseded and replaced by (1,3), the same pair.
	if len(open) != 1 || !open["[tech_1 tech_3]"] {
		t.Fatalf("open candidates after merge: %v", open)
	}
	for _, c := range w.ChangeSet().Conflicts {
		if c.ID == domain.ConflictID(id12) && (c.State != domain.ConflictResolved || c.Resolution == "") {
			t.Errorf("decided conflict: %+v", c)
		}
	}
	// Closed conflicts cannot be decided again.
	if err := w.Decide(domain.ConflictID(id12), Merge, ""); err == nil {
		t.Error("deciding a closed conflict must fail")
	}
	if err := w.Decide("cfl_nope", Merge, ""); err == nil {
		t.Error("unknown conflict must fail")
	}
}

func TestMergedRegistryIsValid(t *testing.T) {
	recs, cs := fixture()
	w := NewWorkspace(recs, nil, cs, alloc, now)
	for _, p := range [][2]string{{"tech_1", "tech_2"}, {"tech_1", "tech_3"}} {
		if _, err := w.MergeTechnologies(p[0], p[1]); err != nil {
			t.Fatal(err)
		}
	}
	cset := w.ChangeSet()
	// Apply the change set to the fixture by hand and validate the result.
	del := map[string]bool{}
	for _, id := range append(append(cset.Delete.Technologies, cset.Delete.Fingerprints...), cset.Delete.Relationships...) {
		del[id] = true
	}
	out := domain.Records{}
	up := map[string]bool{}
	for _, x := range cset.Upsert.Technologies {
		out.Technologies = append(out.Technologies, x)
		up[string(x.ID)] = true
	}
	for _, x := range recs.Technologies {
		if !del[string(x.ID)] && !up[string(x.ID)] {
			out.Technologies = append(out.Technologies, x)
		}
	}
	upf := map[string]bool{}
	for _, x := range cset.Upsert.Fingerprints {
		out.Fingerprints = append(out.Fingerprints, x)
		upf[string(x.ID)] = true
	}
	for _, x := range recs.Fingerprints {
		if !del[string(x.ID)] && !upf[string(x.ID)] {
			out.Fingerprints = append(out.Fingerprints, x)
		}
	}
	upr := map[string]bool{}
	for _, x := range cset.Upsert.Relationships {
		out.Relationships = append(out.Relationships, x)
		upr[string(x.ID)] = true
	}
	for _, x := range recs.Relationships {
		if !del[string(x.ID)] && !upr[string(x.ID)] {
			out.Relationships = append(out.Relationships, x)
		}
	}
	if issues := validator.Validate(out); len(issues) != 0 {
		t.Fatalf("merged records are invalid: %v", issues)
	}
	if len(out.Technologies) != 2 {
		t.Errorf("technologies = %d, want 2", len(out.Technologies))
	}
}

func TestMetadataConflictOnDifferentWebsites(t *testing.T) {
	recs, cs := fixture()
	recs.Technologies[1].Website = "https://bar.example"
	w := NewWorkspace(recs, nil, cs, alloc, now)
	if _, err := w.MergeTechnologies("tech_1", "tech_2"); err != nil {
		t.Fatal(err)
	}
	var n int
	for _, c := range w.ChangeSet().Conflicts {
		if c.Kind == domain.ConflictMetadata && c.Detail["kept"] == "https://foo.com" && c.Detail["other"] == "https://bar.example" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("metadata conflicts = %d", n)
	}
}

func TestMergeCategories(t *testing.T) {
	recs := domain.Records{
		Categories: []domain.Category{
			{ID: "cat_1", Name: "CMS", Provenance: prov("s1", "1", nil)},
			{ID: "cat_2", Name: "cms", ParentID: "", Provenance: prov("s2", "9", nil)},
			{ID: "cat_3", Name: "Sub", ParentID: "cat_2", Provenance: prov("s2", "10", nil)},
		},
		Technologies: []domain.Technology{
			{ID: "tech_1", Name: "A", CategoryIDs: []domain.CategoryID{"cat_1", "cat_2"}, Provenance: prov("s1", "A", nil)},
		},
		Relationships: []domain.Relationship{
			{ID: "rel_1", FromTechnologyID: "tech_1", ToCategoryID: "cat_2", Type: "requires", Provenance: prov("s2", "r", nil)},
		},
	}
	w := NewWorkspace(recs, nil, nil, alloc, now)
	if got, err := w.MergeCategories("cat_2", "cat_1"); err != nil || got != "cat_1" {
		t.Fatalf("survivor %q err=%v", got, err)
	}
	cs := w.ChangeSet()
	if len(cs.Delete.Categories) != 1 || cs.Delete.Categories[0] != "cat_2" {
		t.Errorf("delete: %+v", cs.Delete)
	}
	var tech domain.Technology
	var sub domain.Category
	for _, x := range cs.Upsert.Technologies {
		tech = x
	}
	for _, x := range cs.Upsert.Categories {
		if x.ID == "cat_3" {
			sub = x
		}
	}
	if len(tech.CategoryIDs) != 1 || tech.CategoryIDs[0] != "cat_1" {
		t.Errorf("technology categories: %v", tech.CategoryIDs)
	}
	if sub.ParentID != "cat_1" {
		t.Errorf("parent: %q", sub.ParentID)
	}
	if len(cs.Upsert.Relationships) != 1 || cs.Upsert.Relationships[0].ToCategoryID != "cat_1" {
		t.Errorf("relationships: %+v", cs.Upsert.Relationships)
	}
	if recs.Technologies[0].CategoryIDs[1] != "cat_2" {
		t.Error("the caller's records must not be mutated")
	}
}

func TestMetadataConflictOnDifferentVendors(t *testing.T) {
	recs, cs := fixture()
	recs.Technologies[0].VendorID = "vnd_a"
	recs.Technologies[1].VendorID = "vnd_b"
	w := NewWorkspace(recs, nil, cs, alloc, now)
	if _, err := w.MergeTechnologies("tech_1", "tech_2"); err != nil {
		t.Fatal(err)
	}
	var n int
	for _, c := range w.ChangeSet().Conflicts {
		if c.Kind == domain.ConflictMetadata && c.Detail["field"] == "vendor" && c.Detail["kept"] == "vnd_a" && c.Detail["other"] == "vnd_b" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("vendor conflicts = %d", n)
	}
	// Same vendor, or one missing: no conflict.
	recs, cs = fixture()
	recs.Technologies[1].VendorID = "vnd_b"
	w = NewWorkspace(recs, nil, cs, alloc, now)
	if _, err := w.MergeTechnologies("tech_1", "tech_2"); err != nil {
		t.Fatal(err)
	}
	for _, c := range w.ChangeSet().Conflicts {
		if c.Kind == domain.ConflictMetadata && c.Detail["field"] == "vendor" {
			t.Errorf("unexpected vendor conflict: %+v", c)
		}
	}
	if got := w.ChangeSet().Upsert.Technologies[0].VendorID; got != "vnd_b" {
		t.Errorf("survivor must take the vendor it lacks, got %q", got)
	}
}

func TestRepositoryWebsiteIsNoConflictAndLosesToTheProductSite(t *testing.T) {
	for _, tc := range []struct{ kept, other, want string }{
		{"https://github.com/grafana/grafana", "https://grafana.com", "https://grafana.com"},
		{"https://grafana.com", "https://github.com/grafana/grafana", "https://grafana.com"},
		{"https://www.foo.com", "http://foo.com/", "https://www.foo.com"},
	} {
		recs, cs := fixture()
		recs.Technologies[0].Website, recs.Technologies[1].Website = tc.kept, tc.other
		w := NewWorkspace(recs, nil, cs, alloc, now)
		if _, err := w.MergeTechnologies("tech_1", "tech_2"); err != nil {
			t.Fatal(err)
		}
		for _, c := range w.ChangeSet().Conflicts {
			if c.Kind == domain.ConflictMetadata {
				t.Errorf("%s vs %s: unexpected conflict %+v", tc.kept, tc.other, c.Detail)
			}
		}
		if got := w.ChangeSet().Upsert.Technologies[0].Website; got != tc.want {
			t.Errorf("%s vs %s: website %q, want %q", tc.kept, tc.other, got, tc.want)
		}
	}
	// A website a reviewer set is not replaced.
	recs, cs := fixture()
	recs.Technologies[0].Website, recs.Technologies[0].Curated = "https://github.com/a/b", []string{"website"}
	recs.Technologies[1].Website = "https://b.example"
	w := NewWorkspace(recs, nil, cs, alloc, now)
	if _, err := w.MergeTechnologies("tech_1", "tech_2"); err != nil {
		t.Fatal(err)
	}
	if got := w.ChangeSet().Upsert.Technologies[0].Website; got != "https://github.com/a/b" {
		t.Errorf("curated website replaced: %q", got)
	}
}

func TestKeepSeparateCanBeReversedByMerge(t *testing.T) {
	recs, cs := fixture()
	w := NewWorkspace(recs, nil, cs, alloc, now)
	id12, _ := alloc(domain.KindConflict, reconciler.PairKey(domain.ConflictIdentityCandidate, "tech_1", "tech_2"))
	if err := w.Decide(domain.ConflictID(id12), KeepSeparate, "no"); err != nil {
		t.Fatal(err)
	}
	if err := w.Decide(domain.ConflictID(id12), KeepSeparate, "again"); err == nil {
		t.Error("keeping separate twice must fail")
	}
	if err := w.Decide(domain.ConflictID(id12), Merge, "changed my mind"); err != nil {
		t.Fatalf("a merge reverses a kept-separate decision: %v", err)
	}
}
