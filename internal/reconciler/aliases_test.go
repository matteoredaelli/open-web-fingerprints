// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package reconciler

import (
	"testing"

	"github.com/matteoredaelli/open-web-fingerprints/internal/domain"
)

func p(src, orig string, conf *float64) []domain.Provenance {
	return []domain.Provenance{{SourceID: domain.SourceID(src), OriginalID: orig, OriginalConfidence: conf, State: "present"}}
}

func f64(v float64) *float64 { return &v }

func TestResolve(t *testing.T) {
	al := map[string]string{"a": "b", "b": "c", "x": "x", "p": "q", "q": "p"}
	for in, want := range map[string]string{"a": "c", "b": "c", "c": "c", "z": "z", "x": "x"} {
		if got := Resolve(al, in); got != want {
			t.Errorf("Resolve(%s) = %s, want %s", in, got, want)
		}
	}
	// A corrupt cycle must terminate.
	_ = Resolve(al, "p")
}

func TestTranslateAliasesAndCollapse(t *testing.T) {
	aliases := map[string]string{"tech_b": "tech_a", "cat_b": "cat_a", "fp_old": "fp_keep"}
	fresh := domain.Records{
		Categories: []domain.Category{{ID: "cat_b", Name: "CMS", Provenance: p("s2", "1", nil)}},
		Technologies: []domain.Technology{
			{ID: "tech_b", Name: "B", CategoryIDs: []domain.CategoryID{"cat_b", "cat_c"}, Provenance: p("s2", "B", nil)},
			{ID: "tech_a", Name: "A", CategoryIDs: []domain.CategoryID{"cat_a"}, Provenance: p("s2", "A", nil)},
		},
		Fingerprints: []domain.Fingerprint{
			{ID: "fp_old", TechnologyID: "tech_b", Observation: domain.ObsHTML, Operator: domain.OpExists, Provenance: p("s2", "r1", nil)},
		},
		Relationships: []domain.Relationship{
			{ID: "rel_1", FromTechnologyID: "tech_b", ToTechnologyID: "tech_a", Type: "implies", Provenance: p("s2", "x", nil)},
			{ID: "rel_2", FromTechnologyID: "tech_b", ToCategoryID: "cat_b", Type: "requires", Provenance: p("s2", "y", nil)},
		},
	}
	got := Translate(fresh, domain.Records{}, aliases)
	r := got.Records
	if len(r.Categories) != 1 || r.Categories[0].ID != "cat_a" {
		t.Errorf("categories: %+v", r.Categories)
	}
	if len(r.Technologies) != 1 || r.Technologies[0].ID != "tech_a" || len(r.Technologies[0].Provenance) != 2 {
		t.Errorf("technologies must collapse and keep both provenance entries: %+v", r.Technologies)
	}
	if cats := r.Technologies[0].CategoryIDs; len(cats) != 2 || cats[0] != "cat_a" || cats[1] != "cat_c" {
		t.Errorf("category IDs: %v", cats)
	}
	if len(r.Fingerprints) != 1 || r.Fingerprints[0].ID != "fp_keep" || r.Fingerprints[0].TechnologyID != "tech_a" {
		t.Errorf("fingerprints: %+v", r.Fingerprints)
	}
	if len(r.Relationships) != 1 || r.Relationships[0].ToCategoryID != "cat_a" || r.Relationships[0].FromTechnologyID != "tech_a" {
		t.Errorf("relationships: %+v", r.Relationships)
	}
	if len(got.Warnings) != 1 || got.Warnings[0].Code != "self_relationship" {
		t.Errorf("warnings: %+v", got.Warnings)
	}
}

func TestTranslateMatchesStoredRulesByMeaning(t *testing.T) {
	stored := domain.Records{
		Fingerprints: []domain.Fingerprint{{
			ID: "fp_stored", TechnologyID: "tech_a", Observation: domain.ObsHTTPHeader, Target: "Server",
			Operator: domain.OpExists, Provenance: p("s1", "r", nil),
		}},
		Relationships: []domain.Relationship{{ID: "rel_stored", FromTechnologyID: "tech_a", ToTechnologyID: "tech_z", Type: "implies"}},
	}
	fresh := domain.Records{
		Fingerprints: []domain.Fingerprint{
			// Same meaning as the stored rule (header names are case-insensitive) but another ID.
			{ID: "fp_new", TechnologyID: "tech_b", Observation: domain.ObsHTTPHeader, Target: "server",
				Operator: domain.OpExists, Confidence: 0.9, Provenance: p("s2", "r2", f64(0.9))},
			{ID: "fp_other", TechnologyID: "tech_b", Observation: domain.ObsCookie, Target: "sid",
				Operator: domain.OpExists, Provenance: p("s2", "r3", nil)},
		},
		Relationships: []domain.Relationship{{ID: "rel_new", FromTechnologyID: "tech_b", ToTechnologyID: "tech_z", Type: "implies", Provenance: p("s2", "i", nil)}},
	}
	got := Translate(fresh, stored, map[string]string{"tech_b": "tech_a"})
	if len(got.Records.Fingerprints) != 2 || got.Records.Fingerprints[0].ID != "fp_stored" || got.Records.Fingerprints[1].ID != "fp_other" {
		t.Fatalf("fingerprints: %+v", got.Records.Fingerprints)
	}
	if got.Records.Relationships[0].ID != "rel_stored" {
		t.Errorf("relationships: %+v", got.Records.Relationships)
	}
	if len(got.Aliases) != 2 {
		t.Fatalf("aliases: %+v", got.Aliases)
	}
	want := map[string]string{"fp_new": "fp_stored", "rel_new": "rel_stored"}
	for _, a := range got.Aliases {
		if want[a.OldID] != a.NewID {
			t.Errorf("unexpected alias %+v", a)
		}
	}
}

func TestTranslateCollapsedRulesUseLowestExplicitConfidence(t *testing.T) {
	fresh := domain.Records{Fingerprints: []domain.Fingerprint{
		{ID: "fp_1", TechnologyID: "tech_a", Observation: domain.ObsHTML, Operator: domain.OpExists, Confidence: 0.8, Provenance: p("s", "a", f64(0.8))},
		{ID: "fp_1", TechnologyID: "tech_a", Observation: domain.ObsHTML, Operator: domain.OpExists, Confidence: 0.6, Provenance: p("s", "b", f64(0.6))},
	}}
	got := Translate(fresh, domain.Records{}, nil)
	if len(got.Records.Fingerprints) != 1 || got.Records.Fingerprints[0].Confidence != 0.6 || len(got.Records.Fingerprints[0].Provenance) != 2 {
		t.Fatalf("%+v", got.Records.Fingerprints)
	}
}
