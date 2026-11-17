// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package reconciler

import (
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/matteoredaelli/open-web-fingerprints/internal/domain"
)

func alloc(kind domain.Kind, key string) (string, error) {
	return fmt.Sprintf("%s_%s", kind, key), nil
}

func tech(id, name, site, src string) domain.Technology {
	return domain.Technology{
		ID: domain.TechnologyID(id), Name: name, Website: site,
		Provenance: []domain.Provenance{{SourceID: domain.SourceID(src)}},
	}
}

func TestWebsiteRelation(t *testing.T) {
	for _, c := range []struct{ a, b, want string }{
		{"https://wordpress.org", "https://www.wordpress.org/about", SameDomain},
		{"https://blog.example.co.uk", "https://example.co.uk", SameDomain},
		{"https://example.com", "https://example.org", Different},
		{"https://a.github.io", "https://b.github.io", Different}, // public suffix
		{"", "https://example.com", Unknown},
		{"example.com", "https://example.com:8080", SameDomain},
	} {
		if got := WebsiteRelation(c.a, c.b); got != c.want {
			t.Errorf("%q vs %q = %s, want %s", c.a, c.b, got, c.want)
		}
	}
}

func TestCandidates(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	other := domain.Records{
		Technologies: []domain.Technology{
			tech("tech_a", "WordPress", "https://wordpress.org", "src_1"),
			tech("tech_b", "Next.js", "https://nextjs.org", "src_1"),
		},
		Categories: []domain.Category{{ID: "cat_a", Name: "CMS", Provenance: []domain.Provenance{{SourceID: "src_1"}}}},
	}
	fresh := domain.Records{
		Technologies: []domain.Technology{
			tech("tech_x", "wordpress", "https://www.wordpress.org", "src_2"),
			tech("tech_y", "Next.JS", "https://example.com", "src_2"),
			tech("tech_z", "Only Here", "", "src_2"),
		},
		Categories: []domain.Category{
			{ID: "cat_x", Name: "cms", Provenance: []domain.Provenance{{SourceID: "src_2"}}},
			{ID: "cat_y", Name: "Other", Provenance: []domain.Provenance{{SourceID: "src_2"}}},
		},
	}
	got, err := Candidates(Input{Fresh: fresh, Other: other, Alloc: alloc, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("candidates = %d: %+v", len(got), got)
	}
	byRel := map[string]int{}
	for _, c := range got {
		if c.State != domain.ConflictOpen || len(c.RecordIDs) != 2 || len(c.SourceIDs) != 2 {
			t.Errorf("bad conflict: %+v", c)
		}
		byRel[c.Detail["websites"]]++
	}
	if byRel[SameDomain] != 1 || byRel[Different] != 1 {
		t.Errorf("relations: %v", byRel)
	}

	// Symmetry: the same pair gets the same ID whichever side is "fresh".
	back, err := Candidates(Input{Fresh: other, Other: fresh, Alloc: alloc, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if len(back) != 3 {
		t.Fatalf("reverse candidates = %d", len(back))
	}
	for i := range got {
		if got[i].ID != back[i].ID {
			t.Errorf("IDs differ by direction: %s vs %s", got[i].ID, back[i].ID)
		}
		if !reflect.DeepEqual(got[i].Detail, back[i].Detail) {
			t.Errorf("evidence differs by direction: %v vs %v", got[i].Detail, back[i].Detail)
		}
	}
}

func TestSameRecordIsNotACandidate(t *testing.T) {
	r := domain.Records{Technologies: []domain.Technology{tech("tech_a", "A", "", "src_1")}}
	got, err := Candidates(Input{Fresh: r, Other: r, Alloc: alloc})
	if err != nil || len(got) != 0 {
		t.Fatalf("got %+v err=%v", got, err)
	}
}
