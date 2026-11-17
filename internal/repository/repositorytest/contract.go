// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

// Package repositorytest provides the behavior every repository.Repository
// implementation must satisfy.
package repositorytest

import (
	"context"
	"encoding/json"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/matteoredaelli/open-web-fingerprints/internal/domain"
	"github.com/matteoredaelli/open-web-fingerprints/internal/repository"
)

// Factory returns a fresh, empty repository.
type Factory func(t *testing.T) repository.Repository

// ExamplePath is the public example used for the fidelity test, relative to
// the calling package. Callers set it when their directory differs.
var ExamplePath = "../../../examples/registry.json"

func prov(src domain.SourceID, state string) domain.Provenance {
	return domain.Provenance{
		SourceID: src, SnapshotRevision: "r1", OriginalID: "x", License: "MIT",
		ImportedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), State: state,
	}
}

func tech(id, slug string, p ...domain.Provenance) domain.Technology {
	return domain.Technology{ID: domain.TechnologyID(id), Slug: slug, Name: slug, Status: domain.StatusActive, Provenance: p}
}

func source(id, slug string) domain.Source {
	return domain.Source{ID: domain.SourceID(id), Slug: slug, Name: slug, License: "MIT", Redistributable: "yes"}
}

// Run executes the contract against the factory.
func Run(t *testing.T, newRepo Factory) {
	ctx := context.Background()

	t.Run("allocate is stable and scoped", func(t *testing.T) {
		r := newRepo(t)
		a, err := r.Allocate(domain.KindTechnology, "s", "k")
		if err != nil {
			t.Fatal(err)
		}
		b, _ := r.Allocate(domain.KindTechnology, "s", "k")
		c, _ := r.Allocate(domain.KindTechnology, "s", "other")
		d, _ := r.Allocate(domain.KindTechnology, "t", "k")
		e, _ := r.Allocate(domain.KindFingerprint, "s", "k")
		if a != b || a == c || a == d || a == e {
			t.Fatalf("%s %s %s %s %s", a, b, c, d, e)
		}
	})

	t.Run("sources", func(t *testing.T) {
		r := newRepo(t)
		if _, ok, err := r.GetSourceBySlug(ctx, "nope"); err != nil || ok {
			t.Fatalf("unknown slug: ok=%v err=%v", ok, err)
		}
		s := source("src_1", "one")
		if err := r.UpsertSource(ctx, s); err != nil {
			t.Fatal(err)
		}
		s.Name = "renamed"
		if err := r.UpsertSource(ctx, s); err != nil {
			t.Fatal(err)
		}
		if err := r.UpsertSource(ctx, source("src_0", "zero")); err != nil {
			t.Fatal(err)
		}
		list, err := r.Sources(ctx)
		if err != nil || len(list) != 2 || list[0].Slug != "one" || list[1].Slug != "zero" {
			t.Fatalf("Sources = %+v err=%v", list, err)
		}
		got, ok, err := r.GetSourceBySlug(ctx, "one")
		if err != nil || !ok || got.Name != "renamed" || got.ID != "src_1" {
			t.Fatalf("got %+v ok=%v err=%v", got, ok, err)
		}
	})

	t.Run("snapshots", func(t *testing.T) {
		r := newRepo(t)
		if err := r.UpsertSource(ctx, source("src_1", "one")); err != nil {
			t.Fatal(err)
		}
		s := domain.Snapshot{SourceID: "src_1", Revision: "r1", Checksum: "sha256:a",
			RetrievedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
		if err := r.PutSnapshot(ctx, s); err != nil {
			t.Fatal(err)
		}
		if err := r.PutSnapshot(ctx, s); err != nil {
			t.Fatalf("same snapshot twice must be a no-op: %v", err)
		}
		bad := s
		bad.Checksum = "sha256:b"
		if err := r.PutSnapshot(ctx, bad); err == nil {
			t.Fatal("checksum mismatch must fail")
		}
		s2 := s
		s2.Revision, s2.RetrievedAt = "r2", s.RetrievedAt.Add(time.Hour)
		if err := r.PutSnapshot(ctx, s2); err != nil {
			t.Fatal(err)
		}
		l, err := r.Snapshots(ctx, "src_1")
		if err != nil || len(l) != 2 || l[0].Revision != "r1" || l[1].Revision != "r2" {
			t.Fatalf("snapshots = %+v err=%v", l, err)
		}
	})

	t.Run("apply is atomic", func(t *testing.T) {
		r := newRepo(t)
		err := r.Apply(ctx, repository.ChangeSet{
			Upsert:          domain.Records{Technologies: []domain.Technology{tech("tech_1", "a", prov("src_1", "present"))}},
			SourceID:        "src_1",
			RemovedUpstream: repository.RecordIDs{Fingerprints: []string{"fp_missing"}},
		})
		if err == nil {
			t.Fatal("removing an unknown record must fail")
		}
		if all, _ := r.AllRecords(ctx); len(all.Technologies) != 0 {
			t.Fatal("failed Apply must not write anything")
		}
	})

	t.Run("upsert replaces and keeps provenance of other sources", func(t *testing.T) {
		r := newRepo(t)
		t1 := tech("tech_1", "a", prov("src_1", "present"), prov("src_2", "present"))
		if err := r.Apply(ctx, repository.ChangeSet{Upsert: domain.Records{Technologies: []domain.Technology{t1}}}); err != nil {
			t.Fatal(err)
		}
		t1.Name = "changed"
		t1.Provenance = t1.Provenance[:1]
		if err := r.Apply(ctx, repository.ChangeSet{Upsert: domain.Records{Technologies: []domain.Technology{t1}}}); err != nil {
			t.Fatal(err)
		}
		all, _ := r.AllRecords(ctx)
		if len(all.Technologies) != 1 || all.Technologies[0].Name != "changed" || len(all.Technologies[0].Provenance) != 1 {
			t.Fatalf("%+v", all.Technologies)
		}
		other, _ := r.SourceRecords(ctx, "src_2")
		if len(other.Technologies) != 0 {
			t.Fatal("dropped provenance must no longer match src_2")
		}
	})

	t.Run("source records filter by provenance", func(t *testing.T) {
		r := newRepo(t)
		recs := domain.Records{Technologies: []domain.Technology{
			tech("tech_1", "a", prov("src_1", "present")),
			tech("tech_2", "b", prov("src_2", "present")),
			tech("tech_3", "c", prov("src_1", "present"), prov("src_2", "present")),
		}}
		if err := r.Apply(ctx, repository.ChangeSet{Upsert: recs}); err != nil {
			t.Fatal(err)
		}
		got, err := r.SourceRecords(ctx, "src_1")
		if err != nil || len(got.Technologies) != 2 || got.Technologies[0].ID != "tech_1" || got.Technologies[1].ID != "tech_3" {
			t.Fatalf("%+v err=%v", got.Technologies, err)
		}
		if len(got.Technologies[1].Provenance) != 2 {
			t.Fatal("provenance of other sources must be included")
		}
		all, _ := r.AllRecords(ctx)
		if len(all.Technologies) != 3 {
			t.Fatalf("all = %d", len(all.Technologies))
		}
	})

	t.Run("mark removed touches only one source and one entry", func(t *testing.T) {
		r := newRepo(t)
		t1 := tech("tech_1", "a", prov("src_1", "present"), prov("src_2", "present"))
		if err := r.Apply(ctx, repository.ChangeSet{Upsert: domain.Records{Technologies: []domain.Technology{t1}}}); err != nil {
			t.Fatal(err)
		}
		if err := r.Apply(ctx, repository.ChangeSet{
			SourceID: "src_1", RemovedUpstream: repository.RecordIDs{Technologies: []string{"tech_1"}},
		}); err != nil {
			t.Fatal(err)
		}
		all, _ := r.AllRecords(ctx)
		p := all.Technologies[0].Provenance
		if len(p) != 2 || p[0].State != "removed_upstream" || p[1].State != "present" {
			t.Fatalf("provenance: %+v", p)
		}
		if t1.Provenance[0].State != "present" {
			t.Fatal("caller's data must not be mutated")
		}
		// The record stays visible to the source so a restore can be detected.
		if got, _ := r.SourceRecords(ctx, "src_1"); len(got.Technologies) != 1 {
			t.Fatal("removed record must still be returned for its source")
		}
	})

	t.Run("conflicts", func(t *testing.T) {
		r := newRepo(t)
		now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		c := domain.Conflict{
			ID: "cfl_b", Kind: domain.ConflictIdentityCandidate, State: domain.ConflictOpen,
			RecordIDs: []string{"tech_1", "tech_2"}, SourceIDs: []domain.SourceID{"src_1", "src_2"},
			Detail: map[string]string{"websites": "same_domain"}, CreatedAt: now, UpdatedAt: now,
		}
		a := c
		a.ID = "cfl_a"
		if err := r.Apply(ctx, repository.ChangeSet{Conflicts: []domain.Conflict{c, a}}); err != nil {
			t.Fatal(err)
		}
		c.State, c.Resolution = domain.ConflictIgnored, "not the same product"
		if err := r.Apply(ctx, repository.ChangeSet{Conflicts: []domain.Conflict{c}}); err != nil {
			t.Fatal(err)
		}
		got, err := r.Conflicts(ctx)
		if err != nil || len(got) != 2 || got[0].ID != "cfl_a" || got[1].ID != "cfl_b" {
			t.Fatalf("conflicts = %+v err=%v", got, err)
		}
		if got[1].State != domain.ConflictIgnored || got[1].Resolution == "" || got[1].Detail["websites"] != "same_domain" {
			t.Fatalf("update lost: %+v", got[1])
		}
		if !got[1].CreatedAt.Equal(now) || len(got[1].RecordIDs) != 2 {
			t.Fatalf("fields lost: %+v", got[1])
		}
	})

	t.Run("conflicts are applied atomically with records", func(t *testing.T) {
		r := newRepo(t)
		err := r.Apply(ctx, repository.ChangeSet{
			Conflicts:       []domain.Conflict{{ID: "cfl_1", Kind: "k", State: "open"}},
			SourceID:        "src_1",
			RemovedUpstream: repository.RecordIDs{Technologies: []string{"tech_missing"}},
		})
		if err == nil {
			t.Fatal("must fail")
		}
		if got, _ := r.Conflicts(ctx); len(got) != 0 {
			t.Fatal("failed Apply must not store conflicts")
		}
	})

	t.Run("delete and aliases", func(t *testing.T) {
		r := newRepo(t)
		recs := domain.Records{Technologies: []domain.Technology{
			tech("tech_1", "a", prov("src_1", "present")), tech("tech_2", "b", prov("src_1", "present")),
		}}
		if err := r.Apply(ctx, repository.ChangeSet{Upsert: recs}); err != nil {
			t.Fatal(err)
		}
		err := r.Apply(ctx, repository.ChangeSet{
			Delete:  repository.RecordIDs{Technologies: []string{"tech_2"}},
			Aliases: []domain.Alias{{Kind: domain.KindTechnology, OldID: "tech_2", NewID: "tech_1"}},
		})
		if err != nil {
			t.Fatal(err)
		}
		all, _ := r.AllRecords(ctx)
		if len(all.Technologies) != 1 || all.Technologies[0].ID != "tech_1" {
			t.Fatalf("after delete: %+v", all.Technologies)
		}
		if got, _ := r.SourceRecords(ctx, "src_1"); len(got.Technologies) != 1 {
			t.Fatalf("deleted record must leave no provenance behind: %+v", got.Technologies)
		}
		al, err := r.Aliases(ctx)
		if err != nil || al["tech_2"] != "tech_1" || len(al) != 1 {
			t.Fatalf("aliases = %v err=%v", al, err)
		}
		// Re-pointing an alias replaces it.
		if err := r.Apply(ctx, repository.ChangeSet{Aliases: []domain.Alias{{Kind: domain.KindTechnology, OldID: "tech_2", NewID: "tech_9"}}}); err != nil {
			t.Fatal(err)
		}
		if al, _ := r.Aliases(ctx); al["tech_2"] != "tech_9" {
			t.Fatalf("alias not updated: %v", al)
		}
		// Deleting an unknown record fails and writes nothing.
		err = r.Apply(ctx, repository.ChangeSet{
			Aliases: []domain.Alias{{Kind: domain.KindTechnology, OldID: "tech_x", NewID: "tech_1"}},
			Delete:  repository.RecordIDs{Technologies: []string{"tech_missing"}},
		})
		if err == nil {
			t.Fatal("deleting an unknown record must fail")
		}
		if al, _ := r.Aliases(ctx); len(al) != 1 {
			t.Fatalf("failed Apply must not store aliases: %v", al)
		}
	})

	t.Run("vendors", func(t *testing.T) {
		r := newRepo(t)
		v := func(id, slug, cpe string, p ...domain.Provenance) domain.Vendor {
			return domain.Vendor{ID: domain.VendorID(id), Slug: slug, Name: slug, CPEVendor: cpe, Provenance: p}
		}
		recs := domain.Records{Vendors: []domain.Vendor{
			v("vnd_1", "adobe", "adobe", prov("src_1", "present")),
			v("vnd_2", "acme", "acme", prov("src_2", "present")),
			v("vnd_3", "manual", ""), // curated by hand: no CPE, no provenance
			v("vnd_4", "manual-2", ""),
		}}
		if err := r.Apply(ctx, repository.ChangeSet{Upsert: recs}); err != nil {
			t.Fatal(err)
		}
		all, _ := r.AllRecords(ctx)
		if len(all.Vendors) != 4 {
			t.Fatalf("vendors = %d", len(all.Vendors))
		}
		if got, _ := r.SourceRecords(ctx, "src_1"); len(got.Vendors) != 1 || got.Vendors[0].ID != "vnd_1" {
			t.Fatalf("source vendors: %+v", got.Vendors)
		}
		if err := r.Apply(ctx, repository.ChangeSet{
			SourceID: "src_1", RemovedUpstream: repository.RecordIDs{Vendors: []string{"vnd_1"}},
		}); err != nil {
			t.Fatal(err)
		}
		got, _ := r.SourceRecords(ctx, "src_1")
		if got.Vendors[0].Provenance[0].State != "removed_upstream" {
			t.Errorf("vendor provenance: %+v", got.Vendors[0].Provenance)
		}
		if err := r.Apply(ctx, repository.ChangeSet{Delete: repository.RecordIDs{Vendors: []string{"vnd_2"}}}); err != nil {
			t.Fatal(err)
		}
		if all, _ := r.AllRecords(ctx); len(all.Vendors) != 3 {
			t.Errorf("after delete: %d vendors", len(all.Vendors))
		}
	})

	t.Run("public example round trips without loss", func(t *testing.T) {
		b, err := os.ReadFile(ExamplePath)
		if err != nil {
			t.Fatal(err)
		}
		var reg domain.Registry
		if err := json.Unmarshal(b, &reg); err != nil {
			t.Fatal(err)
		}
		r := newRepo(t)
		for _, s := range reg.Sources {
			if err := r.UpsertSource(ctx, s); err != nil {
				t.Fatal(err)
			}
		}
		for _, s := range reg.Snapshots {
			if err := r.PutSnapshot(ctx, s); err != nil {
				t.Fatal(err)
			}
		}
		want := domain.Records{
			Vendors: reg.Vendors, Categories: reg.Categories, Technologies: reg.Technologies,
			Fingerprints: reg.Fingerprints, Relationships: reg.Relationships,
		}
		if err := r.Apply(ctx, repository.ChangeSet{Upsert: want}); err != nil {
			t.Fatal(err)
		}
		got, err := r.AllRecords(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if a, b := canonical(t, want), canonical(t, got); a != b {
			t.Fatalf("records changed in storage\nwant %s\n got %s", a, b)
		}
	})
}

// canonical marshals records sorted by ID so that order does not matter.
func canonical(t *testing.T, r domain.Records) string {
	t.Helper()
	sort.Slice(r.Vendors, func(i, j int) bool { return r.Vendors[i].ID < r.Vendors[j].ID })
	sort.Slice(r.Categories, func(i, j int) bool { return r.Categories[i].ID < r.Categories[j].ID })
	sort.Slice(r.Technologies, func(i, j int) bool { return r.Technologies[i].ID < r.Technologies[j].ID })
	sort.Slice(r.Fingerprints, func(i, j int) bool { return r.Fingerprints[i].ID < r.Fingerprints[j].ID })
	sort.Slice(r.Relationships, func(i, j int) bool { return r.Relationships[i].ID < r.Relationships[j].ID })
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
