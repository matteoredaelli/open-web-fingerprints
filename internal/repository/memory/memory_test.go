// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package memory

import (
	"context"
	"testing"

	"github.com/matteoredaelli/open-web-fingerprints/internal/domain"
	"github.com/matteoredaelli/open-web-fingerprints/internal/repository"
)

func TestAllocateIsStable(t *testing.T) {
	r := New()
	a, _ := r.Allocate(domain.KindTechnology, "s", "k")
	b, _ := r.Allocate(domain.KindTechnology, "s", "k")
	c, _ := r.Allocate(domain.KindTechnology, "s", "other")
	d, _ := r.Allocate(domain.KindTechnology, "t", "k")
	if a != b || a == c || a == d {
		t.Fatalf("%s %s %s %s", a, b, c, d)
	}
}

func TestSnapshotRules(t *testing.T) {
	r := New()
	ctx := context.Background()
	s := domain.Snapshot{SourceID: "src_1", Revision: "r1", Checksum: "sha256:a"}
	if err := r.PutSnapshot(ctx, s); err != nil {
		t.Fatal(err)
	}
	if err := r.PutSnapshot(ctx, s); err != nil {
		t.Fatalf("same snapshot twice must be a no-op: %v", err)
	}
	s.Checksum = "sha256:b"
	if err := r.PutSnapshot(ctx, s); err == nil {
		t.Fatal("checksum mismatch must fail")
	}
	if l, _ := r.Snapshots(ctx, "src_1"); len(l) != 1 {
		t.Fatalf("snapshots = %d", len(l))
	}
}

func TestApplyIsAtomic(t *testing.T) {
	r := New()
	ctx := context.Background()
	tech := domain.Technology{ID: "tech_1", Name: "A", Provenance: []domain.Provenance{{SourceID: "src_1", State: "present"}}}
	err := r.Apply(ctx, repository.ChangeSet{
		Upsert:          domain.Records{Technologies: []domain.Technology{tech}},
		SourceID:        "src_1",
		RemovedUpstream: repository.RecordIDs{Fingerprints: []string{"fp_missing"}},
	})
	if err == nil {
		t.Fatal("removing an unknown record must fail")
	}
	if all, _ := r.AllRecords(ctx); len(all.Technologies) != 0 {
		t.Fatal("failed Apply must not write anything")
	}
}

func TestMarkRemovedOnlyTouchesOneSource(t *testing.T) {
	r := New()
	ctx := context.Background()
	tech := domain.Technology{ID: "tech_1", Provenance: []domain.Provenance{
		{SourceID: "src_1", State: "present"}, {SourceID: "src_2", State: "present"},
	}}
	if err := r.Apply(ctx, repository.ChangeSet{Upsert: domain.Records{Technologies: []domain.Technology{tech}}}); err != nil {
		t.Fatal(err)
	}
	if err := r.Apply(ctx, repository.ChangeSet{
		SourceID: "src_1", RemovedUpstream: repository.RecordIDs{Technologies: []string{"tech_1"}},
	}); err != nil {
		t.Fatal(err)
	}
	all, _ := r.AllRecords(ctx)
	p := all.Technologies[0].Provenance
	if p[0].State != "removed_upstream" || p[1].State != "present" {
		t.Fatalf("provenance: %+v", p)
	}
	if tech.Provenance[0].State != "present" {
		t.Fatal("caller's data must not be mutated")
	}
}
