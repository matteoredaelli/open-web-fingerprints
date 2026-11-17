// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package sqlite

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/matteoredaelli/open-web-fingerprints/internal/domain"
	"github.com/matteoredaelli/open-web-fingerprints/internal/repository"
	"github.com/matteoredaelli/open-web-fingerprints/internal/repository/repositorytest"
)

func open(t *testing.T, path string) *Repo {
	t.Helper()
	r, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r
}

func TestContract(t *testing.T) {
	repositorytest.Run(t, func(t *testing.T) repository.Repository { return open(t, ":memory:") })
}

func TestMigrationsAndPersistence(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "owf.db")
	r, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if v, err := r.SchemaVersion(ctx); err != nil || v < 1 {
		t.Fatalf("version=%d err=%v", v, err)
	}
	id, _ := r.Allocate(domain.KindTechnology, "s", "k")
	if err := r.Apply(ctx, repository.ChangeSet{Upsert: domain.Records{Technologies: []domain.Technology{{
		ID: domain.TechnologyID(id), Slug: "a", Name: "A", Status: domain.StatusActive,
		Provenance: []domain.Provenance{{SourceID: "src_1", State: "present"}},
	}}}}); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopening keeps data and IDs, and re-running migrations is harmless.
	r2 := open(t, path)
	again, _ := r2.Allocate(domain.KindTechnology, "s", "k")
	if again != id {
		t.Errorf("allocated ID changed across restarts: %s vs %s", again, id)
	}
	all, _ := r2.AllRecords(ctx)
	if len(all.Technologies) != 1 {
		t.Errorf("technologies = %d", len(all.Technologies))
	}
}

func TestForeignKeysAreEnforced(t *testing.T) {
	r := open(t, ":memory:")
	err := r.Apply(context.Background(), repository.ChangeSet{Upsert: domain.Records{Fingerprints: []domain.Fingerprint{{
		ID: "fp_1", TechnologyID: "tech_missing", Observation: domain.ObsHTML, Operator: domain.OpExists,
		Status: domain.StatusActive, Provenance: []domain.Provenance{{SourceID: "src_1", State: "present"}},
	}}}})
	if err == nil {
		t.Fatal("fingerprint without technology must be rejected")
	}
}

func TestDuplicateSlugIsRejected(t *testing.T) {
	r := open(t, ":memory:")
	mk := func(id string) domain.Technology {
		return domain.Technology{ID: domain.TechnologyID(id), Slug: "same", Name: "X", Status: domain.StatusActive,
			Provenance: []domain.Provenance{{SourceID: "src_1", State: "present"}}}
	}
	err := r.Apply(context.Background(), repository.ChangeSet{Upsert: domain.Records{
		Technologies: []domain.Technology{mk("tech_1"), mk("tech_2")}}})
	if err == nil {
		t.Fatal("duplicate slug must be rejected")
	}
	if all, _ := r.AllRecords(context.Background()); len(all.Technologies) != 0 {
		t.Fatal("failed Apply must roll back")
	}
}

func TestCancelledContext(t *testing.T) {
	r := open(t, ":memory:")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := r.AllRecords(ctx); err == nil {
		t.Fatal("cancelled context must fail")
	}
}
