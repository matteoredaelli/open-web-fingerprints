// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package export

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/matteoredaelli/open-web-fingerprints/internal/domain"
	"github.com/matteoredaelli/open-web-fingerprints/internal/repository"
	"github.com/matteoredaelli/open-web-fingerprints/internal/repository/memory"
)

var now = time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)

func src(id, slug, decision string) domain.Source {
	return domain.Source{ID: domain.SourceID(id), Slug: slug, Name: slug, License: "MIT", Redistributable: decision}
}

func prov(srcs ...string) []domain.Provenance {
	var out []domain.Provenance
	for _, s := range srcs {
		out = append(out, domain.Provenance{SourceID: domain.SourceID(s), SnapshotRevision: "r", OriginalID: "x", License: "MIT", ImportedAt: now, State: "present"})
	}
	return out
}

// world has three sources: ok (yes), pending (unreviewed), nope (no), and
// records that depend on each other.
func world(t *testing.T) *memory.Repo {
	t.Helper()
	r := memory.New()
	ctx := context.Background()
	for _, s := range []domain.Source{src("src_ok", "ok", "yes"), src("src_pending", "pending", "unreviewed"), src("src_nope", "nope", "no")} {
		if err := r.UpsertSource(ctx, s); err != nil {
			t.Fatal(err)
		}
		if err := r.PutSnapshot(ctx, domain.Snapshot{SourceID: s.ID, Revision: "r", Checksum: "sha256:" + strings.Repeat("0", 64), RetrievedAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	tech := func(id, slug string, vendor domain.VendorID, cats []domain.CategoryID, p []domain.Provenance) domain.Technology {
		return domain.Technology{ID: domain.TechnologyID(id), Slug: slug, Name: slug, Status: domain.StatusActive, VendorID: vendor, CategoryIDs: cats, Provenance: p}
	}
	fp := func(id, tech string, p []domain.Provenance) domain.Fingerprint {
		return domain.Fingerprint{ID: domain.FingerprintID(id), TechnologyID: domain.TechnologyID(tech), Observation: domain.ObsHTML,
			Operator: domain.OpExists, Confidence: 0.5, Status: domain.StatusActive, Provenance: p}
	}
	recs := domain.Records{
		Vendors: []domain.Vendor{
			{ID: "vnd_ok", Slug: "okv", Name: "Ok", Provenance: prov("src_ok")},
			{ID: "vnd_nope", Slug: "nopev", Name: "Nope", Provenance: prov("src_nope")},
			{ID: "vnd_manual", Slug: "manual", Name: "Manual"}, // curated by hand: no provenance
		},
		Categories: []domain.Category{
			{ID: "cat_ok", Slug: "ok", Name: "Ok", Provenance: prov("src_ok")},
			{ID: "cat_nope", Slug: "nope", Name: "Nope", ParentID: "cat_ok", Provenance: prov("src_nope")},
			{ID: "cat_child", Slug: "child", Name: "Child", ParentID: "cat_nope", Provenance: prov("src_ok")},
		},
		Technologies: []domain.Technology{
			tech("tech_ok", "a", "vnd_nope", []domain.CategoryID{"cat_ok", "cat_nope"}, prov("src_ok")),
			tech("tech_pending", "b", "vnd_manual", nil, prov("src_pending")),
			tech("tech_nope", "c", "", nil, prov("src_nope")),
			tech("tech_mixed", "d", "vnd_ok", nil, prov("src_ok", "src_nope")), // merged: nope contributed
		},
		Fingerprints: []domain.Fingerprint{
			fp("fp_ok", "tech_ok", prov("src_ok")),
			fp("fp_of_nope", "tech_nope", prov("src_ok")), // allowed source, excluded technology
			fp("fp_nope", "tech_ok", prov("src_nope")),
			fp("fp_pending", "tech_pending", prov("src_pending")),
		},
		Relationships: []domain.Relationship{
			{ID: "rel_ok", FromTechnologyID: "tech_ok", ToCategoryID: "cat_ok", Type: "requires", Provenance: prov("src_ok")},
			{ID: "rel_to_nope", FromTechnologyID: "tech_ok", ToTechnologyID: "tech_nope", Type: "implies", Provenance: prov("src_ok")},
			{ID: "rel_from_pending", FromTechnologyID: "tech_pending", ToTechnologyID: "tech_ok", Type: "implies", Provenance: prov("src_pending")},
		},
	}
	if err := r.Apply(ctx, repository.ChangeSet{Upsert: recs}); err != nil {
		t.Fatal(err)
	}
	return r
}

func ids[T any](l []T, id func(T) string) string {
	var out []string
	for _, x := range l {
		out = append(out, id(x))
	}
	return strings.Join(out, ",")
}

func TestUnreviewedSourceBlocksTheExport(t *testing.T) {
	_, err := Build(context.Background(), world(t), now, Options{})
	var blocked *BlockedError
	if !errors.As(err, &blocked) || len(blocked.Sources) != 1 || blocked.Sources[0] != "pending" {
		t.Fatalf("err = %v", err)
	}
	for _, want := range []string{"pending", "owf source review", "--include-unreviewed"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("message lacks %q: %v", want, err)
		}
	}
}

func TestIncludeUnreviewedKeepsNoSourcesOut(t *testing.T) {
	reg, err := Build(context.Background(), world(t), now, Options{IncludeUnreviewed: true})
	if err != nil {
		t.Fatal(err)
	}
	// Sources: ok and pending are allowed, nope is not.
	if got := ids(reg.Sources, func(s domain.Source) string { return s.Slug }); got != "ok,pending" {
		t.Errorf("sources = %s", got)
	}
	if got := ids(reg.Snapshots, func(s domain.Snapshot) string { return string(s.SourceID) }); got != "src_ok,src_pending" {
		t.Errorf("snapshots of excluded sources must not be exported: %s", got)
	}
	// Technologies: a and b stay; c (nope) and d (nope contributed) go.
	if got := ids(reg.Technologies, func(x domain.Technology) string { return x.Slug }); got != "a,b" {
		t.Errorf("technologies = %s", got)
	}
	// Rules of excluded technologies go even from an allowed source, and so
	// do rules of an excluded source.
	if got := ids(reg.Fingerprints, func(x domain.Fingerprint) string { return string(x.ID) }); got != "fp_ok,fp_pending" {
		t.Errorf("fingerprints = %s", got)
	}
	// Relationships need both ends; rel_to_nope points at an excluded technology.
	if got := ids(reg.Relationships, func(x domain.Relationship) string { return string(x.ID) }); got != "rel_from_pending,rel_ok" {
		t.Errorf("relationships = %s", got)
	}
	// The rest has no dangling references.
	for _, tc := range reg.Technologies {
		if tc.Slug == "a" {
			if len(tc.CategoryIDs) != 1 || tc.CategoryIDs[0] != "cat_ok" || tc.VendorID != "" {
				t.Errorf("references to excluded records must be removed: %+v", tc)
			}
		}
		if tc.Slug == "b" && tc.VendorID != "vnd_manual" {
			t.Errorf("a hand-made vendor is exportable: %+v", tc)
		}
	}
	for _, c := range reg.Categories {
		if c.ID == "cat_child" && c.ParentID != "" {
			t.Errorf("parent was excluded: %+v", c)
		}
	}
	if got := ids(reg.Vendors, func(x domain.Vendor) string { return string(x.ID) }); got != "vnd_manual,vnd_ok" && got != "vnd_ok,vnd_manual" {
		t.Errorf("vendors = %s", got)
	}

	e := reg.Export
	if e == nil || !e.IncludeUnreviewed || len(e.UnreviewedSources) != 1 || e.UnreviewedSources[0] != "pending" ||
		len(e.ExcludedSources) != 1 || e.ExcludedSources[0] != "nope" || e.Notice != Notice {
		t.Fatalf("export info: %+v", e)
	}
	// excluded: vendor nope, category nope, technologies c and d, fp_of_nope and fp_nope, rel_to_nope.
	if e.ExcludedRecords != 7 {
		t.Errorf("excluded records = %d, want 7", e.ExcludedRecords)
	}
}

func TestNoNeverExportsEvenAfterReview(t *testing.T) {
	// Without the flag, the only blocker is "pending". Once it is reviewed
	// as yes, "nope" is still left out and no flag is needed.
	r := world(t)
	ctx := context.Background()
	s, _, _ := r.GetSourceBySlug(ctx, "pending")
	s.Redistributable = "yes"
	if err := r.UpsertSource(ctx, s); err != nil {
		t.Fatal(err)
	}
	reg, err := Build(ctx, r, now, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if got := ids(reg.Technologies, func(x domain.Technology) string { return x.Slug }); got != "a,b" {
		t.Errorf("technologies = %s", got)
	}
	if reg.Export == nil || reg.Export.IncludeUnreviewed || reg.Export.Notice != "" || len(reg.Export.ExcludedSources) != 1 {
		t.Errorf("export info: %+v", reg.Export)
	}
}

func TestFullyReviewedExportHasNoExportSection(t *testing.T) {
	r := memory.New()
	ctx := context.Background()
	if err := r.UpsertSource(ctx, src("src_ok", "ok", "yes")); err != nil {
		t.Fatal(err)
	}
	if err := r.Apply(ctx, repository.ChangeSet{Upsert: domain.Records{Technologies: []domain.Technology{
		{ID: "tech_1", Slug: "a", Name: "A", Status: domain.StatusActive, Provenance: prov("src_ok")}}}}); err != nil {
		t.Fatal(err)
	}
	reg, err := Build(ctx, r, now, Options{})
	if err != nil || reg.Export != nil || len(reg.Technologies) != 1 {
		t.Fatalf("reg=%+v err=%v", reg.Export, err)
	}
	b1, err := json.Marshal(reg)
	if err != nil {
		t.Fatal(err)
	}
	reg2, _ := Build(ctx, r, now, Options{})
	if b2, _ := json.Marshal(reg2); string(b1) != string(b2) {
		t.Error("exports of the same data must be identical")
	}
}

func TestProvenanceOfAnUnknownSourceCountsAsUnreviewed(t *testing.T) {
	r := memory.New()
	ctx := context.Background()
	if err := r.Apply(ctx, repository.ChangeSet{Upsert: domain.Records{Technologies: []domain.Technology{
		{ID: "tech_1", Slug: "a", Name: "A", Status: domain.StatusActive, Provenance: prov("src_ghost")}}}}); err != nil {
		t.Fatal(err)
	}
	var blocked *BlockedError
	if _, err := Build(ctx, r, now, Options{}); !errors.As(err, &blocked) || blocked.Sources[0] != "src_ghost" {
		t.Fatalf("err = %v", err)
	}
	reg, err := Build(ctx, r, now, Options{IncludeUnreviewed: true})
	if err != nil || len(reg.Technologies) != 1 {
		t.Fatalf("with the flag the record is included: %v", err)
	}
}

func TestEmptyRegistryExports(t *testing.T) {
	reg, err := Build(context.Background(), memory.New(), now, Options{})
	if err != nil {
		t.Fatal(err)
	}
	// The schema is checked by JSON; an empty registry must still pass.
	if _, err := JSON(reg); err != nil {
		t.Errorf("empty export: %v", err)
	}
}

func TestManifest(t *testing.T) {
	ctx := context.Background()
	r := world(t)
	a, err := Build(ctx, r, now, Options{IncludeUnreviewed: true, Generator: "owf test"})
	if err != nil {
		t.Fatal(err)
	}
	later := now.Add(48 * time.Hour)
	b, err := Build(ctx, r, later, Options{IncludeUnreviewed: true, Generator: "owf other"})
	if err != nil {
		t.Fatal(err)
	}
	m := a.Manifest
	if m == nil || m.Generator != "owf test" || !strings.HasPrefix(m.ContentSHA256, "sha256:") || len(m.ContentSHA256) != 71 {
		t.Fatalf("manifest: %+v", m)
	}
	// The hash is of the data: neither the time nor the generator is part of it.
	if m.ContentSHA256 != b.Manifest.ContentSHA256 {
		t.Error("the same data must have the same content hash")
	}
	want := domain.ManifestCounts{Sources: 2, Vendors: 2, Categories: 2, Technologies: 2, Fingerprints: 2, Relationships: 2}
	if m.Counts != want {
		t.Errorf("counts = %+v, want %+v", m.Counts, want)
	}
	if len(m.Sources) != 2 || m.Sources[0].Slug != "ok" || m.Sources[0].Revision != "r" ||
		!strings.HasPrefix(m.Sources[0].SnapshotChecksum, "sha256:") || m.Sources[1].Redistributable != "unreviewed" {
		t.Errorf("manifest sources: %+v", m.Sources)
	}
	h, err := ContentHash(a)
	if err != nil || h != m.ContentSHA256 {
		t.Errorf("ContentHash = %s, %v", h, err)
	}

	// Changing any record changes the hash.
	a.Technologies[0].Name = "changed"
	if h2, _ := ContentHash(a); h2 == h {
		t.Error("a changed record must change the hash")
	}
	// A different export of the same registry (the guard's choices) differs.
	c, err := Build(ctx, r, now, Options{IncludeUnreviewed: true})
	if err != nil || c.Manifest.Generator != "owf" {
		t.Fatalf("default generator: %+v err=%v", c.Manifest, err)
	}
	if empty, _ := Build(ctx, memory.New(), now, Options{}); empty.Manifest == nil || empty.Manifest.Sources == nil {
		t.Error("an empty export still has a manifest with an empty source list")
	}
}

func TestVerifyRejectsWhatItCannotCheck(t *testing.T) {
	if _, err := Verify([]byte("{")); err == nil {
		t.Error("garbage must fail")
	}
	if _, err := Verify([]byte(`{"schema_version":"0.1.0","sources":[],"technologies":[],"fingerprints":[]}`)); err == nil ||
		!strings.Contains(err.Error(), "no manifest") {
		t.Errorf("an old export has nothing to verify: %v", err)
	}
}
