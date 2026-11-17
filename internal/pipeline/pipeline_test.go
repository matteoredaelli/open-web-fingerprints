// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package pipeline_test

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/matteoredaelli/open-web-fingerprints/internal/domain"
	"github.com/matteoredaelli/open-web-fingerprints/internal/extractor"
	"github.com/matteoredaelli/open-web-fingerprints/internal/extractor/recog"
	"github.com/matteoredaelli/open-web-fingerprints/internal/extractor/wappalyzer"
	"github.com/matteoredaelli/open-web-fingerprints/internal/pipeline"
	"github.com/matteoredaelli/open-web-fingerprints/internal/repository"
	"github.com/matteoredaelli/open-web-fingerprints/internal/repository/memory"
	"github.com/matteoredaelli/open-web-fingerprints/internal/repository/sqlite"
	"github.com/matteoredaelli/open-web-fingerprints/internal/validator"
)

const fixtureDir = "../extractor/wappalyzer/testdata/snapshot"

func source() domain.Source {
	return domain.Source{
		Slug: "enthec-webappanalyzer", Name: "Enthec WebAppAnalyzer", License: "GPL-3.0-only",
		ExtractorID: wappalyzer.ID, Redistributable: "unreviewed",
	}
}

var backend = "memory"

// eachBackend runs a test against every repository implementation.
func eachBackend(t *testing.T, fn func(t *testing.T)) {
	t.Helper()
	for _, name := range []string{"memory", "sqlite"} {
		t.Run(name, func(t *testing.T) {
			backend = name
			fn(t)
		})
	}
}

func newRepo(t *testing.T) repository.Repository {
	t.Helper()
	if backend == "sqlite" {
		r, err := sqlite.Open(context.Background(), ":memory:")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = r.Close() })
		return r
	}
	return memory.New()
}

func setup(t *testing.T) (*pipeline.Pipeline, repository.Repository) {
	t.Helper()
	reg := extractor.NewRegistry()
	for _, e := range []extractor.Extractor{wappalyzer.New(), recog.New()} {
		if err := reg.Register(e); err != nil {
			t.Fatal(err)
		}
	}
	repo := newRepo(t)
	p := pipeline.New(reg, repo)
	tick := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	p.Now = func() time.Time { tick = tick.Add(time.Minute); return tick }
	return p, repo
}

// mapFS copies the fixture into a mutable in-memory filesystem.
func mapFS(t *testing.T) fstest.MapFS {
	t.Helper()
	m := fstest.MapFS{}
	root := os.DirFS(fixtureDir)
	err := fs.WalkDir(root, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := fs.ReadFile(root, p)
		m[p] = &fstest.MapFile{Data: b}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func editTechFile(t *testing.T, m fstest.MapFS, path string, edit func(map[string]map[string]any)) {
	t.Helper()
	var d map[string]map[string]any
	if err := json.Unmarshal(m[path].Data, &d); err != nil {
		t.Fatal(err)
	}
	edit(d)
	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	m[path] = &fstest.MapFile{Data: b}
}

func run(t *testing.T, p *pipeline.Pipeline, fsys fs.FS, rev string) *pipeline.Report {
	t.Helper()
	rep, err := p.Run(context.Background(), pipeline.Request{Source: source(), Revision: rev, FS: fsys})
	if err != nil {
		t.Fatalf("run %s: %v", rev, err)
	}
	return rep
}

func techID(t *testing.T, repo repository.Repository, name string) domain.TechnologyID {
	t.Helper()
	all, _ := repo.AllRecords(context.Background())
	for _, x := range all.Technologies {
		if x.Name == name {
			return x.ID
		}
	}
	t.Fatalf("technology %q not stored", name)
	return ""
}

func getTech(repo repository.Repository, id domain.TechnologyID) domain.Technology {
	all, _ := repo.AllRecords(context.Background())
	for _, x := range all.Technologies {
		if x.ID == id {
			return x
		}
	}
	return domain.Technology{}
}

func TestFirstImport(t *testing.T) {
	eachBackend(t, func(t *testing.T) {
		p, repo := setup(t)
		rep := run(t, p, mapFS(t), "9e52f10")
		if !rep.Applied || rep.Counts.Technologies != 22 {
			t.Fatalf("report: %+v", rep)
		}
		d := rep.Diff
		if len(d.Technologies.Added) != 22 || len(d.Technologies.Modified)+len(d.Technologies.Removed) != 0 {
			t.Errorf("diff: %+v", d.Technologies)
		}
		all, _ := repo.AllRecords(context.Background())
		if issues := validator.Validate(all); len(issues) != 0 {
			t.Errorf("stored records invalid: %v", issues)
		}
		snaps, _ := repo.Snapshots(context.Background(), rep.Source.ID)
		if len(snaps) != 1 || snaps[0].Checksum == "" || len(snaps[0].Files) == 0 {
			t.Errorf("snapshots: %+v", snaps)
		}
		if _, ok, _ := repo.GetSourceBySlug(context.Background(), "enthec-webappanalyzer"); !ok {
			t.Error("source not stored")
		}
	})
}

func TestImportTwiceIsIdempotent(t *testing.T) {
	eachBackend(t, func(t *testing.T) {
		p, repo := setup(t)
		fsys := mapFS(t)
		first := run(t, p, fsys, "9e52f10")
		before, _ := repo.AllRecords(context.Background())
		second := run(t, p, fsys, "9e52f10")
		after, _ := repo.AllRecords(context.Background())

		if !second.Diff.IsEmpty() {
			t.Errorf("second import must change nothing: %+v", second.Diff)
		}
		if !reflect.DeepEqual(before, after) {
			t.Error("repository content changed on re-import")
		}
		if first.Source.ID != second.Source.ID {
			t.Error("source ID must be stable")
		}
		if snaps, _ := repo.Snapshots(context.Background(), first.Source.ID); len(snaps) != 1 {
			t.Errorf("snapshots = %d, want 1", len(snaps))
		}
	})
}

func TestNewRevisionDiff(t *testing.T) {
	eachBackend(t, func(t *testing.T) {
		p, repo := setup(t)
		fsys := mapFS(t)
		run(t, p, fsys, "r1")
		ctx := context.Background()
		aFrame := techID(t, repo, "A-Frame")
		removed := techID(t, repo, "a-blog cms")

		// Curation done by a reviewer between imports.
		st := getTech(repo, aFrame)
		st.Status = domain.StatusDeprecated
		if err := repo.Apply(ctx, repository.ChangeSet{Upsert: domain.Records{Technologies: []domain.Technology{st}}}); err != nil {
			t.Fatal(err)
		}

		editTechFile(t, fsys, "src/technologies/a.json", func(d map[string]map[string]any) {
			d["A-Frame"]["website"] = "https://aframe.example"
			delete(d, "a-blog cms")
			d["Zeta"] = map[string]any{"cats": []int{1}, "website": "https://zeta.example", "headers": map[string]string{"X-Zeta": ""}}
		})
		rep := run(t, p, fsys, "r2")

		d := rep.Diff.Technologies
		if len(d.Added) != 1 || len(d.Modified) != 1 || len(d.Removed) != 1 {
			t.Fatalf("technology diff: %+v", d)
		}
		if d.Modified[0] != string(aFrame) || d.Removed[0] != string(removed) {
			t.Errorf("diff ids: %+v", d)
		}
		if len(rep.Diff.Fingerprints.Added) != 1 {
			t.Errorf("fingerprint diff: %+v", rep.Diff.Fingerprints)
		}

		got := getTech(repo, aFrame)
		if got.Website != "https://aframe.example" {
			t.Errorf("modification not applied: %q", got.Website)
		}
		if got.Status != domain.StatusDeprecated {
			t.Errorf("reviewer status overwritten: %q", got.Status)
		}
		if got.Provenance[0].SnapshotRevision != "r2" {
			t.Errorf("provenance revision = %q", got.Provenance[0].SnapshotRevision)
		}

		// Removal is never a deletion.
		gone := getTech(repo, removed)
		if gone.ID == "" {
			t.Fatal("removed technology was deleted")
		}
		if gone.Provenance[0].State != "removed_upstream" {
			t.Errorf("state = %q", gone.Provenance[0].State)
		}

		// Rule-level removal is reported too, and a third import is stable.
		if third := run(t, p, fsys, "r2"); !third.Diff.IsEmpty() {
			t.Errorf("re-import after removal must be empty: %+v", third.Diff)
		}

		// Restoring the record marks it modified again and present.
		restored := mapFS(t)
		rep = run(t, p, restored, "r3")
		if len(rep.Diff.Technologies.Added) != 0 || !contains(rep.Diff.Technologies.Modified, string(removed)) {
			t.Errorf("restore diff: %+v", rep.Diff.Technologies)
		}
		if getTech(repo, removed).Provenance[0].State != "present" {
			t.Error("restored record must be present again")
		}
		if len(rep.Diff.Technologies.Removed) != 1 || rep.Diff.Technologies.Removed[0] == "" {
			t.Errorf("Zeta should now be removed: %+v", rep.Diff.Technologies)
		}
	})
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func TestProbeSafetyReviewSurvivesReimport(t *testing.T) {
	eachBackend(t, func(t *testing.T) {
		p, repo := setup(t)
		fsys := mapFS(t)
		run(t, p, fsys, "r1")
		ctx := context.Background()
		all, _ := repo.AllRecords(ctx)
		var fp domain.Fingerprint
		for _, f := range all.Fingerprints {
			if f.Probe != nil {
				fp = f
			}
		}
		fp.Probe.SafetyReview = "approved"
		fp.Status = domain.StatusActive
		if err := repo.Apply(ctx, repository.ChangeSet{Upsert: domain.Records{Fingerprints: []domain.Fingerprint{fp}}}); err != nil {
			t.Fatal(err)
		}
		editTechFile(t, fsys, "src/technologies/t.json", func(d map[string]map[string]any) {
			d["TYPO3 CMS"]["description"] = "changed"
		})
		run(t, p, fsys, "r2")
		all, _ = repo.AllRecords(ctx)
		for _, f := range all.Fingerprints {
			if f.ID == fp.ID && (f.Probe.SafetyReview != "approved" || f.Status != domain.StatusActive) {
				t.Errorf("review decision lost: %+v", f)
			}
		}
	})
}

func TestDryRunStoresNothing(t *testing.T) {
	eachBackend(t, func(t *testing.T) {
		p, repo := setup(t)
		rep, err := p.Run(context.Background(), pipeline.Request{
			Source: source(), Revision: "r1", FS: mapFS(t), DryRun: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		if rep.Applied || len(rep.Diff.Technologies.Added) != 22 {
			t.Errorf("report: %+v", rep)
		}
		all, _ := repo.AllRecords(context.Background())
		if len(all.Technologies) != 0 {
			t.Error("dry run stored records")
		}
		if snaps, _ := repo.Snapshots(context.Background(), rep.Source.ID); len(snaps) != 0 {
			t.Error("dry run stored a snapshot")
		}
	})
}

func TestSameRevisionDifferentContentFails(t *testing.T) {
	eachBackend(t, func(t *testing.T) {
		p, repo := setup(t)
		fsys := mapFS(t)
		run(t, p, fsys, "r1")
		before, _ := repo.AllRecords(context.Background())
		editTechFile(t, fsys, "src/technologies/a.json", func(d map[string]map[string]any) {
			d["A-Frame"]["website"] = "https://changed.example"
		})
		if _, err := p.Run(context.Background(), pipeline.Request{Source: source(), Revision: "r1", FS: fsys}); err == nil {
			t.Fatal("a pinned revision must not change")
		}
		after, _ := repo.AllRecords(context.Background())
		if !reflect.DeepEqual(before, after) {
			t.Error("failed run changed the repository")
		}
	})
}

// badExtractor yields a rule that violates semantic constraints.
type badExtractor struct{}

func (badExtractor) ID() string   { return "bad" }
func (badExtractor) Name() string { return "Bad" }
func (badExtractor) Extract(context.Context, extractor.Source) (*extractor.ExtractionResult, error) {
	return &extractor.ExtractionResult{
		Technologies: []extractor.ExtractedTechnology{{Key: "A", Name: "A"}},
		Fingerprints: []extractor.ExtractedFingerprint{{
			TechnologyKey: "A", Observation: domain.ObsHTML, Operator: domain.OpRegex,
			Pattern: "(?!x)", RegexFlavor: domain.FlavorRE2, // lookahead cannot be RE2
		}},
	}, nil
}

func TestValidationFailureStopsBeforeStoring(t *testing.T) {
	reg := extractor.NewRegistry()
	_ = reg.Register(badExtractor{})
	repo := memory.New()
	p := pipeline.New(reg, repo)
	src := domain.Source{Slug: "bad", ExtractorID: "bad", License: "MIT"}
	rep, err := p.Run(context.Background(), pipeline.Request{
		Source: src, Revision: "r1", FS: fstest.MapFS{"x": {Data: []byte("x")}},
	})
	if !errors.Is(err, pipeline.ErrValidation) {
		t.Fatalf("err = %v", err)
	}
	if rep == nil || !validator.HasErrors(rep.Issues) || rep.Applied {
		t.Errorf("report: %+v", rep)
	}
	all, _ := repo.AllRecords(context.Background())
	if len(all.Technologies) != 0 {
		t.Error("invalid import stored records")
	}
}

func TestRequestErrors(t *testing.T) {
	eachBackend(t, func(t *testing.T) {
		p, _ := setup(t)
		ctx := context.Background()
		fsys := mapFS(t)
		for name, req := range map[string]pipeline.Request{
			"empty":             {},
			"no revision":       {Source: source(), FS: fsys},
			"no fs":             {Source: source(), Revision: "r"},
			"unknown extractor": {Source: domain.Source{Slug: "s", ExtractorID: "nope"}, Revision: "r", FS: fsys},
		} {
			if _, err := p.Run(ctx, req); err == nil {
				t.Errorf("%s: expected error", name)
			}
		}
		cctx, cancel := context.WithCancel(ctx)
		cancel()
		if _, err := p.Run(cctx, pipeline.Request{Source: source(), Revision: "r", FS: fsys}); err == nil {
			t.Error("cancelled context must fail")
		}
	})
}

// Opt-in: import a full local Enthec clone twice and check idempotency.
func TestFullSnapshot(t *testing.T) {
	dir := os.Getenv("OWF_ENTHEC_SNAPSHOT")
	if dir == "" {
		t.Skip("OWF_ENTHEC_SNAPSHOT not set")
	}
	backend = "sqlite"
	p, repo := setup(t)
	fsys := os.DirFS(dir)
	include := func(path string) bool {
		return path == "src/categories.json" || path == "src/groups.json" ||
			strings.HasPrefix(path, "src/technologies/")
	}
	req := pipeline.Request{Source: source(), Revision: "full", FS: fsys, IncludeFile: include}
	first, err := p.Run(context.Background(), req)
	if err != nil {
		t.Fatalf("%v: %v", err, first.Issues)
	}
	t.Logf("counts=%+v files=%d checksum=%s", first.Counts, len(first.Snapshot.Files), first.Snapshot.Checksum)
	second, err := p.Run(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if !second.Diff.IsEmpty() {
		t.Errorf("second import changed records: %+v", second.Diff)
	}
	all, _ := repo.AllRecords(context.Background())
	if issues := validator.Validate(all); len(issues) != 0 {
		t.Errorf("%d issues, first: %v", len(issues), issues[0])
	}
}
