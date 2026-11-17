// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

// Package pipeline coordinates one import: checksum the snapshot, extract,
// normalize, validate, diff against stored records, and persist.
package pipeline

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"reflect"
	"sort"
	"time"

	"github.com/matteoredaelli/open-web-fingerprints/internal/domain"
	"github.com/matteoredaelli/open-web-fingerprints/internal/extractor"
	"github.com/matteoredaelli/open-web-fingerprints/internal/normalizer"
	"github.com/matteoredaelli/open-web-fingerprints/internal/reconciler"
	"github.com/matteoredaelli/open-web-fingerprints/internal/repository"
	"github.com/matteoredaelli/open-web-fingerprints/internal/validator"
)

// ErrValidation is returned when the normalized records violate semantic
// constraints. The Report still lists the issues.
var ErrValidation = errors.New("validation failed")

// Pipeline wires the stages. All collaborators are injected.
type Pipeline struct {
	Extractors *extractor.Registry
	// NewNormalizer builds a normalizer bound to the given ID allocator.
	NewNormalizer func(normalizer.IDAllocator) normalizer.Normalizer
	Repo          repository.Repository
	Now           func() time.Time
	Logger        *slog.Logger
}

// New returns a Pipeline with the default normalizer, clock and logger.
func New(ex *extractor.Registry, repo repository.Repository) *Pipeline {
	return &Pipeline{
		Extractors: ex, Repo: repo, Now: time.Now, Logger: slog.Default(),
		NewNormalizer: func(a normalizer.IDAllocator) normalizer.Normalizer { return normalizer.New(a) },
	}
}

// Request describes one import of an already fetched snapshot.
type Request struct {
	// Source holds slug, name, license, extractor_id and so on. ID may be empty.
	Source   domain.Source
	Revision string
	FS       fs.FS
	// IncludeFile selects the files covered by the snapshot checksum.
	// Nil means every file except .git.
	IncludeFile func(path string) bool
	// DryRun computes the report without storing anything. New IDs may still
	// be reserved by the repository's allocator.
	DryRun bool
}

// Report is the outcome of a run.
type Report struct {
	Source   domain.Source
	Snapshot domain.Snapshot
	Counts   Counts
	Diff     Diff
	Warnings []extractor.Warning
	Issues   []validator.Issue
	Applied  bool
}

// Counts are the sizes of the normalized output.
type Counts struct {
	Categories, Technologies, Fingerprints, Relationships int
}

// Run executes the pipeline.
func (p *Pipeline) Run(ctx context.Context, req Request) (*Report, error) {
	if req.Source.Slug == "" || req.Source.ExtractorID == "" || req.Revision == "" || req.FS == nil {
		return nil, fmt.Errorf("pipeline: request needs source slug, extractor_id, revision and snapshot")
	}
	ext, err := p.Extractors.Get(req.Source.ExtractorID)
	if err != nil {
		return nil, fmt.Errorf("pipeline: %w", err)
	}
	log := p.Logger.With("source", req.Source.Slug, "revision", req.Revision)
	rep := &Report{}

	src, err := p.resolveSource(ctx, req.Source)
	if err != nil {
		return nil, err
	}
	rep.Source = src

	sum, files, err := checksumSnapshot(req.FS, req.IncludeFile)
	if err != nil {
		return nil, err
	}
	now := p.Now().UTC()
	rep.Snapshot = domain.Snapshot{
		SourceID: src.ID, Revision: req.Revision, RetrievedAt: now, Checksum: sum, Files: files,
	}
	if err := p.checkSnapshotUnchanged(ctx, rep.Snapshot); err != nil {
		return nil, err
	}
	log.Info("snapshot checksummed", "files", len(files), "checksum", sum)

	res, err := ext.Extract(ctx, extractor.Source{
		ID: src.Slug, URL: src.URL, Revision: req.Revision, License: src.License, FS: req.FS,
	})
	if err != nil {
		return nil, fmt.Errorf("pipeline: extract: %w", err)
	}

	all, err := p.Repo.AllRecords(ctx)
	if err != nil {
		return nil, fmt.Errorf("pipeline: load existing records: %w", err)
	}
	norm, err := p.NewNormalizer(p.Repo).Normalize(normalizer.Input{
		Source: src, Revision: req.Revision, ImportedAt: now, Extraction: res, Existing: all,
	})
	if err != nil {
		return nil, fmt.Errorf("pipeline: normalize: %w", err)
	}
	rep.Warnings = norm.Warnings
	aliases, err := p.Repo.Aliases(ctx)
	if err != nil {
		return nil, fmt.Errorf("pipeline: load aliases: %w", err)
	}
	tr := reconciler.Translate(norm.Records(), all, aliases)
	rep.Warnings = append(rep.Warnings, tr.Warnings...)
	fresh := tr.Records
	rep.Counts = Counts{len(fresh.Categories), len(fresh.Technologies), len(fresh.Fingerprints), len(fresh.Relationships)}

	rep.Issues = validator.Validate(fresh)
	if validator.HasErrors(rep.Issues) {
		return rep, fmt.Errorf("pipeline: %w: %d issues", ErrValidation, len(rep.Issues))
	}

	cs, diff := diffRecords(src.ID, all, fresh)
	cs.Aliases = tr.Aliases

	candidates, err := reconciler.Candidates(reconciler.Input{
		Fresh: effective(fresh, cs.Upsert, all), Other: withoutSource(all, src.ID), Now: now,
		Alloc: func(k domain.Kind, key string) (string, error) { return p.Repo.Allocate(k, "", key) },
	})
	if err != nil {
		return nil, fmt.Errorf("pipeline: reconcile: %w", err)
	}
	known, err := p.Repo.Conflicts(ctx)
	if err != nil {
		return nil, fmt.Errorf("pipeline: load conflicts: %w", err)
	}
	cs.Conflicts, diff.Conflicts = mergeConflicts(known, candidates, now)
	rep.Diff = diff

	if req.DryRun {
		log.Info("dry run: nothing stored")
		return rep, nil
	}
	if err := p.Repo.UpsertSource(ctx, src); err != nil {
		return nil, fmt.Errorf("pipeline: store source: %w", err)
	}
	if err := p.Repo.PutSnapshot(ctx, rep.Snapshot); err != nil {
		return nil, fmt.Errorf("pipeline: store snapshot: %w", err)
	}
	if err := p.Repo.Apply(ctx, cs); err != nil {
		return nil, fmt.Errorf("pipeline: apply changes: %w", err)
	}
	rep.Applied = true
	log.Info("import applied", "unchanged", diff.IsEmpty())
	return rep, nil
}

// resolveSource reuses the stored source ID (and keeps the stored values
// for fields the request leaves empty), or allocates a new ID.
func (p *Pipeline) resolveSource(ctx context.Context, s domain.Source) (domain.Source, error) {
	cur, ok, err := p.Repo.GetSourceBySlug(ctx, s.Slug)
	if err != nil {
		return s, fmt.Errorf("pipeline: look up source: %w", err)
	}
	if ok {
		s.ID = cur.ID
		return s, nil
	}
	id, err := p.Repo.Allocate(domain.KindSource, "", s.Slug)
	if err != nil {
		return s, fmt.Errorf("pipeline: allocate source ID: %w", err)
	}
	s.ID = domain.SourceID(id)
	return s, nil
}

// checkSnapshotUnchanged fails early if this revision was imported before
// with different content: a pinned revision must never change.
func (p *Pipeline) checkSnapshotUnchanged(ctx context.Context, s domain.Snapshot) error {
	prev, err := p.Repo.Snapshots(ctx, s.SourceID)
	if err != nil {
		return fmt.Errorf("pipeline: load snapshots: %w", err)
	}
	for _, e := range prev {
		if e.Revision == s.Revision && e.Checksum != s.Checksum {
			return fmt.Errorf("pipeline: revision %s was imported with checksum %s, now %s",
				s.Revision, e.Checksum, s.Checksum)
		}
	}
	return nil
}

// withoutSource keeps the records that carry no provenance from the source.
func withoutSource(r domain.Records, sid domain.SourceID) domain.Records {
	has := func(p []domain.Provenance) bool { return len(sourceEntries(p, sid)) > 0 }
	var out domain.Records
	for _, x := range r.Categories {
		if !has(x.Provenance) {
			out.Categories = append(out.Categories, x)
		}
	}
	for _, x := range r.Technologies {
		if !has(x.Provenance) {
			out.Technologies = append(out.Technologies, x)
		}
	}
	return out
}

// mergeConflicts returns the conflicts to store and what changed. A known
// conflict is left alone, with its state and resolution, unless the evidence
// changed; then it is reopened so that a reviewer sees the new facts.
func mergeConflicts(known, found []domain.Conflict, now time.Time) ([]domain.Conflict, Change) {
	byID := make(map[domain.ConflictID]domain.Conflict, len(known))
	for _, k := range known {
		byID[k.ID] = k
	}
	var upsert []domain.Conflict
	var ch Change
	for _, f := range found {
		k, ok := byID[f.ID]
		switch {
		case !ok:
			upsert = append(upsert, f)
			ch.Added = append(ch.Added, string(f.ID))
		case !reflect.DeepEqual(k.Detail, f.Detail) || !reflect.DeepEqual(k.RecordIDs, f.RecordIDs):
			f.CreatedAt, f.State, f.Resolution, f.UpdatedAt = k.CreatedAt, domain.ConflictOpen, "", now
			upsert = append(upsert, f)
			ch.Modified = append(ch.Modified, string(f.ID))
		}
	}
	sort.Strings(ch.Added)
	sort.Strings(ch.Modified)
	return upsert, ch
}

// effective returns the technologies and categories as they will be stored
// after this import: the upserted version when there is one, the stored one
// when the import leaves the record alone (for example when another source
// owns its content), and the fresh one for new records. Conflict evidence is
// computed on these, so it never depends on which source imported last.
func effective(fresh, upsert, stored domain.Records) domain.Records {
	ct := map[domain.TechnologyID]domain.Technology{}
	for _, t := range stored.Technologies {
		ct[t.ID] = t
	}
	for _, t := range upsert.Technologies {
		ct[t.ID] = t
	}
	cc := map[domain.CategoryID]domain.Category{}
	for _, c := range stored.Categories {
		cc[c.ID] = c
	}
	for _, c := range upsert.Categories {
		cc[c.ID] = c
	}
	var out domain.Records
	for _, t := range fresh.Technologies {
		if v, ok := ct[t.ID]; ok {
			t = v
		}
		out.Technologies = append(out.Technologies, t)
	}
	for _, c := range fresh.Categories {
		if v, ok := cc[c.ID]; ok {
			c = v
		}
		out.Categories = append(out.Categories, c)
	}
	return out
}
