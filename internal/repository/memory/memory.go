// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

// Package memory is an in-memory repository.Repository, used by tests and
// dry runs.
package memory

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"github.com/matteoredaelli/open-web-fingerprints/internal/domain"
	"github.com/matteoredaelli/open-web-fingerprints/internal/repository"
)

// Repo is a thread-safe in-memory repository.
type Repo struct {
	mu        sync.Mutex
	ids       map[string]string
	sources   map[domain.SourceID]domain.Source
	snapshots map[domain.SourceID][]domain.Snapshot
	cats      map[domain.CategoryID]domain.Category
	techs     map[domain.TechnologyID]domain.Technology
	fps       map[domain.FingerprintID]domain.Fingerprint
	rels      map[domain.RelationshipID]domain.Relationship
	conflicts map[domain.ConflictID]domain.Conflict
}

var _ repository.Repository = (*Repo)(nil)

// New returns an empty repository.
func New() *Repo {
	return &Repo{
		ids:       map[string]string{},
		sources:   map[domain.SourceID]domain.Source{},
		snapshots: map[domain.SourceID][]domain.Snapshot{},
		cats:      map[domain.CategoryID]domain.Category{},
		techs:     map[domain.TechnologyID]domain.Technology{},
		fps:       map[domain.FingerprintID]domain.Fingerprint{},
		rels:      map[domain.RelationshipID]domain.Relationship{},
		conflicts: map[domain.ConflictID]domain.Conflict{},
	}
}

// Allocate implements repository.Repository.
func (r *Repo) Allocate(kind domain.Kind, sourceID, key string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	k := fmt.Sprintf("%s|%s|%s", kind, sourceID, key)
	if id, ok := r.ids[k]; ok {
		return id, nil
	}
	id, err := domain.NewID(kind)
	if err != nil {
		return "", err
	}
	r.ids[k] = id
	return id, nil
}

// GetSourceBySlug implements repository.Repository.
func (r *Repo) GetSourceBySlug(ctx context.Context, slug string) (domain.Source, bool, error) {
	if err := ctx.Err(); err != nil {
		return domain.Source{}, false, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range r.sources {
		if s.Slug == slug {
			return s, true, nil
		}
	}
	return domain.Source{}, false, nil
}

// Sources implements repository.Repository.
func (r *Repo) Sources(ctx context.Context) ([]domain.Source, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]domain.Source, 0, len(r.sources))
	for _, s := range r.sources {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Slug < out[j].Slug })
	return out, nil
}

// UpsertSource implements repository.Repository.
func (r *Repo) UpsertSource(ctx context.Context, s domain.Source) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sources[s.ID] = s
	return nil
}

// PutSnapshot implements repository.Repository.
func (r *Repo) PutSnapshot(ctx context.Context, s domain.Snapshot) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, e := range r.snapshots[s.SourceID] {
		if e.Revision == s.Revision {
			if e.Checksum != s.Checksum {
				return fmt.Errorf("snapshot %s of %s already stored with checksum %s, got %s",
					s.Revision, s.SourceID, e.Checksum, s.Checksum)
			}
			return nil
		}
	}
	r.snapshots[s.SourceID] = append(r.snapshots[s.SourceID], s)
	return nil
}

// Snapshots implements repository.Repository.
func (r *Repo) Snapshots(ctx context.Context, id domain.SourceID) ([]domain.Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]domain.Snapshot(nil), r.snapshots[id]...), nil
}

func hasSource(p []domain.Provenance, id domain.SourceID) bool {
	for _, x := range p {
		if x.SourceID == id {
			return true
		}
	}
	return false
}

// SourceRecords implements repository.Repository.
func (r *Repo) SourceRecords(ctx context.Context, id domain.SourceID) (domain.Records, error) {
	if err := ctx.Err(); err != nil {
		return domain.Records{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.collect(func(p []domain.Provenance) bool { return hasSource(p, id) }), nil
}

// Conflicts implements repository.Repository.
func (r *Repo) Conflicts(ctx context.Context) ([]domain.Conflict, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]domain.Conflict, 0, len(r.conflicts))
	for _, c := range r.conflicts {
		c.RecordIDs = append([]string(nil), c.RecordIDs...)
		c.SourceIDs = append([]domain.SourceID(nil), c.SourceIDs...)
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// AllRecords implements repository.Repository.
func (r *Repo) AllRecords(ctx context.Context) (domain.Records, error) {
	if err := ctx.Err(); err != nil {
		return domain.Records{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.collect(func([]domain.Provenance) bool { return true }), nil
}

// collect returns deep-enough copies sorted by ID. Caller holds the lock.
func (r *Repo) collect(keep func([]domain.Provenance) bool) domain.Records {
	var out domain.Records
	for _, c := range r.cats {
		if keep(c.Provenance) {
			c.Provenance = append([]domain.Provenance(nil), c.Provenance...)
			out.Categories = append(out.Categories, c)
		}
	}
	for _, t := range r.techs {
		if keep(t.Provenance) {
			t.Provenance = append([]domain.Provenance(nil), t.Provenance...)
			out.Technologies = append(out.Technologies, t)
		}
	}
	for _, f := range r.fps {
		if keep(f.Provenance) {
			f.Provenance = append([]domain.Provenance(nil), f.Provenance...)
			out.Fingerprints = append(out.Fingerprints, f)
		}
	}
	for _, x := range r.rels {
		if keep(x.Provenance) {
			x.Provenance = append([]domain.Provenance(nil), x.Provenance...)
			out.Relationships = append(out.Relationships, x)
		}
	}
	sort.Slice(out.Categories, func(i, j int) bool { return out.Categories[i].ID < out.Categories[j].ID })
	sort.Slice(out.Technologies, func(i, j int) bool { return out.Technologies[i].ID < out.Technologies[j].ID })
	sort.Slice(out.Fingerprints, func(i, j int) bool { return out.Fingerprints[i].ID < out.Fingerprints[j].ID })
	sort.Slice(out.Relationships, func(i, j int) bool { return out.Relationships[i].ID < out.Relationships[j].ID })
	return out
}

func markRemoved(p []domain.Provenance, id domain.SourceID) []domain.Provenance {
	out := append([]domain.Provenance(nil), p...)
	for i := range out {
		if out[i].SourceID == id {
			out[i].State = "removed_upstream"
		}
	}
	return out
}

// Apply implements repository.Repository. All checks run before any write,
// so a failing change set leaves the repository untouched.
func (r *Repo) Apply(ctx context.Context, cs repository.ChangeSet) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, id := range cs.RemovedUpstream.Categories {
		if _, ok := r.cats[domain.CategoryID(id)]; !ok {
			return fmt.Errorf("removed category %s does not exist", id)
		}
	}
	for _, id := range cs.RemovedUpstream.Technologies {
		if _, ok := r.techs[domain.TechnologyID(id)]; !ok {
			return fmt.Errorf("removed technology %s does not exist", id)
		}
	}
	for _, id := range cs.RemovedUpstream.Fingerprints {
		if _, ok := r.fps[domain.FingerprintID(id)]; !ok {
			return fmt.Errorf("removed fingerprint %s does not exist", id)
		}
	}
	for _, id := range cs.RemovedUpstream.Relationships {
		if _, ok := r.rels[domain.RelationshipID(id)]; !ok {
			return fmt.Errorf("removed relationship %s does not exist", id)
		}
	}
	for _, c := range cs.Conflicts {
		r.conflicts[c.ID] = c
	}
	for _, c := range cs.Upsert.Categories {
		r.cats[c.ID] = c
	}
	for _, t := range cs.Upsert.Technologies {
		r.techs[t.ID] = t
	}
	for _, f := range cs.Upsert.Fingerprints {
		r.fps[f.ID] = f
	}
	for _, x := range cs.Upsert.Relationships {
		r.rels[x.ID] = x
	}
	for _, id := range cs.RemovedUpstream.Categories {
		c := r.cats[domain.CategoryID(id)]
		c.Provenance = markRemoved(c.Provenance, cs.SourceID)
		r.cats[c.ID] = c
	}
	for _, id := range cs.RemovedUpstream.Technologies {
		t := r.techs[domain.TechnologyID(id)]
		t.Provenance = markRemoved(t.Provenance, cs.SourceID)
		r.techs[t.ID] = t
	}
	for _, id := range cs.RemovedUpstream.Fingerprints {
		f := r.fps[domain.FingerprintID(id)]
		f.Provenance = markRemoved(f.Provenance, cs.SourceID)
		r.fps[f.ID] = f
	}
	for _, id := range cs.RemovedUpstream.Relationships {
		x := r.rels[domain.RelationshipID(id)]
		x.Provenance = markRemoved(x.Provenance, cs.SourceID)
		r.rels[x.ID] = x
	}
	return nil
}
