// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

// Package merge applies reviewer decisions to canonical records. A merge
// keeps the older record (UUIDv7 sorts by time), moves provenance, rules and
// relationships onto it, combines equivalent rules, and records the old IDs as
// aliases so later imports do not undo it. Nothing is deleted by an upstream
// refresh; only a reviewer-approved merge removes the absorbed record.
package merge

import (
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/matteoredaelli/open-web-fingerprints/internal/domain"
	"github.com/matteoredaelli/open-web-fingerprints/internal/reconciler"
	"github.com/matteoredaelli/open-web-fingerprints/internal/repository"
)

// ErrAlreadyMerged means both IDs already resolve to the same record.
var ErrAlreadyMerged = errors.New("records are already merged")

// Decision is what a reviewer decided about a conflict.
type Decision string

// Decisions.
const (
	Merge        Decision = "merge"
	KeepSeparate Decision = "keep-separate"
)

// Allocator returns the stable ID of a derived record such as a conflict.
type Allocator func(kind domain.Kind, key string) (string, error)

// Workspace is an in-memory copy of the registry on which merges are applied.
// It is turned into one atomic ChangeSet at the end.
type Workspace struct {
	cats  map[domain.CategoryID]*domain.Category
	techs map[domain.TechnologyID]*domain.Technology
	fps   map[domain.FingerprintID]*domain.Fingerprint
	rels  map[domain.RelationshipID]*domain.Relationship

	aliases   map[string]string
	conflicts map[domain.ConflictID]*domain.Conflict
	alloc     Allocator
	now       time.Time

	techFPs map[domain.TechnologyID][]domain.FingerprintID
	fpKeys  map[string]domain.FingerprintID
	relKeys map[string]domain.RelationshipID

	changed        map[string]bool // upserted record IDs
	deleted        map[string]domain.Kind
	aliasChanges   map[string]domain.Alias
	changedConfl   map[domain.ConflictID]bool
	selfRelDropped int
}

// NewWorkspace copies the records, aliases and conflicts.
func NewWorkspace(r domain.Records, aliases map[string]string, conflicts []domain.Conflict, alloc Allocator, now time.Time) *Workspace {
	w := &Workspace{
		cats:  map[domain.CategoryID]*domain.Category{},
		techs: map[domain.TechnologyID]*domain.Technology{},
		fps:   map[domain.FingerprintID]*domain.Fingerprint{},
		rels:  map[domain.RelationshipID]*domain.Relationship{},

		aliases: map[string]string{}, conflicts: map[domain.ConflictID]*domain.Conflict{},
		alloc: alloc, now: now,
		techFPs: map[domain.TechnologyID][]domain.FingerprintID{},
		fpKeys:  map[string]domain.FingerprintID{}, relKeys: map[string]domain.RelationshipID{},
		changed: map[string]bool{}, deleted: map[string]domain.Kind{},
		aliasChanges: map[string]domain.Alias{}, changedConfl: map[domain.ConflictID]bool{},
	}
	for k, v := range aliases {
		w.aliases[k] = v
	}
	for i := range r.Categories {
		c := r.Categories[i]
		w.cats[c.ID] = &c
	}
	for i := range r.Technologies {
		t := r.Technologies[i]
		t.CategoryIDs = append([]domain.CategoryID(nil), t.CategoryIDs...)
		w.techs[t.ID] = &t
	}
	for i := range r.Fingerprints {
		f := r.Fingerprints[i]
		w.fps[f.ID] = &f
		w.techFPs[f.TechnologyID] = append(w.techFPs[f.TechnologyID], f.ID)
		w.fpKeys[f.SemanticKey()] = f.ID
	}
	for i := range r.Relationships {
		x := r.Relationships[i]
		w.rels[x.ID] = &x
		w.relKeys[reconciler.RelationshipKey(x)] = x.ID
	}
	for i := range conflicts {
		c := conflicts[i]
		w.conflicts[c.ID] = &c
	}
	return w
}

func (w *Workspace) resolve(id string) string { return reconciler.Resolve(w.aliases, id) }

func (w *Workspace) setAlias(kind domain.Kind, oldID, newID string) {
	w.aliases[oldID] = newID
	w.aliasChanges[oldID] = domain.Alias{Kind: kind, OldID: oldID, NewID: newID}
	// Anything that pointed at the absorbed ID now points at the survivor.
	for k, v := range w.aliases {
		if v == oldID {
			w.aliases[k] = newID
			w.aliasChanges[k] = domain.Alias{Kind: kind, OldID: k, NewID: newID}
		}
	}
}

func (w *Workspace) drop(kind domain.Kind, id string) {
	delete(w.changed, id)
	w.deleted[id] = kind
}

func order(a, b string) (string, string) {
	if b < a {
		return b, a
	}
	return a, b
}

// MergeTechnologies merges two technologies and returns the survivor's ID.
func (w *Workspace) MergeTechnologies(a, b string) (string, error) {
	sid, aid := order(w.resolve(a), w.resolve(b))
	if sid == aid {
		return sid, ErrAlreadyMerged
	}
	surv, ok1 := w.techs[domain.TechnologyID(sid)]
	abs, ok2 := w.techs[domain.TechnologyID(aid)]
	if !ok1 || !ok2 {
		return "", fmt.Errorf("merge: technology %s or %s not found", sid, aid)
	}
	S, A := domain.TechnologyID(sid), domain.TechnologyID(aid)

	if surv.Website != "" && abs.Website != "" &&
		reconciler.WebsiteRelation(surv.Website, abs.Website) == reconciler.Different {
		if err := w.addConflict(domain.ConflictMetadata, "metadata|"+sid+"|website", []string{sid},
			sourcesOf(surv.Provenance, abs.Provenance), map[string]string{
				"field": "website", "kept": surv.Website, "other": abs.Website, "absorbed": aid,
			}); err != nil {
			return "", err
		}
	}

	surv.Provenance = domain.UnionProvenance(surv.Provenance, abs.Provenance)
	if abs.Name != surv.Name {
		surv.Aliases = unionStrings(surv.Aliases, []string{abs.Name})
	}
	surv.Aliases = unionStrings(surv.Aliases, abs.Aliases)
	surv.CPE = unionStrings(surv.CPE, abs.CPE)
	for _, c := range abs.CategoryIDs {
		surv.CategoryIDs = append(surv.CategoryIDs, domain.CategoryID(w.resolve(string(c))))
	}
	surv.CategoryIDs = uniqueCats(surv.CategoryIDs)
	fill(&surv.Description, abs.Description)
	fill(&surv.Website, abs.Website)
	fill(&surv.Kind, abs.Kind)
	if surv.VendorID == "" {
		surv.VendorID = abs.VendorID
	}
	if surv.OpenSource == nil {
		surv.OpenSource = abs.OpenSource
	}
	if surv.SaaS == nil {
		surv.SaaS = abs.SaaS
	}
	w.changed[sid] = true

	// Rules.
	for _, fid := range append([]domain.FingerprintID(nil), w.techFPs[A]...) {
		f := w.fps[fid]
		delete(w.fpKeys, f.SemanticKey())
		f.TechnologyID = S
		key := f.SemanticKey()
		if eid, exists := w.fpKeys[key]; exists && eid != fid {
			e := w.fps[eid]
			e.Provenance = domain.UnionProvenance(e.Provenance, f.Provenance)
			if err := w.mergeConfidence(e); err != nil {
				return "", err
			}
			w.changed[string(eid)] = true
			w.setAlias(domain.KindFingerprint, string(fid), string(eid))
			delete(w.fps, fid)
			w.drop(domain.KindFingerprint, string(fid))
			continue
		}
		w.fpKeys[key] = fid
		w.techFPs[S] = append(w.techFPs[S], fid)
		w.changed[string(fid)] = true
	}
	delete(w.techFPs, A)

	// Relationships.
	ids := make([]string, 0, len(w.rels))
	for id := range w.rels {
		ids = append(ids, string(id))
	}
	sort.Strings(ids)
	for _, id := range ids {
		r := w.rels[domain.RelationshipID(id)]
		if r.FromTechnologyID != A && r.ToTechnologyID != A {
			continue
		}
		delete(w.relKeys, reconciler.RelationshipKey(*r))
		if r.FromTechnologyID == A {
			r.FromTechnologyID = S
		}
		if r.ToTechnologyID == A {
			r.ToTechnologyID = S
		}
		w.settleRelationship(r)
	}

	delete(w.techs, A)
	w.drop(domain.KindTechnology, aid)
	w.setAlias(domain.KindTechnology, aid, sid)
	return sid, nil
}

// settleRelationship stores a rewritten relationship, merging it into an
// equivalent one or dropping it when it became a self reference.
func (w *Workspace) settleRelationship(r *domain.Relationship) {
	id := string(r.ID)
	if r.ToTechnologyID != "" && r.ToTechnologyID == r.FromTechnologyID {
		delete(w.rels, r.ID)
		w.drop(domain.KindRelationship, id)
		w.selfRelDropped++
		return
	}
	key := reconciler.RelationshipKey(*r)
	if eid, exists := w.relKeys[key]; exists && eid != r.ID {
		e := w.rels[eid]
		e.Provenance = domain.UnionProvenance(e.Provenance, r.Provenance)
		w.changed[string(eid)] = true
		w.setAlias(domain.KindRelationship, id, string(eid))
		delete(w.rels, r.ID)
		w.drop(domain.KindRelationship, id)
		return
	}
	w.relKeys[key] = r.ID
	w.changed[id] = true
}

// mergeConfidence applies the lowest explicit confidence and records a
// conflict when sources disagree.
func (w *Workspace) mergeConfidence(f *domain.Fingerprint) error {
	distinct := map[float64]bool{}
	for _, p := range f.Provenance {
		if p.OriginalConfidence != nil {
			distinct[*p.OriginalConfidence] = true
		}
	}
	f.Confidence = domain.LowestExplicitConfidence(f.Provenance, f.Confidence)
	if len(distinct) < 2 {
		return nil
	}
	vals := make([]float64, 0, len(distinct))
	for v := range distinct {
		vals = append(vals, v)
	}
	sort.Float64s(vals)
	return w.addConflict(domain.ConflictConfidence, "confidence|"+string(f.ID), []string{string(f.ID)},
		sourcesOf(f.Provenance), map[string]string{
			"lowest": fmt.Sprint(vals[0]), "highest": fmt.Sprint(vals[len(vals)-1]),
		})
}

// MergeCategories merges two categories and returns the survivor's ID.
func (w *Workspace) MergeCategories(a, b string) (string, error) {
	sid, aid := order(w.resolve(a), w.resolve(b))
	if sid == aid {
		return sid, ErrAlreadyMerged
	}
	surv, ok1 := w.cats[domain.CategoryID(sid)]
	abs, ok2 := w.cats[domain.CategoryID(aid)]
	if !ok1 || !ok2 {
		return "", fmt.Errorf("merge: category %s or %s not found", sid, aid)
	}
	S, A := domain.CategoryID(sid), domain.CategoryID(aid)
	surv.Provenance = domain.UnionProvenance(surv.Provenance, abs.Provenance)
	fill(&surv.Group, abs.Group)
	if surv.ParentID == "" {
		surv.ParentID = abs.ParentID
	}
	w.changed[sid] = true

	for _, c := range w.cats {
		if c.ParentID == A {
			c.ParentID = S
			w.changed[string(c.ID)] = true
		}
	}
	for _, t := range w.techs {
		for i, c := range t.CategoryIDs {
			if c == A {
				t.CategoryIDs[i] = S
				t.CategoryIDs = uniqueCats(t.CategoryIDs)
				w.changed[string(t.ID)] = true
				break
			}
		}
	}
	ids := make([]string, 0, len(w.rels))
	for id := range w.rels {
		ids = append(ids, string(id))
	}
	sort.Strings(ids)
	for _, id := range ids {
		r := w.rels[domain.RelationshipID(id)]
		if r.ToCategoryID != A {
			continue
		}
		delete(w.relKeys, reconciler.RelationshipKey(*r))
		r.ToCategoryID = S
		w.settleRelationship(r)
	}
	delete(w.cats, A)
	w.drop(domain.KindCategory, aid)
	w.setAlias(domain.KindCategory, aid, sid)
	return sid, nil
}

func (w *Workspace) addConflict(kind, key string, records []string, srcs []domain.SourceID, detail map[string]string) error {
	id, err := w.alloc(domain.KindConflict, key)
	if err != nil {
		return fmt.Errorf("merge: allocate conflict: %w", err)
	}
	cid := domain.ConflictID(id)
	if c, ok := w.conflicts[cid]; ok {
		c.Detail, c.RecordIDs, c.SourceIDs, c.UpdatedAt = detail, records, srcs, w.now
		w.changedConfl[cid] = true
		return nil
	}
	w.conflicts[cid] = &domain.Conflict{
		ID: cid, Kind: kind, State: domain.ConflictOpen, RecordIDs: records, SourceIDs: srcs,
		Detail: detail, CreatedAt: w.now, UpdatedAt: w.now,
	}
	w.changedConfl[cid] = true
	return nil
}

// Decide applies a reviewer decision to an open conflict.
func (w *Workspace) Decide(id domain.ConflictID, d Decision, note string) error {
	c, ok := w.conflicts[id]
	if !ok {
		return fmt.Errorf("conflict %s not found", id)
	}
	if c.State != domain.ConflictOpen {
		return fmt.Errorf("conflict %s is %s, not open", id, c.State)
	}
	switch d {
	case KeepSeparate:
		c.State, c.Resolution = domain.ConflictIgnored, withNote("kept separate", note)
	case Merge:
		var survivor string
		var err error
		switch c.Kind {
		case domain.ConflictIdentityCandidate:
			survivor, err = w.MergeTechnologies(c.RecordIDs[0], c.RecordIDs[1])
		case domain.ConflictCategoryCandidate:
			survivor, err = w.MergeCategories(c.RecordIDs[0], c.RecordIDs[1])
		default:
			return fmt.Errorf("conflict %s of kind %s cannot be merged", id, c.Kind)
		}
		switch {
		case errors.Is(err, ErrAlreadyMerged):
			c.Resolution = withNote("already merged into "+survivor, note)
		case err != nil:
			return err
		default:
			c.Resolution = withNote("merged into "+survivor, note)
		}
		c.State = domain.ConflictResolved
		w.supersede(c.ID)
	default:
		return fmt.Errorf("unknown decision %q", d)
	}
	c.UpdatedAt = w.now
	w.changedConfl[id] = true
	return nil
}

// supersede closes open candidate conflicts whose records were merged away or
// have become the same record.
func (w *Workspace) supersede(except domain.ConflictID) {
	for id, c := range w.conflicts {
		if id == except || c.State != domain.ConflictOpen {
			continue
		}
		if c.Kind != domain.ConflictIdentityCandidate && c.Kind != domain.ConflictCategoryCandidate {
			continue
		}
		if len(c.RecordIDs) != 2 {
			continue
		}
		a, b := w.resolve(c.RecordIDs[0]), w.resolve(c.RecordIDs[1])
		if a == c.RecordIDs[0] && b == c.RecordIDs[1] {
			continue
		}
		c.State, c.UpdatedAt = domain.ConflictResolved, w.now
		w.changedConfl[id] = true
		if a == b {
			c.Resolution = "superseded: both records were merged"
			continue
		}
		c.Resolution = "superseded: a record was merged; the pair is now tracked by a new candidate"
		w.reopenPair(c.Kind, a, b)
	}
}

// ConflictState returns the current state of a conflict in the workspace.
func (w *Workspace) ConflictState(id domain.ConflictID) (string, bool) {
	c, ok := w.conflicts[id]
	if !ok {
		return "", false
	}
	return c.State, true
}

// reopenPair makes sure the pair that remains after a merge is still
// reviewed. It uses the same key and evidence as the detector, so the next
// import finds it unchanged. An existing decision about the pair is kept.
func (w *Workspace) reopenPair(kind, a, b string) {
	var detail map[string]string
	var srcs []domain.SourceID
	switch kind {
	case domain.ConflictIdentityCandidate:
		x, ok1 := w.techs[domain.TechnologyID(a)]
		y, ok2 := w.techs[domain.TechnologyID(b)]
		if !ok1 || !ok2 {
			return
		}
		detail, srcs = reconciler.IdentityDetail(*x, *y), reconciler.Sources(x.Provenance, y.Provenance)
	case domain.ConflictCategoryCandidate:
		x, ok1 := w.cats[domain.CategoryID(a)]
		y, ok2 := w.cats[domain.CategoryID(b)]
		if !ok1 || !ok2 {
			return
		}
		detail, srcs = reconciler.CategoryDetail(*x, *y), reconciler.Sources(x.Provenance, y.Provenance)
	default:
		return
	}
	ids := []string{a, b}
	sort.Strings(ids)
	// addConflict keeps the state of a conflict that already exists.
	_ = w.addConflict(kind, reconciler.PairKey(kind, a, b), ids, srcs, detail)
}

// Stats reports side effects of the merges done so far.
type Stats struct {
	DroppedSelfRelationships int
}

// Stats returns merge side effects.
func (w *Workspace) Stats() Stats { return Stats{DroppedSelfRelationships: w.selfRelDropped} }

// ChangeSet returns everything to store, sorted for determinism.
func (w *Workspace) ChangeSet() repository.ChangeSet {
	var cs repository.ChangeSet
	for id := range w.changed {
		switch {
		case w.cats[domain.CategoryID(id)] != nil:
			cs.Upsert.Categories = append(cs.Upsert.Categories, *w.cats[domain.CategoryID(id)])
		case w.techs[domain.TechnologyID(id)] != nil:
			cs.Upsert.Technologies = append(cs.Upsert.Technologies, *w.techs[domain.TechnologyID(id)])
		case w.fps[domain.FingerprintID(id)] != nil:
			cs.Upsert.Fingerprints = append(cs.Upsert.Fingerprints, *w.fps[domain.FingerprintID(id)])
		case w.rels[domain.RelationshipID(id)] != nil:
			cs.Upsert.Relationships = append(cs.Upsert.Relationships, *w.rels[domain.RelationshipID(id)])
		}
	}
	sort.Slice(cs.Upsert.Categories, func(i, j int) bool { return cs.Upsert.Categories[i].ID < cs.Upsert.Categories[j].ID })
	sort.Slice(cs.Upsert.Technologies, func(i, j int) bool { return cs.Upsert.Technologies[i].ID < cs.Upsert.Technologies[j].ID })
	sort.Slice(cs.Upsert.Fingerprints, func(i, j int) bool { return cs.Upsert.Fingerprints[i].ID < cs.Upsert.Fingerprints[j].ID })
	sort.Slice(cs.Upsert.Relationships, func(i, j int) bool { return cs.Upsert.Relationships[i].ID < cs.Upsert.Relationships[j].ID })
	for id, kind := range w.deleted {
		switch kind {
		case domain.KindCategory:
			cs.Delete.Categories = append(cs.Delete.Categories, id)
		case domain.KindTechnology:
			cs.Delete.Technologies = append(cs.Delete.Technologies, id)
		case domain.KindFingerprint:
			cs.Delete.Fingerprints = append(cs.Delete.Fingerprints, id)
		case domain.KindRelationship:
			cs.Delete.Relationships = append(cs.Delete.Relationships, id)
		}
	}
	for _, l := range []*[]string{&cs.Delete.Categories, &cs.Delete.Technologies, &cs.Delete.Fingerprints, &cs.Delete.Relationships} {
		sort.Strings(*l)
	}
	for _, a := range w.aliasChanges {
		cs.Aliases = append(cs.Aliases, a)
	}
	sort.Slice(cs.Aliases, func(i, j int) bool { return cs.Aliases[i].OldID < cs.Aliases[j].OldID })
	for id := range w.changedConfl {
		cs.Conflicts = append(cs.Conflicts, *w.conflicts[id])
	}
	sort.Slice(cs.Conflicts, func(i, j int) bool { return cs.Conflicts[i].ID < cs.Conflicts[j].ID })
	return cs
}

func withNote(base, note string) string {
	if note == "" {
		return base
	}
	return base + ": " + note
}

func fill(dst *string, v string) {
	if *dst == "" {
		*dst = v
	}
}

func unionStrings(a, b []string) []string {
	out := append([]string(nil), a...)
	have := map[string]bool{}
	for _, x := range a {
		have[x] = true
	}
	for _, x := range b {
		if !have[x] {
			have[x] = true
			out = append(out, x)
		}
	}
	return out
}

func uniqueCats(in []domain.CategoryID) []domain.CategoryID {
	var out []domain.CategoryID
	seen := map[domain.CategoryID]bool{}
	for _, c := range in {
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	return out
}

func sourcesOf(lists ...[]domain.Provenance) []domain.SourceID {
	seen := map[domain.SourceID]bool{}
	var out []domain.SourceID
	for _, l := range lists {
		for _, p := range l {
			if !seen[p.SourceID] {
				seen[p.SourceID] = true
				out = append(out, p.SourceID)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
