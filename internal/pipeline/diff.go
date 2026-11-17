// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package pipeline

import (
	"reflect"
	"sort"
	"time"

	"github.com/matteoredaelli/open-web-fingerprints/internal/domain"
	"github.com/matteoredaelli/open-web-fingerprints/internal/repository"
)

// Change lists record IDs by kind of change.
type Change struct {
	Added    []string
	Modified []string
	// Removed lists records the source no longer provides. They are not
	// deleted: their provenance is marked removed_upstream for review.
	Removed []string
}

// Diff is the reviewable result of comparing a normalized import with the
// stored records of the same source.
type Diff struct {
	Categories    Change
	Technologies  Change
	Fingerprints  Change
	Relationships Change
}

// IsEmpty reports whether nothing changes.
func (d Diff) IsEmpty() bool {
	for _, c := range []Change{d.Categories, d.Technologies, d.Fingerprints, d.Relationships} {
		if len(c.Added)+len(c.Modified)+len(c.Removed) > 0 {
			return false
		}
	}
	return true
}

// spec tells the generic diff how to treat one record type.
type spec[T any] struct {
	id      func(T) string
	prov    func(*T) *[]domain.Provenance
	curated func(dst *T, old T) // keeps fields owned by reviewers
}

func sourceEntry(p []domain.Provenance, sid domain.SourceID) (domain.Provenance, bool) {
	for _, x := range p {
		if x.SourceID == sid {
			return x, true
		}
	}
	return domain.Provenance{}, false
}

func mergeProvenance(existing, fresh []domain.Provenance, sid domain.SourceID) []domain.Provenance {
	var out []domain.Provenance
	for _, p := range existing {
		if p.SourceID != sid {
			out = append(out, p)
		}
	}
	return append(out, fresh...)
}

// comparable strips what is allowed to differ between two imports of
// equivalent data: other sources' provenance, and this source's snapshot
// revision and import time.
func comparable[T any](s spec[T], rec T, sid domain.SourceID) T {
	p := s.prov(&rec)
	var keep []domain.Provenance
	if e, ok := sourceEntry(*p, sid); ok {
		e.SnapshotRevision, e.ImportedAt = "", time.Time{}
		keep = append(keep, e)
	}
	*p = keep
	return rec
}

// compute diffs fresh records against stored ones. It returns the records to
// upsert (with merged provenance and preserved curation) and the change list.
func compute[T any](s spec[T], sid domain.SourceID, stored, fresh []T) (upsert []T, ch Change) {
	old := make(map[string]T, len(stored))
	for _, o := range stored {
		old[s.id(o)] = o
	}
	seen := map[string]bool{}
	for _, n := range fresh {
		id := s.id(n)
		seen[id] = true
		o, exists := old[id]
		if !exists {
			upsert = append(upsert, n)
			ch.Added = append(ch.Added, id)
			continue
		}
		merged := n
		s.curated(&merged, o)
		fp := s.prov(&merged)
		*fp = mergeProvenance(*s.prov(&o), *fp, sid)
		oe, _ := sourceEntry(*s.prov(&o), sid)
		if oe.State == "present" &&
			reflect.DeepEqual(comparable(s, o, sid), comparable(s, merged, sid)) {
			continue
		}
		upsert = append(upsert, merged)
		ch.Modified = append(ch.Modified, id)
	}
	for id, o := range old {
		if seen[id] {
			continue
		}
		if e, ok := sourceEntry(*s.prov(&o), sid); ok && e.State == "present" {
			ch.Removed = append(ch.Removed, id)
		}
	}
	sort.Strings(ch.Added)
	sort.Strings(ch.Modified)
	sort.Strings(ch.Removed)
	return upsert, ch
}

var (
	catSpec = spec[domain.Category]{
		id:      func(c domain.Category) string { return string(c.ID) },
		prov:    func(c *domain.Category) *[]domain.Provenance { return &c.Provenance },
		curated: func(*domain.Category, domain.Category) {},
	}
	techSpec = spec[domain.Technology]{
		id:      func(t domain.Technology) string { return string(t.ID) },
		prov:    func(t *domain.Technology) *[]domain.Provenance { return &t.Provenance },
		curated: func(dst *domain.Technology, old domain.Technology) { dst.Status = old.Status },
	}
	fpSpec = spec[domain.Fingerprint]{
		id:   func(f domain.Fingerprint) string { return string(f.ID) },
		prov: func(f *domain.Fingerprint) *[]domain.Provenance { return &f.Provenance },
		curated: func(dst *domain.Fingerprint, old domain.Fingerprint) {
			dst.Status, dst.Validation = old.Status, old.Validation
			// A probe's safety review is a human decision; never reset it.
			if dst.Probe != nil && old.Probe != nil {
				dst.Probe.SafetyReview = old.Probe.SafetyReview
			}
		},
	}
	relSpec = spec[domain.Relationship]{
		id:      func(r domain.Relationship) string { return string(r.ID) },
		prov:    func(r *domain.Relationship) *[]domain.Provenance { return &r.Provenance },
		curated: func(*domain.Relationship, domain.Relationship) {},
	}
)

// diffRecords compares fresh records of a source with its stored records.
func diffRecords(sid domain.SourceID, stored, fresh domain.Records) (repository.ChangeSet, Diff) {
	var cs repository.ChangeSet
	var d Diff
	cs.SourceID = sid
	cs.Upsert.Categories, d.Categories = compute(catSpec, sid, stored.Categories, fresh.Categories)
	cs.Upsert.Technologies, d.Technologies = compute(techSpec, sid, stored.Technologies, fresh.Technologies)
	cs.Upsert.Fingerprints, d.Fingerprints = compute(fpSpec, sid, stored.Fingerprints, fresh.Fingerprints)
	cs.Upsert.Relationships, d.Relationships = compute(relSpec, sid, stored.Relationships, fresh.Relationships)
	cs.RemovedUpstream = repository.RecordIDs{
		Categories: d.Categories.Removed, Technologies: d.Technologies.Removed,
		Fingerprints: d.Fingerprints.Removed, Relationships: d.Relationships.Removed,
	}
	return cs, d
}
