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
	Vendors       Change
	Categories    Change
	Technologies  Change
	Fingerprints  Change
	Relationships Change
	// Conflicts lists review items opened (Added) or changed (Modified).
	Conflicts Change
}

// IsEmpty reports whether nothing changes.
func (d Diff) IsEmpty() bool {
	for _, c := range []Change{d.Vendors, d.Categories, d.Technologies, d.Fingerprints, d.Relationships, d.Conflicts} {
		if len(c.Added)+len(c.Modified)+len(c.Removed) > 0 {
			return false
		}
	}
	return true
}

// spec tells the generic diff how to treat one record type.
type spec[T any] struct {
	id   func(T) string
	prov func(*T) *[]domain.Provenance
	// curated runs after provenance is merged. It keeps what reviewers own and
	// what other sources contributed: see ownership in docs/dedup-design.md.
	curated func(dst *T, old T, sid domain.SourceID)
}

// isPrimary reports whether the source owns the content of a record: it is
// the source of the record's first provenance entry. Other sources only add
// their provenance to a merged record.
func isPrimary(old []domain.Provenance, sid domain.SourceID) bool {
	return len(old) == 0 || old[0].SourceID == sid
}

func multiSource(p []domain.Provenance) bool {
	for _, x := range p[1:] {
		if x.SourceID != p[0].SourceID {
			return true
		}
	}
	return false
}

// sourceEntries returns the provenance entries a source contributed to a
// record. One canonical record may have several (equivalent upstream rules).
func sourceEntries(p []domain.Provenance, sid domain.SourceID) []domain.Provenance {
	var out []domain.Provenance
	for _, x := range p {
		if x.SourceID == sid {
			out = append(out, x)
		}
	}
	return out
}

func anyState(p []domain.Provenance, state string) bool {
	for _, x := range p {
		if x.State == state {
			return true
		}
	}
	return false
}

func allState(p []domain.Provenance, state string) bool {
	for _, x := range p {
		if x.State != state {
			return false
		}
	}
	return len(p) > 0
}

// mergeProvenance replaces the entries of one source with fresh ones. Order
// matters: the first entry names the source that owns a record's content, so
// the replacement happens in place instead of moving the source to the end.
func mergeProvenance(existing, fresh []domain.Provenance, sid domain.SourceID) []domain.Provenance {
	var out []domain.Provenance
	placed := false
	for _, p := range existing {
		if p.SourceID != sid {
			out = append(out, p)
			continue
		}
		if !placed {
			out = append(out, fresh...)
			placed = true
		}
	}
	if !placed {
		out = append(out, fresh...)
	}
	return out
}

// forCompare strips what is allowed to differ between two imports of
// equivalent data: other sources' provenance, and this source's snapshot
// revision and import time. Entries are ordered by upstream ID.
func forCompare[T any](s spec[T], rec T, sid domain.SourceID) T {
	p := s.prov(&rec)
	keep := sourceEntries(*p, sid)
	for i := range keep {
		keep[i].SnapshotRevision, keep[i].ImportedAt = "", time.Time{}
	}
	sort.Slice(keep, func(i, j int) bool { return keep[i].OriginalID < keep[j].OriginalID })
	*p = keep
	return rec
}

// compute diffs fresh records against all stored ones. It returns the records
// to upsert (with merged provenance and preserved curation) and the change
// list. Records are matched by ID across sources, because a merged record
// carries several sources' provenance.
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
		mp := s.prov(&merged)
		*mp = mergeProvenance(*s.prov(&o), *mp, sid)
		s.curated(&merged, o, sid)
		if allState(sourceEntries(*s.prov(&o), sid), "present") &&
			reflect.DeepEqual(forCompare(s, o, sid), forCompare(s, merged, sid)) {
			continue
		}
		upsert = append(upsert, merged)
		ch.Modified = append(ch.Modified, id)
	}
	for id, o := range old {
		if seen[id] {
			continue
		}
		if anyState(sourceEntries(*s.prov(&o), sid), "present") {
			ch.Removed = append(ch.Removed, id)
		}
	}
	sort.Strings(ch.Added)
	sort.Strings(ch.Modified)
	sort.Strings(ch.Removed)
	return upsert, ch
}

func union[T comparable](a, b []T) []T {
	out := append([]T(nil), a...)
	have := map[T]bool{}
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

var (
	// Vendor content is derived from an identifier and meant to be curated,
	// so a stored vendor keeps its content; refreshes only add provenance.
	vendorSpec = spec[domain.Vendor]{
		id:   func(v domain.Vendor) string { return string(v.ID) },
		prov: func(v *domain.Vendor) *[]domain.Provenance { return &v.Provenance },
		curated: func(dst *domain.Vendor, old domain.Vendor, _ domain.SourceID) {
			prov := dst.Provenance
			*dst = old
			dst.Provenance = prov
		},
	}
	catSpec = spec[domain.Category]{
		id:   func(c domain.Category) string { return string(c.ID) },
		prov: func(c *domain.Category) *[]domain.Provenance { return &c.Provenance },
		curated: func(dst *domain.Category, old domain.Category, sid domain.SourceID) {
			if !isPrimary(old.Provenance, sid) {
				prov := dst.Provenance
				*dst = old
				dst.Provenance = prov
			}
		},
	}
	techSpec = spec[domain.Technology]{
		id:   func(t domain.Technology) string { return string(t.ID) },
		prov: func(t *domain.Technology) *[]domain.Provenance { return &t.Provenance },
		curated: func(dst *domain.Technology, old domain.Technology, sid domain.SourceID) {
			prov := dst.Provenance
			if !isPrimary(old.Provenance, sid) {
				*dst = old
				dst.Provenance = prov
				return
			}
			defer keepCurated(dst, old)
			dst.Status = old.Status
			if multiSource(prov) {
				// What other sources contributed through a merge is kept: extra
				// names, CPEs and categories, and fields this source leaves empty.
				dst.Aliases = union(old.Aliases, dst.Aliases)
				dst.CPE = union(old.CPE, dst.CPE)
				dst.CategoryIDs = union(old.CategoryIDs, dst.CategoryIDs)
				if dst.Description == "" {
					dst.Description = old.Description
				}
				if dst.Website == "" {
					dst.Website = old.Website
				}
				if dst.Kind == "" {
					dst.Kind = old.Kind
				}
				if dst.VendorID == "" {
					dst.VendorID = old.VendorID
				}
				if dst.OpenSource == nil {
					dst.OpenSource = old.OpenSource
				}
				if dst.SaaS == nil {
					dst.SaaS = old.SaaS
				}
			}
		},
	}
	fpSpec = spec[domain.Fingerprint]{
		id:   func(f domain.Fingerprint) string { return string(f.ID) },
		prov: func(f *domain.Fingerprint) *[]domain.Provenance { return &f.Provenance },
		curated: func(dst *domain.Fingerprint, old domain.Fingerprint, sid domain.SourceID) {
			prov := dst.Provenance
			if !isPrimary(old.Provenance, sid) {
				*dst = old
				dst.Provenance = prov
			} else {
				dst.Status, dst.Validation = old.Status, old.Validation
				// A probe's safety review is a human decision; never reset it.
				if dst.Probe != nil && old.Probe != nil {
					p := *dst.Probe
					p.SafetyReview, p.ReviewedAt, p.ReviewNote = old.Probe.SafetyReview, old.Probe.ReviewedAt, old.Probe.ReviewNote
					dst.Probe = &p
				}
			}
			keepCorrection(dst, old)
			if multiSource(prov) {
				dst.Confidence = domain.LowestExplicitConfidence(prov, dst.Confidence)
			}
		},
	}
	relSpec = spec[domain.Relationship]{
		id:   func(r domain.Relationship) string { return string(r.ID) },
		prov: func(r *domain.Relationship) *[]domain.Provenance { return &r.Provenance },
		curated: func(dst *domain.Relationship, old domain.Relationship, sid domain.SourceID) {
			if !isPrimary(old.Provenance, sid) {
				prov := dst.Provenance
				*dst = old
				dst.Provenance = prov
			}
		},
	}
)

// diffRecords compares fresh records of a source with its stored records.
func diffRecords(sid domain.SourceID, stored, fresh domain.Records) (repository.ChangeSet, Diff) {
	var cs repository.ChangeSet
	var d Diff
	cs.SourceID = sid
	cs.Upsert.Vendors, d.Vendors = compute(vendorSpec, sid, stored.Vendors, fresh.Vendors)
	cs.Upsert.Categories, d.Categories = compute(catSpec, sid, stored.Categories, fresh.Categories)
	cs.Upsert.Technologies, d.Technologies = compute(techSpec, sid, stored.Technologies, fresh.Technologies)
	cs.Upsert.Fingerprints, d.Fingerprints = compute(fpSpec, sid, stored.Fingerprints, fresh.Fingerprints)
	cs.Upsert.Relationships, d.Relationships = compute(relSpec, sid, stored.Relationships, fresh.Relationships)
	cs.RemovedUpstream = repository.RecordIDs{
		Vendors: d.Vendors.Removed, Categories: d.Categories.Removed, Technologies: d.Technologies.Removed,
		Fingerprints: d.Fingerprints.Removed, Relationships: d.Relationships.Removed,
	}
	return cs, d
}

// keepCorrection carries a reviewer's correction over to a freshly imported rule. It
// applies only if the source still gives the value the reviewer corrected. (Today a
// changed value is a different rule with a different ID, so this guard is for the day
// identity stops including the content.)
func keepCorrection(dst *domain.Fingerprint, old domain.Fingerprint) {
	c := old.Correction
	if c == nil {
		return
	}
	field := fieldOf(dst, c.Field)
	if field == nil || *field != c.Original {
		return
	}
	*field = c.Value
	dst.Correction = c
}

// fieldOf returns a pointer to a correctable field of a rule.
func fieldOf(f *domain.Fingerprint, name string) *string {
	switch name {
	case "target":
		return &f.Target
	case "pattern":
		return &f.Pattern
	}
	return nil
}

// keepCurated restores the fields a reviewer set on a technology.
func keepCurated(dst *domain.Technology, old domain.Technology) {
	dst.Curated = old.Curated
	for _, f := range old.Curated {
		switch f {
		case "website":
			dst.Website = old.Website
		case "description":
			dst.Description = old.Description
		case "vendor":
			dst.VendorID = old.VendorID
		}
	}
}
