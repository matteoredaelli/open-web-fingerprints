// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package reconciler

import (
	"fmt"
	"strings"

	"github.com/matteoredaelli/open-web-fingerprints/internal/domain"
	"github.com/matteoredaelli/open-web-fingerprints/internal/extractor"
)

// Resolve follows an alias chain to the surviving ID. Unknown IDs are
// returned unchanged. The hop limit guards against corrupt alias cycles.
func Resolve(aliases map[string]string, id string) string {
	for i := 0; i < 64; i++ {
		next, ok := aliases[id]
		if !ok || next == id {
			return id
		}
		id = next
	}
	return id
}

// Translated is the outcome of Translate.
type Translated struct {
	Records domain.Records
	// Aliases are new old-ID to stored-ID mappings discovered while matching
	// fresh rules against stored ones. They must be persisted.
	Aliases  []domain.Alias
	Warnings []extractor.Warning
}

// Translate rewrites freshly normalized records so that they fit the stored
// registry after merges:
//
//   - IDs of merged-away records are replaced through the alias table;
//   - a fresh rule or relationship that means the same as a stored one takes
//     the stored ID (and the pair is recorded as a new alias), so equivalent
//     rules of different sources end up as one record;
//   - records that collapse onto the same ID are combined.
func Translate(fresh, stored domain.Records, aliases map[string]string) Translated {
	var out Translated
	rc := func(id domain.CategoryID) domain.CategoryID { return domain.CategoryID(Resolve(aliases, string(id))) }
	rt := func(id domain.TechnologyID) domain.TechnologyID {
		return domain.TechnologyID(Resolve(aliases, string(id)))
	}

	// Vendors: the ID is global per CPE vendor, so equal IDs only need their
	// provenance combined.
	vendIdx := map[domain.VendorID]int{}
	for _, v := range fresh.Vendors {
		if i, dup := vendIdx[v.ID]; dup {
			out.Records.Vendors[i].Provenance = domain.UnionProvenance(out.Records.Vendors[i].Provenance, v.Provenance)
			continue
		}
		vendIdx[v.ID] = len(out.Records.Vendors)
		out.Records.Vendors = append(out.Records.Vendors, v)
	}

	// Categories.
	catIdx := map[domain.CategoryID]int{}
	for _, c := range fresh.Categories {
		c.ID = rc(c.ID)
		if c.ParentID != "" {
			c.ParentID = rc(c.ParentID)
		}
		if i, dup := catIdx[c.ID]; dup {
			out.Records.Categories[i].Provenance = domain.UnionProvenance(out.Records.Categories[i].Provenance, c.Provenance)
			continue
		}
		catIdx[c.ID] = len(out.Records.Categories)
		out.Records.Categories = append(out.Records.Categories, c)
	}

	// Technologies.
	techIdx := map[domain.TechnologyID]int{}
	for _, t := range fresh.Technologies {
		t.ID = rt(t.ID)
		t.CategoryIDs = dedupeCats(t.CategoryIDs, rc)
		if i, dup := techIdx[t.ID]; dup {
			cur := &out.Records.Technologies[i]
			cur.Provenance = domain.UnionProvenance(cur.Provenance, t.Provenance)
			cur.CategoryIDs = dedupeCats(append(cur.CategoryIDs, t.CategoryIDs...), rc)
			continue
		}
		techIdx[t.ID] = len(out.Records.Technologies)
		out.Records.Technologies = append(out.Records.Technologies, t)
	}

	// Fingerprints: translate, then match stored rules by meaning.
	storedFP := make(map[string]domain.FingerprintID, len(stored.Fingerprints))
	for _, f := range stored.Fingerprints {
		storedFP[f.SemanticKey()] = f.ID
	}
	fpIdx := map[domain.FingerprintID]int{}
	for _, f := range fresh.Fingerprints {
		f.TechnologyID = rt(f.TechnologyID)
		f.ID = domain.FingerprintID(Resolve(aliases, string(f.ID)))
		if id, ok := storedFP[f.SemanticKey()]; ok && id != f.ID {
			out.Aliases = append(out.Aliases, domain.Alias{Kind: domain.KindFingerprint, OldID: string(f.ID), NewID: string(id)})
			f.ID = id
		}
		if i, dup := fpIdx[f.ID]; dup {
			cur := &out.Records.Fingerprints[i]
			cur.Provenance = domain.UnionProvenance(cur.Provenance, f.Provenance)
			cur.Confidence = domain.LowestExplicitConfidence(cur.Provenance, cur.Confidence)
			continue
		}
		fpIdx[f.ID] = len(out.Records.Fingerprints)
		out.Records.Fingerprints = append(out.Records.Fingerprints, f)
	}

	// Relationships.
	storedRel := make(map[string]domain.RelationshipID, len(stored.Relationships))
	for _, r := range stored.Relationships {
		storedRel[RelationshipKey(r)] = r.ID
	}
	relIdx := map[domain.RelationshipID]int{}
	for _, r := range fresh.Relationships {
		r.FromTechnologyID = rt(r.FromTechnologyID)
		if r.ToTechnologyID != "" {
			r.ToTechnologyID = rt(r.ToTechnologyID)
		}
		if r.ToCategoryID != "" {
			r.ToCategoryID = rc(r.ToCategoryID)
		}
		if r.ToTechnologyID != "" && r.ToTechnologyID == r.FromTechnologyID {
			out.Warnings = append(out.Warnings, extractor.Warning{
				Code: "self_relationship", Ref: string(r.ID),
				Message: fmt.Sprintf("%s relationship became a self reference after a merge; dropped", r.Type),
			})
			continue
		}
		r.ID = domain.RelationshipID(Resolve(aliases, string(r.ID)))
		if id, ok := storedRel[RelationshipKey(r)]; ok && id != r.ID {
			out.Aliases = append(out.Aliases, domain.Alias{Kind: domain.KindRelationship, OldID: string(r.ID), NewID: string(id)})
			r.ID = id
		}
		if i, dup := relIdx[r.ID]; dup {
			cur := &out.Records.Relationships[i]
			cur.Provenance = domain.UnionProvenance(cur.Provenance, r.Provenance)
			continue
		}
		relIdx[r.ID] = len(out.Records.Relationships)
		out.Records.Relationships = append(out.Records.Relationships, r)
	}
	return out
}

// RelationshipKey identifies what a relationship means.
func RelationshipKey(r domain.Relationship) string {
	return strings.Join([]string{string(r.FromTechnologyID), r.Type, string(r.ToTechnologyID), string(r.ToCategoryID)}, "\x1f")
}

func dedupeCats(in []domain.CategoryID, resolve func(domain.CategoryID) domain.CategoryID) []domain.CategoryID {
	var out []domain.CategoryID
	seen := map[domain.CategoryID]bool{}
	for _, c := range in {
		c = resolve(c)
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	return out
}
