// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

// Package normalizer maps source-neutral extraction results into the
// canonical domain model. It knows nothing about any particular source.
package normalizer

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/matteoredaelli/open-web-fingerprints/internal/domain"
	"github.com/matteoredaelli/open-web-fingerprints/internal/extractor"
)

// DefaultConfidence is applied to rules whose source gives no confidence.
// It is an unvalidated estimate, not evidence of reliability.
const DefaultConfidence = 0.5

// Input is one extraction to normalize.
type Input struct {
	Source     domain.Source
	Revision   string // snapshot revision
	ImportedAt time.Time
	Extraction *extractor.ExtractionResult
	// Existing holds every stored record, from all sources. It keeps slugs
	// stable (a known record keeps its slug) and unique across sources.
	Existing domain.Records
}

// Result holds canonical records and the warnings raised while mapping.
// Source and snapshot records are produced by the pipeline, not here.
type Result struct {
	Categories    []domain.Category
	Technologies  []domain.Technology
	Fingerprints  []domain.Fingerprint
	Relationships []domain.Relationship
	Warnings      []extractor.Warning
}

// Normalizer maps extraction results to canonical records.
type Normalizer interface {
	Normalize(in Input) (*Result, error)
}

// Default is the standard Normalizer.
type Default struct {
	Alloc             IDAllocator
	DefaultConfidence float64 // used when zero-valued: DefaultConfidence
}

// New returns a Default normalizer using the given allocator.
func New(alloc IDAllocator) *Default {
	return &Default{Alloc: alloc, DefaultConfidence: DefaultConfidence}
}

type run struct {
	n       *Default
	in      Input
	res     *Result
	srcID   string
	cats    map[string]domain.CategoryID
	techs   map[string]domain.TechnologyID
	usedFP  map[string]bool
	usedRel map[string]bool
}

// Normalize implements Normalizer. It is deterministic given the same input
// and allocator state.
func (n *Default) Normalize(in Input) (*Result, error) {
	if in.Extraction == nil {
		return nil, fmt.Errorf("normalizer: nil extraction")
	}
	if in.Source.ID == "" {
		return nil, fmt.Errorf("normalizer: source has no ID")
	}
	r := &run{
		n: n, in: in, res: &Result{}, srcID: string(in.Source.ID),
		cats:    map[string]domain.CategoryID{},
		techs:   map[string]domain.TechnologyID{},
		usedFP:  map[string]bool{},
		usedRel: map[string]bool{},
	}
	r.res.Warnings = append(r.res.Warnings, in.Extraction.Warnings...)
	if err := r.categories(); err != nil {
		return nil, err
	}
	if err := r.technologies(); err != nil {
		return nil, err
	}
	if err := r.fingerprints(); err != nil {
		return nil, err
	}
	if err := r.relationships(); err != nil {
		return nil, err
	}
	return r.res, nil
}

func (r *run) warn(code, ref, msg string) {
	r.res.Warnings = append(r.res.Warnings, extractor.Warning{Code: code, Ref: ref, Message: msg})
}

func (r *run) alloc(kind domain.Kind, key string) (string, error) {
	id, err := r.n.Alloc.Allocate(kind, r.srcID, key)
	if err != nil {
		return "", fmt.Errorf("normalizer: allocate %s %q: %w", kind, key, err)
	}
	return id, nil
}

func (r *run) prov(originalID, file string, conf *float64) []domain.Provenance {
	return []domain.Provenance{{
		SourceID: r.in.Source.ID, SnapshotRevision: r.in.Revision,
		OriginalID: originalID, OriginalFile: file, OriginalConfidence: conf,
		License: r.in.Source.License, ImportedAt: r.in.ImportedAt, State: "present",
	}}
}

func (r *run) categories() error {
	slugs := newSlugSet("category")
	known := map[domain.CategoryID]string{}
	for _, c := range r.in.Existing.Categories {
		known[c.ID] = c.Slug
		slugs.reserve(c.Slug)
	}
	for _, c := range r.in.Extraction.Categories {
		id, err := r.alloc(domain.KindCategory, "category:"+c.Key)
		if err != nil {
			return err
		}
		r.cats[c.Key] = domain.CategoryID(id)
	}
	for _, c := range r.in.Extraction.Categories {
		id := r.cats[c.Key]
		slug, ok := known[id]
		if !ok {
			slug = slugs.unique(c.Name)
		}
		cat := domain.Category{
			ID: id, Slug: slug, Name: c.Name, Group: c.Group,
			Provenance: r.prov(c.Key, c.File, nil),
		}
		if c.ParentKey != "" {
			if p, ok := r.cats[c.ParentKey]; ok {
				cat.ParentID = p
			} else {
				r.warn("unknown_parent_category", c.Key, fmt.Sprintf("parent %q not found", c.ParentKey))
			}
		}
		r.res.Categories = append(r.res.Categories, cat)
	}
	return nil
}

func (r *run) technologies() error {
	slugs := newSlugSet("technology")
	known := map[domain.TechnologyID]string{}
	for _, t := range r.in.Existing.Technologies {
		known[t.ID] = t.Slug
		slugs.reserve(t.Slug)
	}
	for _, t := range r.in.Extraction.Technologies {
		id, err := r.alloc(domain.KindTechnology, "technology:"+t.Key)
		if err != nil {
			return err
		}
		r.techs[t.Key] = domain.TechnologyID(id)
		slug, ok := known[domain.TechnologyID(id)]
		if !ok {
			slug = slugs.unique(t.Name)
		}
		tech := domain.Technology{
			ID: domain.TechnologyID(id), Slug: slug, Name: t.Name,
			Description: t.Description, Website: t.Website, Kind: t.Kind, CPE: t.CPE,
			OpenSource: t.OpenSource, SaaS: t.SaaS, Status: domain.StatusActive,
			Provenance: r.prov(t.Key, t.File, nil),
		}
		for _, ck := range t.CategoryKeys {
			if cid, ok := r.cats[ck]; ok {
				tech.CategoryIDs = append(tech.CategoryIDs, cid)
			} else {
				r.warn("unknown_category", t.Key, fmt.Sprintf("category %q not found", ck))
			}
		}
		r.res.Technologies = append(r.res.Technologies, tech)
	}
	return nil
}

// ruleKey is a stable per-source identifier for one rule: the technology key
// plus a short hash of the source's own fragment (or of the mapped fields).
func ruleKey(f extractor.ExtractedFingerprint) string {
	h := sha256.New()
	if len(f.Raw) > 0 {
		h.Write(f.Raw)
	} else {
		h.Write([]byte(strings.Join([]string{
			string(f.Observation), f.Target, string(f.Operator), f.Pattern, f.VersionExtract,
		}, "|")))
	}
	return f.TechnologyKey + "#" + hex.EncodeToString(h.Sum(nil))[:12]
}

func (r *run) fingerprints() error {
	conf := r.n.DefaultConfidence
	if conf == 0 {
		conf = DefaultConfidence
	}
	bySK := map[string]int{} // semantic key -> index in res.Fingerprints
	for _, f := range r.in.Extraction.Fingerprints {
		tid, ok := r.techs[f.TechnologyKey]
		if !ok {
			r.warn("unknown_technology", f.TechnologyKey, "fingerprint references unknown technology; skipped")
			continue
		}
		key := ruleKey(f)
		if r.usedFP[key] {
			r.warn("duplicate_rule", key, "identical source rule seen twice; later one skipped")
			continue
		}
		r.usedFP[key] = true

		fp := domain.Fingerprint{
			TechnologyID: tid, Observation: f.Observation,
			Target: f.Target, Operator: f.Operator, Pattern: f.Pattern,
			RegexFlavor: f.RegexFlavor, VersionExtract: f.VersionExtract, Confidence: conf,
			Status: domain.StatusActive, Validation: &domain.Validation{Health: "unknown"},
			Provenance: r.prov(key, f.File, f.Confidence), Raw: f.Raw,
		}
		if f.Confidence != nil {
			fp.Confidence = *f.Confidence
		}
		if f.GroupKey != "" {
			gid, err := r.alloc(domain.KindGroup, "group:"+f.TechnologyKey+"#"+f.GroupKey)
			if err != nil {
				return err
			}
			fp.GroupID = domain.GroupID(gid)
		}
		if f.Probe != nil {
			p := *f.Probe
			p.SafetyReview = "pending" // never inherited from a source
			fp.Probe = &p
			fp.Status = domain.StatusDraft
		}
		sk := fp.SemanticKey()

		// Equivalent rules inside one source are one canonical rule with one
		// provenance entry per upstream rule.
		if i, dup := bySK[sk]; dup {
			cur := &r.res.Fingerprints[i]
			cur.Provenance = append(cur.Provenance, fp.Provenance...)
			r.warn("merged_duplicate_rule", key,
				fmt.Sprintf("equivalent to %s; merged as an extra provenance entry", cur.Provenance[0].OriginalID))
			r.mergeConfidence(cur, conf)
			continue
		}
		id, err := r.alloc(domain.KindFingerprint, "fingerprint:"+sk)
		if err != nil {
			return err
		}
		fp.ID = domain.FingerprintID(id)
		bySK[sk] = len(r.res.Fingerprints)
		r.res.Fingerprints = append(r.res.Fingerprints, fp)
	}
	return nil
}

// mergeConfidence sets the canonical confidence to the lowest explicit value
// among the rule's provenance entries, or the default when none is explicit.
func (r *run) mergeConfidence(f *domain.Fingerprint, def float64) {
	var explicit []float64
	for _, p := range f.Provenance {
		if p.OriginalConfidence != nil {
			explicit = append(explicit, *p.OriginalConfidence)
		}
	}
	if len(explicit) == 0 {
		f.Confidence = def
		return
	}
	lowest := explicit[0]
	for _, v := range explicit[1:] {
		if v != lowest {
			r.warn("confidence_disagreement", string(f.ID), "equivalent rules carry different confidence; the lowest is used")
		}
		if v < lowest {
			lowest = v
		}
	}
	f.Confidence = lowest
}

func (r *run) relationships() error {
	for _, x := range r.in.Extraction.Relationships {
		from, ok := r.techs[x.FromKey]
		if !ok {
			r.warn("unknown_technology", x.FromKey, "relationship source unknown; skipped")
			continue
		}
		rel := domain.Relationship{
			FromTechnologyID: from, Type: x.Type, Confidence: x.Confidence,
		}
		target := ""
		switch {
		case x.ToTechnologyKey != "":
			to, ok := r.techs[x.ToTechnologyKey]
			if !ok {
				r.warn("unresolved_relationship", x.FromKey,
					fmt.Sprintf("%s -> technology %q not in source; skipped", x.Type, x.ToTechnologyKey))
				continue
			}
			if to == from {
				r.warn("self_relationship", x.FromKey,
					fmt.Sprintf("%s points to the technology itself; skipped", x.Type))
				continue
			}
			rel.ToTechnologyID, target = to, "technology:"+x.ToTechnologyKey
		case x.ToCategoryKey != "":
			to, ok := r.cats[x.ToCategoryKey]
			if !ok {
				r.warn("unresolved_relationship", x.FromKey,
					fmt.Sprintf("%s -> category %q not in source; skipped", x.Type, x.ToCategoryKey))
				continue
			}
			rel.ToCategoryID, target = to, "category:"+x.ToCategoryKey
		default:
			r.warn("invalid_relationship", x.FromKey, "relationship has no target; skipped")
			continue
		}
		key := x.FromKey + "|" + x.Type + "|" + target
		if r.usedRel[key] {
			r.warn("duplicate_relationship", x.FromKey, "identical relationship seen twice; later one skipped")
			continue
		}
		r.usedRel[key] = true
		id, err := r.alloc(domain.KindRelationship, "relationship:"+key)
		if err != nil {
			return err
		}
		rel.ID = domain.RelationshipID(id)
		rel.Provenance = r.prov(key, x.File, x.Confidence)
		r.res.Relationships = append(r.res.Relationships, rel)
	}
	return nil
}

// Records returns the canonical records of the result.
func (r *Result) Records() domain.Records {
	return domain.Records{
		Categories: r.Categories, Technologies: r.Technologies,
		Fingerprints: r.Fingerprints, Relationships: r.Relationships,
	}
}
