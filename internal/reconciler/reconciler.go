// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

// Package reconciler finds records of different sources that may describe the
// same thing. It only proposes candidates as conflicts for review; it never
// merges or changes canonical records.
package reconciler

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"

	"github.com/matteoredaelli/open-web-fingerprints/internal/domain"
	"github.com/matteoredaelli/open-web-fingerprints/internal/normalizer"
)

// Websites relation values stored in conflict details.
const (
	SameDomain = "same_domain"
	Different  = "different"
	Unknown    = "unknown"
)

// Input is one reconciliation run.
type Input struct {
	// Fresh holds the records just normalized from one source.
	Fresh domain.Records
	// Other holds stored records that have no provenance from that source.
	Other domain.Records
	// Alloc returns the stable ID of a conflict for a deterministic key.
	Alloc func(kind domain.Kind, key string) (string, error)
	Now   time.Time
}

// Candidates returns identity and category candidates, sorted by ID. The same
// pair always gets the same conflict ID, whichever source is imported first.
func Candidates(in Input) ([]domain.Conflict, error) {
	var out []domain.Conflict

	techs := map[string][]domain.Technology{}
	for _, t := range in.Other.Technologies {
		if k := normalizer.Slugify(t.Name); k != "" {
			techs[k] = append(techs[k], t)
		}
	}
	for _, f := range in.Fresh.Technologies {
		for _, o := range techs[normalizer.Slugify(f.Name)] {
			if o.ID == f.ID {
				continue
			}
			c, err := build(in, domain.ConflictIdentityCandidate, IdentityDetail(o, f), string(o.ID), string(f.ID),
				sources(o.Provenance, f.Provenance))
			if err != nil {
				return nil, err
			}
			out = append(out, c)
		}
	}

	cats := map[string][]domain.Category{}
	for _, c := range in.Other.Categories {
		if k := normalizer.Slugify(c.Name); k != "" {
			cats[k] = append(cats[k], c)
		}
	}
	for _, f := range in.Fresh.Categories {
		for _, o := range cats[normalizer.Slugify(f.Name)] {
			if o.ID == f.ID {
				continue
			}
			c, err := build(in, domain.ConflictCategoryCandidate, CategoryDetail(o, f), string(o.ID), string(f.ID),
				sources(o.Provenance, f.Provenance))
			if err != nil {
				return nil, err
			}
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// IdentityDetail is the evidence for a technology candidate. Sides are
// ordered by ID, not by which source is being imported, so the evidence is
// the same whichever import (or merge) finds the pair.
func IdentityDetail(x, y domain.Technology) map[string]string {
	a, b := x, y
	if b.ID < a.ID {
		a, b = b, a
	}
	return map[string]string{
		"identity":  normalizer.Slugify(a.Name),
		"name_a":    a.Name,
		"name_b":    b.Name,
		"website_a": a.Website,
		"website_b": b.Website,
		"websites":  WebsiteRelation(a.Website, b.Website),
	}
}

// CategoryDetail is the evidence for a category candidate.
func CategoryDetail(x, y domain.Category) map[string]string {
	a, b := x, y
	if b.ID < a.ID {
		a, b = b, a
	}
	return map[string]string{"identity": normalizer.Slugify(a.Name), "name_a": a.Name, "name_b": b.Name}
}

// PairKey is the deterministic key of a candidate conflict for two records.
func PairKey(kind, a, b string) string {
	ids := []string{a, b}
	sort.Strings(ids)
	return kind + "|" + strings.Join(ids, "|")
}

func build(in Input, kind string, detail map[string]string, a, b string, srcs []domain.SourceID) (domain.Conflict, error) {
	ids := []string{a, b}
	sort.Strings(ids)
	id, err := in.Alloc(domain.KindConflict, PairKey(kind, a, b))
	if err != nil {
		return domain.Conflict{}, fmt.Errorf("reconciler: allocate conflict: %w", err)
	}
	return domain.Conflict{
		ID: domain.ConflictID(id), Kind: kind, State: domain.ConflictOpen,
		RecordIDs: ids, SourceIDs: srcs, Detail: detail,
		CreatedAt: in.Now, UpdatedAt: in.Now,
	}, nil
}

// Sources lists the distinct sources of the given provenance lists, sorted.
func Sources(lists ...[]domain.Provenance) []domain.SourceID {
	return sources(lists...)
}

func sources(lists ...[]domain.Provenance) []domain.SourceID {
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

// WebsiteRelation compares the registrable domains of two URLs.
func WebsiteRelation(a, b string) string {
	da, db := registrable(a), registrable(b)
	switch {
	case da == "" || db == "":
		return Unknown
	case da == db:
		return SameDomain
	}
	return Different
}

func registrable(raw string) string {
	if raw == "" {
		return ""
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return ""
	}
	host := strings.ToLower(u.Hostname())
	if d, err := publicsuffix.EffectiveTLDPlusOne(host); err == nil {
		return d
	}
	return host
}
