// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package engine

import (
	"sort"
	"strings"

	"github.com/matteoredaelli/open-web-fingerprints/internal/domain"
	"github.com/matteoredaelli/open-web-fingerprints/scan"
)

// relations are the registry's relationships between technologies, indexed for Resolve.
type relations struct {
	excludes map[domain.TechnologyID][]domain.TechnologyID
	requires map[domain.TechnologyID][]domain.TechnologyID
	// requiresCat are category requirements: a technology needs one technology of the category.
	requiresCat map[domain.TechnologyID][]domain.CategoryID
	implies     map[domain.TechnologyID][]domain.TechnologyID
}

func indexRelations(reg *domain.Registry) relations {
	r := relations{
		excludes: map[domain.TechnologyID][]domain.TechnologyID{}, requires: map[domain.TechnologyID][]domain.TechnologyID{},
		requiresCat: map[domain.TechnologyID][]domain.CategoryID{}, implies: map[domain.TechnologyID][]domain.TechnologyID{},
	}
	for _, rel := range reg.Relationships {
		if len(rel.Provenance) > 0 && allRemoved(rel.Provenance) {
			continue
		}
		switch rel.Type {
		case "excludes":
			r.excludes[rel.FromTechnologyID] = append(r.excludes[rel.FromTechnologyID], rel.ToTechnologyID)
		case "requires":
			if rel.ToCategoryID != "" {
				r.requiresCat[rel.FromTechnologyID] = append(r.requiresCat[rel.FromTechnologyID], rel.ToCategoryID)
			} else {
				r.requires[rel.FromTechnologyID] = append(r.requires[rel.FromTechnologyID], rel.ToTechnologyID)
			}
		case "implies":
			r.implies[rel.FromTechnologyID] = append(r.implies[rel.FromTechnologyID], rel.ToTechnologyID)
		}
	}
	return r
}

func allRemoved(p []domain.Provenance) bool {
	for _, x := range p {
		if x.State != "removed_upstream" {
			return false
		}
	}
	return true
}

// Resolve applies what the registry says about how technologies relate, to the technologies
// found. It changes nothing a rule matched; it only decides what is reported, and lists every
// technology it holds back in Suppressed.
//
//   - excludes: if A excludes B and A was detected, B is not reported. When A and B exclude
//     each other (Lodash and Underscore.js share a global variable), the one with the higher
//     confidence is kept; if they are equal both are kept and a warning says so.
//   - requires: a technology is reported only if at least one of the technologies it requires
//     is detected (or implied by one that is), and, for a category requirement, at least one
//     detected technology is in the category. With several required technologies "at least one"
//     is used, the reading that holds back less.
//   - implies is used only to decide the requirements; implied technologies are not added.
//
// Every relationship comes from a source and is only as good as that source: the registry
// carries them as data, they are not verified here.
func (e *Engine) Resolve(out Output) Output {
	if len(out.Technologies) == 0 {
		return out
	}
	rel := e.rel
	// Each detected technology is known by its own ID and by those of the same-name records
	// that were shown as one.
	idsOf := func(t scan.Technology) []domain.TechnologyID {
		ids := []domain.TechnologyID{domain.TechnologyID(t.ID)}
		for _, s := range t.SameName {
			ids = append(ids, domain.TechnologyID(s))
		}
		return ids
	}
	byID := map[domain.TechnologyID]int{}
	for i, t := range out.Technologies {
		for _, id := range idsOf(t) {
			byID[id] = i
		}
	}

	// Exclusions, decided on the technologies as detected.
	excludedBy := map[int][]int{}
	for i, a := range out.Technologies {
		for _, aid := range idsOf(a) {
			for _, bid := range rel.excludes[aid] {
				j, ok := byID[bid]
				if !ok || j == i {
					continue
				}
				excludedBy[j] = append(excludedBy[j], i)
			}
		}
	}
	dropped := map[int]*scan.Suppressed{}
	var warns []scan.Warning
	for j, by := range excludedBy {
		b := out.Technologies[j]
		var winners []string
		for _, i := range uniqueInts(by) {
			a := out.Technologies[i]
			mutual := e.excludesTech(a, b) && e.excludesTech(b, a)
			switch {
			case !mutual, a.Confidence > b.Confidence:
				winners = append(winners, a.Name)
			case a.Confidence == b.Confidence && a.Name < b.Name: // the pair is reported once
				warns = append(warns, scan.Warning{Code: "mutual_exclusion_tie", Ref: a.Slug,
					Message: a.Name + " and " + b.Name + " exclude each other and have the same confidence; both are reported"})
			}
		}
		if len(winners) > 0 {
			sort.Strings(winners)
			dropped[j] = &scan.Suppressed{ID: b.ID, Slug: b.Slug, Name: b.Name, Reason: scan.SuppressedExcluded, By: winners, Confidence: b.Confidence}
		}
	}

	// Requirements, against what is detected (before exclusions: an excluded technology was
	// still seen) together with what those technologies imply.
	present := map[domain.TechnologyID]bool{}
	for id := range byID {
		present[id] = true
	}
	var queue []domain.TechnologyID
	for id := range present {
		queue = append(queue, id)
	}
	for len(queue) > 0 {
		id := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		for _, next := range rel.implies[id] {
			if !present[next] {
				present[next] = true
				queue = append(queue, next)
			}
		}
	}
	catNames := map[domain.CategoryID]string{}
	for id, n := range e.categories {
		catNames[id] = n
	}
	for i, t := range out.Technologies {
		if dropped[i] != nil {
			continue
		}
		var needTech []string
		missing := false
		var reqs []domain.TechnologyID
		for _, id := range idsOf(t) {
			reqs = append(reqs, rel.requires[id]...)
		}
		if len(reqs) > 0 {
			met := false
			for _, r := range reqs {
				if present[r] {
					met = true
				}
				needTech = append(needTech, e.techName(r))
			}
			missing = !met
		}
		var cats []domain.CategoryID
		for _, id := range idsOf(t) {
			cats = append(cats, rel.requiresCat[id]...)
		}
		if !missing && len(cats) > 0 {
			met := false
			for _, c := range cats {
				name := catNames[c]
				for j, o := range out.Technologies {
					if j == i {
						continue
					}
					for _, oc := range o.Categories {
						if strings.EqualFold(oc, name) {
							met = true
						}
					}
				}
				needTech = append(needTech, "category "+name)
			}
			missing = !met
		}
		if missing {
			sort.Strings(needTech)
			dropped[i] = &scan.Suppressed{ID: t.ID, Slug: t.Slug, Name: t.Name, Reason: scan.SuppressedRequirement, By: uniqueStrings(needTech), Confidence: t.Confidence}
		}
	}

	if len(dropped) == 0 && len(warns) == 0 {
		return out
	}
	kept := make([]scan.Technology, 0, len(out.Technologies))
	for i, t := range out.Technologies {
		if s, ok := dropped[i]; ok {
			out.Suppressed = append(out.Suppressed, *s)
			continue
		}
		kept = append(kept, t)
	}
	sort.SliceStable(out.Suppressed, func(i, j int) bool { return out.Suppressed[i].Name < out.Suppressed[j].Name })
	out.Technologies = kept
	out.Warnings = append(out.Warnings, warns...)
	return out
}

func (e *Engine) excludesTech(a, b scan.Technology) bool {
	for _, aid := range append([]string{a.ID}, a.SameName...) {
		for _, x := range e.rel.excludes[domain.TechnologyID(aid)] {
			for _, bid := range append([]string{b.ID}, b.SameName...) {
				if string(x) == bid {
					return true
				}
			}
		}
	}
	return false
}

func (e *Engine) techName(id domain.TechnologyID) string {
	for _, t := range e.techs {
		if t.ID == id {
			return t.Name
		}
	}
	return string(id)
}

func uniqueInts(l []int) []int {
	seen := map[int]bool{}
	var out []int
	for _, x := range l {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	sort.Ints(out)
	return out
}

func uniqueStrings(l []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range l {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
