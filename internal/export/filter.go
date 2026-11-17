// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package export

import (
	"sort"

	"github.com/matteoredaelli/open-web-fingerprints/internal/domain"
)

// Notice is written into exports that contain unreviewed data.
const Notice = "This export contains data from sources whose redistribution terms have not been reviewed. " +
	"It is for internal use only: do not publish or redistribute it."

type filtered struct {
	sources []domain.Source
	recs    domain.Records
	info    *domain.ExportInfo
}

// filter applies the redistribution rules.
func filter(srcs []domain.Source, recs domain.Records, opt Options) (*filtered, error) {
	byID := map[domain.SourceID]domain.Source{}
	for _, s := range srcs {
		byID[s.ID] = s
	}
	// A source is allowed if it may be exported under the options. A
	// provenance entry naming an unknown source is treated as unreviewed: the
	// decision cannot be looked up.
	status := func(id domain.SourceID) string {
		if s, ok := byID[id]; ok {
			return s.Redistributable
		}
		return "unreviewed"
	}
	allowed := func(id domain.SourceID) bool {
		switch status(id) {
		case "yes":
			return true
		case "unreviewed":
			return opt.IncludeUnreviewed
		}
		return false
	}
	ok := func(p []domain.Provenance) bool {
		for _, x := range p {
			if !allowed(x.SourceID) {
				return false
			}
		}
		return true // a record without provenance was made by hand
	}

	// Sources that contributed to any record, to refuse unreviewed ones.
	used := map[domain.SourceID]bool{}
	mark := func(p []domain.Provenance) {
		for _, x := range p {
			used[x.SourceID] = true
		}
	}
	for _, v := range recs.Vendors {
		mark(v.Provenance)
	}
	for _, c := range recs.Categories {
		mark(c.Provenance)
	}
	for _, t := range recs.Technologies {
		mark(t.Provenance)
	}
	for _, f := range recs.Fingerprints {
		mark(f.Provenance)
	}
	for _, r := range recs.Relationships {
		mark(r.Provenance)
	}
	if !opt.IncludeUnreviewed {
		var blocked []string
		for id := range used {
			if status(id) == "unreviewed" {
				name := string(id)
				if s, ok := byID[id]; ok {
					name = s.Slug
				}
				blocked = append(blocked, name)
			}
		}
		if len(blocked) > 0 {
			sort.Strings(blocked)
			return nil, &BlockedError{Sources: blocked}
		}
	}

	out := &filtered{}
	excluded := 0
	vend := map[domain.VendorID]bool{}
	for _, v := range recs.Vendors {
		if ok(v.Provenance) {
			vend[v.ID] = true
			out.recs.Vendors = append(out.recs.Vendors, v)
		} else {
			excluded++
		}
	}
	cat := map[domain.CategoryID]bool{}
	for _, c := range recs.Categories {
		if ok(c.Provenance) {
			cat[c.ID] = true
		}
	}
	for _, c := range recs.Categories {
		if !cat[c.ID] {
			excluded++
			continue
		}
		if c.ParentID != "" && !cat[c.ParentID] {
			c.ParentID = ""
		}
		out.recs.Categories = append(out.recs.Categories, c)
	}
	tech := map[domain.TechnologyID]bool{}
	for _, t := range recs.Technologies {
		if !ok(t.Provenance) {
			excluded++
			continue
		}
		tech[t.ID] = true
		var cats []domain.CategoryID
		for _, c := range t.CategoryIDs {
			if cat[c] {
				cats = append(cats, c)
			}
		}
		t.CategoryIDs = cats
		if t.VendorID != "" && !vend[t.VendorID] {
			t.VendorID = ""
		}
		out.recs.Technologies = append(out.recs.Technologies, t)
	}
	for _, f := range recs.Fingerprints {
		if tech[f.TechnologyID] && ok(f.Provenance) {
			out.recs.Fingerprints = append(out.recs.Fingerprints, f)
		} else {
			excluded++
		}
	}
	for _, r := range recs.Relationships {
		to := (r.ToTechnologyID != "" && tech[r.ToTechnologyID]) || (r.ToCategoryID != "" && cat[r.ToCategoryID])
		if tech[r.FromTechnologyID] && to && ok(r.Provenance) {
			out.recs.Relationships = append(out.recs.Relationships, r)
		} else {
			excluded++
		}
	}

	info := &domain.ExportInfo{IncludeUnreviewed: opt.IncludeUnreviewed, ExcludedRecords: excluded}
	for _, s := range srcs {
		switch {
		case allowed(s.ID):
			out.sources = append(out.sources, s)
			if s.Redistributable == "unreviewed" {
				info.UnreviewedSources = append(info.UnreviewedSources, s.Slug)
			}
		default:
			info.ExcludedSources = append(info.ExcludedSources, s.Slug)
		}
	}
	if len(info.UnreviewedSources) > 0 {
		info.Notice = Notice
	}
	sort.Strings(info.UnreviewedSources)
	sort.Strings(info.ExcludedSources)
	// The section is only written when it says something.
	if opt.IncludeUnreviewed || excluded > 0 || len(info.ExcludedSources) > 0 {
		out.info = info
	}
	return out, nil
}
