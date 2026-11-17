// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

// Package builtin is the static catalogue of sources and extractors shipped
// with owf. Registration is explicit; there is no dynamic plugin loading.
package builtin

import (
	"sort"
	"strings"

	"github.com/matteoredaelli/open-web-fingerprints/internal/domain"
	"github.com/matteoredaelli/open-web-fingerprints/internal/extractor"
	"github.com/matteoredaelli/open-web-fingerprints/internal/extractor/wappalyzer"
)

// Entry describes a known upstream source.
type Entry struct {
	Source domain.Source
	// IncludeFile selects the snapshot files covered by the checksum.
	IncludeFile func(path string) bool
	// Branch is the upstream branch that refresh follows.
	Branch string
	// SparsePaths are the directories fetched from the repository. They keep
	// downloads small (no icons, images or tests).
	SparsePaths []string
}

// Sources returns the known sources sorted by slug. IDs are assigned by the
// repository on first import.
func Sources() []Entry {
	// Both sources use the Wappalyzer JSON layout, so they share the
	// extractor, the snapshot filter and the sparse checkout.
	include := func(p string) bool {
		return p == "src/categories.json" || p == "src/groups.json" ||
			(strings.HasPrefix(p, "src/technologies/") && strings.HasSuffix(p, ".json"))
	}
	// Cone mode also checks out the files directly in src/.
	sparse := []string{"src/technologies"}
	out := []Entry{{
		Source: domain.Source{
			Slug: "enthec-webappanalyzer", Name: "Enthec WebAppAnalyzer",
			URL:         "https://github.com/enthec/webappanalyzer",
			License:     "GPL-3.0-only",
			ExtractorID: wappalyzer.ID, Redistributable: "unreviewed",
			Notes: "Community continuation of Wappalyzer. Data lineage and the exact GPL-3.0 variant need legal review (docs/sources.md).",
		},
		Branch: "main", SparsePaths: sparse, IncludeFile: include,
	}, {
		Source: domain.Source{
			Slug: "httparchive-wappalyzer", Name: "HTTP Archive Wappalyzer",
			URL:         "https://github.com/HTTPArchive/wappalyzer",
			License:     "GPL-3.0-only",
			ExtractorID: wappalyzer.ID, Redistributable: "unreviewed",
			Notes: "Fork of the last open-source Wappalyzer, used for the HTTP Archive crawl. It shares an ancestor with Enthec, so agreement between the two is not independent evidence. Lineage and license need legal review (docs/sources.md).",
		},
		Branch: "main", SparsePaths: sparse, IncludeFile: include,
	}}
	sort.Slice(out, func(i, j int) bool { return out[i].Source.Slug < out[j].Source.Slug })
	return out
}

// Find returns the known source with the given slug.
func Find(slug string) (Entry, bool) {
	for _, e := range Sources() {
		if e.Source.Slug == slug {
			return e, true
		}
	}
	return Entry{}, false
}

// Extractors returns a registry with every built-in extractor.
func Extractors() *extractor.Registry {
	r := extractor.NewRegistry()
	if err := r.Register(wappalyzer.New()); err != nil {
		panic(err) // static registration cannot collide
	}
	return r
}
