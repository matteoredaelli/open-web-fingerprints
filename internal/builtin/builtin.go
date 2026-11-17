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
	"github.com/matteoredaelli/open-web-fingerprints/internal/extractor/enthec"
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
	out := []Entry{{
		Source: domain.Source{
			Slug: "enthec-webappanalyzer", Name: "Enthec WebAppAnalyzer",
			URL:         "https://github.com/enthec/webappanalyzer",
			License:     "GPL-3.0-only",
			ExtractorID: enthec.ID, Redistributable: "unreviewed",
			Notes: "Community continuation of Wappalyzer. Data lineage and the exact GPL-3.0 variant need legal review (docs/sources.md).",
		},
		Branch: "main",
		// Cone mode also checks out the files directly in src/.
		SparsePaths: []string{"src/technologies"},
		IncludeFile: func(p string) bool {
			return p == "src/categories.json" || p == "src/groups.json" ||
				(strings.HasPrefix(p, "src/technologies/") && strings.HasSuffix(p, ".json"))
		},
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
	if err := r.Register(enthec.New()); err != nil {
		panic(err) // static registration cannot collide
	}
	return r
}
