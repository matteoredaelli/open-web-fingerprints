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
	"github.com/matteoredaelli/open-web-fingerprints/internal/extractor/fingerprinthub"
	"github.com/matteoredaelli/open-web-fingerprints/internal/extractor/nuclei"
	"github.com/matteoredaelli/open-web-fingerprints/internal/extractor/opentechalyzer"
	"github.com/matteoredaelli/open-web-fingerprints/internal/extractor/recog"
	"github.com/matteoredaelli/open-web-fingerprints/internal/extractor/wafw00f"
	"github.com/matteoredaelli/open-web-fingerprints/internal/extractor/wappalyzer"
	"github.com/matteoredaelli/open-web-fingerprints/internal/extractor/whatweb"
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
	}, {
		Source: domain.Source{
			Slug: "rapid7-recog", Name: "Rapid7 Recog",
			URL:         "https://github.com/rapid7/recog",
			License:     "BSD-2-Clause",
			ExtractorID: recog.ID, Redistributable: "unreviewed",
			Notes: "Banner, header, cookie, title and favicon fingerprints that give product, vendor, version and CPE. Only the web databases are read. The repository states BSD-2-Clause in debian/copyright (the GitHub API reports none); the data has many contributors, so it still needs review (docs/sources.md).",
		},
		Branch: "main", SparsePaths: []string{"xml"},
		IncludeFile: func(p string) bool { return recog.IsDatabase(p) },
	}, {
		Source: domain.Source{
			Slug: "projectdiscovery-nuclei-templates", Name: "Nuclei technology templates",
			URL:         "https://github.com/projectdiscovery/nuclei-templates",
			License:     "MIT",
			ExtractorID: nuclei.ID, Redistributable: "unreviewed",
			Notes: "Only http/technologies is read; CVE, vulnerability, misconfiguration and default-login templates are out of scope. Templates generated from Wappalyzer and FingerprintHub data are skipped. Templates with a path other than the base URL become probes, imported as drafts with a pending safety review. The repository is MIT, but individual templates have many authors and some derive from other projects, so the data still needs review (docs/sources.md).",
		},
		Branch: "main", SparsePaths: []string{nuclei.Root},
		IncludeFile: func(p string) bool {
			return strings.HasPrefix(p, nuclei.Root+"/") && strings.HasSuffix(p, ".yaml")
		},
	}, {
		Source: domain.Source{
			Slug: "houseofmvps-opentechalyzer", Name: "OpenTechalyzer",
			URL:         "https://github.com/Houseofmvps/opentechalyzer",
			License:     "MIT",
			ExtractorID: opentechalyzer.ID, Redistributable: "unreviewed",
			Notes: "TypeScript fingerprints under src/fingerprints, read as data (nothing is executed). The README says the built-in database is written for the project and is not a copy of another dataset; only about 9% of its script and html patterns equal a rule already in the registry. npmDep signals and pattern identifiers are kept in Raw. Probes marked intrusive (exposed files) are out of scope. The project's optional import of the GPL-3.0 Wappalyzer set is not part of these files. Needs legal review (docs/sources.md).",
		},
		Branch: "main", SparsePaths: []string{opentechalyzer.Root},
		IncludeFile: opentechalyzer.IsFingerprintFile,
	}, {
		Source: domain.Source{
			Slug: "urbanadventurer-whatweb", Name: "WhatWeb plugins",
			URL:         "https://github.com/urbanadventurer/WhatWeb",
			License:     "GPL-2.0-only",
			ExtractorID: whatweb.ID, Redistributable: "unreviewed",
			Notes: "Ruby plugins under plugins/, read as data (nothing is executed): the matches list of each plugin. Detection written as Ruby code (passive and aggressive blocks), md5 of files and page-shape patterns are not read. A clause with a :url becomes a probe, imported as a draft with a pending safety review. Matching is case-sensitive in WhatWeb, so rules are wrapped in (?-i:). The repository is GPL-2.0 and each plugin says it may be subject to redistribution and commercial restrictions; the maintainer decided the licence question is settled (docs/sources-plan.md), to be recorded with owf source review (docs/sources.md).",
		},
		Branch: "master", SparsePaths: []string{whatweb.Root},
		IncludeFile: whatweb.IsPluginFile,
	}, {
		Source: domain.Source{
			Slug: "enablesecurity-wafw00f", Name: "WAFW00F",
			URL:         "https://github.com/EnableSecurity/wafw00f",
			License:     "BSD-3-Clause",
			ExtractorID: wafw00f.ID, Redistributable: "unreviewed",
			Notes: "Python plugins under wafw00f/plugins that identify web application firewalls and CDNs, read as data (nothing is executed). Only header and cookie checks on the normal response are read; everything that looks at the response to an attack payload (body, status, reason) is skipped, because this project never sends one. Needs legal review (docs/sources.md).",
		},
		Branch: "master", SparsePaths: []string{wafw00f.Root},
		IncludeFile: wafw00f.IsPluginFile,
	}, {
		Source: domain.Source{
			Slug: "0x727-fingerprinthub", Name: "FingerprintHub",
			URL:         "https://github.com/0x727/FingerprintHub",
			License:     "MIT",
			ExtractorID: fingerprinthub.ID, Redistributable: "unreviewed",
			Notes: "Nuclei-style templates under web-fingerprint/, the database of observer_ward; read with the nuclei reading (word and regex matchers, favicon md5 and mmh3 hashes). Many products are Chinese or industrial software the other sources lack. The repository is MIT, but its README says the content is for study and security work, not for profit; that is not a licence condition but the maintainer should read it when recording the review. The nuclei source skips the template generated from this data (docs/sources-plan.md).",
		},
		Branch: "main", SparsePaths: []string{fingerprinthub.Root},
		IncludeFile: func(p string) bool {
			return strings.HasPrefix(p, fingerprinthub.Root+"/") && strings.HasSuffix(p, ".yaml")
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
	for _, e := range []extractor.Extractor{wappalyzer.New(), recog.New(), nuclei.New(), fingerprinthub.New(), opentechalyzer.New(), wafw00f.New(), whatweb.New()} {
		if err := r.Register(e); err != nil {
			panic(err) // static registration cannot collide
		}
	}
	return r
}
