// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package scan

import "time"

// StatsSchemaVersion is the version of the statistics format (a draft, like the others).
const StatsSchemaVersion = "0.1.0"

// Stats are aggregates over many scans of home pages (owfscan stats). Every share has
// the number of sites reached as its denominator, and "reached" means the home page
// answered 2xx: a figure says "detected on the home page", never "used by the site".
// No address, handle or contact detail of a site is in it.
type Stats struct {
	SchemaVersion string    `json:"schema_version"`
	GeneratedAt   time.Time `json:"generated_at"`
	Scanner       string    `json:"scanner,omitempty"`
	// List is where the sites came from (a file name; for Tranco its list id belongs in the note).
	List     string      `json:"list,omitempty"`
	Registry StatsSource `json:"registry"`
	Filters  StatsFilter `json:"filters"`
	Sites    StatsSites  `json:"sites"`
	// Technologies are web technologies: something the page or its headers show.
	Technologies []StatTech `json:"technologies"`
	// DomainSignals are technologies seen only in DNS records (a domain verification for
	// a vendor, a mail provider): true of the domain, not part of the web stack.
	DomainSignals []StatTech    `json:"domain_signals"`
	Categories    []StatCount   `json:"categories"`
	Headers       []StatCount   `json:"headers"`
	TLS           StatsTLS      `json:"tls"`
	Social        []StatCount   `json:"social"`
	Pairs         []StatPair    `json:"pairs"`
	Coverage      StatsCoverage `json:"coverage"`
	Other         StatsOther    `json:"other"`
	Notes         []string      `json:"notes"`
}

// StatsSource says which registry the rules came from.
type StatsSource struct {
	ContentSHA256 string   `json:"content_sha256,omitempty"`
	Sources       []string `json:"sources,omitempty"`
	Notice        string   `json:"notice,omitempty"`
}

// StatsFilter lists what was left out of the figures, so they can be read correctly.
type StatsFilter struct {
	MinConfidence float64  `json:"min_confidence"`
	MinSites      int      `json:"min_sites"`
	ExcludedTech  []string `json:"excluded_technologies,omitempty"`
}

// StatsSites counts the list and what became of it.
type StatsSites struct {
	Listed  int         `json:"listed"`
	Scanned int         `json:"scanned"`
	Reached int         `json:"reached"` // the denominator of every share
	Failed  int         `json:"failed"`
	Pending int         `json:"pending"`
	Status  []StatCount `json:"http_status"`
	Errors  []StatCount `json:"failures"`
}

// StatCount is a number of sites and its share of the sites reached.
type StatCount struct {
	Name  string  `json:"name"`
	Sites int     `json:"sites"`
	Share float64 `json:"share"`
}

// StatTech is a technology with how many sites show it.
type StatTech struct {
	Name       string      `json:"name"`
	Categories []string    `json:"categories,omitempty"`
	Sites      int         `json:"sites"`
	Share      float64     `json:"share"`
	Versions   []StatCount `json:"versions,omitempty"`
}

// StatPair is two technologies seen together.
type StatPair struct {
	A     string  `json:"a"`
	B     string  `json:"b"`
	Sites int     `json:"sites"`
	Share float64 `json:"share"`
}

// StatsTLS summarises certificates.
type StatsTLS struct {
	WithCertificate int         `json:"with_certificate"`
	DaysLeft        []StatCount `json:"days_left"`
	Issuers         []StatCount `json:"issuers"`
}

// StatsCoverage is how much of the registry could be applied.
type StatsCoverage struct {
	MeanPercent   float64 `json:"mean_percent"`
	MedianTechs   int     `json:"median_technologies_per_site"`
	MeanTechs     float64 `json:"mean_technologies_per_site"`
	SitesWithNone int     `json:"sites_without_technology"`
}

// StatsOther counts what was too rare to list one by one (fewer than filters.min_sites).
type StatsOther struct {
	TechnologiesHidden int `json:"technologies_hidden"`
}
