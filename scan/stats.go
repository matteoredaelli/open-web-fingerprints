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
	DomainSignals []StatTech `json:"domain_signals"`
	// Families group the technologies by kind (CMS, web server, CDN...); each technology is
	// in one family. Sites counts the sites with at least one technology of the family.
	Families   []StatFamily  `json:"families"`
	Categories []StatCount   `json:"categories"`
	Headers    []StatCount   `json:"headers"`
	TLS        StatsTLS      `json:"tls"`
	Social     []StatCount   `json:"social"`
	Pairs      []StatPair    `json:"pairs"`
	Coverage   StatsCoverage `json:"coverage"`
	Other      StatsOther    `json:"other"`
	// Checks is present only when the scans were made with --checks.
	Checks *StatsChecks `json:"checks,omitempty"`
	Notes  []string     `json:"notes"`
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
	// ExcludedGeneric is true when technologies the registry marks as generic were left out.
	ExcludedGeneric bool `json:"excluded_generic,omitempty"`
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

// StatFamily is a family of technologies, with the ones named (seen on enough sites).
type StatFamily struct {
	Name         string     `json:"name"`
	Sites        int        `json:"sites"`
	Share        float64    `json:"share"`
	Technologies []StatTech `json:"technologies"`
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

// StatsChecks aggregates the checks of the scans (owfscan scan --checks). It has its own
// denominators, stated in each field, because not every site has every check: the mail
// review needs DNS and a domain with no mail exchanger is left out of the mail shares.
type StatsChecks struct {
	// Sites is how many reached sites have a header review: the denominator of Headers,
	// Connection, Cookies and Policies.
	Sites   int                `json:"sites"`
	Headers []StatHeaderStatus `json:"headers"`
	// Connection counts sites by protocol and TLS version (a site can be in several lines).
	Connection []StatCount  `json:"connection"`
	Cookies    StatsCookies `json:"cookies"`
	// Policies counts robots.txt, security.txt and AI crawler bans (see AIBots).
	Policies []StatCount `json:"policies"`
	// AIBots counts, per crawler, the sites whose robots.txt has a group for it that bans it from
	// the whole site. A blanket ban under "*" is not counted here: it says nothing about that crawler.
	AIBots []StatCount `json:"ai_bots"`
	// MailReviewed is how many reached sites have a mail review; MailSites how many of them have
	// a mail exchanger: the denominator of SPF, DMARC, Mail and the provider lists below,
	// except DNSProviders, which is of MailReviewed.
	MailReviewed int `json:"mail_reviewed"`
	MailSites    int `json:"mail_sites"`
	// SPF counts sites by the closing qualifier of their record (or "no record", "no all").
	SPF []StatCount `json:"spf"`
	// DMARC counts sites by policy (or "no record").
	DMARC []StatCount `json:"dmarc"`
	// Mail counts DKIM (a common selector found), MTA-STS, TLS-RPT, BIMI and SPF trees over ten lookups.
	Mail             []StatCount `json:"mail"`
	MailProviders    []StatCount `json:"mail_providers"`
	SendingProviders []StatCount `json:"sending_providers"`
	DNSProviders     []StatCount `json:"dns_providers"`
}

// StatHeaderStatus counts the sites by the status of one header.
type StatHeaderStatus struct {
	Name    string `json:"name"`
	OK      int    `json:"ok"`
	Weak    int    `json:"weak"`
	Missing int    `json:"missing"`
	Info    int    `json:"info"`
}

// StatsCookies counts sites, not cookies.
type StatsCookies struct {
	Sites      int `json:"sites"`       // sites that set at least one cookie on the first response
	NoSecure   int `json:"no_secure"`   // ... at least one without Secure (over https)
	NoHTTPOnly int `json:"no_httponly"` // ... at least one without HttpOnly
	NoSameSite int `json:"no_samesite"` // ... at least one without SameSite
}
