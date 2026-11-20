// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

// Package scan defines the result of scanning a web site: what was fetched,
// which technologies were recognised and on what evidence, the links found,
// the domains they point to, the social profiles, the contact details and,
// when asked for, the "friend" domains. It is the public contract of the
// scanner (the owfscan command of github.com/matteoredaelli/open-web-fingerprints);
// its JSON form is described by the scan-result schema, which the schemas package
// embeds and can validate against.
//
// The types are plain data, with no behaviour and no dependencies besides the
// standard library. They say what was observed, never more than that: a technology
// comes with the rules that matched, the health of each rule (most are "unknown":
// they have no tests) and the sources the rules come from, and Coverage says how
// many rules could not be evaluated and why. A missing technology therefore does not
// mean the site does not use it.
//
// # Reading a result
//
// Decode the JSON into a Result and check SchemaVersion. Slices are never null in
// the JSON the scanner writes, and optional parts (Host, Friends) are nil when they
// were not collected.
//
// # Stability
//
// SchemaVersion is 0.1.0: the format is a draft. Fields may be added in any release
// before 1.0; consumers should ignore fields they do not know, which encoding/json
// does by default.
package scan

import "time"

// SchemaVersion is the version of the result format.
const SchemaVersion = "0.1.0"

// Result is the outcome of scanning one target.
type Result struct {
	Schema        string       `json:"$schema,omitempty"`
	SchemaVersion string       `json:"schema_version"`
	ScannedAt     time.Time    `json:"scanned_at"`
	Scanner       string       `json:"scanner"`
	Target        Target       `json:"target"`
	Pages         []Page       `json:"pages"`
	Host          *Host        `json:"host,omitempty"`
	Technologies  []Technology `json:"technologies"`
	Links         []Link       `json:"links"`
	Domains       []Domain     `json:"domains"`
	Socials       []Social     `json:"socials"`
	Contacts      []Contact    `json:"contacts"`
	// Friends is present only when friend detection was asked for.
	Friends *Friends `json:"friends,omitempty"`
	// Browser is present only when the first page was also run in a browser.
	Browser  *Browser    `json:"browser,omitempty"`
	Coverage Coverage    `json:"coverage"`
	Registry RegistryRef `json:"registry"`
	Warnings []Warning   `json:"warnings"`
}

// Target is what was asked for and where it led.
type Target struct {
	Input             string `json:"input"`                        // as given by the user
	URL               string `json:"url"`                          // final URL after redirects
	Host              string `json:"host"`                         // host of the final URL
	RegistrableDomain string `json:"registrable_domain,omitempty"` // eTLD+1, for example pirelli.com
}

// Page is one fetched page.
type Page struct {
	URL         string     `json:"url"`
	FinalURL    string     `json:"final_url"`
	Status      int        `json:"status"`
	ContentType string     `json:"content_type,omitempty"`
	Bytes       int        `json:"bytes"`
	DurationMS  int        `json:"duration_ms"`
	Redirects   []Redirect `json:"redirects,omitempty"`
	// Headers are the response headers of the final response, lower-cased names.
	Headers map[string]string `json:"headers,omitempty"`
	Cached  bool              `json:"cached,omitempty"` // read from the response cache, not the network
}

// Redirect is one hop of a redirect chain.
type Redirect struct {
	URL    string `json:"url"`
	Status int    `json:"status"`
}

// Host holds what is known about the host itself, not the page.
type Host struct {
	IPs []string            `json:"ips,omitempty"`
	DNS map[string][]string `json:"dns,omitempty"` // record type -> values
	TLS *TLS                `json:"tls,omitempty"`
}

// TLS is the certificate presented by the host.
type TLS struct {
	Version   string    `json:"version,omitempty"`
	Issuer    string    `json:"issuer,omitempty"`
	Subject   string    `json:"subject,omitempty"`
	NotBefore time.Time `json:"not_before,omitzero"`
	NotAfter  time.Time `json:"not_after,omitzero"`
	DNSNames  []string  `json:"dns_names,omitempty"`
}

// Technology is something recognised on the target.
type Technology struct {
	ID         string   `json:"id"` // registry ID, tech_<uuidv7>
	Slug       string   `json:"slug"`
	Name       string   `json:"name"`
	Vendor     string   `json:"vendor,omitempty"`
	Version    string   `json:"version,omitempty"`
	Categories []string `json:"categories,omitempty"`
	// SameName lists the IDs of other registry records with the same name that were
	// also detected and are shown here as one. The registry keeps them apart until a
	// reviewer merges them (often the same product imported from two sources); this is
	// presentation only, and the evidence of all of them is listed below.
	SameName []string `json:"same_name,omitempty"`
	// Confidence is the highest confidence among the matching rules that are not
	// known to be broken. Agreement between rules does not raise it: rules that
	// share an ancestor are not independent evidence.
	Confidence float64 `json:"confidence"`
	// Sources lists the registry sources of the matching rules.
	Sources  []string   `json:"sources"`
	Evidence []Evidence `json:"evidence"`
}

// Evidence is one matching rule and what it matched.
type Evidence struct {
	RuleID      string `json:"rule_id"` // registry ID, fp_<uuidv7>
	Observation string `json:"observation"`
	Target      string `json:"target,omitempty"`
	// Matched is the observed value, cut to a short length.
	Matched string `json:"matched,omitempty"`
	Version string `json:"version,omitempty"`
	// Health is the health of the rule in the registry: unknown, ok, degraded or
	// broken. Most rules are unknown.
	Health string `json:"health"`
	Source string `json:"source"`
	// Group is set when the rule is part of a group that matched as a whole.
	Group string `json:"group,omitempty"`
	Page  string `json:"page,omitempty"` // the page the observation comes from
}

// Link is a URL found in a page.
type Link struct {
	URL      string `json:"url"`  // absolute, normalised, without fragment
	Kind     string `json:"kind"` // a, link, script, iframe, form, img, source
	Rel      string `json:"rel,omitempty"`
	Internal bool   `json:"internal"` // same registrable domain as the target
	Domain   string `json:"domain"`   // registrable domain of the link
	FoundIn  string `json:"found_in"` // URL of the page
}

// Domain summarises the links that point to one registrable domain.
type Domain struct {
	Domain   string   `json:"domain"`
	Internal bool     `json:"internal"`
	Links    int      `json:"links"`
	Examples []string `json:"examples,omitempty"`
}

// Browser says that the first page was opened in a headless browser, and how that went.
// With it the page's global variables and XHR calls are known (the rules that need them are
// evaluated), and the first page's HTML, links, social profiles and contacts are those of the
// document after its scripts ran.
type Browser struct {
	Version string `json:"version,omitempty"` // for example Chrome/158
	// Requests is how many requests the page made through the scanner's proxy; Blocked is
	// how many connections the proxy refused (non-public addresses).
	Requests int `json:"requests"`
	Blocked  int `json:"blocked"`
	// TimedOut is true when the page had not settled in time: what had loaded was used.
	TimedOut bool `json:"timed_out,omitempty"`
	// Globals is how many of the global variables looked for were found.
	Globals int `json:"globals_found"`
}

// Friends is the outcome of looking for "friend" domains: sites that the target's home
// page links to and whose own home page links back to the target. It says what two home
// pages link to, no more: it does not say the two sites are related in any other way.
type Friends struct {
	// Candidates is how many external domains the home page links to, after leaving out
	// the social platforms; Checked is how many of them were looked at (the rest hit the
	// limit).
	Candidates int      `json:"candidates"`
	Checked    int      `json:"checked"`
	Domains    []Friend `json:"domains"`
}

// Friend statuses.
const (
	FriendYes        = "friend"      // its home page links back to the target
	FriendNo         = "not_friend"  // its home page was read and does not link back
	FriendBlocked    = "not_allowed" // its robots.txt asks crawlers not to fetch the home page
	FriendUnreadable = "unreachable" // could not be fetched or was not a page
	FriendNotChecked = "not_checked" // over the limit
)

// Friend is one candidate domain.
type Friend struct {
	Domain string `json:"domain"`
	Status string `json:"status"`
	// URL is the home page that was fetched (after redirects).
	URL string `json:"url,omitempty"`
	// LinkedFrom lists links on the target's home page that point to the domain.
	LinkedFrom []string `json:"linked_from"`
	// LinksBack lists links on the domain's home page that point to the target.
	LinksBack []string `json:"links_back,omitempty"`
	Detail    string   `json:"detail,omitempty"`
}

// Social is a profile of a person or organisation on a platform.
type Social struct {
	Platform string `json:"platform"`       // linkedin, github, tiktok, ...
	Kind     string `json:"kind,omitempty"` // company, user, channel, ...
	Handle   string `json:"handle"`         // normalised identifier
	URL      string `json:"url"`            // canonical profile URL
	Found    []Find `json:"found"`
}

// Contact is an email address or a telephone number published on the target.
type Contact struct {
	Kind  string `json:"kind"`  // email, phone
	Value string `json:"value"` // normalised: lower-case address, +E.164-like number when possible
	Found []Find `json:"found"`
}

// Find says where a social profile (or other item) was seen.
type Find struct {
	Page string `json:"page"`
	Via  string `json:"via"` // a, meta, jsonld, rel-me, link, text
}

// Coverage says how much of the registry could be applied.
type Coverage struct {
	RulesTotal       int `json:"rules_total"`
	RulesEvaluated   int `json:"rules_evaluated"`
	RulesUnsupported int `json:"rules_unsupported"`
	// Skipped counts rules that were not evaluated, by reason, for example
	// "needs a browser", "probe disabled", "pattern needs a backtracking engine".
	Skipped map[string]int `json:"skipped,omitempty"`
}

// RegistryRef names the registry export the rules come from.
type RegistryRef struct {
	ContentSHA256 string   `json:"content_sha256"`
	SchemaVersion string   `json:"schema_version"`
	Sources       []string `json:"sources"`
	// Notice is repeated from the export when it contains unreviewed data.
	Notice string `json:"notice,omitempty"`
}

// Warning is something that could not be done or read.
type Warning struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Ref     string `json:"ref,omitempty"`
}
