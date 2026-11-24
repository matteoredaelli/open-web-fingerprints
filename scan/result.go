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
	// DomainSignals are technologies seen only in the domain's DNS records (a TXT record that
	// verifies an account with a service, an MX of a mail provider). They say which services the
	// organization uses, not how the site is built, so they are kept apart from Technologies.
	DomainSignals []Technology `json:"domain_signals,omitempty"`
	Links         []Link       `json:"links"`
	Domains       []Domain     `json:"domains"`
	Socials       []Social     `json:"socials"`
	Contacts      []Contact    `json:"contacts"`
	// Suppressed lists technologies that a rule matched but that are not reported, and why:
	// the registry says another detected technology excludes them, or something they need
	// is missing. Nothing is dropped without being listed here.
	Suppressed []Suppressed `json:"suppressed,omitempty"`
	// Friends is present only when friend detection was asked for.
	Friends *Friends `json:"friends,omitempty"`
	// Implied lists technologies that the registry says follow from the ones found (WordPress
	// implies PHP and MySQL) but that no rule matched on this site. They are not detections: there
	// is no evidence of their own, only the technologies that imply them.
	Implied []Implied `json:"implied,omitempty"`
	// Related is present only when related domains were asked for.
	Related *Related `json:"related,omitempty"`
	// Active is present only when probes were allowed (--active).
	Active *Active `json:"active,omitempty"`
	// Browser is present only when the first page was also run in a browser.
	Browser *Browser `json:"browser,omitempty"`
	// Checks is present only when they were asked for (--checks): observations about the
	// site and its domain that are not registry fingerprints.
	Checks   *Checks     `json:"checks,omitempty"`
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
	// HeadersFiltered is true when headers that change on every call (date, request ids,
	// cache hits, cookies, ...) were left out of Headers. The rules still saw them.
	HeadersFiltered bool `json:"headers_filtered,omitempty"`
	Cached          bool `json:"cached,omitempty"` // read from the response cache, not the network
	// Proto is the protocol of the response (HTTP/1.1, HTTP/2.0); empty when read from a cache
	// written before it was kept.
	Proto string `json:"proto,omitempty"`
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
	Version string `json:"version,omitempty"`
	// ALPN is the application protocol negotiated in the handshake (h2, http/1.1).
	ALPN      string    `json:"alpn,omitempty"`
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
	// Generic is the registry's mark: the rules detect a signal that says little about the
	// stack, not a product somebody chose. It is reported; statistics leave it out.
	Generic bool `json:"generic,omitempty"`
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
	// Matched is the observed value, cut to a short length. It is empty for a header or
	// cookie that changes on every call (see Page.HeadersFiltered): the rule matched it, but
	// the value is not repeated here.
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

// Suppressed is a technology that matched but is not in Technologies.
type Suppressed struct {
	ID   string `json:"id"`
	Slug string `json:"slug"`
	Name string `json:"name"`
	// Reason is SuppressedExcluded or SuppressedRequirement.
	Reason string `json:"reason"`
	// By names the technologies that exclude it, or, for a missing requirement, the ones
	// (or categories) of which one was needed.
	By []string `json:"by"`
	// Confidence is what it would have had.
	Confidence float64 `json:"confidence"`
}

// Reasons a technology is suppressed.
const (
	SuppressedExcluded    = "excluded"
	SuppressedRequirement = "requirement_not_met"
)

// Implied is a technology that follows from others that were found.
type Implied struct {
	ID         string   `json:"id"`
	Slug       string   `json:"slug"`
	Name       string   `json:"name"`
	Vendor     string   `json:"vendor,omitempty"`
	Categories []string `json:"categories,omitempty"`
	// ImpliedBy names the technologies that imply it directly, found or themselves implied.
	ImpliedBy []string `json:"implied_by"`
	// Confidence is at most that of what implies it, lowered by the relationship's own
	// confidence when the source gave one.
	Confidence float64 `json:"confidence"`
}

// Related lists domains that may belong to the same owner as the target, with what ties each
// to it. It says what the pages and certificates have in common, never that the owner is the
// same: an agency can share an account across clients, and a domain with the same name can be
// someone else's.
type Related struct {
	// Candidates is how many domains were found by any signal; Checked how many had their home
	// page read (the rest hit the limit).
	Candidates int `json:"candidates"`
	Checked    int `json:"checked"`
	// VariantsTried and VariantsResolved are set when the name was tried under other TLDs
	// (--related-tlds): how many names were looked up and how many exist in DNS.
	VariantsTried    int `json:"variants_tried,omitempty"`
	VariantsResolved int `json:"variants_resolved,omitempty"`
	// Probable lists the domains whose level is probable, in the order of Domains: the short answer.
	Probable []string        `json:"probable"`
	Domains  []RelatedDomain `json:"domains"`
}

// Related levels and statuses.
const (
	RelatedProbable  = "probable"  // at least one strong signal, or the two home pages link to each other
	RelatedCandidate = "candidate" // found, with only weak signals
)

// Evidence kinds of a related domain. The strong ones are things only the owner of both sites
// would normally put in place.
const (
	RelEvLinkedFromHome   = "linked_from_home"    // the target's home page links to it (medium)
	RelEvLinksBack        = "links_back"          // its home page links to the target (medium)
	RelEvHreflangHome     = "hreflang_home"       // the target declares it as an alternate version (strong)
	RelEvHreflangBack     = "hreflang_back"       // it declares the target as an alternate version (medium)
	RelEvCertSAN          = "cert_san"            // the target's certificate lists it (strong)
	RelEvCertOrg          = "cert_org"            // its certificate names the same organization (strong)
	RelEvSiteVerification = "site_verification"   // the same search-engine or social ownership token (strong)
	RelEvAnalyticsID      = "analytics_id"        // the same Tag Manager or Analytics identifier (strong)
	RelEvRedirect         = "redirects_to_target" // its home page redirects to the target (strong)
	RelEvNameVariant      = "name_variant"        // the same name under another TLD exists in DNS (weak: anyone can register it)
)

// RelatedDomain is one domain and why it was listed.
type RelatedDomain struct {
	Domain string `json:"domain"`
	Level  string `json:"level"`
	// Status is "checked" (its home page was read), "not_allowed" (robots.txt), "unreachable" or
	// "not_checked" (over the limit).
	Status   string            `json:"status"`
	URL      string            `json:"url,omitempty"`
	Evidence []RelatedEvidence `json:"evidence"`
	Detail   string            `json:"detail,omitempty"`
}

// RelatedEvidence is one thing that ties a domain to the target.
type RelatedEvidence struct {
	Kind     string `json:"kind"`
	Strength string `json:"strength"` // strong, medium or weak
	Detail   string `json:"detail,omitempty"`
}

// Active says what the approved probes did. Probes are requests to paths of the scanned site
// that the scanner was not told to read; only probes a reviewer approved are ever sent.
type Active struct {
	Approved   int `json:"approved"`   // distinct probe paths approved in the registry
	Sent       int `json:"sent"`       // requests made
	Failed     int `json:"failed"`     // sent, but no usable answer (error, or it left the site)
	NotSent    int `json:"not_sent"`   // approved but not sent (limit, robots.txt, refused path)
	Disallowed int `json:"disallowed"` // of those, paths robots.txt asks crawlers not to fetch
	Refused    int `json:"refused"`    // of those, paths or methods the scanner will not send
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

// Checks are passive observations about the site and its domain, kept apart from the
// technologies: they come from fixed code, not from registry rules. Each says what was seen
// and, where a common recommendation exists, how it compares. They are not a security audit
// and carry no score: a missing header or record is a fact about the answer received, not a
// finding about the whole site.
type Checks struct {
	// Headers is the review of the response headers and cookies of the first page.
	Headers *HeaderChecks `json:"headers,omitempty"`
	// Mail is the review of the domain's mail and name server records (DNS only).
	Mail *MailChecks `json:"mail,omitempty"`
	// Transport is what the first response says about the connection.
	Transport *TransportCheck `json:"transport,omitempty"`
	// Policies are the site's published statements: robots.txt and security.txt.
	Policies *Policies `json:"policies,omitempty"`
}

// TransportCheck reviews the connection of the first response.
type TransportCheck struct {
	HTTPS      bool   `json:"https"`
	Proto      string `json:"proto,omitempty"`       // HTTP/1.1, HTTP/2.0
	TLSVersion string `json:"tls_version,omitempty"` // TLS 1.3
	ALPN       string `json:"alpn,omitempty"`
	HTTP2      bool   `json:"http2"`
	// HTTP3Advertised is true when an Alt-Svc header offers h3: the page was not fetched over
	// HTTP/3, the site says it could be.
	HTTP3Advertised bool   `json:"http3_advertised"`
	AltSvc          string `json:"alt_svc,omitempty"`
	// TLSStatus is weak for TLS older than 1.2 or an expired certificate, ok for 1.2 and later.
	TLSStatus string `json:"tls_status,omitempty"`
	// CertDaysLeft is the days the certificate still has to run (negative: expired); set only
	// when the certificate was read.
	CertDaysLeft *int   `json:"cert_days_left,omitempty"`
	Note         string `json:"note,omitempty"`
}

// Policies are the files a site publishes to say what it wants of robots and researchers.
type Policies struct {
	// Robots is set when robots.txt was read (not with --ignore-robots, which skips it).
	Robots      *RobotsCheck `json:"robots,omitempty"`
	SecurityTxt *SecurityTxt `json:"security_txt,omitempty"`
}

// RobotsCheck summarises robots.txt.
type RobotsCheck struct {
	Present bool `json:"present"`
	// SitemapCount is how many Sitemap lines it has; Sitemaps lists the first few.
	SitemapCount int      `json:"sitemap_count"`
	Sitemaps     []string `json:"sitemaps,omitempty"`
	// AIBots says, for crawlers of AI services, whether the file bans them from the whole site
	// ("/"). Named is true when the file has a group for that crawler, false when it only
	// falls under the "*" group.
	AIBots []AIBot `json:"ai_bots,omitempty"`
	// AIBlocked counts the AI crawlers that are banned; AINamed those the file names.
	AIBlocked int `json:"ai_blocked"`
	AINamed   int `json:"ai_named"`
}

// AIBot is one crawler's treatment in robots.txt.
type AIBot struct {
	Name    string `json:"name"`
	Blocked bool   `json:"blocked"`
	Named   bool   `json:"named"`
}

// SecurityTxt is /.well-known/security.txt (RFC 9116).
type SecurityTxt struct {
	Present bool   `json:"present"`
	URL     string `json:"url,omitempty"`
	// Contacts counts the Contact fields; their values are not kept.
	Contacts      int       `json:"contacts"`
	Expires       time.Time `json:"expires,omitzero"`
	Expired       bool      `json:"expired,omitempty"`
	HasPolicy     bool      `json:"has_policy,omitempty"`
	HasEncryption bool      `json:"has_encryption,omitempty"`
	Signed        bool      `json:"signed,omitempty"`
	// Status is info when the file is not there, weak when it lacks Contact or Expires or has
	// expired, ok otherwise.
	Status string `json:"status"`
	Note   string `json:"note,omitempty"`
}

// Statuses of a single check.
const (
	CheckOK      = "ok"      // present and in line with the usual recommendation
	CheckWeak    = "weak"    // present, but with a value the recommendation advises against
	CheckMissing = "missing" // absent, and the recommendation says it should be there
	CheckInfo    = "info"    // absent but optional, or present and only worth knowing
)

// HeaderChecks reviews the headers of one response.
type HeaderChecks struct {
	Page    string        `json:"page"`           // the page the headers come from
	HTTPS   bool          `json:"https"`          // it was served over https
	Headers []HeaderCheck `json:"headers"`        // always the same headers, in the same order
	Cookies []CookieCheck `json:"cookies"`        // cookies set by that response (values are never kept)
	OK      int           `json:"ok"`             // how many headers are ok
	Weak    int           `json:"weak"`           // how many are weak
	Missing int           `json:"missing"`        // how many are missing
	Note    string        `json:"note,omitempty"` // what the review cannot tell
}

// HeaderCheck is the review of one header.
type HeaderCheck struct {
	Name    string `json:"name"`            // lower-case
	Present bool   `json:"present"`         //
	Value   string `json:"value,omitempty"` // cut to a short length
	Status  string `json:"status"`
	Note    string `json:"note,omitempty"`
}

// CookieCheck lists the attributes of one cookie.
type CookieCheck struct {
	Name     string `json:"name"`
	Secure   bool   `json:"secure"`
	HTTPOnly bool   `json:"http_only"`
	SameSite string `json:"same_site,omitempty"` // lax, strict, none; empty if not set
	// Issues name the attributes the usual recommendation expects and the cookie lacks:
	// no_secure (on https), no_httponly, no_samesite, samesite_none_without_secure. Whether
	// a cookie needs HttpOnly depends on what it is used for, which is not known here.
	Issues []string `json:"issues,omitempty"`
}

// MailChecks reviews the DNS records that concern mail and name servers of the registrable domain.
type MailChecks struct {
	Domain string `json:"domain"`
	// MX lists the mail exchangers ("10 mx.example.com"); NullMX is true for "0 ." (the domain
	// says it does not receive mail).
	MX     []string `json:"mx,omitempty"`
	NullMX bool     `json:"null_mx,omitempty"`
	// NS lists the name servers.
	NS []string `json:"ns,omitempty"`
	// Providers are the services recognised from the MX, SPF and NS records by a fixed list of
	// host names. A service that is not in the list is not reported.
	Providers []Provider `json:"providers,omitempty"`
	SPF       *SPF       `json:"spf,omitempty"`
	DMARC     *DMARC     `json:"dmarc,omitempty"`
	// DKIM lists the selectors found among a short list of common names. DKIM selectors cannot be
	// listed in DNS, so a domain with no entry here may still sign mail under another selector.
	DKIM         []DKIM `json:"dkim,omitempty"`
	DKIMSelTried int    `json:"dkim_selectors_tried,omitempty"`
	MTASTS       *Tag   `json:"mta_sts,omitempty"`
	TLSRPT       *Tag   `json:"tls_rpt,omitempty"`
	BIMI         *Tag   `json:"bimi,omitempty"`
	// CAA and DNSSEC are the certificate-authority and signature records of the domain.
	CAA    *CAA    `json:"caa,omitempty"`
	DNSSEC *DNSSEC `json:"dnssec,omitempty"`
}

// CAA is the review of the domain's CAA records (which authorities may issue certificates).
type CAA struct {
	Present bool     `json:"present"`
	Records []string `json:"records,omitempty"` // "flags tag value"
	// Issuers are the authorities named by issue and issuewild records.
	Issuers []string `json:"issuers,omitempty"`
	// NoIssue is true when an issue record with no authority forbids issuance.
	NoIssue bool   `json:"no_issue,omitempty"`
	IODEF   bool   `json:"iodef,omitempty"` // a violation report address is given
	Status  string `json:"status"`
	Note    string `json:"note,omitempty"`
}

// DNSSEC is the review of the domain's DNSSEC records.
type DNSSEC struct {
	Signed bool `json:"signed"` // the zone publishes DNSKEY records
	DS     bool `json:"ds"`     // the parent holds a DS record
	// Validated is true when the resolver used validated the answer; a resolver that does not
	// validate leaves it false whatever the zone.
	Validated  bool     `json:"validated"`
	Algorithms []string `json:"algorithms,omitempty"`
	Status     string   `json:"status"`
	Note       string   `json:"note,omitempty"`
}

// Provider roles.
const (
	RoleMailbox = "mailbox" // receives the domain's mail (MX)
	RoleSending = "sending" // allowed to send for the domain (SPF)
	RoleDNS     = "dns"     // hosts the DNS zone (NS)
)

// Provider is a service recognised in the mail or DNS records.
type Provider struct {
	Name string `json:"name"`
	Role string `json:"role"`
	Via  string `json:"via"` // the record value that revealed it
}

// SPF is the Sender Policy Framework record.
type SPF struct {
	Record string `json:"record,omitempty"` // empty when there is none
	// All is the closing qualifier: "-all" (fail), "~all" (soft fail), "?all" (neutral),
	// "+all" (anything allowed), "" (none, or a redirect).
	All      string   `json:"all,omitempty"`
	Includes []string `json:"includes,omitempty"`
	// Lookups counts the terms that cost a DNS lookup in this record alone (include, a, mx,
	// ptr, exists, redirect); the standard allows ten in total, nested records included.
	Lookups int `json:"lookups"`
	// TotalLookups counts the lookups of the whole tree, includes followed (0 if they were not).
	TotalLookups int `json:"total_lookups,omitempty"`
	// Nested lists the hosts reached by following the includes, one level or more down.
	Nested []string `json:"nested,omitempty"`
	// TreeComplete is false when following the includes stopped (a failed lookup, or too many
	// queries): TotalLookups is then a lower bound.
	TreeComplete bool   `json:"tree_complete,omitempty"`
	Status       string `json:"status"`
	Note         string `json:"note,omitempty"`
}

// DMARC is the policy record at _dmarc.<domain>.
type DMARC struct {
	Record string `json:"record,omitempty"`
	Policy string `json:"policy,omitempty"` // none, quarantine, reject
	// SubdomainPolicy is set when sp= differs from the policy.
	SubdomainPolicy string   `json:"subdomain_policy,omitempty"`
	Pct             int      `json:"pct,omitempty"` // 0 when not given (the default is 100)
	Rua             []string `json:"rua,omitempty"`
	Ruf             []string `json:"ruf,omitempty"`
	Status          string   `json:"status"`
	Note            string   `json:"note,omitempty"`
}

// DKIM is a selector that has a key record.
type DKIM struct {
	Selector string `json:"selector"`
	KeyType  string `json:"key_type,omitempty"` // k= (rsa by default)
	// Revoked is true for an empty p= (the key was withdrawn).
	Revoked bool `json:"revoked,omitempty"`
}

// Tag is a record that is present or not, with its text (MTA-STS, TLS-RPT, BIMI).
type Tag struct {
	Present bool   `json:"present"`
	Record  string `json:"record,omitempty"`
}
