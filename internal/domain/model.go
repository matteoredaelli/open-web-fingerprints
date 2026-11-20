// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package domain

import (
	"encoding/json"
	"time"
)

// Status is the lifecycle state of a record.
type Status string

// Lifecycle states.
const (
	StatusDraft        Status = "draft"
	StatusActive       Status = "active"
	StatusExperimental Status = "experimental"
	StatusDeprecated   Status = "deprecated"
)

// Operator is how a fingerprint pattern is compared with an observation.
type Operator string

// Operators.
const (
	OpExists     Operator = "exists"
	OpEquals     Operator = "equals"
	OpContains   Operator = "contains"
	OpRegex      Operator = "regex"
	OpHashEquals Operator = "hash_equals"
)

// RegexFlavor identifies the regular expression dialect of a pattern.
type RegexFlavor string

// Regex flavors.
const (
	FlavorRE2        RegexFlavor = "re2"
	FlavorECMAScript RegexFlavor = "ecmascript"
	// FlavorPCRE is for Perl/Ruby-style patterns that RE2 cannot run (lookaround,
	// backreferences, possessive quantifiers).
	FlavorPCRE RegexFlavor = "pcre"
)

// Observation is an open set of observation types. Unknown values are kept.
type Observation string

// Known observation types.
const (
	ObsHTTPHeader    Observation = "http_header"
	ObsCookie        Observation = "cookie"
	ObsHTML          Observation = "html"
	ObsMetaTag       Observation = "meta_tag"
	ObsScriptURL     Observation = "script_url"
	ObsStylesheetURL Observation = "stylesheet_url"
	ObsJSGlobal      Observation = "js_global"
	ObsDOM           Observation = "dom"
	ObsURLPath       Observation = "url_path"
	ObsRedirect      Observation = "redirect"
	ObsDNSRecord     Observation = "dns_record"
	ObsIPASN         Observation = "ip_asn"
	ObsTLSCert       Observation = "tls_cert"
	ObsTLSHandshake  Observation = "tls_handshake"
	ObsFaviconHash   Observation = "favicon_hash"
	ObsXHR           Observation = "xhr"
	ObsRobots        Observation = "robots"
	ObsProbeResponse Observation = "probe_response"
)

// RoleVersion is the Role of a rule that reads a version and does not detect.
const RoleVersion = "version"

// Registry is the root of an export document.
type Registry struct {
	Schema        string         `json:"$schema,omitempty"`
	SchemaVersion string         `json:"schema_version"`
	GeneratedAt   *time.Time     `json:"generated_at,omitempty"`
	Sources       []Source       `json:"sources"`
	Snapshots     []Snapshot     `json:"snapshots,omitempty"`
	Vendors       []Vendor       `json:"vendors,omitempty"`
	Categories    []Category     `json:"categories,omitempty"`
	Technologies  []Technology   `json:"technologies"`
	Fingerprints  []Fingerprint  `json:"fingerprints"`
	Relationships []Relationship `json:"relationships,omitempty"`
	Export        *ExportInfo    `json:"export,omitempty"`
	Manifest      *Manifest      `json:"manifest,omitempty"`
}

// Manifest describes an export so that it can be reproduced and verified.
// ContentSHA256 is the hash of the document without generated_at and without
// the manifest itself, so two exports of the same data have the same hash.
type Manifest struct {
	Generator     string           `json:"generator"`
	ContentSHA256 string           `json:"content_sha256"`
	Counts        ManifestCounts   `json:"counts"`
	Sources       []ManifestSource `json:"sources"`
}

// ManifestCounts are the sizes of the exported collections.
type ManifestCounts struct {
	Sources       int `json:"sources"`
	Vendors       int `json:"vendors"`
	Categories    int `json:"categories"`
	Technologies  int `json:"technologies"`
	Fingerprints  int `json:"fingerprints"`
	Relationships int `json:"relationships"`
}

// ManifestSource names the snapshot each exported source was last imported from.
type ManifestSource struct {
	Slug             string `json:"slug"`
	License          string `json:"license"`
	Redistributable  string `json:"redistributable"`
	Revision         string `json:"revision,omitempty"`
	SnapshotChecksum string `json:"snapshot_checksum,omitempty"`
}

// ExportInfo describes what an export contains and what was left out.
type ExportInfo struct {
	IncludeUnreviewed bool     `json:"include_unreviewed"`
	UnreviewedSources []string `json:"unreviewed_sources,omitempty"`
	ExcludedSources   []string `json:"excluded_sources,omitempty"`
	ExcludedRecords   int      `json:"excluded_records,omitempty"`
	Notice            string   `json:"notice,omitempty"`
}

// Source describes an upstream data source.
type Source struct {
	ID              SourceID `json:"id"`
	Slug            string   `json:"slug"`
	Name            string   `json:"name"`
	URL             string   `json:"url,omitempty"`
	License         string   `json:"license"`
	ExtractorID     string   `json:"extractor_id,omitempty"`
	Redistributable string   `json:"redistributable"` // yes | no | unreviewed
	Notes           string   `json:"notes,omitempty"`
	// ReviewNote and ReviewedAt record who decided the redistribution status
	// and on what basis. A reviewed decision is never reset by an import.
	ReviewNote string     `json:"review_note,omitempty"`
	ReviewedAt *time.Time `json:"reviewed_at,omitempty"`
}

// Snapshot is one retrieved revision of a source.
type Snapshot struct {
	SourceID    SourceID       `json:"source_id"`
	Revision    string         `json:"revision"`
	RetrievedAt time.Time      `json:"retrieved_at"`
	Checksum    string         `json:"checksum"`
	Files       []SnapshotFile `json:"files,omitempty"`
}

// SnapshotFile records the checksum of one file in a snapshot.
type SnapshotFile struct {
	Path     string `json:"path"`
	Checksum string `json:"checksum"`
}

// Vendor is an organization responsible for a technology.
type Vendor struct {
	ID      VendorID `json:"id"`
	Slug    string   `json:"slug"`
	Name    string   `json:"name"`
	Aliases []string `json:"aliases,omitempty"`
	Website string   `json:"website,omitempty"`
	// CPEVendor is the vendor identifier of the CPE dictionary. It is the key
	// that identifies the same vendor across sources.
	CPEVendor string `json:"cpe_vendor,omitempty"`
	// Curated is true once a person reviewed the record. Until then the name
	// of an imported vendor is only a guess derived from the identifier.
	Curated    bool         `json:"curated,omitempty"`
	Provenance []Provenance `json:"provenance,omitempty"`
}

// Category is a taxonomy entry.
type Category struct {
	ID         CategoryID   `json:"id"`
	Slug       string       `json:"slug"`
	Name       string       `json:"name"`
	ParentID   CategoryID   `json:"parent_id,omitempty"`
	Group      string       `json:"group,omitempty"`
	Provenance []Provenance `json:"provenance,omitempty"`
}

// Technology is a recognizable product, service or platform.
type Technology struct {
	ID          TechnologyID `json:"id"`
	Slug        string       `json:"slug"`
	Name        string       `json:"name"`
	Aliases     []string     `json:"aliases,omitempty"`
	Description string       `json:"description,omitempty"`
	Website     string       `json:"website,omitempty"`
	Kind        string       `json:"kind,omitempty"`
	CategoryIDs []CategoryID `json:"category_ids,omitempty"`
	VendorID    VendorID     `json:"vendor_id,omitempty"`
	CPE         []string     `json:"cpe,omitempty"`
	OpenSource  *bool        `json:"open_source,omitempty"`
	SaaS        *bool        `json:"saas,omitempty"`
	Status      Status       `json:"status"`
	Provenance  []Provenance `json:"provenance"`
}

// Fingerprint is one observation rule for one technology.
type Fingerprint struct {
	ID             FingerprintID `json:"id"`
	TechnologyID   TechnologyID  `json:"technology_id"`
	GroupID        GroupID       `json:"group_id,omitempty"`
	Observation    Observation   `json:"observation"`
	Target         string        `json:"target,omitempty"`
	Operator       Operator      `json:"operator"`
	Pattern        string        `json:"pattern,omitempty"`
	RegexFlavor    RegexFlavor   `json:"regex_flavor,omitempty"`
	VersionExtract string        `json:"version_extract,omitempty"`
	// Role is empty for a rule that detects the technology. RoleVersion marks a
	// rule that only reads a version: it never detects by itself, and applies
	// when a detection rule of the same technology matched on the same request.
	Role       string      `json:"role,omitempty"`
	Confidence float64     `json:"confidence"`
	Probe      *Probe      `json:"probe,omitempty"`
	Status     Status      `json:"status"`
	Validation *Validation `json:"validation,omitempty"`
	// Correction records a reviewer's change to one field of the rule, with the value
	// the source gave. The upstream value also stays in Raw.
	Correction *Correction     `json:"correction,omitempty"`
	Provenance []Provenance    `json:"provenance"`
	Raw        json.RawMessage `json:"raw,omitempty"`
}

// Correction is a reviewed change to a rule that the source got wrong. The importer
// never makes one by itself; a reviewer does, with a reason, and it survives
// refreshes. A rule's identity includes its content, so if the source changes the
// value that was corrected, that is a new rule: it starts without a correction,
// and the corrected one stays as removed upstream with the reviewer's record.
type Correction struct {
	Field    string    `json:"field"` // CorrectableFields
	Original string    `json:"original"`
	Value    string    `json:"value"`
	Reason   string    `json:"reason"`
	At       time.Time `json:"at"`
}

// CorrectableFields are the rule fields a reviewer may correct.
var CorrectableFields = []string{"target", "pattern"}

// Probe is an active, non-destructive request.
type Probe struct {
	Method         string `json:"method"`
	Path           string `json:"path"`
	RateLimitClass string `json:"rate_limit_class,omitempty"`
	SafetyReview   string `json:"safety_review"` // pending | approved | rejected
	// ReviewedAt and ReviewNote record the reviewer's decision (empty while pending).
	ReviewedAt *time.Time `json:"reviewed_at,omitempty"`
	ReviewNote string     `json:"review_note,omitempty"`
}

// Validation holds test evidence and rule health.
type Validation struct {
	Health              string     `json:"health"` // unknown | ok | degraded | broken
	LastValidatedAt     *time.Time `json:"last_validated_at,omitempty"`
	TestRuns            []TestRun  `json:"test_runs,omitempty"`
	KnownFalsePositives []string   `json:"known_false_positives,omitempty"`
}

// TestRun is one fixture-based test outcome.
type TestRun struct {
	Result string `json:"result"` // pass | fail
	// Expect is what the test asserted: match | no_match.
	Expect string `json:"expect,omitempty"`
	// Origin says where the case came from: empty for a case file written for
	// this registry, "upstream_example" for an example shipped by the source.
	Origin     string    `json:"origin,omitempty"`
	FixtureRef string    `json:"fixture_ref,omitempty"`
	At         time.Time `json:"at"`
}

// Relationship links technologies, or a technology and a category.
type Relationship struct {
	ID               RelationshipID `json:"id"`
	FromTechnologyID TechnologyID   `json:"from_technology_id"`
	ToTechnologyID   TechnologyID   `json:"to_technology_id,omitempty"`
	ToCategoryID     CategoryID     `json:"to_category_id,omitempty"`
	Type             string         `json:"type"`
	Confidence       *float64       `json:"confidence,omitempty"`
	Provenance       []Provenance   `json:"provenance"`
}

// Provenance is the origin of an imported record.
type Provenance struct {
	SourceID           SourceID  `json:"source_id"`
	SnapshotRevision   string    `json:"snapshot_revision"`
	OriginalID         string    `json:"original_id"`
	OriginalFile       string    `json:"original_file,omitempty"`
	OriginalConfidence *float64  `json:"original_confidence,omitempty"`
	License            string    `json:"license"`
	ImportedAt         time.Time `json:"imported_at"`
	State              string    `json:"state"` // present | removed_upstream
}
