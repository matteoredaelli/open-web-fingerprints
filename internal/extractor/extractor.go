// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

// Package extractor defines the contract between upstream sources and the
// import pipeline. An extractor adapts one source-specific format to the
// intermediate types below. It never touches the database or the network:
// it reads a local snapshot and returns data plus references to the origin.
//
// Source-specific code lives in subpackages (internal/extractor/<source>).
package extractor

import (
	"context"
	"encoding/json"
	"io/fs"
	"regexp"
	"strings"

	"github.com/matteoredaelli/open-web-fingerprints/internal/domain"
)

// Extractor is the strategy implemented once per upstream source.
type Extractor interface {
	// ID is the stable extractor identifier, for example "wappalyzer".
	ID() string
	// Name is a human-readable name.
	Name() string
	// Extract parses a local snapshot. It must be deterministic, honor ctx
	// cancellation and never write to storage.
	Extract(ctx context.Context, src Source) (*ExtractionResult, error)
}

// Capability is an optional declaration of what a source contributes.
type Capability string

// Capabilities.
const (
	CapTechnologies  Capability = "technologies"
	CapFingerprints  Capability = "fingerprints"
	CapVersions      Capability = "versions"
	CapCategories    Capability = "categories"
	CapVendors       Capability = "vendors"
	CapRelationships Capability = "relationships"
)

// CapabilityReporter may be implemented by extractors to list capabilities.
type CapabilityReporter interface {
	Capabilities() []Capability
}

// Source is a snapshot of an upstream source, prepared by the pipeline.
type Source struct {
	ID       string // stable source slug, for example "enthec-webappanalyzer"
	URL      string
	Revision string // commit SHA or dataset version
	License  string // SPDX expression or NOASSERTION
	FS       fs.FS  // root of the local snapshot
}

// ExtractionResult is the intermediate, source-neutral output.
// Keys are upstream identifiers; they are not canonical IDs.
type ExtractionResult struct {
	Categories    []ExtractedCategory
	Technologies  []ExtractedTechnology
	Fingerprints  []ExtractedFingerprint
	Relationships []ExtractedRelationship
	Warnings      []Warning
	Metadata      map[string]any
}

// Warning reports something the extractor could not represent or skipped.
type Warning struct {
	Code    string // stable machine-readable code, for example "unsupported_regex"
	Message string
	Ref     string // key or file the warning refers to
}

// ExtractedCategory is a category as described upstream.
type ExtractedCategory struct {
	Key       string
	Name      string
	Group     string
	ParentKey string
	File      string
	Raw       json.RawMessage
}

// ExtractedTechnology is a technology as described upstream.
type ExtractedTechnology struct {
	Key          string // original identifier; unique within the source
	File         string
	Name         string
	Description  string
	Website      string
	Kind         string
	CategoryKeys []string
	CPE          []string
	OpenSource   *bool
	SaaS         *bool
	Raw          json.RawMessage
}

// ExtractedFingerprint is one observation rule. Several rules of the same
// technology that must hold together share a non-empty GroupKey.
type ExtractedFingerprint struct {
	TechnologyKey  string
	GroupKey       string
	Observation    domain.Observation
	Target         string
	Operator       domain.Operator
	Pattern        string
	RegexFlavor    domain.RegexFlavor
	VersionExtract string
	// Role is domain.RoleVersion for a rule that only reads a version.
	Role       string
	Confidence *float64 // nil when the source gives none
	Probe      *domain.Probe
	File       string
	Raw        json.RawMessage
}

// ExtractedRelationship links technologies or a technology and a category.
type ExtractedRelationship struct {
	FromKey         string
	ToTechnologyKey string
	ToCategoryKey   string
	Type            string
	Confidence      *float64 // nil when the source gives none
	File            string
	Raw             json.RawMessage
}

// RegexFlavorFor reports whether a pattern runs under RE2 and otherwise
// returns fallback, the flavor of the source's own regex dialect. Matching is
// case-insensitive in the registry's semantics, so (?i) is applied for the
// check.
func RegexFlavorFor(pattern string, fallback domain.RegexFlavor) domain.RegexFlavor {
	if _, err := regexp.Compile("(?i)" + pattern); err != nil {
		return fallback
	}
	return domain.FlavorRE2
}

// NormalizeCPE converts a CPE 2.2 URI ("cpe:/a:f5:nginx:-") or a CPE 2.3
// string into a CPE 2.3 string that keeps only the part, vendor and product.
// It returns false when vendor or product is missing, a wildcard or contains a
// placeholder such as {service.version}.
func NormalizeCPE(v string) (string, bool) {
	var fields []string
	switch {
	case strings.HasPrefix(v, "cpe:2.3:"):
		fields = strings.Split(strings.TrimPrefix(v, "cpe:2.3:"), ":")
	case strings.HasPrefix(v, "cpe:/"):
		fields = strings.Split(strings.TrimPrefix(v, "cpe:/"), ":")
	default:
		return "", false
	}
	if len(fields) < 3 {
		return "", false
	}
	part, vendor, product := fields[0], strings.ToLower(fields[1]), strings.ToLower(fields[2])
	for _, s := range []string{vendor, product} {
		if s == "" || s == "*" || s == "-" || strings.ContainsAny(s, `{}%\ `) {
			return "", false
		}
	}
	if part != "a" && part != "o" && part != "h" {
		return "", false
	}
	return "cpe:2.3:" + part + ":" + vendor + ":" + product + ":*:*:*:*:*:*:*:*", true
}

// QualifyNames prefixes the vendor to a product name that several vendors
// use, so that "Dashboard" becomes "Kubernetes Dashboard" and "Ceph
// Dashboard". A name is not qualified when it already contains the vendor.
// vendorOf maps a technology key to its vendor. It returns how many
// technologies were renamed.
func QualifyNames(res *ExtractionResult, vendorOf map[string]string) int {
	byName := map[string]map[string]bool{}
	for _, t := range res.Technologies {
		n := strings.ToLower(t.Name)
		if byName[n] == nil {
			byName[n] = map[string]bool{}
		}
		byName[n][strings.ToLower(vendorOf[t.Key])] = true
	}
	renamed := 0
	for i, t := range res.Technologies {
		v := vendorOf[t.Key]
		if len(byName[strings.ToLower(t.Name)]) < 2 || v == "" || strings.Contains(strings.ToLower(t.Name), strings.ToLower(v)) {
			continue
		}
		res.Technologies[i].Name = v + " " + t.Name
		renamed++
	}
	return renamed
}
