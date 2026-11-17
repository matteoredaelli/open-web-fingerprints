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

	"github.com/matteoredaelli/open-web-fingerprints/internal/domain"
)

// Extractor is the strategy implemented once per upstream source.
type Extractor interface {
	// ID is the stable extractor identifier, for example "enthec".
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
	Confidence     *float64 // nil when the source gives none
	Probe          *domain.Probe
	File           string
	Raw            json.RawMessage
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
