// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

// Package validator checks semantic constraints that JSON Schema cannot
// express: referential integrity, uniqueness and rule consistency.
package validator

import (
	"fmt"
	"regexp"

	"github.com/matteoredaelli/open-web-fingerprints/internal/domain"
)

// Severity of an issue.
type Severity string

// Severities.
const (
	Error   Severity = "error"
	Warning Severity = "warning"
)

// Issue is one finding.
type Issue struct {
	Severity Severity
	Code     string
	Ref      string
	Message  string
}

// HasErrors reports whether any issue is an error.
func HasErrors(issues []Issue) bool {
	for _, i := range issues {
		if i.Severity == Error {
			return true
		}
	}
	return false
}

type checker struct{ issues []Issue }

func (c *checker) err(code, ref, format string, a ...any) {
	c.issues = append(c.issues, Issue{Error, code, ref, fmt.Sprintf(format, a...)})
}

// Validate checks a record set on its own: every reference must resolve
// inside the set.
func Validate(r domain.Records) []Issue {
	c := &checker{}
	cats := map[domain.CategoryID]bool{}
	techs := map[domain.TechnologyID]bool{}
	ids := map[string]bool{}
	dup := func(id string) bool {
		if ids[id] {
			c.err("duplicate_id", id, "ID used twice")
			return true
		}
		ids[id] = true
		return false
	}
	vendors := map[domain.VendorID]bool{}
	slugs := map[string]bool{}
	cpeVendors := map[string]bool{}
	for _, x := range r.Vendors {
		dup(string(x.ID))
		vendors[x.ID] = true
		if slugs["v:"+x.Slug] {
			c.err("duplicate_slug", string(x.ID), "vendor slug %q used twice", x.Slug)
		}
		slugs["v:"+x.Slug] = true
		if x.CPEVendor != "" {
			if cpeVendors[x.CPEVendor] {
				c.err("duplicate_cpe_vendor", string(x.ID), "CPE vendor %q used by two vendors", x.CPEVendor)
			}
			cpeVendors[x.CPEVendor] = true
		}
	}
	for _, x := range r.Categories {
		dup(string(x.ID))
		cats[x.ID] = true
		if slugs["c:"+x.Slug] {
			c.err("duplicate_slug", string(x.ID), "category slug %q used twice", x.Slug)
		}
		slugs["c:"+x.Slug] = true
	}
	for _, x := range r.Categories {
		if x.ParentID != "" && !cats[x.ParentID] {
			c.err("dangling_reference", string(x.ID), "parent category %s not found", x.ParentID)
		}
	}
	for _, x := range r.Technologies {
		dup(string(x.ID))
		techs[x.ID] = true
		if slugs["t:"+x.Slug] {
			c.err("duplicate_slug", string(x.ID), "technology slug %q used twice", x.Slug)
		}
		slugs["t:"+x.Slug] = true
		if len(x.Provenance) == 0 {
			c.err("missing_provenance", string(x.ID), "technology has no provenance")
		}
		if x.VendorID != "" && !vendors[x.VendorID] {
			c.err("dangling_reference", string(x.ID), "vendor %s not found", x.VendorID)
		}
		for _, cid := range x.CategoryIDs {
			if !cats[cid] {
				c.err("dangling_reference", string(x.ID), "category %s not found", cid)
			}
		}
	}
	for _, f := range r.Fingerprints {
		dup(string(f.ID))
		ref := string(f.ID)
		if !techs[f.TechnologyID] {
			c.err("dangling_reference", ref, "technology %s not found", f.TechnologyID)
		}
		c.fingerprint(f)
	}
	for _, x := range r.Relationships {
		dup(string(x.ID))
		ref := string(x.ID)
		if !techs[x.FromTechnologyID] {
			c.err("dangling_reference", ref, "technology %s not found", x.FromTechnologyID)
		}
		if x.ToTechnologyID != "" && !techs[x.ToTechnologyID] {
			c.err("dangling_reference", ref, "technology %s not found", x.ToTechnologyID)
		}
		if x.ToCategoryID != "" && !cats[x.ToCategoryID] {
			c.err("dangling_reference", ref, "category %s not found", x.ToCategoryID)
		}
		if (x.ToTechnologyID == "") == (x.ToCategoryID == "") {
			c.err("invalid_relationship", ref, "exactly one target is required")
		}
		if x.ToTechnologyID == x.FromTechnologyID && x.ToTechnologyID != "" {
			c.err("self_relationship", ref, "technology relates to itself")
		}
		if len(x.Provenance) == 0 {
			c.err("missing_provenance", ref, "relationship has no provenance")
		}
	}
	return c.issues
}

func (c *checker) fingerprint(f domain.Fingerprint) {
	ref := string(f.ID)
	if f.Confidence < 0 || f.Confidence > 1 {
		c.err("invalid_confidence", ref, "confidence %v out of range", f.Confidence)
	}
	if len(f.Provenance) == 0 {
		c.err("missing_provenance", ref, "fingerprint has no provenance")
	}
	if f.Operator != domain.OpExists && f.Pattern == "" {
		c.err("missing_pattern", ref, "operator %s needs a pattern", f.Operator)
	}
	if f.Operator == domain.OpRegex {
		switch f.RegexFlavor {
		case domain.FlavorRE2:
			if _, err := regexp.Compile("(?i)" + f.Pattern); err != nil {
				c.err("invalid_regex", ref, "flavor re2 but pattern does not compile: %v", err)
			}
		case domain.FlavorECMAScript:
		default:
			c.err("missing_regex_flavor", ref, "regex needs a flavor")
		}
	}
	if f.Observation == domain.ObsProbeResponse && f.Probe == nil {
		c.err("missing_probe", ref, "probe_response needs probe details")
	}
	if p := f.Probe; p != nil {
		switch p.Method {
		case "GET", "HEAD", "OPTIONS":
		default:
			c.err("unsafe_probe", ref, "probe method %q is not allowed", p.Method)
		}
		if len(p.Path) == 0 || p.Path[0] != '/' {
			c.err("invalid_probe", ref, "probe path must start with /")
		}
		if f.Status == domain.StatusActive && p.SafetyReview != "approved" {
			c.err("unreviewed_probe", ref, "active probe without approved safety review")
		}
	}
}
