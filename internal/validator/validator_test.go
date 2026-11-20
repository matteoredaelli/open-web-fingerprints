// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package validator

import (
	"testing"

	"github.com/matteoredaelli/open-web-fingerprints/internal/domain"
)

func prov() []domain.Provenance { return []domain.Provenance{{SourceID: "src_x", State: "present"}} }

func valid() domain.Records {
	return domain.Records{
		Categories:   []domain.Category{{ID: "cat_1", Slug: "cms", Name: "CMS"}},
		Technologies: []domain.Technology{{ID: "tech_1", Slug: "a", Name: "A", CategoryIDs: []domain.CategoryID{"cat_1"}, Provenance: prov()}, {ID: "tech_2", Slug: "b", Name: "B", Provenance: prov()}},
		Fingerprints: []domain.Fingerprint{{
			ID: "fp_1", TechnologyID: "tech_1", Observation: domain.ObsHTML, Operator: domain.OpRegex,
			Pattern: "x", RegexFlavor: domain.FlavorRE2, Confidence: 0.5, Status: domain.StatusActive, Provenance: prov(),
		}},
		Relationships: []domain.Relationship{{ID: "rel_1", FromTechnologyID: "tech_1", ToTechnologyID: "tech_2", Type: "implies", Provenance: prov()}},
	}
}

func codes(issues []Issue) map[string]bool {
	m := map[string]bool{}
	for _, i := range issues {
		m[i.Code] = true
	}
	return m
}

func TestValid(t *testing.T) {
	if issues := Validate(valid()); len(issues) != 0 {
		t.Fatalf("unexpected: %v", issues)
	}
}

func TestIssues(t *testing.T) {
	cases := map[string]struct {
		mutate func(*domain.Records)
		want   string
	}{
		"duplicate id":            {func(r *domain.Records) { r.Technologies[1].ID = "tech_1" }, "duplicate_id"},
		"duplicate tech slug":     {func(r *domain.Records) { r.Technologies[1].Slug = "a" }, "duplicate_slug"},
		"dangling category":       {func(r *domain.Records) { r.Technologies[0].CategoryIDs = []domain.CategoryID{"cat_9"} }, "dangling_reference"},
		"dangling parent":         {func(r *domain.Records) { r.Categories[0].ParentID = "cat_9" }, "dangling_reference"},
		"dangling technology":     {func(r *domain.Records) { r.Fingerprints[0].TechnologyID = "tech_9" }, "dangling_reference"},
		"dangling relationship":   {func(r *domain.Records) { r.Relationships[0].ToTechnologyID = "tech_9" }, "dangling_reference"},
		"two targets":             {func(r *domain.Records) { r.Relationships[0].ToCategoryID = "cat_1" }, "invalid_relationship"},
		"self relationship":       {func(r *domain.Records) { r.Relationships[0].ToTechnologyID = "tech_1" }, "self_relationship"},
		"no provenance":           {func(r *domain.Records) { r.Technologies[0].Provenance = nil }, "missing_provenance"},
		"confidence":              {func(r *domain.Records) { r.Fingerprints[0].Confidence = 2 }, "invalid_confidence"},
		"missing pattern":         {func(r *domain.Records) { r.Fingerprints[0].Pattern = "" }, "missing_pattern"},
		"re2 does not compile":    {func(r *domain.Records) { r.Fingerprints[0].Pattern = "(?!x)" }, "invalid_regex"},
		"no flavor":               {func(r *domain.Records) { r.Fingerprints[0].RegexFlavor = "" }, "missing_regex_flavor"},
		"probe response no probe": {func(r *domain.Records) { r.Fingerprints[0].Observation = domain.ObsProbeResponse }, "missing_probe"},
		"unsafe method": {func(r *domain.Records) {
			r.Fingerprints[0].Probe = &domain.Probe{Method: "POST", Path: "/", SafetyReview: "pending"}
		}, "unsafe_probe"},
		"relative probe path": {func(r *domain.Records) {
			r.Fingerprints[0].Probe = &domain.Probe{Method: "GET", Path: "x", SafetyReview: "pending"}
		}, "invalid_probe"},
		"active unreviewed probe": {func(r *domain.Records) {
			r.Fingerprints[0].Probe = &domain.Probe{Method: "GET", Path: "/x", SafetyReview: "pending"}
		}, "unreviewed_probe"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			r := valid()
			tc.mutate(&r)
			issues := Validate(r)
			if !codes(issues)[tc.want] || !HasErrors(issues) {
				t.Fatalf("want %s, got %v", tc.want, issues)
			}
		})
	}
}

func TestEcmaScriptRegexNeedsNoCompile(t *testing.T) {
	r := valid()
	r.Fingerprints[0].Pattern = "(?!x)"
	r.Fingerprints[0].RegexFlavor = domain.FlavorECMAScript
	if issues := Validate(r); len(issues) != 0 {
		t.Fatalf("unexpected: %v", issues)
	}
}

func TestAConsistentGroupIsValid(t *testing.T) {
	r := valid()
	second := r.Fingerprints[0]
	second.ID = "fp_2"
	r.Fingerprints[0].GroupID, second.GroupID = "fpg_1", "fpg_1"
	r.Fingerprints = append(r.Fingerprints, second)
	if issues := Validate(r); len(issues) != 0 {
		t.Fatalf("unexpected: %v", issues)
	}
}

func TestAVersionRuleIsValid(t *testing.T) {
	r := valid()
	r.Fingerprints[0].Role, r.Fingerprints[0].VersionExtract = domain.RoleVersion, `\1`
	if issues := Validate(r); len(issues) != 0 {
		t.Fatalf("unexpected: %v", issues)
	}
}
