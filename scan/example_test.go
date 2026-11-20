// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package scan_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/matteoredaelli/open-web-fingerprints/scan"
	"github.com/matteoredaelli/open-web-fingerprints/schemas"
)

// A scan result written by `owfscan scan --json` decodes into a Result. The values here
// are made up for the example.
const doc = `{
  "schema_version": "0.1.0",
  "scanned_at": "2026-01-02T03:04:05Z",
  "scanner": "owfscan",
  "target": {"input": "example.org", "url": "https://www.example.org/", "host": "www.example.org", "registrable_domain": "example.org"},
  "pages": [{"url": "https://example.org", "final_url": "https://www.example.org/", "status": 200, "bytes": 1234, "duration_ms": 80}],
  "technologies": [
    {"id": "tech_01a1f9ac-67ad-7aa2-9ef9-43d88dc74a4e", "slug": "hugo", "name": "Hugo", "version": "0.119.0",
     "confidence": 0.5, "sources": ["enthec-webappanalyzer"],
     "evidence": [{"rule_id": "fp_01a1f9ac-6969-7e6f-a646-cbae610161c6", "observation": "meta_tag", "target": "generator", "matched": "Hugo 0.119.0", "health": "unknown", "source": "enthec-webappanalyzer"}]}
  ],
  "implied": [{"id": "tech_01a1f9ac-67ad-7aa2-9ef9-43d88dc74a50", "slug": "go-lang", "name": "Go", "implied_by": ["Hugo"], "confidence": 0.5}],
  "suppressed": [{"id": "tech_01a1f9ac-67ad-7aa2-9ef9-43d88dc74a4f", "slug": "underscore-js", "name": "Underscore.js", "reason": "excluded", "by": ["Lodash"], "confidence": 0}],
  "links": [], "domains": [], "socials": [{"platform": "github", "kind": "account", "handle": "example", "url": "https://github.com/example", "found": [{"page": "https://www.example.org/", "via": "a"}]}],
  "contacts": [],
  "related": {"candidates": 1, "checked": 1, "probable": ["sister.example"], "domains": [{"domain": "sister.example", "level": "probable", "status": "checked", "evidence": [{"kind": "cert_org", "strength": "strong", "detail": "Example SA"}]}]},
  "friends": {"candidates": 2, "checked": 2, "domains": [
    {"domain": "partner.example", "status": "friend", "linked_from": ["https://partner.example/"], "links_back": ["https://www.example.org/about"]},
    {"domain": "other.example", "status": "not_friend", "linked_from": ["https://other.example/"]}]},
  "coverage": {"rules_total": 100, "rules_evaluated": 60, "rules_unsupported": 40, "skipped": {"needs a browser": 40}},
  "registry": {"content_sha256": "sha256:0000000000000000000000000000000000000000000000000000000000000000", "schema_version": "0.2.0", "sources": ["enthec-webappanalyzer"]},
  "warnings": []
}`

func ExampleResult() {
	var r scan.Result
	if err := json.NewDecoder(strings.NewReader(doc)).Decode(&r); err != nil {
		panic(err)
	}
	fmt.Println(r.Target.RegistrableDomain, r.SchemaVersion)
	for _, t := range r.Technologies {
		fmt.Printf("%s %s (confidence %.2f, %d piece of evidence)\n", t.Name, t.Version, t.Confidence, len(t.Evidence))
	}
	// The coverage says how much was not looked at: a technology that is not listed may
	// still be there.
	c := r.Coverage
	fmt.Printf("%d of %d rules evaluated\n", c.RulesEvaluated, c.RulesTotal)
	// Output:
	// example.org 0.1.0
	// Hugo 0.119.0 (confidence 0.50, 1 piece of evidence)
	// 60 of 100 rules evaluated
}

func ExampleFriends() {
	var r scan.Result
	if err := json.Unmarshal([]byte(doc), &r); err != nil {
		panic(err)
	}
	if r.Friends == nil {
		fmt.Println("friends were not asked for")
		return
	}
	for _, d := range r.Friends.Domains {
		if d.Status == scan.FriendYes {
			fmt.Println(d.Domain, "links back from", d.LinksBack[0])
		}
	}
	// Output: partner.example links back from https://www.example.org/about
}

// The example document is itself a valid result, so the documentation cannot drift from
// the schema.
func TestExampleDocumentIsValid(t *testing.T) {
	if err := schemas.ValidateScanResult([]byte(doc)); err != nil {
		t.Fatal(err)
	}
}

func ExampleSuppressed() {
	var r scan.Result
	if err := json.Unmarshal([]byte(doc), &r); err != nil {
		panic(err)
	}
	// A technology can match and still not be reported: the registry says another one excludes it.
	for _, s := range r.Suppressed {
		fmt.Printf("%s: %s by %s\n", s.Name, s.Reason, s.By[0])
	}
	// Output: Underscore.js: excluded by Lodash
}

func ExampleImplied() {
	var r scan.Result
	if err := json.Unmarshal([]byte(doc), &r); err != nil {
		panic(err)
	}
	// Implied technologies were not matched: nothing in the page shows them, the registry says
	// they follow from the ones that were found.
	for _, im := range r.Implied {
		fmt.Printf("%s is implied by %s\n", im.Name, im.ImpliedBy[0])
	}
	// Output: Go is implied by Hugo
}

func ExampleRelated() {
	var r scan.Result
	if err := json.Unmarshal([]byte(doc), &r); err != nil {
		panic(err)
	}
	// The short answer; each domain in Domains says why it is listed.
	fmt.Println(r.Related.Probable)
	// Output: [sister.example]
}
