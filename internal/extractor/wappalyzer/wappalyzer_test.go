// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package wappalyzer

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"testing/fstest"

	"github.com/matteoredaelli/open-web-fingerprints/internal/domain"
	"github.com/matteoredaelli/open-web-fingerprints/internal/extractor"
	"github.com/matteoredaelli/open-web-fingerprints/internal/extractor/extractortest"
)

func fixtureSource() extractor.Source {
	return extractor.Source{
		ID: "enthec-webappanalyzer", URL: "https://github.com/enthec/webappanalyzer",
		Revision: "9e52f10", License: "GPL-3.0-only",
		FS: os.DirFS("testdata/snapshot"),
	}
}

func TestContract(t *testing.T) {
	extractortest.RunContract(t, New(), fixtureSource())
}

func extract(t *testing.T) *extractor.ExtractionResult {
	t.Helper()
	res, err := New().Extract(context.Background(), fixtureSource())
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func fingerprints(res *extractor.ExtractionResult, tech string) []extractor.ExtractedFingerprint {
	var out []extractor.ExtractedFingerprint
	for _, f := range res.Fingerprints {
		if f.TechnologyKey == tech {
			out = append(out, f)
		}
	}
	return out
}

func find(t *testing.T, fs []extractor.ExtractedFingerprint, obs domain.Observation, target string) extractor.ExtractedFingerprint {
	t.Helper()
	for _, f := range fs {
		if f.Observation == obs && f.Target == target {
			return f
		}
	}
	t.Fatalf("no %s fingerprint with target %q in %+v", obs, target, fs)
	return extractor.ExtractedFingerprint{}
}

func TestCounts(t *testing.T) {
	res := extract(t)
	if got := len(res.Technologies); got != 22 {
		t.Errorf("technologies = %d, want 22", got)
	}
	if len(res.Categories) == 0 || len(res.Fingerprints) == 0 || len(res.Relationships) == 0 {
		t.Error("expected categories, fingerprints and relationships")
	}
}

func TestTechnologyFields(t *testing.T) {
	res := extract(t)
	var a extractor.ExtractedTechnology
	for _, x := range res.Technologies {
		if x.Key == "A-Frame" {
			a = x
		}
	}
	if a.Name == "" || a.Website != "https://aframe.io" || a.File != "src/technologies/a.json" {
		t.Errorf("bad A-Frame: %+v", a)
	}
	if a.OpenSource == nil || !*a.OpenSource {
		t.Error("A-Frame should be open source")
	}
	if len(a.CategoryKeys) != 2 || a.CategoryKeys[0] != "25" {
		t.Errorf("category keys = %v", a.CategoryKeys)
	}
	if len(a.Raw) == 0 {
		t.Error("raw must be preserved")
	}
}

func TestVersionModifier(t *testing.T) {
	f := find(t, fingerprints(extract(t), "A-Frame"), domain.ObsJSGlobal, "AFRAME.version")
	if f.Operator != domain.OpRegex || f.Pattern != "^(.+)$" || f.VersionExtract != `\1` {
		t.Errorf("unexpected: %+v", f)
	}
	if f.RegexFlavor != domain.FlavorRE2 {
		t.Errorf("flavor = %q", f.RegexFlavor)
	}
}

func TestConfidenceModifier(t *testing.T) {
	var n int
	for _, f := range fingerprints(extract(t), "AdOcean") {
		if f.Confidence != nil {
			n++
			if *f.Confidence <= 0 || *f.Confidence > 1 {
				t.Errorf("confidence out of range: %v", *f.Confidence)
			}
		}
	}
	if n == 0 {
		t.Error("AdOcean should carry an explicit confidence")
	}
}

func TestEmptyPatternIsExists(t *testing.T) {
	f := find(t, fingerprints(extract(t), "A-Frame"), domain.ObsJSGlobal, "aframeStats")
	if f.Operator != domain.OpExists || f.Pattern != "" {
		t.Errorf("unexpected: %+v", f)
	}
}

func TestLookaheadIsEcmaScriptWithWarning(t *testing.T) {
	res := extract(t)
	var ecma int
	for _, f := range fingerprints(res, "AngularJS") {
		if f.RegexFlavor == domain.FlavorECMAScript {
			ecma++
		}
	}
	if ecma == 0 {
		t.Fatal("AngularJS lookahead must be ecmascript")
	}
	var w bool
	for _, x := range res.Warnings {
		if x.Code == "unsupported_regex" && x.Ref == "AngularJS" {
			w = true
		}
	}
	if !w {
		t.Error("missing unsupported_regex warning")
	}
}

func TestDOMForms(t *testing.T) {
	res := extract(t)
	f := find(t, fingerprints(res, "T-Soft"), domain.ObsDOM, "a[href*='.tsoft.com.tr'][target='_blank'][title='T-Soft E-ticaret Sistemleri']")
	if f.Operator != domain.OpExists {
		t.Errorf("list form: %+v", f)
	}
	f = find(t, fingerprints(res, "TableBooker"), domain.ObsDOM, "iframe::attr(id)")
	if f.Operator != domain.OpRegex || f.Pattern != "tablebookerResFrame_" {
		t.Errorf("attribute form: %+v", f)
	}
	f = find(t, fingerprints(res, "PixelFed"), domain.ObsDOM, "a[href='pixelfed.org'][title*='version']::attr(title)")
	if f.VersionExtract != `\1` {
		t.Errorf("dom version: %+v", f)
	}
	find(t, fingerprints(res, "PixelFed"), domain.ObsDOM, "a[href='pixelfed.org'][title*='version']::text")
	f = find(t, fingerprints(res, "Twenty Twenty-Two"), domain.ObsDOM, "link#twentytwentytwo-style-css")
	if f.Operator != domain.OpExists {
		t.Errorf("empty spec: %+v", f)
	}
}

func TestOtherObservations(t *testing.T) {
	res := extract(t)
	find(t, fingerprints(res, "Tangled Network"), domain.ObsDNSRecord, "NS")
	find(t, fingerprints(res, "Thawte"), domain.ObsTLSCert, "issuer")
	find(t, fingerprints(res, "Shoporama"), domain.ObsRobots, "")
	find(t, fingerprints(res, "Taboola"), domain.ObsXHR, "")
	find(t, fingerprints(res, "Taggbox"), "page_url", "")
	find(t, fingerprints(res, "Tipsa"), "page_text", "")
}

func TestProbeIsPendingAndNeverApproved(t *testing.T) {
	f := find(t, fingerprints(extract(t), "TYPO3 CMS"), domain.ObsProbeResponse, "status")
	if f.Probe == nil || f.Probe.Method != "GET" || f.Probe.SafetyReview != "pending" ||
		f.Probe.Path != "/typo3/sysext/core/Resources/Public/Images/typo3_orange.svg" {
		t.Errorf("unexpected probe: %+v", f.Probe)
	}
}

func TestRelationships(t *testing.T) {
	res := extract(t)
	var implies, reqCat bool
	for _, r := range res.Relationships {
		if r.FromKey == "A-Frame" && r.Type == "implies" && r.ToTechnologyKey == "Three.js" {
			implies = true
		}
		if r.FromKey == "Tipsa" && r.ToCategoryKey == "6" && r.Type == "requires" {
			reqCat = true
		}
	}
	if !implies || !reqCat {
		t.Errorf("implies=%v requiresCategory=%v", implies, reqCat)
	}
}

func TestIconNotExtracted(t *testing.T) {
	res := extract(t)
	for _, x := range res.Technologies {
		if x.Raw == nil {
			t.Fatal("raw missing")
		}
	}
	for _, w := range res.Warnings {
		if w.Code == "unknown_field" {
			t.Errorf("unexpected unknown_field warning: %+v", w)
		}
	}
}

func TestParsePattern(t *testing.T) {
	p := parsePattern(`a([\d.]+)\;confidence:50\;version:\1\;weird:x`)
	if p.Regex != `a([\d.]+)` || p.Version != `\1` || p.Confidence == nil || *p.Confidence != 0.5 {
		t.Errorf("%+v", p)
	}
	if len(p.Unknown) != 1 || p.Unknown[0] != "weird:x" {
		t.Errorf("unknown = %v", p.Unknown)
	}
	if p := parsePattern(`x\;confidence:abc`); p.Confidence != nil || len(p.Unknown) != 1 {
		t.Errorf("bad confidence must be reported: %+v", p)
	}
	if p := parsePattern(`x\;confidence:150`); p.Confidence != nil {
		t.Errorf("out of range confidence must be rejected: %+v", p)
	}
}

func snapshot(tech string) extractor.Source {
	return extractor.Source{ID: "s", FS: fstest.MapFS{
		"src/categories.json":     {Data: []byte(`{"1":{"name":"CMS","groups":[1,2]}}`)},
		"src/groups.json":         {Data: []byte(`{"1":{"name":"Content"},"2":{"name":"Other"}}`)},
		"src/technologies/a.json": {Data: []byte(tech)},
		"src/technologies/b.json": {Data: []byte(`{"X":{"cats":[1],"website":"https://b"}}`)},
	}}
}

func codes(res *extractor.ExtractionResult) map[string]int {
	m := map[string]int{}
	for _, w := range res.Warnings {
		m[w.Code]++
	}
	return m
}

func TestEdgeCases(t *testing.T) {
	res, err := New().Extract(context.Background(), snapshot(
		`{"X":{"cats":[1],"website":"https://a","mystery":1,"headers":"oops","scriptSrc":["a\\;weird:1"]}}`))
	if err != nil {
		t.Fatal(err)
	}
	c := codes(res)
	for _, want := range []string{"duplicate_technology", "unknown_field", "unexpected_shape", "unknown_modifier", "multiple_category_groups"} {
		if c[want] == 0 {
			t.Errorf("missing warning %s (have %v)", want, c)
		}
	}
	if len(res.Technologies) != 1 || res.Technologies[0].Website != "https://a" {
		t.Errorf("first definition must win: %+v", res.Technologies)
	}
	if res.Categories[0].Group != "Content" {
		t.Errorf("group = %q", res.Categories[0].Group)
	}
}

func TestErrors(t *testing.T) {
	if _, err := New().Extract(context.Background(), extractor.Source{}); err == nil {
		t.Error("nil FS must fail")
	}
	if _, err := New().Extract(context.Background(), extractor.Source{FS: fstest.MapFS{}}); err == nil {
		t.Error("missing categories must fail")
	}
	bad := snapshot(`{not json`)
	if _, err := New().Extract(context.Background(), bad); err == nil {
		t.Error("invalid JSON must fail")
	}
}

// TestFullSnapshot runs against a full local clone when OWF_ENTHEC_SNAPSHOT
// points to it. It is skipped by default so unit tests stay hermetic.
func TestFullSnapshot(t *testing.T) {
	dir := os.Getenv("OWF_ENTHEC_SNAPSHOT")
	if dir == "" {
		t.Skip("OWF_ENTHEC_SNAPSHOT not set")
	}
	src := extractor.Source{ID: "enthec-webappanalyzer", FS: os.DirFS(dir)}
	res, err := New().Extract(context.Background(), src)
	if err != nil {
		t.Fatal(err)
	}
	counts := map[domain.Observation]int{}
	for _, f := range res.Fingerprints {
		counts[f.Observation]++
	}
	t.Logf("technologies=%d categories=%d fingerprints=%d relationships=%d warnings=%v",
		len(res.Technologies), len(res.Categories), len(res.Fingerprints), len(res.Relationships), codes(res))
	t.Logf("by observation: %v", counts)
	extractortest.RunContract(t, New(), src)
}

func TestDOMSelectorModifiers(t *testing.T) {
	src := extractor.Source{ID: "s", FS: fstest.MapFS{
		"src/categories.json": {Data: []byte(`{"1":{"name":"CMS","groups":[1]}}`)},
		"src/technologies/a.json": {Data: []byte(`{"X":{"cats":[1],"dom":[
			"form[name='f'][action='a.aspx' i]\\;confidence:40", "div.plain"]}}`)},
	}}
	res, err := New().Extract(context.Background(), src)
	if err != nil {
		t.Fatal(err)
	}
	got := fingerprints(res, "X")
	if len(got) != 2 {
		t.Fatalf("fingerprints: %+v", got)
	}
	if got[0].Target != "form[name='f'][action='a.aspx' i]" || got[0].Confidence == nil || *got[0].Confidence != 0.4 {
		t.Errorf("modifier must not stay in the selector: %+v", got[0])
	}
	if got[1].Target != "div.plain" || got[1].Confidence != nil {
		t.Errorf("plain selector: %+v", got[1])
	}
}

func legacySource() extractor.Source {
	return extractor.Source{
		ID: "httparchive-wappalyzer", URL: "https://github.com/HTTPArchive/wappalyzer",
		Revision: "35b0847", License: "GPL-3.0-only", FS: os.DirFS("testdata/legacy"),
	}
}

func TestLegacyShapesContract(t *testing.T) {
	extractortest.RunContract(t, New(), legacySource())
}

// The HTTP Archive fork writes single values as plain strings. Reading them
// must not lose rules or raise shape warnings.
func TestLegacyShapes(t *testing.T) {
	res, err := New().Extract(context.Background(), legacySource())
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range res.Warnings {
		if w.Code == "unexpected_shape" {
			t.Errorf("legacy shape not understood: %+v", w)
		}
	}
	seen := map[domain.Observation]bool{}
	for _, f := range res.Fingerprints {
		seen[f.Observation] = true
	}
	for _, want := range []domain.Observation{
		domain.ObsHTML, domain.ObsScriptURL, domain.ObsDOM, domain.ObsXHR, domain.ObsDNSRecord,
		domain.ObsMetaTag, "css_rule", "page_url", "page_text", "script_content",
	} {
		if !seen[want] {
			t.Errorf("no %s fingerprint extracted from the legacy records", want)
		}
	}
	types := map[string]bool{}
	var catRel bool
	for _, r := range res.Relationships {
		types[r.Type] = true
		if r.ToCategoryKey != "" {
			catRel = true
		}
	}
	if !types["implies"] || !types["requires"] || !types["excludes"] || !catRel {
		t.Errorf("relationships: types=%v requiresCategory=%v", types, catRel)
	}
}

func TestFlexShapes(t *testing.T) {
	var l flexList
	for in, want := range map[string]int{`"a"`: 1, `["a","b"]`: 2, `[]`: 0, `""`: 1} {
		if err := json.Unmarshal([]byte(in), &l); err != nil || len(l) != want {
			t.Errorf("flexList %s: %v err=%v", in, l, err)
		}
	}
	for _, bad := range []string{`1`, `{"a":1}`, `[1]`} {
		if err := json.Unmarshal([]byte(bad), &l); err == nil {
			t.Errorf("flexList must reject %s", bad)
		}
	}
	var n flexInts
	for in, want := range map[string]int{`6`: 1, `[6,7]`: 2} {
		if err := json.Unmarshal([]byte(in), &n); err != nil || len(n) != want {
			t.Errorf("flexInts %s: %v err=%v", in, n, err)
		}
	}
	if err := json.Unmarshal([]byte(`"x"`), &n); err == nil {
		t.Error("flexInts must reject a string")
	}
}
