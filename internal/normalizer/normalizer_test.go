// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package normalizer_test

import (
	"context"
	"encoding/json"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/matteoredaelli/open-web-fingerprints/internal/domain"
	"github.com/matteoredaelli/open-web-fingerprints/internal/extractor"
	"github.com/matteoredaelli/open-web-fingerprints/internal/extractor/wappalyzer"
	"github.com/matteoredaelli/open-web-fingerprints/internal/normalizer"
	"github.com/matteoredaelli/open-web-fingerprints/schemas"
)

var importedAt = time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)

func testSource() domain.Source {
	return domain.Source{
		ID: "src_0192f0a0-0000-7000-8000-000000000001", Slug: "enthec-webappanalyzer",
		Name: "Enthec WebAppAnalyzer", License: "GPL-3.0-only", Redistributable: "unreviewed",
	}
}

func extractFixture(t *testing.T, dir string) *extractor.ExtractionResult {
	t.Helper()
	res, err := wappalyzer.New().Extract(context.Background(), extractor.Source{
		ID: "enthec-webappanalyzer", Revision: "9e52f10", FS: os.DirFS(dir),
	})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func normalize(t *testing.T, n normalizer.Normalizer, ex *extractor.ExtractionResult) *normalizer.Result {
	t.Helper()
	res, err := n.Normalize(normalizer.Input{
		Source: testSource(), Revision: "9e52f10", ImportedAt: importedAt, Extraction: ex,
	})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func registry(res *normalizer.Result) domain.Registry {
	gen := importedAt
	return domain.Registry{
		SchemaVersion: "0.1.0", GeneratedAt: &gen,
		Sources: []domain.Source{testSource()},
		Snapshots: []domain.Snapshot{{
			SourceID: testSource().ID, Revision: "9e52f10", RetrievedAt: importedAt,
			Checksum: "sha256:" + string(make([]byte, 0)) + "0000000000000000000000000000000000000000000000000000000000000000",
		}},
		Categories: res.Categories, Technologies: res.Technologies,
		Fingerprints: res.Fingerprints, Relationships: res.Relationships,
	}
}

func validate(t *testing.T, res *normalizer.Result) {
	t.Helper()
	b, err := json.Marshal(registry(res))
	if err != nil {
		t.Fatal(err)
	}
	if err := schemas.ValidateRegistry(b); err != nil {
		t.Fatalf("normalized output violates schema: %v", err)
	}
}

func TestFixtureOutputIsSchemaValid(t *testing.T) {
	res := normalize(t, normalizer.New(normalizer.NewMemoryAllocator()),
		extractFixture(t, "../extractor/wappalyzer/testdata/snapshot"))
	validate(t, res)
	if len(res.Technologies) != 22 {
		t.Errorf("technologies = %d", len(res.Technologies))
	}
}

func TestIdempotentIDs(t *testing.T) {
	alloc := normalizer.NewMemoryAllocator()
	n := normalizer.New(alloc)
	ex := extractFixture(t, "../extractor/wappalyzer/testdata/snapshot")
	a := normalize(t, n, ex)
	b := normalize(t, n, ex)
	if !reflect.DeepEqual(a, b) {
		t.Fatal("normalizing the same extraction twice with the same allocator must give identical records")
	}
}

func byName(res *normalizer.Result, name string) domain.Technology {
	for _, x := range res.Technologies {
		if x.Name == name {
			return x
		}
	}
	return domain.Technology{}
}

func TestMapping(t *testing.T) {
	res := normalize(t, normalizer.New(normalizer.NewMemoryAllocator()),
		extractFixture(t, "../extractor/wappalyzer/testdata/snapshot"))

	af := byName(res, "A-Frame")
	if af.Slug != "a-frame" || af.Status != domain.StatusActive || len(af.CategoryIDs) != 2 {
		t.Errorf("A-Frame: %+v", af)
	}
	p := af.Provenance[0]
	if p.OriginalID != "A-Frame" || p.SnapshotRevision != "9e52f10" || p.License != "GPL-3.0-only" ||
		p.State != "present" || p.OriginalFile != "src/technologies/a.json" {
		t.Errorf("provenance: %+v", p)
	}

	var typo, angular, withConf *domain.Fingerprint
	typoID := byName(res, "TYPO3 CMS").ID
	angID := byName(res, "AngularJS").ID
	for i := range res.Fingerprints {
		f := &res.Fingerprints[i]
		switch {
		case f.TechnologyID == typoID && f.Probe != nil:
			typo = f
		case f.TechnologyID == angID && f.RegexFlavor == domain.FlavorECMAScript:
			angular = f
		case f.Provenance[0].OriginalConfidence != nil:
			withConf = f
		}
	}
	if typo == nil || typo.Status != domain.StatusDraft || typo.Probe.SafetyReview != "pending" {
		t.Errorf("probe must be draft and pending: %+v", typo)
	}
	if angular == nil || angular.Status != domain.StatusActive {
		t.Errorf("ecmascript rule: %+v", angular)
	}
	if withConf == nil || withConf.Confidence != *withConf.Provenance[0].OriginalConfidence {
		t.Errorf("explicit confidence must be preserved: %+v", withConf)
	}
	for _, f := range res.Fingerprints {
		if f.Validation == nil || f.Validation.Health != "unknown" {
			t.Fatalf("imported rules must start with unknown health: %+v", f)
		}
		if f.Provenance[0].OriginalConfidence == nil && f.Confidence != normalizer.DefaultConfidence {
			t.Fatalf("default confidence not applied: %v", f.Confidence)
		}
	}
}

func TestProbeApprovalIsNeverInherited(t *testing.T) {
	ex := &extractor.ExtractionResult{
		Technologies: []extractor.ExtractedTechnology{{Key: "A", Name: "A"}},
		Fingerprints: []extractor.ExtractedFingerprint{{
			TechnologyKey: "A", Observation: domain.ObsProbeResponse, Operator: domain.OpExists,
			Probe: &domain.Probe{Method: "GET", Path: "/x", SafetyReview: "approved"},
		}},
	}
	res := normalize(t, normalizer.New(normalizer.NewMemoryAllocator()), ex)
	f := res.Fingerprints[0]
	if f.Probe.SafetyReview != "pending" || f.Status != domain.StatusDraft {
		t.Errorf("%+v", f)
	}
}

func TestWarningsAndSkips(t *testing.T) {
	ex := &extractor.ExtractionResult{
		Warnings:     []extractor.Warning{{Code: "from_extractor"}},
		Categories:   []extractor.ExtractedCategory{{Key: "1", Name: "CMS", ParentKey: "9"}},
		Technologies: []extractor.ExtractedTechnology{{Key: "A", Name: "A", CategoryKeys: []string{"1", "2"}}, {Key: "B", Name: "a"}},
		Fingerprints: []extractor.ExtractedFingerprint{
			{TechnologyKey: "A", Observation: "x", Operator: domain.OpExists, Raw: json.RawMessage(`{"a":1}`)},
			{TechnologyKey: "A", Observation: "x", Operator: domain.OpExists, Raw: json.RawMessage(`{"a":1}`)},
			{TechnologyKey: "Z", Observation: "x", Operator: domain.OpExists},
		},
		Relationships: []extractor.ExtractedRelationship{
			{FromKey: "A", ToTechnologyKey: "B", Type: "implies"},
			{FromKey: "A", ToTechnologyKey: "B", Type: "implies"},
			{FromKey: "A", ToTechnologyKey: "Nope", Type: "implies"},
			{FromKey: "A", ToCategoryKey: "77", Type: "requires"},
			{FromKey: "Q", ToTechnologyKey: "B", Type: "implies"},
			{FromKey: "A", Type: "implies"},
			{FromKey: "A", ToTechnologyKey: "A", Type: "implies"},
		},
	}
	res := normalize(t, normalizer.New(normalizer.NewMemoryAllocator()), ex)
	got := map[string]int{}
	for _, w := range res.Warnings {
		got[w.Code]++
	}
	for _, want := range []string{"from_extractor", "unknown_parent_category", "unknown_category",
		"duplicate_rule", "unknown_technology", "duplicate_relationship", "unresolved_relationship", "invalid_relationship", "self_relationship"} {
		if got[want] == 0 {
			t.Errorf("missing warning %s: %v", want, got)
		}
	}
	if len(res.Fingerprints) != 1 || len(res.Relationships) != 1 {
		t.Errorf("fingerprints=%d relationships=%d", len(res.Fingerprints), len(res.Relationships))
	}
	if res.Technologies[0].Slug != "a" || res.Technologies[1].Slug != "a-2" {
		t.Errorf("slugs: %q %q", res.Technologies[0].Slug, res.Technologies[1].Slug)
	}
}

func TestErrors(t *testing.T) {
	n := normalizer.New(normalizer.NewMemoryAllocator())
	if _, err := n.Normalize(normalizer.Input{Source: testSource()}); err == nil {
		t.Error("nil extraction must fail")
	}
	if _, err := n.Normalize(normalizer.Input{Extraction: &extractor.ExtractionResult{}}); err == nil {
		t.Error("missing source ID must fail")
	}
}

// Opt-in: normalize a full local Enthec clone and validate against the schema.
func TestFullSnapshot(t *testing.T) {
	dir := os.Getenv("OWF_ENTHEC_SNAPSHOT")
	if dir == "" {
		t.Skip("OWF_ENTHEC_SNAPSHOT not set")
	}
	res := normalize(t, normalizer.New(normalizer.NewMemoryAllocator()), extractFixture(t, dir))
	codes := map[string]int{}
	for _, w := range res.Warnings {
		codes[w.Code]++
	}
	t.Logf("technologies=%d categories=%d fingerprints=%d relationships=%d warnings=%v",
		len(res.Technologies), len(res.Categories), len(res.Fingerprints), len(res.Relationships), codes)
	validate(t, res)
}

func conf(v float64) *float64 { return &v }

func TestEquivalentRulesMergeWithProvenance(t *testing.T) {
	ex := &extractor.ExtractionResult{
		Technologies: []extractor.ExtractedTechnology{{Key: "A", Name: "A"}},
		Fingerprints: []extractor.ExtractedFingerprint{
			// Header names are case-insensitive: same rule.
			{TechnologyKey: "A", Observation: domain.ObsHTTPHeader, Target: "X-Powered-By", Operator: domain.OpExists, Raw: json.RawMessage(`{"n":1}`), Confidence: conf(0.8)},
			{TechnologyKey: "A", Observation: domain.ObsHTTPHeader, Target: "x-powered-by", Operator: domain.OpExists, Raw: json.RawMessage(`{"n":2}`), Confidence: conf(0.6)},
			// Cookie names are case-sensitive: different rule.
			{TechnologyKey: "A", Observation: domain.ObsCookie, Target: "SID", Operator: domain.OpExists, Raw: json.RawMessage(`{"n":3}`)},
			{TechnologyKey: "A", Observation: domain.ObsCookie, Target: "sid", Operator: domain.OpExists, Raw: json.RawMessage(`{"n":4}`)},
		},
	}
	n := normalizer.New(normalizer.NewMemoryAllocator())
	res := normalize(t, n, ex)
	if len(res.Fingerprints) != 3 {
		t.Fatalf("fingerprints = %d, want 3", len(res.Fingerprints))
	}
	h := res.Fingerprints[0]
	if len(h.Provenance) != 2 || h.Provenance[0].OriginalID == h.Provenance[1].OriginalID {
		t.Errorf("provenance: %+v", h.Provenance)
	}
	if h.Confidence != 0.6 {
		t.Errorf("canonical confidence must be the lowest explicit value, got %v", h.Confidence)
	}
	got := map[string]int{}
	for _, w := range res.Warnings {
		got[w.Code]++
	}
	if got["merged_duplicate_rule"] != 1 || got["confidence_disagreement"] != 1 {
		t.Errorf("warnings: %v", got)
	}
	// The ID depends on the meaning of the rule, not on which duplicate came first.
	rev := &extractor.ExtractionResult{Technologies: ex.Technologies,
		Fingerprints: []extractor.ExtractedFingerprint{ex.Fingerprints[1], ex.Fingerprints[0]}}
	again := normalize(t, n, rev)
	if again.Fingerprints[0].ID != h.ID {
		t.Errorf("ID must not depend on duplicate order: %s vs %s", again.Fingerprints[0].ID, h.ID)
	}
}

func TestSlugsStayStableAndUniqueAcrossSources(t *testing.T) {
	n := normalizer.New(normalizer.NewMemoryAllocator())
	ex := func(names ...string) *extractor.ExtractionResult {
		r := &extractor.ExtractionResult{}
		for _, nm := range names {
			r.Technologies = append(r.Technologies, extractor.ExtractedTechnology{Key: nm, Name: nm})
		}
		return r
	}
	first := normalize(t, n, ex("WordPress"))
	if first.Technologies[0].Slug != "wordpress" {
		t.Fatal(first.Technologies[0].Slug)
	}
	// Another source with the same name must not take the slug.
	other := testSource()
	other.ID = "src_0192f0a0-0000-7000-8000-000000000002"
	res, err := n.Normalize(normalizer.Input{
		Source: other, Revision: "r", ImportedAt: importedAt, Extraction: ex("WordPress"),
		Existing: domain.Records{Technologies: first.Technologies},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Technologies[0].Slug != "wordpress-2" {
		t.Errorf("slug = %q, want wordpress-2", res.Technologies[0].Slug)
	}
	// Re-importing the first source keeps its slug even though the new
	// record exists.
	all := append(append([]domain.Technology{}, first.Technologies...), res.Technologies...)
	again, err := n.Normalize(normalizer.Input{
		Source: testSource(), Revision: "r2", ImportedAt: importedAt, Extraction: ex("Brand New", "WordPress"),
		Existing: domain.Records{Technologies: all},
	})
	if err != nil {
		t.Fatal(err)
	}
	slugs := map[string]string{}
	for _, x := range again.Technologies {
		slugs[x.Name] = x.Slug
	}
	if slugs["WordPress"] != "wordpress" || slugs["Brand New"] != "brand-new" {
		t.Errorf("slugs: %v", slugs)
	}
}

func TestVendorsFromCPE(t *testing.T) {
	ex := &extractor.ExtractionResult{Technologies: []extractor.ExtractedTechnology{
		{Key: "A", Name: "A", File: "a.json", CPE: []string{"cpe:2.3:a:experience_manager_inc:aem:*:*:*:*:*:*:*:*"}},
		{Key: "B", Name: "B", File: "b.json", CPE: []string{"cpe:2.3:a:experience_manager_inc:other:*:*:*:*:*:*:*:*"}},
		{Key: "C", Name: "C", File: "c.json", CPE: []string{"not a cpe", "cpe:2.3:a:F5:nginx:*:*:*:*:*:*:*:*"}},
		{Key: "D", Name: "D", File: "d.json"},
		{Key: "E", Name: "E", File: "e.json", CPE: []string{"cpe:2.3:a:*:x:*:*:*:*:*:*:*:*"}},
	}}
	n := normalizer.New(normalizer.NewMemoryAllocator())
	res := normalize(t, n, ex)
	if len(res.Vendors) != 2 {
		t.Fatalf("vendors = %+v", res.Vendors)
	}
	byTok := map[string]domain.Vendor{}
	for _, v := range res.Vendors {
		byTok[v.CPEVendor] = v
	}
	v := byTok["experience_manager_inc"]
	if v.Name != "Experience Manager Inc" || v.Slug != "experience-manager-inc" ||
		len(v.Provenance) != 1 || v.Provenance[0].OriginalID != "experience_manager_inc" || v.Provenance[0].OriginalFile != "a.json" {
		t.Errorf("vendor: %+v", v)
	}
	if byTok["f5"].Name != "F5" {
		t.Errorf("name: %q", byTok["f5"].Name)
	}
	vendorOf := map[string]domain.VendorID{}
	for _, x := range res.Technologies {
		vendorOf[x.Name] = x.VendorID
	}
	if vendorOf["A"] != v.ID || vendorOf["B"] != v.ID || vendorOf["C"] != byTok["f5"].ID || vendorOf["D"] != "" || vendorOf["E"] != "" {
		t.Errorf("technology vendors: %v", vendorOf)
	}

	// The vendor ID does not depend on the source: two sources share it.
	other := testSource()
	other.ID = "src_0192f0a0-0000-7000-8000-000000000002"
	res2, err := n.Normalize(normalizer.Input{Source: other, Revision: "r", ImportedAt: importedAt, Extraction: ex, Existing: domain.Records{Vendors: res.Vendors}})
	if err != nil {
		t.Fatal(err)
	}
	for _, v2 := range res2.Vendors {
		if v2.ID != byTok[v2.CPEVendor].ID || v2.Slug != byTok[v2.CPEVendor].Slug {
			t.Errorf("vendor must be the same record in every source: %+v vs %+v", v2, byTok[v2.CPEVendor])
		}
		if v2.Provenance[0].SourceID != other.ID {
			t.Errorf("provenance must name this source: %+v", v2.Provenance)
		}
	}
}

func TestVendorSlugsAreUniqueAndStable(t *testing.T) {
	ex := &extractor.ExtractionResult{Technologies: []extractor.ExtractedTechnology{
		{Key: "A", Name: "A", CPE: []string{"cpe:2.3:a:foo_bar:x:*:*:*:*:*:*:*:*"}},
		{Key: "B", Name: "B", CPE: []string{"cpe:2.3:a:foo-bar:x:*:*:*:*:*:*:*:*"}}, // same slug, different identifier
	}}
	res := normalize(t, normalizer.New(normalizer.NewMemoryAllocator()), ex)
	if len(res.Vendors) != 2 || res.Vendors[0].Slug != "foo-bar" || res.Vendors[1].Slug != "foo-bar-2" {
		t.Fatalf("vendors: %+v", res.Vendors)
	}
}
