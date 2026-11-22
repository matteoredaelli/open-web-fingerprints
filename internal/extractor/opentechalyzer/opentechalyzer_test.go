// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package opentechalyzer

import (
	"context"
	"os"
	"regexp"
	"testing"
	"testing/fstest"

	"github.com/matteoredaelli/open-web-fingerprints/internal/domain"
	"github.com/matteoredaelli/open-web-fingerprints/internal/extractor"
	"github.com/matteoredaelli/open-web-fingerprints/internal/extractor/extractortest"
)

func fixtureSource() extractor.Source {
	return extractor.Source{
		ID: "houseofmvps-opentechalyzer", URL: "https://github.com/Houseofmvps/opentechalyzer",
		Revision: "a3d30e4", License: "MIT", FS: os.DirFS("testdata/snapshot"),
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

func rules(res *extractor.ExtractionResult, tech string, obs domain.Observation) []extractor.ExtractedFingerprint {
	var out []extractor.ExtractedFingerprint
	for _, f := range res.Fingerprints {
		if f.TechnologyKey == tech && f.Observation == obs {
			out = append(out, f)
		}
	}
	return out
}

func warnings(res *extractor.ExtractionResult, code string) []extractor.Warning {
	var out []extractor.Warning
	for _, w := range res.Warnings {
		if w.Code == code {
			out = append(out, w)
		}
	}
	return out
}

func TestTechnologiesAndCategories(t *testing.T) {
	res := extract(t)
	if len(res.Technologies) < 200 {
		t.Fatalf("only %d technologies", len(res.Technologies))
	}
	names := map[string]bool{}
	for _, tc := range res.Technologies {
		names[tc.Name] = true
	}
	for _, n := range []string{"Google Tag Manager", "Next.js", "Tailwind CSS", "Cloudflare DNS"} {
		if !names[n] {
			t.Errorf("%s missing", n)
		}
	}
	if len(res.Categories) == 0 {
		t.Fatal("no categories")
	}
	if res.Metadata["fingerprint_files"] != 5 {
		t.Errorf("files = %v, want 5 (index.ts is code)", res.Metadata["fingerprint_files"])
	}
	if len(warnings(res, "unparsable_file")) != 0 {
		t.Errorf("a fixture failed to parse: %+v", warnings(res, "unparsable_file"))
	}
}

func TestCaseSensitiveIdentifier(t *testing.T) {
	res := extract(t)
	var got *extractor.ExtractedFingerprint
	for _, f := range rules(res, "Google Analytics 4", domain.ObsHTML) {
		if regexp.MustCompile(`G-`).MatchString(f.Pattern) {
			got = &f
		}
	}
	if got == nil {
		t.Fatal("no GA4 html rule")
	}
	re := regexp.MustCompile("(?i)" + got.Pattern)
	if !re.MatchString("gtag G-ABCDEF1234") {
		t.Error("the identifier should match")
	}
	if re.MatchString("class=g-recaptcha-widget") {
		t.Error("a case-sensitive pattern must stay case-sensitive under the (?i) engine")
	}
	if got.RegexFlavor != domain.FlavorRE2 {
		t.Errorf("flavor = %s", got.RegexFlavor)
	}
	if len(warnings(res, "unsupported_signal")) == 0 {
		t.Error("the id of a pattern should be counted as not mapped")
	}
}

func TestVersionAndHeaders(t *testing.T) {
	res := extract(t)
	var h *extractor.ExtractedFingerprint
	for _, f := range rules(res, "Next.js", domain.ObsHTTPHeader) {
		if f.Target == "x-powered-by" {
			h = &f
		}
	}
	if h == nil || h.Operator != domain.OpRegex || h.VersionExtract != `\1` {
		t.Fatalf("x-powered-by rule = %+v", h)
	}
	var present *extractor.ExtractedFingerprint
	for _, f := range rules(res, "Next.js", domain.ObsHTTPHeader) {
		if f.Target == "x-nextjs-cache" {
			present = &f
		}
	}
	if present == nil || present.Operator != domain.OpExists {
		t.Fatalf("x-nextjs-cache rule = %+v", present)
	}
}

func TestCookies(t *testing.T) {
	res := extract(t)
	var php *extractor.ExtractedFingerprint
	for _, tc := range res.Technologies {
		for _, f := range rules(res, tc.Name, "set_cookie") {
			if regexp.MustCompile("(?i)" + f.Pattern).MatchString("PHPSESSID=abc; path=/") {
				php = &f
			}
		}
	}
	if php == nil {
		t.Fatal("no rule matches a PHPSESSID Set-Cookie line")
	}
}

func TestCookieLine(t *testing.T) {
	cases := []struct {
		in, match, miss string
	}{
		{`^PHPSESSID$`, "PHPSESSID=1", "XPHPSESSID=1"},
		{`^PrestaShop-`, "PrestaShop-abc=1", "my-PrestaShop-abc=1"},
		{`_key$`, "_phoenix_key=1; path=/", "_key_x=1"},
		{`^(?:YII_CSRF_TOKEN|_csrf)$`, "_csrf=1", "_csrf2=1"},
	}
	for _, c := range cases {
		re := regexp.MustCompile("(?i)" + cookieLine(c.in))
		if !re.MatchString(c.match) || re.MatchString(c.miss) {
			t.Errorf("%s -> %s: match %q=%v miss %q=%v", c.in, cookieLine(c.in), c.match, re.MatchString(c.match), c.miss, re.MatchString(c.miss))
		}
	}
}

func TestDNSAndCSS(t *testing.T) {
	res := extract(t)
	ns := rules(res, "Cloudflare DNS", domain.ObsDNSRecord)
	if len(ns) != 1 || ns[0].Target != "NS" || ns[0].Operator != domain.OpRegex {
		t.Fatalf("Cloudflare DNS = %+v", ns)
	}
	if len(rules(res, "Tailwind CSS", "css_content")) == 0 {
		t.Error("cssContent not mapped")
	}
}

func TestProbes(t *testing.T) {
	res := extract(t)
	pr := rules(res, "Grafana", domain.ObsProbeResponse)
	if len(pr) != 1 || pr[0].Probe == nil || pr[0].Probe.Method != "GET" || pr[0].Probe.Path != "/api/health" ||
		pr[0].Probe.SafetyReview != "pending" || pr[0].Target != "body" {
		t.Fatalf("Grafana probe = %+v", pr)
	}
	for _, f := range res.Fingerprints {
		if f.Probe != nil && f.Probe.SafetyReview != "pending" {
			t.Errorf("an extractor must never approve a probe: %+v", f)
		}
	}
	for _, tc := range res.Technologies {
		if tc.Name == "Exposed Git repository" || tc.Name == "Exposed .env file" {
			t.Errorf("%s is out of scope and must be skipped", tc.Name)
		}
	}
	if len(warnings(res, "out_of_scope")) != 2 {
		t.Errorf("out_of_scope warnings = %+v", warnings(res, "out_of_scope"))
	}
}

func TestRelationshipsAndRaw(t *testing.T) {
	res := extract(t)
	var implies int
	for _, r := range res.Relationships {
		if r.FromKey == "Stape" && r.Type == "implies" && r.ToTechnologyKey == "Google Tag Manager" {
			implies++
		}
	}
	if implies != 1 {
		t.Errorf("Stape implies GTM: %d", implies)
	}
	for _, tc := range res.Technologies {
		if len(tc.Raw) == 0 {
			t.Errorf("%s has no Raw", tc.Name)
		}
	}
}

func TestNpmDepIsCountedNotImported(t *testing.T) {
	res := extract(t)
	found := false
	for _, w := range warnings(res, "unsupported_signal") {
		if w.Ref == "npmDep" {
			found = true
		}
	}
	if !found {
		t.Error("npmDep should be reported as not mapped")
	}
	for _, f := range res.Fingerprints {
		if f.Observation == "npm_dep" {
			t.Error("npmDep must not become a fingerprint")
		}
	}
}

func TestUnparsableFileIsSkippedWithWarning(t *testing.T) {
	fsys := fstest.MapFS{
		"src/fingerprints/bad.ts": {Data: []byte("export const x = [...other];")},
		"src/fingerprints/ok.ts": {Data: []byte(`export const a: Fingerprint[] = [
  { name: 'A', categories: ['cms'], html: ['<a>'] }, // comment
];`)},
	}
	res, err := New().Extract(context.Background(), extractor.Source{ID: "x", FS: fsys})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Technologies) != 1 || len(warnings(res, "unparsable_file")) != 1 {
		t.Fatalf("technologies %d warnings %+v", len(res.Technologies), res.Warnings)
	}
}

func TestInvalidWebsiteIsLeftOut(t *testing.T) {
	fsys := fstest.MapFS{"src/fingerprints/a.ts": {Data: []byte(`export const a = [
  { name: 'A', categories: ['cms'], website: 'https://a\\.example', html: ['x'] },
  { name: 'B', categories: ['cms'], website: 'https://b.example', html: ['x'] },
];`)}}
	res, err := New().Extract(context.Background(), extractor.Source{ID: "x", FS: fsys})
	if err != nil {
		t.Fatal(err)
	}
	if res.Technologies[0].Website != "" || res.Technologies[1].Website != "https://b.example" || len(warnings(res, "invalid_website")) != 1 {
		t.Fatalf("%+v %+v", res.Technologies, res.Warnings)
	}
}

func TestCategoryNames(t *testing.T) {
	res := extract(t)
	names := map[string]string{}
	for _, c := range res.Categories {
		names[c.Key] = c.Name
	}
	for key, want := range map[string]string{"js-library": "JavaScript libraries", "web-server": "Web servers", "error-tracking": "Error tracking", "analytics": "Analytics"} {
		if got, ok := names[key]; ok && got != want {
			t.Errorf("%s -> %q, want %q", key, got, want)
		}
	}
	if names["js-library"] == "" {
		t.Error("js-library is in the fixtures and must be mapped")
	}
}

func TestParseSubset(t *testing.T) {
	decls, err := parseModule(`import type { X } from './x.js';
/* block */ export const a: X[] = [
  { 'k-1': "a\\d" + 'b', n: -1.5, ok: true, nothing: null, list: ['\u0041\x42\n'], },
] as const;`)
	if err != nil {
		t.Fatal(err)
	}
	m := decls[0].Value.([]any)[0].(map[string]any)
	if m["k-1"] != `a\db` || m["n"] != -1.5 || m["ok"] != true || m["nothing"] != nil {
		t.Errorf("parsed %#v", m)
	}
	if m["list"].([]any)[0] != "AB\n" {
		t.Errorf("escapes: %q", m["list"])
	}
	for _, bad := range []string{"export function f() {}", "export const a = f();", "export const a = `x${y}`;", "export const a = [1 2];", "export const a = 'x"} {
		if _, err := parseModule(bad); err == nil {
			t.Errorf("%q should not parse", bad)
		}
	}
}
