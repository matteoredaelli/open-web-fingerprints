// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package nuclei

import (
	"context"
	"os"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/matteoredaelli/open-web-fingerprints/internal/domain"
	"github.com/matteoredaelli/open-web-fingerprints/internal/extractor"
	"github.com/matteoredaelli/open-web-fingerprints/internal/extractor/extractortest"
	"github.com/matteoredaelli/open-web-fingerprints/internal/matcher"
)

func fixtureSource() extractor.Source {
	return extractor.Source{
		ID: "projectdiscovery-nuclei-templates", URL: "https://github.com/projectdiscovery/nuclei-templates",
		Revision: "91be390", License: "MIT", FS: os.DirFS("testdata/snapshot"),
	}
}

func extract(t *testing.T) *extractor.ExtractionResult {
	t.Helper()
	res, err := New().Extract(context.Background(), fixtureSource())
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestContract(t *testing.T) {
	extractortest.RunContract(t, New(), fixtureSource())
}

// one extracts a single template written in the test.
func one(t *testing.T, body string) *extractor.ExtractionResult {
	t.Helper()
	src := extractor.Source{ID: "n", FS: fstest.MapFS{"http/technologies/t.yaml": {Data: []byte(body)}}}
	res, err := New().Extract(context.Background(), src)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func skipMessages(res *extractor.ExtractionResult) string {
	var out []string
	for _, w := range res.Warnings {
		if w.Code == "skipped" {
			out = append(out, w.Message)
		}
	}
	return strings.Join(out, "\n")
}

func toRule(f extractor.ExtractedFingerprint) domain.Fingerprint {
	return domain.Fingerprint{
		Observation: f.Observation, Target: f.Target, Operator: f.Operator, Pattern: f.Pattern,
		RegexFlavor: f.RegexFlavor, VersionExtract: f.VersionExtract, Role: f.Role, Probe: f.Probe,
	}
}

// byTech returns the rules of the technology with the given name, with the
// rules of one group together, in the order of the extraction.
func byTech(res *extractor.ExtractionResult, name string) (singles []domain.Fingerprint, groups map[string][]domain.Fingerprint) {
	key := ""
	for _, x := range res.Technologies {
		if x.Name == name {
			key = x.Key
		}
	}
	groups = map[string][]domain.Fingerprint{}
	for _, f := range res.Fingerprints {
		if f.TechnologyKey != key {
			continue
		}
		if f.GroupKey == "" {
			singles = append(singles, toRule(f))
		} else {
			groups[f.GroupKey] = append(groups[f.GroupKey], toRule(f))
		}
	}
	return singles, groups
}

func matches(t *testing.T, rules []domain.Fingerprint, o *matcher.Observation) bool {
	t.Helper()
	var got matcher.Outcome
	var err error
	if len(rules) == 1 {
		got, err = matcher.Evaluate(rules[0], o)
	} else {
		got, err = matcher.EvaluateGroup(rules, o)
	}
	if err != nil {
		t.Fatal(err)
	}
	return got.Matched
}

func anyGroup(t *testing.T, groups map[string][]domain.Fingerprint, o *matcher.Observation) bool {
	t.Helper()
	for _, g := range groups {
		if matches(t, g, o) {
			return true
		}
	}
	return false
}

func TestTemplateMatchersBecomeGroupsAndRules(t *testing.T) {
	res := extract(t)

	// matchers-condition: and  ->  one group of header regex AND status.
	singles, groups := byTech(res, "Apache")
	if len(singles) != 0 || len(groups) != 1 {
		t.Fatalf("Apache: singles=%d groups=%d", len(singles), len(groups))
	}
	for _, g := range groups {
		if len(g) != 2 || g[0].Observation != "response_headers" || g[1].Observation != "http_status" || g[0].Probe != nil {
			t.Errorf("Apache group: %+v", g)
		}
		if g[0].Pattern != "(?-i)Apache+" || g[0].RegexFlavor != domain.FlavorRE2 {
			t.Errorf("a nuclei regex is case-sensitive: %+v", g[0])
		}
		if !matches(t, g, &matcher.Observation{Status: 200, Headers: map[string]string{"Server": "Apache/2.4.58"}}) {
			t.Error("Apache on a 200 must match")
		}
		if matches(t, g, &matcher.Observation{Status: 404, Headers: map[string]string{"Server": "Apache/2.4.58"}}) {
			t.Error("the status is part of the template: a 404 must not match")
		}
		if matches(t, g, &matcher.Observation{Status: 200, Headers: map[string]string{"Server": "nginx"}}) {
			t.Error("the header is part of the template")
		}
		if matches(t, g, &matcher.Observation{Status: 200, Headers: map[string]string{"Server": "apache"}}) {
			t.Error("nuclei regexes are case-sensitive")
		}
	}

	// A word matcher with condition or: independent rules; part server and so on.
	singles, groups = byTech(res, "Cleo Technology")
	if len(singles) != 3 || len(groups) != 0 {
		t.Fatalf("Cleo: singles=%d groups=%d", len(singles), len(groups))
	}
	for _, r := range singles {
		if r.Observation != domain.ObsHTTPHeader || r.Target != "Server" || r.Operator != domain.OpContains {
			t.Errorf("Cleo rule: %+v", r)
		}
	}
	if !matches(t, singles[1:2], &matcher.Observation{Headers: map[string]string{"Server": "Cleo Harmony 5.8"}}) {
		t.Error("Cleo Harmony in Server must match")
	}

	// An active probe: a path other than the base URL.
	_, groups = byTech(res, "Accellion")
	if len(groups) != 2 {
		t.Fatalf("Accellion groups = %d", len(groups))
	}
	for _, g := range groups {
		for _, r := range g {
			if r.Observation != domain.ObsProbeResponse || r.Probe == nil || r.Probe.Path != "/cfadmin/" || r.Probe.Method != "GET" {
				t.Errorf("probe rule: %+v", r)
			}
		}
	}
	good := &matcher.Observation{Probes: map[string]matcher.ProbeResponse{"/cfadmin/": {Status: 200, Body: `<img src="/cfadmin/img/accellion-logo.png">`}}}
	bad := &matcher.Observation{Probes: map[string]matcher.ProbeResponse{"/cfadmin/": {Status: 404, Body: `<img src="/cfadmin/img/accellion-logo.png">`}}}
	if !anyGroup(t, groups, good) || anyGroup(t, groups, bad) {
		t.Error("the probe needs the logo and a 200")
	}
	if anyGroup(t, groups, &matcher.Observation{}) {
		t.Error("no recorded answer, no match")
	}

	// dsl contains_any(to_lower(body), ...) with status: alternatives, case-insensitive.
	_, groups = byTech(res, "AdmiralCloud")
	if len(groups) != 2 {
		t.Fatalf("AdmiralCloud groups = %d", len(groups))
	}
	if !anyGroup(t, groups, &matcher.Observation{Status: 200, HTML: `<TITLE>AdmiralCloud Login</title>`}) {
		t.Error("to_lower(body) makes the match case-insensitive")
	}
	if anyGroup(t, groups, &matcher.Observation{Status: 500, HTML: `<title>admiralcloud</title>`}) {
		t.Error("the status is required")
	}

	// A template that states product, vendor and CPE.
	for _, x := range res.Technologies {
		if x.Name == "Adobe ColdFusion" {
			if x.Key != "adobe|coldfusion" || len(x.CPE) != 1 || x.CPE[0] != "cpe:2.3:a:adobe:coldfusion:*:*:*:*:*:*:*:*" {
				t.Errorf("ColdFusion: %+v", x)
			}
		}
	}
}

func TestFaviconTable(t *testing.T) {
	res := extract(t)
	var proxmox, n int
	for _, f := range res.Fingerprints {
		if f.Observation != domain.ObsFaviconHash {
			continue
		}
		n++
		if f.Target != "mmh3" || f.Operator != domain.OpHashEquals || f.Probe != nil || f.GroupKey != "" {
			t.Errorf("favicon rule: %+v", f)
		}
		if f.TechnologyKey == "|proxmox" {
			proxmox++
			if !matches(t, []domain.Fingerprint{toRule(f)}, &matcher.Observation{FaviconHashes: map[string]string{"mmh3": f.Pattern}}) ||
				matches(t, []domain.Fingerprint{toRule(f)}, &matcher.Observation{FaviconHashes: map[string]string{"md5": f.Pattern}}) {
				t.Error("an mmh3 rule reads the mmh3 hash only")
			}
		}
	}
	if n != 12 || proxmox != 1 {
		t.Errorf("favicon rules = %d, proxmox = %d, want 12 and 1", n, proxmox)
	}
}

func TestCaseInsensitiveWordsAndRegexFlags(t *testing.T) {
	res := extract(t)
	_, groups := byTech(res, "ImpressCMS")
	if len(groups) != 1 {
		t.Fatalf("ImpressCMS groups = %d", len(groups))
	}
	// The template's own (?i) must win over the case-sensitive default.
	if !anyGroup(t, groups, &matcher.Observation{Status: 200, HTML: `<meta name="generator" content="impresscms">`}) {
		t.Error("the template's (?i) must be honoured")
	}
}

func TestSkippedTemplatesAreCounted(t *testing.T) {
	res := extract(t)
	skipped := skipMessages(res)
	for _, want := range []string{
		"raw request", "method POST", "payload list", "negative matcher", "the template uses a flow",
		"dsl outside the subset", "template skipped: generated from Wappalyzer data",
	} {
		if !strings.Contains(skipped, want) {
			t.Errorf("no skip count for %q:\n%s", want, skipped)
		}
	}
	// Nothing from a skipped template leaks into the result.
	for _, x := range res.Technologies {
		if strings.Contains(strings.ToLower(x.Name), "nginx") {
			t.Errorf("the nginx-eol template needs compare_versions and must be skipped: %+v", x)
		}
	}
	// The probed favicon hash and its template are dropped as a whole, not half-mapped.
	for _, x := range res.Technologies {
		if x.Name == "Maian Cart" {
			t.Errorf("a template whose only rule is not representable must not create a technology")
		}
	}
	if res.Metadata["templates_with_extractors"].(int) == 0 {
		t.Error("templates whose version extractors are not mapped must be counted")
	}
}

func TestClausesAreAllOrNothing(t *testing.T) {
	// A term that cannot be represented (a favicon hash on a probed path)
	// takes its whole clause with it: keeping the status alone would match
	// every site that serves a favicon.
	res := one(t, `id: x
info: {name: X Detect}
http:
  - method: GET
    path: ["{{BaseURL}}/favicon.ico"]
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: dsl
        dsl: ['"123" == mmh3(base64_py(body))']
`)
	if len(res.Fingerprints) != 0 || len(res.Technologies) != 0 {
		t.Fatalf("partial clause kept: %+v", res.Fingerprints)
	}
}

func TestFormulaExpansion(t *testing.T) {
	// (a or b) and (c or d) is four clauses of two terms each.
	res := one(t, `id: x
info: {name: X Detect}
http:
  - method: GET
    path: ["{{BaseURL}}"]
    matchers-condition: and
    matchers:
      - type: word
        words: [a, b]
      - type: word
        part: header
        words: [c, d]
`)
	if len(res.Fingerprints) != 8 {
		t.Fatalf("rules = %d, want 8", len(res.Fingerprints))
	}
	groups := map[string]int{}
	for _, f := range res.Fingerprints {
		groups[f.GroupKey]++
	}
	if len(groups) != 4 {
		t.Errorf("groups = %v", groups)
	}
	for k, n := range groups {
		if n != 2 || k == "" {
			t.Errorf("group %q has %d rules", k, n)
		}
	}

	// A word matcher with condition and is one clause of several terms.
	res = one(t, `id: x
info: {name: Y Detect}
http:
  - method: GET
    path: ["{{BaseURL}}"]
    matchers:
      - type: word
        condition: and
        words: [a, b, c]
      - type: status
        status: [200, 301]
`)
	if len(res.Fingerprints) != 5 { // one group of 3 words, and two status rules
		t.Errorf("rules = %d, want 5", len(res.Fingerprints))
	}

	// Too many combinations are skipped, not truncated.
	words := strings.Repeat("a, b, c, d, e", 1)
	res = one(t, `id: x
info: {name: Z Detect}
http:
  - method: GET
    path: ["{{BaseURL}}"]
    matchers-condition: and
    matchers:
      - {type: word, words: [`+words+`]}
      - {type: word, part: header, words: [`+words+`]}
      - {type: regex, regex: [r1, r2, r3, r4, r5]}
`)
	if len(res.Fingerprints) != 0 || !strings.Contains(skipMessages(res), "more than 32 combinations") {
		t.Errorf("rules=%d skips=%s", len(res.Fingerprints), skipMessages(res))
	}
}

func TestRequestShapes(t *testing.T) {
	cases := map[string]struct {
		block string
		want  string // the skip reason, or "" when the block is mapped
	}{
		"base":       {`method: GET, path: ["{{BaseURL}}"]`, ""},
		"root url":   {`method: GET, path: ["{{RootURL}}/"]`, ""},
		"head":       {`method: HEAD, path: ["{{BaseURL}}/x"]`, ""},
		"post":       {`method: POST, path: ["{{BaseURL}}/x"]`, "method POST"},
		"variable":   {`method: GET, path: ["{{BaseURL}}/{{p}}"]`, "path with a variable"},
		"other host": {`method: GET, path: ["http://example.com/x"]`, "path not relative to the base URL"},
		"headers":    {`method: GET, path: ["{{BaseURL}}"], headers: {X-A: b}`, "request headers or body"},
		"body":       {`method: GET, path: ["{{BaseURL}}"], body: x`, "request headers or body"},
		"payloads":   {`method: GET, path: ["{{BaseURL}}/{{x}}"], payloads: {x: [a]}`, "payload list"},
		"raw":        {`raw: ["GET / HTTP/1.1"]`, "raw request"},
		"no path":    {`method: GET`, "no path"},
	}
	for name, tc := range cases {
		res := one(t, "id: x\ninfo: {name: X Detect}\nhttp:\n  - {"+tc.block+", matchers: [{type: word, words: [w]}]}\n")
		if tc.want == "" {
			if len(res.Fingerprints) != 1 {
				t.Errorf("%s: rules = %d (%s)", name, len(res.Fingerprints), skipMessages(res))
			}
			continue
		}
		if len(res.Fingerprints) != 0 || !strings.Contains(skipMessages(res), tc.want) {
			t.Errorf("%s: want skip %q, got rules=%d skips=%q", name, tc.want, len(res.Fingerprints), skipMessages(res))
		}
	}
	// HEAD keeps its method; a probe is always pending review.
	res := one(t, "id: x\ninfo: {name: X Detect}\nhttp:\n  - {method: HEAD, path: ['{{BaseURL}}/x?a=1'], matchers: [{type: word, words: [w]}]}\n")
	f := res.Fingerprints[0]
	if f.Probe == nil || f.Probe.Method != "HEAD" || f.Probe.Path != "/x?a=1" || f.Probe.SafetyReview != "pending" {
		t.Errorf("probe: %+v", f.Probe)
	}
}

func TestTechnologyIdentity(t *testing.T) {
	tpl := func(id, name, meta string) string {
		return "id: " + id + "\ninfo:\n  name: " + name + "\n  metadata: {" + meta + "}\nhttp:\n  - {method: GET, path: ['{{BaseURL}}'], matchers: [{type: word, words: [" + id + "]}]}\n"
	}
	src := extractor.Source{ID: "n", FS: fstest.MapFS{
		"http/technologies/a.yaml": {Data: []byte(tpl("a", "Acme Server Detect", "vendor: acme, product: server"))},
		"http/technologies/b.yaml": {Data: []byte(tpl("b", "Acme Server Login Panel", "vendor: ACME, product: Server"))},
		"http/technologies/c.yaml": {Data: []byte(tpl("c", "Other Detection", ""))},
		"http/technologies/d.yaml": {Data: []byte(tpl("d", "Dashboard", "vendor: alpha, product: dashboard"))},
		"http/technologies/e.yaml": {Data: []byte(tpl("e", "Dashboard", "vendor: beta, product: dashboard"))},
	}}
	res, err := New().Extract(context.Background(), src)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, x := range res.Technologies {
		names = append(names, x.Name+"="+x.Key)
	}
	got := strings.Join(names, " ")
	// a and b are one technology (vendor and product, any case); c has no product so
	// its title is cleaned; d and e share a product name across vendors and get the vendor.
	for _, want := range []string{"Acme Server=acme|server", "Other=|other", "alpha Dashboard=alpha|dashboard", "beta Dashboard=beta|dashboard"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in %s", want, got)
		}
	}
	if len(res.Technologies) != 4 {
		t.Errorf("technologies = %d: %s", len(res.Technologies), got)
	}
	if res.Metadata["derived_names"] != 1 {
		t.Errorf("derived names = %v", res.Metadata["derived_names"])
	}
}

func TestCleanName(t *testing.T) {
	for in, want := range map[string]string{
		"Apache Detection": "Apache", "a-blog cms - Detect": "a-blog cms", "Detect Abyss Web Server": "Abyss Web Server",
		"Accellion - Detect": "Accellion", "ADFS Detect": "ADFS", "Cleo Technology Detect": "Cleo Technology",
		"BIG-IP Configuration Utility detected": "BIG-IP Configuration Utility", "AEM Finder": "AEM",
		"Kafka Manager Panel Detect": "Kafka Manager Panel", "Detect": "", "Plain Name": "Plain Name",
	} {
		if got := cleanName(in); got != want {
			t.Errorf("cleanName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestErrorsAndInvalidTemplates(t *testing.T) {
	ctx := context.Background()
	if _, err := New().Extract(ctx, extractor.Source{}); err == nil {
		t.Error("nil FS must fail")
	}
	if _, err := New().Extract(ctx, extractor.Source{FS: fstest.MapFS{}}); err == nil {
		t.Error("no templates must fail")
	}
	src := extractor.Source{FS: fstest.MapFS{
		"http/technologies/bad.yaml":  {Data: []byte("id: [")},
		"http/technologies/noid.yaml": {Data: []byte("info: {name: X}\n")},
		"http/technologies/a.yaml":    {Data: []byte("id: dup\ninfo: {name: A}\nhttp:\n  - {method: GET, path: ['{{BaseURL}}'], matchers: [{type: word, words: [a]}]}\n")},
		"http/technologies/z.yaml":    {Data: []byte("id: dup\ninfo: {name: B}\nhttp:\n  - {method: GET, path: ['{{BaseURL}}'], matchers: [{type: word, words: [b]}]}\n")},
	}}
	res, err := New().Extract(ctx, src)
	if err != nil {
		t.Fatal(err)
	}
	codes := map[string]int{}
	for _, w := range res.Warnings {
		codes[w.Code]++
	}
	if codes["invalid_template"] != 2 || codes["duplicate_template"] != 1 || len(res.Technologies) != 1 {
		t.Errorf("warnings: %v technologies: %d", codes, len(res.Technologies))
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := New().Extract(cctx, fixtureSource()); err == nil {
		t.Error("cancelled context must fail")
	}
}

func TestPCRELikePatternsAreFlagged(t *testing.T) {
	res := one(t, "id: x\ninfo: {name: X Detect}\nhttp:\n  - method: GET\n    path: ['{{BaseURL}}']\n    matchers:\n      - {type: regex, regex: ['(?<=a)b']}\n")
	if len(res.Fingerprints) != 1 || res.Fingerprints[0].RegexFlavor != domain.FlavorPCRE {
		t.Errorf("%+v", res.Fingerprints)
	}
}

// TestFullSnapshot runs against a full local clone when OWF_NUCLEI_SNAPSHOT
// points to it. It is skipped by default so unit tests stay hermetic.
func TestFullSnapshot(t *testing.T) {
	dir := os.Getenv("OWF_NUCLEI_SNAPSHOT")
	if dir == "" {
		t.Skip("OWF_NUCLEI_SNAPSHOT not set")
	}
	src := extractor.Source{ID: "projectdiscovery-nuclei-templates", FS: os.DirFS(dir)}
	res, err := New().Extract(context.Background(), src)
	if err != nil {
		t.Fatal(err)
	}
	by := map[domain.Observation]int{}
	groups := map[string]bool{}
	probes := 0
	for _, f := range res.Fingerprints {
		by[f.Observation]++
		if f.GroupKey != "" {
			groups[f.GroupKey] = true
		}
		if f.Probe != nil {
			probes++
		}
	}
	t.Logf("technologies=%d fingerprints=%d groups=%d probe rules=%d by observation=%v", len(res.Technologies), len(res.Fingerprints), len(groups), probes, by)
	t.Logf("metadata=%v", res.Metadata)
	t.Log(skipMessages(res))
	extractortest.RunContract(t, New(), src)
}

func versionRules(res *extractor.ExtractionResult) []extractor.ExtractedFingerprint {
	var out []extractor.ExtractedFingerprint
	for _, f := range res.Fingerprints {
		if f.Role == domain.RoleVersion {
			out = append(out, f)
		}
	}
	return out
}

func TestVersionExtractorsOfARealTemplate(t *testing.T) {
	res := extract(t)
	var v []extractor.ExtractedFingerprint
	for _, f := range versionRules(res) {
		if strings.HasPrefix(f.TechnologyKey, "4d|") {
			v = append(v, f)
		}
	}
	if len(v) != 1 {
		t.Fatalf("4D version rules: %+v", v)
	}
	f := v[0]
	if f.Observation != "response_headers" || f.Operator != domain.OpRegex || f.VersionExtract != `\1` ||
		f.GroupKey != "" || f.Probe != nil || f.Pattern != `(?-i)Server:\s+4D(?:_V[0-9]+)?/([0-9.]+)` {
		t.Errorf("rule: %+v", f)
	}
	o := &matcher.Observation{Headers: map[string]string{"Server": "4D_V20/20.4.1"}}
	ver, err := matcher.Version([]domain.Fingerprint{toRule(f)}, o)
	if err != nil || ver != "20.4.1" {
		t.Errorf("version = %q err=%v", ver, err)
	}
	// A version rule never detects: it is not part of a clause.
	if got, _ := matcher.Evaluate(toRule(f), &matcher.Observation{Headers: map[string]string{"Server": "nginx"}}); got.Matched {
		t.Error("must not match another server")
	}
	if res.Metadata["version_rules"].(int) == 0 || res.Metadata["templates_with_version"].(int) == 0 {
		t.Errorf("metadata: %v", res.Metadata)
	}
}

func TestVersionExtractorRules(t *testing.T) {
	tpl := func(path, extractors string) string {
		return "id: x\ninfo: {name: X Detect}\nhttp:\n  - method: GET\n    path: ['{{BaseURL}}" + path + "']\n    matchers:\n      - {type: word, words: [w]}\n    extractors:\n" + extractors
	}
	type want struct {
		n      int
		skip   string
		part   string
		target string
		group  string
	}
	cases := map[string]struct {
		ex string
		w  want
	}{
		"unnamed with digits": {"      - {type: regex, part: body, group: 1, regex: ['v([0-9.]+)']}\n", want{n: 1, part: "html", group: `\1`}},
		"named version":       {"      - {type: regex, name: version, part: header, group: 2, regex: ['(a)(b)']}\n", want{n: 1, part: "response_headers", group: `\2`}},
		"detected_version":    {"      - {type: regex, name: detected_version, internal: true, group: 1, regex: ['(.+)']}\n", want{n: 1, part: "html", group: `\1`}},
		"name has version":    {"      - {type: regex, name: version_by_js, group: 1, regex: ['x=(.+)']}\n", want{n: 1, part: "html", group: `\1`}},
		"two patterns":        {"      - {type: regex, name: version, group: 1, regex: ['a([0-9]+)', 'b([0-9]+)']}\n", want{n: 2, part: "html", group: `\1`}},
		"server part":         {"      - {type: regex, name: version, part: server, group: 1, regex: ['/([0-9.]+)']}\n", want{n: 1, part: "http_header", target: "Server", group: `\1`}},
		"other thing":         {"      - {type: regex, name: domain, group: 1, regex: ['d=([a-z0-9]+)']}\n", want{skip: "reads something else than a version"}},
		"unnamed, no number":  {"      - {type: regex, part: body, group: 1, regex: ['<title>([A-Za-z ]+)</title>']}\n", want{skip: "reads something else than a version"}},
		"no group":            {"      - {type: regex, name: version, regex: ['[0-9.]+']}\n", want{skip: "without a capture group"}},
		"group out of range":  {"      - {type: regex, name: version, group: 3, regex: ['([0-9.]+)']}\n", want{skip: "group does not exist"}},
		"kval":                {"      - {type: kval, kval: [Server]}\n", want{skip: "not a regex"}},
		"json":                {"      - {type: json, name: version, json: ['.version']}\n", want{skip: "not a regex"}},
		"status part":         {"      - {type: regex, name: version, part: status, group: 1, regex: ['([0-9]+)']}\n", want{skip: "unsupported part"}},
	}
	for name, tc := range cases {
		res := one(t, tpl("", tc.ex))
		v := versionRules(res)
		if tc.w.skip != "" {
			if len(v) != 0 || !strings.Contains(skipMessages(res), tc.w.skip) {
				t.Errorf("%s: rules=%d skips=%q", name, len(v), skipMessages(res))
			}
			continue
		}
		if len(v) != tc.w.n {
			t.Errorf("%s: version rules = %d, want %d (%s)", name, len(v), tc.w.n, skipMessages(res))
			continue
		}
		if v[0].Observation != domain.Observation(tc.w.part) || v[0].Target != tc.w.target || v[0].VersionExtract != tc.w.group {
			t.Errorf("%s: %+v", name, v[0])
		}
	}

	// On a probed path the version rule reads the recorded answer of that path.
	res := one(t, tpl("/about", "      - {type: regex, name: version, part: body, group: 1, regex: ['v([0-9.]+)']}\n"))
	v := versionRules(res)
	if len(v) != 1 || v[0].Observation != domain.ObsProbeResponse || v[0].Target != "body" ||
		v[0].Probe == nil || v[0].Probe.Path != "/about" || v[0].Probe.SafetyReview != "pending" {
		t.Errorf("probed version rule: %+v", v)
	}

	// No detection rule on a request, no version rule: a template whose matchers
	// cannot be represented gives nothing, not an orphan version.
	res = one(t, "id: x\ninfo: {name: X Detect}\nhttp:\n  - method: POST\n    path: ['{{BaseURL}}']\n    matchers: [{type: word, words: [w]}]\n    extractors:\n      - {type: regex, name: version, group: 1, regex: ['v([0-9.]+)']}\n")
	if len(res.Fingerprints) != 0 || len(res.Technologies) != 0 {
		t.Errorf("orphan version rule: %+v", res.Fingerprints)
	}
}
