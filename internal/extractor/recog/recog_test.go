// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package recog

import (
	"context"
	"encoding/json"
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
		ID: "rapid7-recog", URL: "https://github.com/rapid7/recog",
		Revision: "f1191e2", License: "BSD-2-Clause", FS: os.DirFS("testdata/snapshot"),
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

func tech(res *extractor.ExtractionResult, name string) (extractor.ExtractedTechnology, bool) {
	for _, x := range res.Technologies {
		if x.Name == name {
			return x, true
		}
	}
	return extractor.ExtractedTechnology{}, false
}

// rules returns the fingerprints of the technology with the given name.
func rules(res *extractor.ExtractionResult, name string) []extractor.ExtractedFingerprint {
	t, ok := tech(res, name)
	if !ok {
		return nil
	}
	var out []extractor.ExtractedFingerprint
	for _, f := range res.Fingerprints {
		if f.TechnologyKey == t.Key {
			out = append(out, f)
		}
	}
	return out
}

func warningsOf(res *extractor.ExtractionResult, code string) []string {
	var out []string
	for _, w := range res.Warnings {
		if w.Code == code {
			out = append(out, w.Ref+": "+w.Message)
		}
	}
	return out
}

func TestMapping(t *testing.T) {
	res := extract(t)

	// A literal product with vendor, a capture-group version and the database
	// preference as confidence. Recog is case-sensitive unless flagged.
	sq := rules(res, "Squeezebox")
	if len(sq) != 1 {
		t.Fatalf("Squeezebox rules: %+v", sq)
	}
	f := sq[0]
	if f.Observation != domain.ObsHTTPHeader || f.Target != "Server" || f.Operator != domain.OpRegex ||
		f.Pattern != `(?-i)^Logitech Media Server \(([0-9.]+) - [0-9]+\)$` || f.VersionExtract != `\1` ||
		f.RegexFlavor != domain.FlavorRE2 || f.File != "xml/http_servers.xml" {
		t.Errorf("Squeezebox rule: %+v", f)
	}
	if f.Confidence == nil || *f.Confidence != 0.90 {
		t.Errorf("confidence = %v, want the database preference 0.90", f.Confidence)
	}

	// A literal version parameter becomes a literal version_extract.
	var literal bool
	for _, r := range rules(res, "IIS") {
		if r.VersionExtract == "5.0" {
			literal = true
		}
	}
	if !literal {
		t.Errorf("IIS 5.0 must keep its literal version: %+v", rules(res, "IIS"))
	}

	// Cookies match the raw Set-Cookie line; the favicon is an MD5; the title is its own thing.
	if r := rules(res, "CloudFlare Load Balancer"); len(r) != 1 || r[0].Observation != "set_cookie" || r[0].Target != "" {
		t.Errorf("cookie rule: %+v", r)
	}
	var fav, title int
	for _, r := range res.Fingerprints {
		switch r.Observation {
		case domain.ObsFaviconHash:
			fav++
			if r.Target != "md5" {
				t.Errorf("favicon target = %q", r.Target)
			}
		case "page_title":
			title++
		}
	}
	if fav != 2 || title == 0 {
		t.Errorf("favicon=%d title=%d", fav, title)
	}

	// Header names for the generic http_header.<name> database.
	r := rules(res, "FortiSandbox")
	if len(r) != 1 || r[0].Target != "X-FortiSandbox-Version" || r[0].VersionExtract != `\1` {
		t.Errorf("FortiSandbox: %+v", r)
	}
	if r := rules(res, "Transmission"); len(r) != 2 { // Server header and WWW-Authenticate
		t.Errorf("Transmission has %d rules, want one per database: %+v", len(r), r)
	}
}

func TestTechnologiesAndCPE(t *testing.T) {
	res := extract(t)
	seen := map[string]bool{}
	for _, x := range res.Technologies {
		if seen[x.Key] || x.Key != strings.ToLower(x.Key) || !strings.Contains(x.Key, "|") {
			t.Errorf("technology keys must be unique, lower case vendor|product: %+v", x)
		}
		seen[x.Key] = true
	}
	// The CPE keeps only what is literal: part, vendor and product.
	ngx, ok := tech(res, "nginx")
	if !ok || len(ngx.CPE) != 1 || ngx.CPE[0] != "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*" {
		t.Errorf("nginx: %+v", ngx)
	}
	iis, _ := tech(res, "IIS")
	if len(iis.CPE) != 1 || iis.CPE[0] != "cpe:2.3:a:microsoft:iis:*:*:*:*:*:*:*:*" {
		t.Errorf("IIS must have one CPE (the version is not part of it): %v", iis.CPE)
	}
	for _, x := range res.Technologies {
		for _, c := range x.CPE {
			if v, ok := domain.CPEVendor(c); !ok || v == "" {
				t.Errorf("%s: %q does not give a vendor", x.Name, c)
			}
		}
	}
	// One product, several fingerprints: a single technology.
	n := 0
	for _, x := range res.Technologies {
		if x.Name == "IIS" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("IIS technologies = %d", n)
	}
}

func TestSkippedFingerprintsAreCountedNotLost(t *testing.T) {
	res := extract(t)
	skipped := strings.Join(warningsOf(res, "skipped_fingerprints"), "\n")
	for _, want := range []string{
		"it identifies no service (operating system or hardware only)",
		"the product is taken from a capture group",
	} {
		if !strings.Contains(skipped, want) {
			t.Errorf("no warning about %q:\n%s", want, skipped)
		}
	}
	// Skipped entries contribute no technology.
	for _, x := range res.Technologies {
		if strings.Contains(strings.ToLower(x.Name), "windows") {
			t.Errorf("an operating-system entry became a technology: %+v", x)
		}
	}
}

func TestRawKeepsExamplesAndParams(t *testing.T) {
	res := extract(t)
	f := rules(res, "Squeezebox")[0]
	var raw struct {
		Matches  string
		Pattern  string
		Index    int
		Examples []struct {
			Text    string
			Version string
			Attrs   map[string]string
		}
		Params []struct {
			Pos   int
			Name  string
			Value *string
		}
	}
	if err := json.Unmarshal(f.Raw, &raw); err != nil {
		t.Fatal(err)
	}
	if raw.Matches != "http_header.server" || len(raw.Examples) != 1 || raw.Examples[0].Attrs["service.version"] != "7.9.3" ||
		raw.Examples[0].Version != "7.9.3" {
		t.Errorf("raw: %s", f.Raw)
	}
	// Recog tries fingerprints in file order, and validation needs that order.
	var last = -1
	for _, r := range res.Fingerprints {
		if r.File != "xml/http_servers.xml" {
			continue
		}
		var x struct{ Index int }
		if err := json.Unmarshal(r.Raw, &x); err != nil {
			t.Fatal(err)
		}
		if x.Index <= last {
			t.Errorf("index must grow with the position in the file: %d after %d", x.Index, last)
		}
		last = x.Index
	}
	var captured bool
	for _, p := range raw.Params {
		if p.Name == "service.version" && p.Pos == 1 && p.Value == nil {
			captured = true
		}
	}
	if !captured {
		t.Errorf("params lost: %s", f.Raw)
	}
}

// observationFor builds the observation an example string stands for.
func observationFor(f extractor.ExtractedFingerprint, text string) *matcher.Observation {
	switch f.Observation {
	case domain.ObsHTTPHeader:
		return &matcher.Observation{Headers: map[string]string{f.Target: text}}
	case "set_cookie":
		return &matcher.Observation{SetCookies: []string{text}}
	case "page_title":
		return &matcher.Observation{Title: text}
	case domain.ObsFaviconHash:
		return &matcher.Observation{FaviconHashes: map[string]string{f.Target: text}}
	}
	return &matcher.Observation{}
}

type example struct {
	Text  string            `json:"text"`
	Attrs map[string]string `json:"attrs"`
}

func examplesOf(t *testing.T, f extractor.ExtractedFingerprint) []example {
	t.Helper()
	var raw struct{ Examples []example }
	if err := json.Unmarshal(f.Raw, &raw); err != nil {
		t.Fatal(err)
	}
	return raw.Examples
}

// conformance runs every upstream example against its own rule with the
// registry's matcher. Upstream's examples are its own tests, so this checks
// that the mapping (case rules, version extraction) keeps Recog's meaning.
func conformance(t *testing.T, res *extractor.ExtractionResult) (ran, skipped int, failures []string) {
	t.Helper()
	for _, f := range res.Fingerprints {
		rule := domain.Fingerprint{
			Observation: f.Observation, Target: f.Target, Operator: f.Operator, Pattern: f.Pattern,
			RegexFlavor: f.RegexFlavor, VersionExtract: f.VersionExtract,
		}
		for _, ex := range examplesOf(t, f) {
			if f.RegexFlavor != domain.FlavorRE2 {
				skipped++
				continue
			}
			ran++
			got, err := matcher.Evaluate(rule, observationFor(f, ex.Text))
			if err != nil {
				failures = append(failures, f.TechnologyKey+": "+err.Error())
				continue
			}
			want := ex.Attrs["service.version"]
			switch {
			case !got.Matched:
				failures = append(failures, f.TechnologyKey+": example "+ex.Text+" does not match "+f.Pattern)
			case want != "" && f.VersionExtract != "" && got.Version != want:
				failures = append(failures, f.TechnologyKey+": example "+ex.Text+": version "+got.Version+", want "+want)
			}
		}
	}
	return ran, skipped, failures
}

func TestUpstreamExamplesPassWithOurMatcher(t *testing.T) {
	ran, _, failures := conformance(t, extract(t))
	if ran < 20 {
		t.Fatalf("only %d examples ran", ran)
	}
	for _, f := range failures {
		t.Error(f)
	}
}

func TestCaseSensitivityIsKept(t *testing.T) {
	res := extract(t)
	var f extractor.ExtractedFingerprint
	for _, r := range rules(res, "Transmission") {
		if r.Target == "Server" {
			f = r
		}
	}
	rule := domain.Fingerprint{Observation: f.Observation, Target: f.Target, Operator: f.Operator, Pattern: f.Pattern, RegexFlavor: f.RegexFlavor}
	for in, want := range map[string]bool{"Transmission": true, "transmission": false, "TRANSMISSION": false} {
		got, err := matcher.Evaluate(rule, &matcher.Observation{Headers: map[string]string{"Server": in}})
		if err != nil || got.Matched != want {
			t.Errorf("%q: matched=%v err=%v, want %v (Recog patterns are case-sensitive)", in, got.Matched, err, want)
		}
	}
}

func TestFlagPrefix(t *testing.T) {
	for in, want := range map[string]string{
		"": "(?-i)", "REG_ICASE": "", "REG_DOT_NEWLINE": "(?-i)(?s)", "REG_LINE_ANCHORS": "(?-i)(?m)",
		"REG_ICASE, REG_DOT_NEWLINE": "(?s)", "REG_ICASE|REG_LINE_ANCHORS": "(?m)",
	} {
		got, err := flagPrefix(in)
		if err != nil || got != want {
			t.Errorf("flagPrefix(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := flagPrefix("REG_WEIRD"); err == nil {
		t.Error("an unknown flag must be refused, not guessed")
	}
}

func TestCPEConversion(t *testing.T) {
	p := func(v string) []paramXML { return []paramXML{{Pos: 0, Name: "service.cpe23", Value: &v}} }
	for in, want := range map[string]string{
		"cpe:/a:f5:nginx:-":                           "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*",
		"cpe:/a:apache:http_server:{service.version}": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
		"cpe:2.3:a:Microsoft:IIS:5.0:*:*:*:*:*:*:*":   "cpe:2.3:a:microsoft:iis:*:*:*:*:*:*:*:*",
		"cpe:/o:microsoft:windows_nt:4.0":             "cpe:2.3:o:microsoft:windows_nt:*:*:*:*:*:*:*:*",
		"cpe:/a:{service.vendor}:x:-":                 "",
		"cpe:/a:vendor:{service.product}":             "",
		"cpe:/x:vendor:product":                       "",
		"cpe:/a:vendor":                               "",
		"not a cpe":                                   "",
	} {
		got, ok := cpeOf(p(in))
		if got != want || ok != (want != "") {
			t.Errorf("cpeOf(%q) = %q,%v; want %q", in, got, ok, want)
		}
	}
	if _, ok := cpeOf(nil); ok {
		t.Error("no param, no CPE")
	}
}

func TestErrors(t *testing.T) {
	ctx := context.Background()
	if _, err := New().Extract(ctx, extractor.Source{}); err == nil {
		t.Error("nil FS must fail")
	}
	if _, err := New().Extract(ctx, extractor.Source{FS: fstest.MapFS{}}); err == nil {
		t.Error("an empty snapshot must fail")
	}
	renamed := fstest.MapFS{"xml/http_servers.xml": {Data: []byte(`<fingerprints matches="ssh.banner"></fingerprints>`)}}
	if _, err := New().Extract(ctx, extractor.Source{FS: renamed}); err == nil || !strings.Contains(err.Error(), "upstream changed") {
		t.Errorf("a repurposed database must be noticed: %v", err)
	}
	broken := fstest.MapFS{"xml/http_servers.xml": {Data: []byte(`<fingerprints`)}}
	if _, err := New().Extract(ctx, extractor.Source{FS: broken}); err == nil {
		t.Error("invalid XML must fail")
	}
	// A missing database is a warning as long as another one is read.
	one := fstest.MapFS{"xml/http_xpoweredby.xml": {Data: []byte(`<fingerprints matches="http_header.x-powered-by" preference="0.90">
	  <fingerprint pattern="^PHP/([0-9.]+)$"><param pos="0" name="service.product" value="PHP"/><param pos="1" name="service.version"/></fingerprint>
	</fingerprints>`)}}
	res, err := New().Extract(ctx, extractor.Source{FS: one})
	if err != nil || len(res.Technologies) != 1 || len(warningsOf(res, "missing_file")) != 6 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	unknown := fstest.MapFS{"xml/http_servers.xml": {Data: []byte(`<fingerprints matches="http_header.server">
	  <fingerprint pattern="x" flags="REG_WEIRD"><param pos="0" name="service.product" value="X"/></fingerprint>
	  <fingerprint pattern="y"><param pos="0" name="service.product" value="Y"/></fingerprint>
	</fingerprints>`)}}
	res, err = New().Extract(ctx, extractor.Source{FS: unknown})
	if err != nil || len(res.Technologies) != 1 || len(warningsOf(res, "unknown_flag")) != 1 {
		t.Errorf("unknown flag: %+v err=%v", res, err)
	}
}

func TestPCREPatternsAreFlagged(t *testing.T) {
	src := fstest.MapFS{"xml/http_servers.xml": {Data: []byte(`<fingerprints matches="http_header.server" preference="0.90">
	  <fingerprint pattern="^(?&lt;=x)abc"><param pos="0" name="service.product" value="Lookbehind"/></fingerprint>
	  <fingerprint pattern="^plain$"><param pos="0" name="service.product" value="Plain"/></fingerprint>
	</fingerprints>`)}}
	res, err := New().Extract(context.Background(), extractor.Source{FS: src})
	if err != nil {
		t.Fatal(err)
	}
	if rules(res, "Lookbehind")[0].RegexFlavor != domain.FlavorPCRE || rules(res, "Plain")[0].RegexFlavor != domain.FlavorRE2 {
		t.Errorf("flavors: %+v", res.Fingerprints)
	}
	if len(warningsOf(res, "unsupported_regex")) != 1 {
		t.Errorf("warnings: %+v", res.Warnings)
	}
}

// TestFullSnapshot runs against a full local clone when OWF_RECOG_SNAPSHOT
// points to it. It is skipped by default so unit tests stay hermetic.
func TestFullSnapshot(t *testing.T) {
	dir := os.Getenv("OWF_RECOG_SNAPSHOT")
	if dir == "" {
		t.Skip("OWF_RECOG_SNAPSHOT not set")
	}
	src := extractor.Source{ID: "rapid7-recog", FS: os.DirFS(dir)}
	res, err := New().Extract(context.Background(), src)
	if err != nil {
		t.Fatal(err)
	}
	by := map[domain.Observation]int{}
	for _, f := range res.Fingerprints {
		by[f.Observation]++
	}
	t.Logf("technologies=%d fingerprints=%d by observation=%v", len(res.Technologies), len(res.Fingerprints), by)
	for _, w := range res.Warnings {
		if w.Code == "skipped_fingerprints" || w.Code == "vendor_mismatch" {
			t.Logf("%s %s: %s", w.Code, w.Ref, w.Message)
		}
	}
	ran, skipped, failures := conformance(t, res)
	t.Logf("upstream examples: %d ran, %d skipped (non-RE2 pattern), %d failed", ran, skipped, len(failures))
	for i, f := range failures {
		if i < 15 {
			t.Logf("  %s", f)
		}
	}
	extractortest.RunContract(t, New(), src)
}

func TestCertaintyOverridesPreferenceAndZeroIsSkipped(t *testing.T) {
	src := fstest.MapFS{"xml/http_servers.xml": {Data: []byte(`<fingerprints matches="http_header.server" preference="0.90">
	  <fingerprint pattern="^a$"><param pos="0" name="service.product" value="A"/><param pos="0" name="service.certainty" value="0.5"/></fingerprint>
	  <fingerprint pattern="^b$"><param pos="0" name="service.product" value="B"/><param pos="0" name="service.certainty" value="0.0"/></fingerprint>
	  <fingerprint pattern="^c$"><param pos="0" name="service.product" value="C"/></fingerprint>
	</fingerprints>`)}}
	res, err := New().Extract(context.Background(), extractor.Source{FS: src})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Technologies) != 2 {
		t.Fatalf("technologies: %+v", res.Technologies)
	}
	if c := rules(res, "A")[0].Confidence; c == nil || *c != 0.5 {
		t.Errorf("certainty must override the preference: %v", c)
	}
	if c := rules(res, "C")[0].Confidence; c == nil || *c != 0.9 {
		t.Errorf("preference is the default: %v", c)
	}
	if w := warningsOf(res, "skipped_fingerprints"); len(w) != 1 || !strings.Contains(w[0], "certainty 0") {
		t.Errorf("warnings: %v", w)
	}
}

func TestProductNamesSharedByVendorsAreQualified(t *testing.T) {
	src := fstest.MapFS{"xml/http_servers.xml": {Data: []byte(`<fingerprints matches="http_header.server" preference="0.90">
	  <fingerprint pattern="^k8s$"><param pos="0" name="service.vendor" value="Kubernetes"/><param pos="0" name="service.product" value="Dashboard"/></fingerprint>
	  <fingerprint pattern="^ceph$"><param pos="0" name="service.vendor" value="Ceph"/><param pos="0" name="service.product" value="Dashboard"/></fingerprint>
	  <fingerprint pattern="^ceph2$"><param pos="0" name="service.vendor" value="ceph"/><param pos="0" name="service.product" value="dashboard"/></fingerprint>
	  <fingerprint pattern="^nginx$"><param pos="0" name="service.vendor" value="F5"/><param pos="0" name="service.product" value="nginx"/></fingerprint>
	  <fingerprint pattern="^f5$"><param pos="0" name="service.vendor" value="F5"/><param pos="0" name="service.product" value="F5 BIG-IP"/></fingerprint>
	  <fingerprint pattern="^other$"><param pos="0" name="service.vendor" value="Other Inc"/><param pos="0" name="service.product" value="F5 BIG-IP"/></fingerprint>
	</fingerprints>`)}}
	res, err := New().Extract(context.Background(), extractor.Source{FS: src})
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, x := range res.Technologies {
		names = append(names, x.Name)
	}
	// Same vendor in another spelling is one technology; a name that already
	// contains the vendor is left alone; a unique name is left alone.
	want := "Kubernetes Dashboard,Ceph Dashboard,nginx,F5 BIG-IP,Other Inc F5 BIG-IP"
	if got := strings.Join(names, ","); got != want {
		t.Errorf("names = %s\nwant    %s", got, want)
	}
	if n := res.Metadata["qualified_names"]; n != 3 {
		t.Errorf("qualified_names = %v", n)
	}
	if len(rules(res, "Ceph Dashboard")) != 2 {
		t.Errorf("both spellings are the same technology: %+v", rules(res, "Ceph Dashboard"))
	}
}
