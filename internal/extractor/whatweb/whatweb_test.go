// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package whatweb

import (
	"context"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/matteoredaelli/open-web-fingerprints/internal/domain"
	"github.com/matteoredaelli/open-web-fingerprints/internal/extractor"
	"github.com/matteoredaelli/open-web-fingerprints/internal/extractor/extractortest"
)

func fixtureSource() extractor.Source {
	return extractor.Source{
		ID: "urbanadventurer-whatweb", URL: "https://github.com/urbanadventurer/WhatWeb",
		Revision: "d279d93", License: "GPL-2.0-only", FS: os.DirFS("testdata/snapshot"),
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

func rulesOf(res *extractor.ExtractionResult, tech string) []extractor.ExtractedFingerprint {
	var out []extractor.ExtractedFingerprint
	for _, f := range res.Fingerprints {
		if f.TechnologyKey == tech {
			out = append(out, f)
		}
	}
	return out
}

func warned(res *extractor.ExtractionResult, code, ref string) bool {
	for _, w := range res.Warnings {
		if w.Code == code && (ref == "" || w.Ref == ref) {
			return true
		}
	}
	return false
}

func TestTechnologies(t *testing.T) {
	res := extract(t)
	names := map[string]bool{}
	for _, tech := range res.Technologies {
		names[tech.Name] = true
	}
	for _, want := range []string{"4images", "Apache", "ATutor", "CodeIgniter-PHP-Framework", "Dell-KACE-Appliance", "Magento", "1&1 Hosting"} {
		if !names[want] {
			t.Errorf("%s not extracted: %v", want, names)
		}
	}
	for _, not := range []string{"Content-Security-Policy", "Cookies", "Country"} {
		if names[not] {
			t.Errorf("%s reports a value, it is not a technology", not)
		}
	}
	if !warned(res, "header_plugin", "Content-Security-Policy") {
		t.Error("a plugin that only reports a header is counted")
	}
	if !warned(res, "code_only_plugin", "") {
		t.Error("plugins that are only code are counted")
	}
	if !warned(res, "code_not_imported", "Apache") {
		t.Error("a plugin that also has Ruby code says so")
	}
}

func TestTextRegexpAndVersion(t *testing.T) {
	res := extract(t)
	var version, text *extractor.ExtractedFingerprint
	for _, f := range rulesOf(res, "4images") {
		f := f
		if f.VersionExtract != "" {
			version = &f
		} else {
			text = &f
		}
	}
	if version == nil || version.VersionExtract != `\1` || version.Observation != domain.ObsHTML || version.Operator != domain.OpRegex {
		t.Fatalf("4images version rule: %+v", version)
	}
	if version.Role != "" {
		t.Error("a :version clause also detects: it is not a version-only rule")
	}
	// Ruby matches case-sensitively: the rule says so, the registry's default is not.
	if !strings.HasPrefix(version.Pattern, "(?m-i:") || text == nil {
		t.Errorf("pattern: %q", version.Pattern)
	}
	re := regexp.MustCompile(version.Pattern)
	m := re.FindStringSubmatch(`<p>Powered by <b>4images</b> 1.7.11</p>`)
	if len(m) != 2 || m[1] != "1.7.11" {
		t.Errorf("version: %v", m)
	}
	if re.MatchString(`powered by <b>4IMAGES</b> 1.0`) {
		t.Error("the clause is case-sensitive")
	}
}

func TestLiteralTextIsEscapedAndCaseSensitive(t *testing.T) {
	res := extract(t)
	var got string
	for _, f := range rulesOf(res, "Apache") {
		if strings.Contains(f.Pattern, "Test Page for Apache Installation") {
			got = f.Pattern
		}
	}
	if got == "" {
		t.Fatal("apache default title rule missing")
	}
	re := regexp.MustCompile(got)
	if !re.MatchString("<title>Test Page for Apache Installation</title>") || re.MatchString("<TITLE>test page for apache installation</TITLE>") {
		t.Errorf("literal text: %q", got)
	}
}

func TestHeadersAndCookies(t *testing.T) {
	res := extract(t)
	var server, any, cookie int
	for _, f := range rulesOf(res, "Apache") {
		if f.Observation == domain.ObsHTTPHeader && f.Target == "server" {
			server++
		}
	}
	for _, f := range rulesOf(res, "Dell-KACE-Appliance") {
		if f.Observation == domain.ObsHTTPHeader && f.Operator == domain.OpExists && f.Pattern == "" {
			any++
		}
	}
	for _, f := range rulesOf(res, "1&1 Hosting") {
		if f.Observation == "set_cookie" {
			cookie++
		}
	}
	if server == 0 {
		t.Error("headers[server] rules of Apache")
	}
	if any == 0 {
		t.Error("a rule that matches any header value is an exists rule")
	}
	if cookie == 0 {
		t.Error("headers[set-cookie] rules are set_cookie rules")
	}
}

func TestPercentRegexpAndOffset(t *testing.T) {
	res := extract(t)
	if rs := rulesOf(res, "ATutor"); len(rs) == 0 || !strings.Contains(rs[0].Pattern, "Copyright ([0-9]{4}) by http://atutor.ca") {
		t.Errorf("%%r{} literal: %+v", rs)
	}
	// :offset=>1 on Magento: the version is the second group.
	found := false
	for _, f := range rulesOf(res, "Magento") {
		if f.VersionExtract == `\2` {
			found = true
		}
	}
	if !found {
		t.Errorf("Magento's :offset=>1 maps to the second group: %+v", rulesOf(res, "Magento"))
	}
}

func TestProbesArePendingDrafts(t *testing.T) {
	res := extract(t)
	n := 0
	for _, f := range res.Fingerprints {
		if f.Probe == nil {
			continue
		}
		n++
		if f.Observation != domain.ObsProbeResponse || f.Probe.Method != "GET" || f.Probe.SafetyReview != "pending" || !strings.HasPrefix(f.Probe.Path, "/") {
			t.Errorf("probe of %s: %+v", f.TechnologyKey, f.Probe)
		}
	}
	if n == 0 {
		t.Error("the fixtures contain probes (:url)")
	}
}

func TestClausesThatAreNotDataAreSkippedWhole(t *testing.T) {
	res := extract(t)
	if !warned(res, "unparsable_clause", "CodeIgniter-PHP-Framework") || !warned(res, "unparsable_clause", "Pro-Chat-Rooms") {
		t.Error("an expression or an interpolation loses its clause, with a warning")
	}
	for _, f := range res.Fingerprints {
		if strings.Contains(f.Pattern, "randstr") || strings.Contains(f.Pattern, "rand(") {
			t.Errorf("code leaked into a pattern: %q", f.Pattern)
		}
	}
	skipped := map[string]bool{}
	for _, w := range res.Warnings {
		if w.Code == "unsupported_clause" {
			skipped[w.Ref] = true
		}
	}
	if !skipped["md5 of a file"] {
		t.Errorf("md5 clauses are counted, not mapped: %v", skipped)
	}
}

func TestEveryPatternCompiles(t *testing.T) {
	for _, f := range extract(t).Fingerprints {
		if f.Operator == domain.OpRegex && f.RegexFlavor == domain.FlavorRE2 {
			if _, err := regexp.Compile("(?i)" + f.Pattern); err != nil {
				t.Errorf("%s: %q: %v", f.TechnologyKey, f.Pattern, err)
			}
		}
	}
}

func TestIsPluginFile(t *testing.T) {
	for p, want := range map[string]bool{"plugins/wordpress.rb": true, "plugins/a/b.rb": false, "plugins-disabled/x.rb": false, "plugins/x.txt": false, "lib/x.rb": false} {
		if IsPluginFile(p) != want {
			t.Errorf("%s: %v", p, !want)
		}
	}
}

func TestRubyReader(t *testing.T) {
	src := "name \"X\"\nmatches [\n# comment, } ]\n{:text=>'a\\'b', :regexp=>/x\\/y[/]z/i, :certainty=>75},\n{ :string=>%r{a{2}b} },\n{:text=>\"#{bad}\"},\n{:text=>\"ok\"},\n]\n"
	h, bad, found, err := readMatches(src)
	if err != nil || !found {
		t.Fatalf("%v %v", found, err)
	}
	if len(h) != 3 || len(bad) != 1 {
		t.Fatalf("hashes=%v bad=%v", h, bad)
	}
	if h[0]["text"] != "a'b" || h[0]["regexp"].(rubyRegexp).Flags != "i" || h[0]["certainty"] != float64(75) {
		t.Errorf("first: %#v", h[0])
	}
	if h[1]["string"].(rubyRegexp).Source != "a{2}b" || h[2]["text"] != "ok" {
		t.Errorf("others: %#v %#v", h[1], h[2])
	}
	if _, _, _, err := readMatches("matches [\n{:text=>'unterminated}\n]"); err == nil {
		t.Error("an unterminated string ends the plugin")
	}
	if _, _, found, _ := readMatches("name \"X\"\n"); found {
		t.Error("no matches list")
	}
}

func TestTranslate(t *testing.T) {
	got, ok := translate(rubyRegexp{Source: `a\hb^c\Z`, Flags: "im"})
	if !ok || got != `(?ms:a[0-9a-fA-F]b^c\z)` {
		t.Errorf("%q %v", got, ok)
	}
	if _, ok := translate(rubyRegexp{Source: `a(?#c)`}); ok {
		t.Error("comments are not translated")
	}
	if groupCount(`(a)(?:b)(?<n>c)\(d\)[(]`) != 2 {
		t.Errorf("groups: %d", groupCount(`(a)(?:b)(?<n>c)\(d\)[(]`))
	}
}
