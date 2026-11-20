// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package engine

import (
	"fmt"
	"strings"
	"testing"

	"github.com/matteoredaelli/open-web-fingerprints/internal/domain"
	"github.com/matteoredaelli/open-web-fingerprints/internal/matcher"
	"github.com/matteoredaelli/open-web-fingerprints/scan"
)

func prov(src string) []domain.Provenance {
	return []domain.Provenance{{SourceID: domain.SourceID(src), State: "present"}}
}

func rule(id, tech string, obs domain.Observation, target string, op domain.Operator, pattern string) domain.Fingerprint {
	f := domain.Fingerprint{
		ID: domain.FingerprintID(id), TechnologyID: domain.TechnologyID(tech), Observation: obs, Target: target,
		Operator: op, Pattern: pattern, Confidence: 0.5, Status: domain.StatusActive, Provenance: prov("src_a"),
	}
	if op == domain.OpRegex {
		f.RegexFlavor = domain.FlavorRE2
	}
	return f
}

func health(f domain.Fingerprint, h string) domain.Fingerprint {
	f.Validation = &domain.Validation{Health: h}
	return f
}

func reg(techs []domain.Technology, rules ...domain.Fingerprint) *domain.Registry {
	return &domain.Registry{
		Sources:      []domain.Source{{ID: "src_a", Slug: "alpha"}, {ID: "src_b", Slug: "beta"}},
		Vendors:      []domain.Vendor{{ID: "vnd_1", Name: "Acme Inc"}},
		Categories:   []domain.Category{{ID: "cat_1", Name: "Web servers"}, {ID: "cat_2", Name: "CMS"}},
		Technologies: techs, Fingerprints: rules,
	}
}

func tech(id, name string) domain.Technology {
	return domain.Technology{ID: domain.TechnologyID(id), Slug: strings.ToLower(name), Name: name, Status: domain.StatusActive,
		VendorID: "vnd_1", CategoryIDs: []domain.CategoryID{"cat_2", "cat_1"}, Provenance: prov("src_a")}
}

func input() Input {
	return Input{
		Page: "https://www.example.org/", DNSLooked: true, HasTLS: true, FaviconTried: true,
		Observation: &matcher.Observation{
			URL: "https://www.example.org/", Status: 200,
			Headers:       map[string]string{"server": "nginx/1.25.3", "x-powered-by": "PHP/8.2.1"},
			Cookies:       map[string]string{"PHPSESSID": "abc"},
			HTML:          `<html><head><title>Acme</title></head><body><div class="wp-block">hi</div> /4DACTION/ </body></html>`,
			DNS:           map[string][]string{"NS": {"ns1.cloudflare.com."}},
			TLS:           map[string]string{"issuer": "CN=R3,O=Let's Encrypt"},
			FaviconHashes: map[string]string{"mmh3": "123", "md5": "abc"},
		},
	}
}

func byName(o Output, name string) *scan.Technology {
	for i := range o.Technologies {
		if o.Technologies[i].Name == name {
			return &o.Technologies[i]
		}
	}
	return nil
}

func TestDetectionVersionAndEvidence(t *testing.T) {
	nginxRule := rule("fp_1", "tech_1", domain.ObsHTTPHeader, "Server", domain.OpRegex, `(?-i)^nginx/([\d.]+)`)
	nginxRule.VersionExtract, nginxRule.Confidence = `\1`, 0.9
	nginxRule = health(nginxRule, "ok")
	e := New(reg([]domain.Technology{tech("tech_1", "nginx"), tech("tech_2", "Apache")},
		nginxRule,
		rule("fp_2", "tech_1", domain.ObsHTML, "", domain.OpContains, "no such text"),
		rule("fp_3", "tech_2", domain.ObsHTTPHeader, "Server", domain.OpRegex, `^apache`)))
	o := e.Run(input(), Options{})
	if len(o.Technologies) != 1 {
		t.Fatalf("technologies: %+v", o.Technologies)
	}
	n := o.Technologies[0]
	if n.Name != "nginx" || n.Version != "1.25.3" || n.Vendor != "Acme Inc" || n.Confidence != 0.9 ||
		strings.Join(n.Categories, ",") != "CMS,Web servers" || strings.Join(n.Sources, ",") != "alpha" {
		t.Errorf("technology: %+v", n)
	}
	if len(n.Evidence) != 1 {
		t.Fatalf("evidence: %+v", n.Evidence)
	}
	ev := n.Evidence[0]
	if ev.RuleID != "fp_1" || ev.Observation != "http_header" || ev.Target != "Server" || ev.Matched != "nginx/1.25.3" ||
		ev.Version != "1.25.3" || ev.Health != "ok" || ev.Source != "alpha" || ev.Page != "https://www.example.org/" {
		t.Errorf("evidence: %+v", ev)
	}
	if o.Coverage.RulesTotal != 3 || o.Coverage.RulesEvaluated != 3 || o.Coverage.RulesUnsupported != 0 || o.Coverage.Skipped != nil {
		t.Errorf("coverage: %+v", o.Coverage)
	}
}

func TestGroupsNeedEveryMember(t *testing.T) {
	g := func(id, obs string, o domain.Observation, op domain.Operator, p string) domain.Fingerprint {
		f := rule(id, "tech_1", o, "", op, p)
		f.GroupID = domain.GroupID(obs)
		return f
	}
	e := New(reg([]domain.Technology{tech("tech_1", "4D")},
		g("fp_a1", "fpg_1", domain.ObsHTML, domain.OpContains, "/4DACTION/"),
		g("fp_a2", "fpg_1", "http_status", domain.OpEquals, "200"),
		g("fp_b1", "fpg_2", domain.ObsHTML, domain.OpContains, "/4DSTATS"), // absent
		g("fp_b2", "fpg_2", "http_status", domain.OpEquals, "200")))
	o := e.Run(input(), Options{})
	n := byName(o, "4D")
	if n == nil || len(n.Evidence) != 2 {
		t.Fatalf("the complete group must match and only it: %+v", o.Technologies)
	}
	for _, ev := range n.Evidence {
		if ev.Group != "fpg_1" {
			t.Errorf("evidence: %+v", ev)
		}
	}
	if o.Coverage.RulesEvaluated != 4 || o.Coverage.RulesUnsupported != 0 {
		t.Errorf("every member counts as evaluated: %+v", o.Coverage)
	}
}

func TestVersionRulesNeedADetection(t *testing.T) {
	ver := rule("fp_v", "tech_1", "response_headers", "", domain.OpRegex, `(?-i)x-powered-by: PHP/([\d.]+)`)
	ver.Role, ver.VersionExtract = domain.RoleVersion, `\1`
	ver2 := rule("fp_v2", "tech_2", "response_headers", "", domain.OpRegex, `(?-i)x-powered-by: PHP/([\d.]+)`)
	ver2.Role, ver2.VersionExtract = domain.RoleVersion, `\1`
	e := New(reg([]domain.Technology{tech("tech_1", "PHP"), tech("tech_2", "Ghost")},
		rule("fp_c", "tech_1", domain.ObsCookie, "PHPSESSID", domain.OpExists, ""), ver,
		ver2))
	o := e.Run(input(), Options{})
	if len(o.Technologies) != 1 || o.Technologies[0].Name != "PHP" || o.Technologies[0].Version != "8.2.1" {
		t.Fatalf("%+v", o.Technologies)
	}
	// Ghost has only a version rule: no detection, so no technology and no skip.
	if o.Coverage.RulesTotal != 3 || o.Coverage.RulesEvaluated != 2 || o.Coverage.RulesUnsupported != 0 {
		t.Errorf("a version rule of an undetected technology is not counted: %+v", o.Coverage)
	}
	if len(o.Technologies[0].Evidence) != 2 {
		t.Errorf("the version rule is evidence too: %+v", o.Technologies[0].Evidence)
	}
}

func TestRulesThatCannotBeEvaluatedAreCountedWithAReason(t *testing.T) {
	probe := rule("fp_probe", "tech_1", domain.ObsProbeResponse, "status", domain.OpExists, "")
	probe.Probe = &domain.Probe{Method: "GET", Path: "/x", SafetyReview: "approved"}
	pcre := rule("fp_pcre", "tech_1", domain.ObsHTML, "", domain.OpRegex, `(?<=a)b`)
	pcre.RegexFlavor = domain.FlavorPCRE
	dep := rule("fp_dep", "tech_1", domain.ObsHTML, "", domain.OpContains, "Acme")
	dep.Status = domain.StatusDeprecated
	prop := rule("fp_prop", "tech_1", domain.ObsDOM, "div::prop(foo)", domain.OpExists, "")
	bad := rule("fp_bad", "tech_1", domain.ObsHTML, "", domain.OpRegex, "(")
	inert := rule("fp_inert", "tech_1", domain.ObsCookie, `connect\.sid`, domain.OpExists, "")
	good := rule("fp_ok", "tech_1", domain.ObsHTML, "", domain.OpContains, "Acme")
	e := New(reg([]domain.Technology{tech("tech_1", "X")},
		probe, pcre, dep, prop, bad, good, inert,
		rule("fp_js", "tech_1", domain.ObsJSGlobal, "jQuery", domain.OpExists, ""),
		rule("fp_xhr", "tech_1", domain.ObsXHR, "", domain.OpRegex, "x"),
		rule("fp_rb", "tech_1", domain.ObsRobots, "", domain.OpRegex, "x")))
	in := input()
	o := e.Run(in, Options{})
	want := map[string]int{ReasonProbe: 1, ReasonFlavor: 1, ReasonDeprecated: 1, ReasonBrowser: 3, ReasonInvalid: 1, ReasonRobots: 1, ReasonInert: 1}
	for k, v := range want {
		if o.Coverage.Skipped[k] != v {
			t.Errorf("skipped[%q] = %d, want %d (%v)", k, o.Coverage.Skipped[k], v, o.Coverage.Skipped)
		}
	}
	if o.Coverage.RulesUnsupported != 9 || o.Coverage.RulesEvaluated != 1 || o.Coverage.RulesTotal != 10 {
		t.Errorf("coverage: %+v", o.Coverage)
	}
	if n := byName(o, "X"); n == nil || len(n.Evidence) != 1 {
		t.Errorf("only the valid rule matched: %+v", o.Technologies)
	}
	var w bool
	for _, x := range o.Warnings {
		w = w || x.Code == "invalid_rules"
	}
	if !w {
		t.Errorf("a rule that does not compile must be reported: %+v", o.Warnings)
	}

	// What the observation does not have is a reason, not a miss.
	in.DNSLooked, in.HasTLS, in.FaviconTried = false, false, false
	e = New(reg([]domain.Technology{tech("tech_1", "X")},
		rule("fp_dns", "tech_1", domain.ObsDNSRecord, "NS", domain.OpExists, ""),
		rule("fp_tls", "tech_1", domain.ObsTLSCert, "issuer", domain.OpContains, "x"),
		rule("fp_fav", "tech_1", domain.ObsFaviconHash, "mmh3", domain.OpHashEquals, "123")))
	o = e.Run(in, Options{})
	if o.Coverage.Skipped[ReasonNoDNS] != 1 || o.Coverage.Skipped[ReasonNoTLS] != 1 || o.Coverage.Skipped[ReasonNoFavicon] != 1 || o.Coverage.RulesEvaluated != 0 {
		t.Errorf("coverage: %+v", o.Coverage)
	}
	// ...and with the data, the same rules run.
	o = e.Run(input(), Options{})
	if o.Coverage.RulesEvaluated != 3 || byName(o, "X") == nil {
		t.Errorf("%+v %+v", o.Coverage, o.Technologies)
	}
}

func TestGroupWithAnUnsupportedMemberIsSkippedAsAWhole(t *testing.T) {
	a := rule("fp_1", "tech_1", domain.ObsHTML, "", domain.OpContains, "Acme")
	b := rule("fp_2", "tech_1", domain.ObsProbeResponse, "body", domain.OpContains, "x")
	b.Probe = &domain.Probe{Method: "GET", Path: "/x", SafetyReview: "pending"}
	a.GroupID, b.GroupID = "fpg_1", "fpg_1"
	o := New(reg([]domain.Technology{tech("tech_1", "X")}, a, b)).Run(input(), Options{})
	if len(o.Technologies) != 0 || o.Coverage.Skipped[ReasonProbe] != 2 || o.Coverage.RulesEvaluated != 0 {
		t.Errorf("a group that needs a probe is skipped, members and all: %+v %+v", o.Technologies, o.Coverage)
	}
}

func TestHealthAndConfidence(t *testing.T) {
	hi := health(rule("fp_1", "tech_1", domain.ObsHTML, "", domain.OpContains, "Acme"), "ok")
	hi.Confidence = 0.4
	mid := rule("fp_2", "tech_1", domain.ObsHTML, "", domain.OpContains, "hi")
	mid.Confidence = 0.7
	broken := health(rule("fp_3", "tech_1", domain.ObsHTML, "", domain.OpContains, "wp-block"), "broken")
	broken.Confidence = 0.95
	e := New(reg([]domain.Technology{tech("tech_1", "X")}, hi, mid, broken))

	o := e.Run(input(), Options{})
	n := byName(o, "X")
	if n == nil || len(n.Evidence) != 3 {
		t.Fatalf("%+v", o.Technologies)
	}
	if n.Confidence != 0.7 {
		t.Errorf("confidence is the highest among rules that are not broken, got %v", n.Confidence)
	}
	healths := map[string]string{}
	for _, ev := range n.Evidence {
		healths[ev.RuleID] = ev.Health
	}
	if healths["fp_1"] != "ok" || healths["fp_2"] != "unknown" || healths["fp_3"] != "broken" {
		t.Errorf("the health of each rule is part of its evidence: %v", healths)
	}

	o = e.Run(input(), Options{MinHealth: "unknown"})
	if n := byName(o, "X"); n == nil || len(n.Evidence) != 2 || o.Coverage.Skipped[ReasonHealth] != 1 {
		t.Errorf("min health unknown drops broken rules: %+v %+v", o.Technologies, o.Coverage)
	}
	o = e.Run(input(), Options{MinHealth: "ok"})
	if n := byName(o, "X"); n == nil || len(n.Evidence) != 1 || n.Confidence != 0.4 || o.Coverage.Skipped[ReasonHealth] != 2 {
		t.Errorf("min health ok: %+v %+v", o.Technologies, o.Coverage)
	}
	// Only broken rules match: the technology is reported without confidence.
	only := New(reg([]domain.Technology{tech("tech_1", "X")}, broken))
	if n := byName(only.Run(input(), Options{}), "X"); n == nil || n.Confidence != 0 {
		t.Errorf("%+v", n)
	}
}

func TestConflictingVersionsAreReported(t *testing.T) {
	a := rule("fp_1", "tech_1", domain.ObsHTTPHeader, "Server", domain.OpRegex, `^nginx/([\d.]+)`)
	a.VersionExtract, a.Confidence = `\1`, 0.5
	b := rule("fp_2", "tech_1", domain.ObsHTTPHeader, "X-Powered-By", domain.OpRegex, `^PHP/([\d.]+)`)
	b.VersionExtract, b.Confidence = `\1`, 0.9
	o := New(reg([]domain.Technology{tech("tech_1", "X")}, a, b)).Run(input(), Options{})
	n := byName(o, "X")
	if n == nil || n.Version != "8.2.1" {
		t.Fatalf("the more confident rule wins: %+v", n)
	}
	var w *scan.Warning
	for i := range o.Warnings {
		if o.Warnings[i].Code == "conflicting_versions" {
			w = &o.Warnings[i]
		}
	}
	if w == nil || !strings.Contains(w.Message, "1.25.3") || !strings.Contains(w.Message, "8.2.1") || w.Ref != "x" {
		t.Errorf("warnings: %+v", o.Warnings)
	}
}

func TestEvidenceIsBoundedAndClipped(t *testing.T) {
	var rules []domain.Fingerprint
	for i := 0; i < 8; i++ {
		rules = append(rules, rule(fmt.Sprintf("fp_%02d", i), "tech_1", domain.ObsHTML, "", domain.OpContains, "Acme"))
	}
	o := New(reg([]domain.Technology{tech("tech_1", "X")}, rules...)).Run(input(), Options{MaxEvidence: 3})
	if n := byName(o, "X"); n == nil || len(n.Evidence) != 3 || n.Confidence != 0.5 {
		t.Fatalf("%+v", n)
	}
	var w bool
	for _, x := range o.Warnings {
		w = w || x.Code == "evidence_truncated"
	}
	if !w {
		t.Error("a truncated list must be reported")
	}

	long := input()
	long.Observation.Headers["server"] = strings.Repeat("é", 1000)
	o = New(reg([]domain.Technology{tech("tech_1", "X")}, rule("fp_l", "tech_1", domain.ObsHTTPHeader, "Server", domain.OpRegex, `é+`))).Run(long, Options{})
	m := o.Technologies[0].Evidence[0].Matched
	if len([]rune(m)) != 300 || !strings.HasSuffix(m, "…") {
		t.Errorf("matched value: %d runes", len([]rune(m)))
	}
}

func TestDeprecatedTechnologyAndDeterminism(t *testing.T) {
	old := tech("tech_9", "Old")
	old.Status = domain.StatusDeprecated
	r := reg([]domain.Technology{tech("tech_2", "beta"), old, tech("tech_1", "Alpha")},
		rule("fp_1", "tech_1", domain.ObsHTML, "", domain.OpContains, "Acme"),
		rule("fp_2", "tech_2", domain.ObsHTML, "", domain.OpContains, "Acme"),
		rule("fp_3", "tech_9", domain.ObsHTML, "", domain.OpContains, "Acme"))
	e := New(r)
	a, b := e.Run(input(), Options{}), e.Run(input(), Options{})
	if len(a.Technologies) != 2 || a.Technologies[0].Name != "Alpha" || a.Technologies[1].Name != "beta" {
		t.Errorf("technologies are sorted by name, case-insensitively, and deprecated ones are left out: %+v", a.Technologies)
	}
	if a.Coverage.Skipped[ReasonDeprecated] != 1 {
		t.Errorf("%+v", a.Coverage)
	}
	if fmt.Sprint(a) != fmt.Sprint(b) {
		t.Error("two runs on the same input must give the same result")
	}
	if e.Rules() != 3 {
		t.Error(e.Rules())
	}
	if !ValidHealth("ok") || ValidHealth("great") {
		t.Error("ValidHealth")
	}
}
