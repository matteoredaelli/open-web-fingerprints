// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package validation_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/matteoredaelli/open-web-fingerprints/internal/domain"
	"github.com/matteoredaelli/open-web-fingerprints/internal/validation"
)

type ex struct {
	Text    string `json:"text"`
	Version string `json:"version,omitempty"`
}

// rule builds a header rule with the source's examples in its raw fragment.
func rule(id, tech string, index int, pattern, ver string, examples ...ex) domain.Fingerprint {
	raw, _ := json.Marshal(map[string]any{"file": "xml/http_servers.xml", "matches": "http_header.server", "index": index, "examples": examples})
	return domain.Fingerprint{
		ID: domain.FingerprintID(id), TechnologyID: domain.TechnologyID(tech), Observation: domain.ObsHTTPHeader,
		Target: "Server", Operator: domain.OpRegex, Pattern: pattern, RegexFlavor: domain.FlavorRE2,
		VersionExtract: ver, Confidence: 0.9, Status: domain.StatusActive, Raw: raw,
	}
}

func names(ls []validation.Loaded) string {
	var out []string
	for _, l := range ls {
		out = append(out, l.Case.ID)
	}
	return strings.Join(out, ",")
}

func byRule(ls []validation.Loaded, id string) (pos, neg []validation.Loaded) {
	for _, l := range ls {
		if string(l.RuleID) != id {
			continue
		}
		if l.Case.Expect.Match {
			pos = append(pos, l)
		} else {
			neg = append(neg, l)
		}
	}
	return pos, neg
}

func TestPositivesAndNegativesFromUpstreamExamples(t *testing.T) {
	recs := domain.Records{Fingerprints: []domain.Fingerprint{
		rule("fp_a", "tech_a", 0, `(?-i)^alpha/([\d.]+)$`, `\1`, ex{"alpha/1.2", "1.2"}, ex{"alpha/3.4", "3.4"}),
		rule("fp_b", "tech_b", 1, `(?-i)^beta$`, "", ex{"beta", ""}),
		rule("fp_c", "tech_c", 2, `(?-i)^gamma$`, "", ex{"gamma", ""}),
		// Same technology as fp_a: its banner is not a negative for fp_a.
		rule("fp_a2", "tech_a", 3, `(?-i)^alpha-lite$`, "", ex{"alpha-lite", ""}),
	}}
	cases, st := validation.FromUpstreamExamples(recs)

	pos, neg := byRule(cases, "fp_a")
	if len(pos) != 2 || pos[0].Case.Expect.Version != "1.2" || pos[1].Case.Expect.Version != "3.4" {
		t.Errorf("positives with versions: %+v", pos)
	}
	// Negatives: the banners of beta and gamma (later rules, other products).
	if len(neg) != 2 {
		t.Fatalf("negatives of fp_a: %s", names(neg))
	}
	for _, n := range neg {
		if n.Origin != validation.OriginUpstream || n.Case.Expect.Match || !strings.HasPrefix(n.Ref(), "upstream#neg:") {
			t.Errorf("negative case: %+v", n)
		}
	}
	// A version is expected only where the rule reads one.
	pos, _ = byRule(cases, "fp_b")
	if len(pos) != 1 || pos[0].Case.Expect.Version != "" {
		t.Errorf("fp_b positive: %+v", pos)
	}
	// Order: fp_c is later than fp_a and fp_b, fp_b only has later rules fp_c and fp_a2.
	_, negB := byRule(cases, "fp_b")
	if len(negB) != 2 {
		t.Errorf("fp_b negatives: %s", names(negB))
	}
	// The last rule has nothing after it, so no negative: it cannot get ok from upstream data.
	if _, n := byRule(cases, "fp_a2"); len(n) != 0 {
		t.Errorf("the last rule has no negatives: %s", names(n))
	}
	if st.Rules != 4 || st.Positive != 5 || st.Negative != 5 {
		t.Errorf("stats: %+v", st)
	}

	// Run and apply: every case passes and the rules with both kinds become ok.
	rs := validation.Run(cases, recs)
	if s := validation.Summarize(rs); s[validation.Pass] != len(rs) {
		t.Fatalf("summary: %v", s)
	}
	updated := validation.Apply(rs, recs, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	health := map[domain.FingerprintID]string{}
	for _, f := range updated {
		health[f.ID] = f.Validation.Health
		for _, tr := range f.Validation.TestRuns {
			if tr.Origin != validation.OriginUpstream {
				t.Errorf("the evidence must say where it came from: %+v", tr)
			}
		}
	}
	if health["fp_a"] != "ok" || health["fp_b"] != "ok" || health["fp_c"] != "ok" || health["fp_a2"] != "unknown" {
		t.Errorf("health: %v", health)
	}
}

func TestOnlyLaterRulesProvideNegatives(t *testing.T) {
	// "broad" comes first and matches the banner of "narrow", which comes later:
	// applied alone the broad rule would claim another product's banner. That is a
	// failure. The narrow rule matches nothing of the broad rule's kind, and the
	// broad banner is not a negative for it, because in the source the broad
	// rule is tried first and never reaches the narrow one.
	recs := domain.Records{Fingerprints: []domain.Fingerprint{
		rule("fp_narrow", "tech_n", 1, `(?-i)^acme server/([\d.]+)$`, `\1`, ex{"acme server/2.0", "2.0"}),
		rule("fp_broad", "tech_b", 0, `(?-i)^acme`, "", ex{Text: "acme"}),
		rule("fp_other", "tech_o", 2, `(?-i)^other$`, "", ex{Text: "other"}),
	}}
	cases, _ := validation.FromUpstreamExamples(recs)
	rs := validation.Run(cases, recs)
	var failed []string
	for _, r := range rs {
		if r.Status == validation.Fail {
			failed = append(failed, string(r.RuleID)+" "+r.Case.Input.Headers["Server"])
		}
	}
	if len(failed) != 1 || failed[0] != "fp_broad acme server/2.0" {
		t.Errorf("the broad rule must fail on the narrow rule's banner: %v", failed)
	}
	// fp_narrow gets no negative from fp_broad (earlier owner).
	_, neg := byRule(cases, "fp_narrow")
	for _, n := range neg {
		if n.Case.Input.Headers["Server"] == "acme" {
			t.Errorf("an earlier rule's banner is not a fair negative: %+v", n)
		}
	}
	up := validation.Apply(rs, recs, time.Now())
	for _, f := range up {
		if f.ID == "fp_broad" && f.Validation.Health != "broken" {
			t.Errorf("a failing negative makes the rule broken: %+v", f.Validation)
		}
	}
}

func TestNegativesAreSampledButFailuresAreAlwaysKept(t *testing.T) {
	var fps []domain.Fingerprint
	fps = append(fps, rule("fp_0", "tech_0", 0, `(?-i)^zzz`, "", ex{Text: "zzz"}))
	for i := 1; i <= 30; i++ {
		fps = append(fps, rule(fmt.Sprintf("fp_%d", i), fmt.Sprintf("tech_%d", i), i, fmt.Sprintf(`(?-i)^p%d$`, i), "", ex{fmt.Sprintf("p%d", i), ""}))
	}
	// A later rule whose banner fp_0 also matches: always among the cases.
	fps = append(fps, rule("fp_bad", "tech_bad", 31, `(?-i)^zzz-extended$`, "", ex{"zzz-extended", ""}))
	cases, st := validation.FromUpstreamExamples(domain.Records{Fingerprints: fps})
	_, neg := byRule(cases, "fp_0")
	if len(neg) != 6 { // 3 nearest + 2 spread + 1 failing
		t.Errorf("negatives of fp_0 = %d: %s", len(neg), names(neg))
	}
	rs := validation.Run(cases, domain.Records{Fingerprints: fps})
	var fails int
	for _, r := range rs {
		if r.Status == validation.Fail {
			fails++
		}
	}
	if fails != 1 {
		t.Errorf("fails = %d, want the one banner fp_0 claims", fails)
	}
	if st.NegativeChecks < 30 {
		t.Errorf("every candidate must be checked, not only the sample: %d", st.NegativeChecks)
	}
	// The sample is stable: the same input gives the same cases.
	again, _ := validation.FromUpstreamExamples(domain.Records{Fingerprints: fps})
	if names(cases) != names(again) {
		t.Error("generation must be deterministic")
	}
}

func TestRulesThatCannotBeTestedAreCounted(t *testing.T) {
	fav := rule("fp_fav", "tech_f", 0, `^[0-9a-f]{32}$`, "", ex{Text: "4297c114f263c206ed12aaff4b0c7a50"})
	fav.Observation, fav.Target = domain.ObsFaviconHash, "md5"
	other := rule("fp_fav2", "tech_g", 1, `^abc$`, "", ex{Text: "abc"})
	other.Observation, other.Target = domain.ObsFaviconHash, "md5"
	pcre := rule("fp_pcre", "tech_p", 2, `(?<=x)y`, "", ex{Text: "xy"})
	pcre.RegexFlavor = domain.FlavorPCRE
	dom := rule("fp_dom", "tech_d", 3, "x", "", ex{Text: "x"})
	dom.Observation = domain.ObsDOM
	exists := rule("fp_exists", "tech_e", 5, "", "", ex{Text: "x"})
	exists.Operator = domain.OpExists
	noExamples := rule("fp_none", "tech_n", 4, `^n$`, "")
	cases, st := validation.FromUpstreamExamples(domain.Records{Fingerprints: []domain.Fingerprint{fav, other, pcre, dom, exists, noExamples}})
	if st.Skipped["pattern needs a backtracking engine"] != 1 || st.Skipped["observation type not supported"] != 1 || st.Skipped["operator not testable offline"] != 1 {
		t.Errorf("skipped: %v", st.Skipped)
	}
	// Favicon hashes get positives only: a negative against other digests proves nothing.
	_, n := byRule(cases, "fp_fav")
	if len(n) != 0 {
		t.Errorf("an exact digest has no meaningful negatives: %s", names(n))
	}
	up := validation.Apply(validation.Run(cases, domain.Records{Fingerprints: []domain.Fingerprint{fav, other}}), domain.Records{Fingerprints: []domain.Fingerprint{fav, other}}, time.Now())
	for _, f := range up {
		if f.Validation.Health != "unknown" {
			t.Errorf("positives alone must not make a rule ok: %+v", f.Validation)
		}
	}
}

func TestRegeneratedEvidenceReplacesTheOldSet(t *testing.T) {
	recs := domain.Records{Fingerprints: []domain.Fingerprint{
		rule("fp_a", "tech_a", 0, `(?-i)^a$`, "", ex{Text: "a"}),
		rule("fp_b", "tech_b", 1, `(?-i)^b$`, "", ex{Text: "b"}),
	}}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cases, _ := validation.FromUpstreamExamples(recs)
	first := validation.Apply(validation.Run(cases, recs), recs, now)

	// A fixture-based run is stored on the same rule.
	own := validation.Loaded{File: "x.json", Case: validation.Case{ID: "mine"}, RuleID: "fp_a"}
	own.Case.Input.Headers = map[string]string{"Server": "a"}
	own.Case.Expect.Match = true
	for i := range recs.Fingerprints {
		for _, f := range first {
			if recs.Fingerprints[i].ID == f.ID {
				recs.Fingerprints[i] = f
			}
		}
	}
	withOwn := validation.Apply(validation.Run([]validation.Loaded{own}, recs), recs, now)
	for i := range recs.Fingerprints {
		for _, f := range withOwn {
			if recs.Fingerprints[i].ID == f.ID {
				recs.Fingerprints[i] = f
			}
		}
	}

	// The source changes its examples: the old generated set is replaced, the fixture run stays.
	recs.Fingerprints[0] = withRaw(recs.Fingerprints[0], ex{Text: "a"}, ex{Text: "A-second"})
	recs.Fingerprints[0].Pattern = `(?-i)^a`
	cases, _ = validation.FromUpstreamExamples(recs)
	second := validation.Apply(validation.Run(cases, recs), recs, now.Add(time.Hour))
	for _, f := range second {
		if f.ID != "fp_a" {
			continue
		}
		var up, mine int
		for _, tr := range f.Validation.TestRuns {
			if tr.Origin == validation.OriginUpstream {
				up++
			} else {
				mine++
			}
		}
		// ex1, ex2 and the one negative (b's banner)
		if up != 3 || mine != 1 {
			t.Errorf("runs: %d upstream, %d own: %+v", up, mine, f.Validation.TestRuns)
		}
	}
}

func withRaw(f domain.Fingerprint, examples ...ex) domain.Fingerprint {
	raw, _ := json.Marshal(map[string]any{"file": "xml/http_servers.xml", "matches": "http_header.server", "index": 0, "examples": examples})
	f.Raw = raw
	return f
}
