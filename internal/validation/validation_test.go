// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package validation_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/matteoredaelli/open-web-fingerprints/internal/domain"
	"github.com/matteoredaelli/open-web-fingerprints/internal/extractor"
	"github.com/matteoredaelli/open-web-fingerprints/internal/extractor/enthec"
	"github.com/matteoredaelli/open-web-fingerprints/internal/matcher"
	"github.com/matteoredaelli/open-web-fingerprints/internal/pipeline"
	"github.com/matteoredaelli/open-web-fingerprints/internal/repository/memory"
	"github.com/matteoredaelli/open-web-fingerprints/internal/validation"
)

var now = time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)

// registry imports the Enthec fixture snapshot.
func registry(t *testing.T) domain.Records {
	t.Helper()
	reg := extractor.NewRegistry()
	if err := reg.Register(enthec.New()); err != nil {
		t.Fatal(err)
	}
	repo := memory.New()
	_, err := pipeline.New(reg, repo).Run(context.Background(), pipeline.Request{
		Source:   domain.Source{Slug: "enthec-webappanalyzer", ExtractorID: enthec.ID, License: "GPL-3.0-only"},
		Revision: "x", FS: os.DirFS("../extractor/enthec/testdata/snapshot"),
	})
	if err != nil {
		t.Fatal(err)
	}
	recs, _ := repo.AllRecords(context.Background())
	return recs
}

func load(t *testing.T) []validation.Loaded {
	t.Helper()
	cases, err := validation.Load("testdata/cases")
	if err != nil {
		t.Fatal(err)
	}
	return cases
}

func byID(rs []validation.Result, id string) validation.Result {
	for _, r := range rs {
		if r.Case.ID == id {
			return r
		}
	}
	return validation.Result{}
}

func TestRunSeedCases(t *testing.T) {
	cases := load(t)
	if len(cases) != 18 {
		t.Fatalf("cases = %d", len(cases))
	}
	rs := validation.Run(cases, registry(t))
	for _, r := range rs {
		want := validation.Pass
		switch r.Case.ID {
		case "angular-lookahead-not-evaluated", "typo3-dom-not-evaluated":
			want = validation.Unsupported
		}
		if r.Status != want {
			t.Errorf("%s: %s %s", r.Case.ID, r.Status, r.Message)
		}
	}
	s := validation.Summarize(rs)
	if s[validation.Pass] != 16 || s[validation.Unsupported] != 2 || s[validation.Fail] != 0 {
		t.Errorf("summary: %v", s)
	}
	if got := byID(rs, "php-cookie-positive").Ref(); got != "php.json#php-cookie-positive" {
		t.Errorf("ref = %q", got)
	}
}

func TestApplyHealthNeedsPositiveAndNegativeEvidence(t *testing.T) {
	recs := registry(t)
	rs := validation.Run(load(t), recs)
	updated := validation.Apply(rs, recs, now)
	health := map[domain.FingerprintID]string{}
	for _, f := range updated {
		health[f.ID] = f.Validation.Health
		if f.Validation.LastValidatedAt == nil || !f.Validation.LastValidatedAt.Equal(now) {
			t.Errorf("last validated not set: %+v", f.Validation)
		}
	}
	h := func(id string) string { return health[byID(rs, id).RuleID] }
	if h("php-x-powered-by-positive") != "ok" {
		t.Errorf("positive and negative evidence must give ok, got %q", h("php-x-powered-by-positive"))
	}
	if h("php-cookie-positive") != "ok" {
		t.Errorf("cookie: %q", h("php-cookie-positive"))
	}
	if h("aframe-html-positive") != "ok" {
		t.Errorf("a-frame html: %q", h("aframe-html-positive"))
	}
	if h("aframe-script-url-positive") != "unknown" {
		t.Errorf("a positive test alone is not enough, got %q", h("aframe-script-url-positive"))
	}
	if h("thawte-issuer-positive") != "unknown" {
		t.Errorf("thawte: %q", h("thawte-issuer-positive"))
	}
	// Unsupported cases leave no evidence behind.
	if _, ok := health[byID(rs, "angular-lookahead-not-evaluated").RuleID]; ok {
		t.Error("unsupported cases must not touch the rule")
	}
	for _, f := range updated {
		for _, tr := range f.Validation.TestRuns {
			if tr.Expect != "match" && tr.Expect != "no_match" || tr.FixtureRef == "" || tr.Result != "pass" {
				t.Errorf("bad test run: %+v", tr)
			}
		}
	}
}

func TestApplyIsRepeatableAndKeepsReviewedFields(t *testing.T) {
	recs := registry(t)
	// A reviewer approved a probe and set a rule's status; testing must not undo it.
	for i := range recs.Fingerprints {
		f := &recs.Fingerprints[i]
		if f.Probe != nil {
			f.Probe.SafetyReview = "approved"
			f.Status = domain.StatusActive
		}
		if f.Validation != nil {
			f.Validation.KnownFalsePositives = []string{"some forum"}
		}
	}
	rs := validation.Run(load(t), recs)
	first := validation.Apply(rs, recs, now)
	for _, f := range first {
		for i := range recs.Fingerprints {
			if recs.Fingerprints[i].ID == f.ID {
				recs.Fingerprints[i] = f
			}
		}
	}
	later := now.Add(time.Hour)
	second := validation.Apply(validation.Run(load(t), recs), recs, later)
	if len(second) != len(first) {
		t.Fatalf("second run touched %d rules, first %d", len(second), len(first))
	}
	for _, f := range second {
		if n := len(f.Validation.TestRuns); n != countRuns(first, f.ID) {
			t.Errorf("test runs must be replaced, not appended: %d", n)
		}
		if !f.Validation.LastValidatedAt.Equal(later) {
			t.Error("last validated must move forward")
		}
		if len(f.Validation.KnownFalsePositives) != 1 {
			t.Error("known false positives were lost")
		}
		if f.Probe != nil && (f.Probe.SafetyReview != "approved" || f.Status != domain.StatusActive) {
			t.Errorf("reviewer decision overwritten: %+v", f)
		}
	}
}

func countRuns(fs []domain.Fingerprint, id domain.FingerprintID) int {
	for _, f := range fs {
		if f.ID == id {
			return len(f.Validation.TestRuns)
		}
	}
	return -1
}

func TestFailingCaseMakesTheRuleBroken(t *testing.T) {
	recs := registry(t)
	cases := []validation.Loaded{
		{File: "x.json", Case: validation.Case{
			ID:   "php-header-wrong-expectation",
			Rule: validation.Selector{Technology: "php", Observation: "http_header", Target: "X-Powered-By"},
			// The rule matches this, so expecting no match is a failure.
			Input:  matcher.Observation{Headers: map[string]string{"X-Powered-By": "PHP/8.2"}},
			Expect: validation.Expect{Match: false},
		}},
		{File: "x.json", Case: validation.Case{
			ID:     "php-header-wrong-version",
			Rule:   validation.Selector{Technology: "php", Observation: "http_header", Target: "X-Powered-By"},
			Input:  matcher.Observation{Headers: map[string]string{"X-Powered-By": "PHP/8.2"}},
			Expect: validation.Expect{Match: true, Version: "9.9"},
		}},
	}
	rs := validation.Run(cases, recs)
	for _, r := range rs {
		if r.Status != validation.Fail {
			t.Errorf("%s: %s", r.Case.ID, r.Status)
		}
	}
	if !strings.Contains(rs[0].Message, "expected match=false") || !strings.Contains(rs[1].Message, `expected version "9.9"`) {
		t.Errorf("messages: %q / %q", rs[0].Message, rs[1].Message)
	}
	up := validation.Apply(rs, recs, now)
	if len(up) != 1 || up[0].Validation.Health != "broken" {
		t.Fatalf("a failing test must mark the rule broken: %+v", up)
	}
	// Fixing the rule later is not automatic: a passing run replaces only its own ref.
	good := validation.Loaded{File: "x.json", Case: validation.Case{
		ID: "php-header-wrong-version", Rule: cases[1].Case.Rule, Input: cases[1].Case.Input,
		Expect: validation.Expect{Match: true, Version: "8.2"},
	}}
	recs.Fingerprints = replace(recs.Fingerprints, up[0])
	again := validation.Apply(validation.Run([]validation.Loaded{good}, recs), recs, now)
	if again[0].Validation.Health != "broken" {
		t.Errorf("the other failing case still counts: %s", again[0].Validation.Health)
	}
}

func replace(fs []domain.Fingerprint, f domain.Fingerprint) []domain.Fingerprint {
	for i := range fs {
		if fs[i].ID == f.ID {
			fs[i] = f
		}
	}
	return fs
}

func TestCasesThatDoNotFitTheRegistryAreErrors(t *testing.T) {
	recs := registry(t)
	mk := func(s validation.Selector) validation.Loaded {
		return validation.Loaded{File: "x.json", Case: validation.Case{ID: "c", Rule: s, Expect: validation.Expect{Match: true}}}
	}
	for name, tc := range map[string]struct {
		sel  validation.Selector
		want string
	}{
		"unknown technology": {validation.Selector{Technology: "nope", Observation: "html"}, "no rules"},
		"stale selector":     {validation.Selector{Technology: "php", Observation: "http_header", Target: "X-Gone"}, "stale"},
		"ambiguous":          {validation.Selector{Technology: "a-frame", Observation: "js_global"}, "matches 2 rules"},
		"missing fields":     {validation.Selector{Technology: "php"}, "needs technology"},
		"wrong pattern":      {validation.Selector{Technology: "php", Observation: "http_header", Target: "Server", Pattern: "other"}, "stale"},
	} {
		r := validation.Run([]validation.Loaded{mk(tc.sel)}, recs)[0]
		if r.Status != validation.Error || !strings.Contains(r.Message, tc.want) {
			t.Errorf("%s: %s %q", name, r.Status, r.Message)
		}
		if up := validation.Apply([]validation.Result{r}, recs, now); len(up) != 0 {
			t.Errorf("%s: errors must not become evidence", name)
		}
	}
}

func writeCase(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

const okCase = `{"schema_version":"0.1.0","cases":[{"id":"%s","rule":{"technology":"php","observation":"html"},"input":{},"expect":{"match":false}}]}`

func TestLoadRejectsBadFiles(t *testing.T) {
	good := strings.Replace(okCase, "%s", "a", 1)
	for name, files := range map[string]map[string]string{
		"duplicate id across files": {"1.json": good, "2.json": good},
		"unknown field":             {"1.json": strings.Replace(good, `"input":{}`, `"input":{},"surprise":1`, 1)},
		"unknown input field":       {"1.json": strings.Replace(good, `"input":{}`, `"input":{"nope":1}`, 1)},
		"bad id":                    {"1.json": strings.Replace(okCase, "%s", "Bad ID", 1)},
		"version without match":     {"1.json": strings.Replace(good, `"match":false`, `"match":false,"version":"1"`, 1)},
		"not json":                  {"1.json": "{"},
		"no cases":                  {"1.json": `{"schema_version":"0.1.0","cases":[]}`},
		"bad operator":              {"1.json": strings.Replace(good, `"observation":"html"`, `"observation":"html","operator":"fuzzy"`, 1)},
		"bad technology slug":       {"1.json": strings.Replace(good, `"technology":"php"`, `"technology":"PHP!"`, 1)},
	} {
		dir := t.TempDir()
		for n, b := range files {
			writeCase(t, dir, n, b)
		}
		if _, err := validation.Load(dir); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	if _, err := validation.Load(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("missing path must fail")
	}
	// A single file works, and refs are relative to its folder.
	dir := t.TempDir()
	writeCase(t, dir, "one.json", good)
	got, err := validation.Load(filepath.Join(dir, "one.json"))
	if err != nil || len(got) != 1 || got[0].Ref() != "one.json#a" {
		t.Errorf("single file: %+v err=%v", got, err)
	}
}

func TestLint(t *testing.T) {
	rule := func(obs domain.Observation, target string, op domain.Operator, pattern string) domain.Fingerprint {
		f := domain.Fingerprint{ID: "fp_1", Observation: obs, Target: target, Operator: op, Pattern: pattern}
		if op == domain.OpRegex {
			f.RegexFlavor = domain.FlavorRE2
		}
		return f
	}
	codes := func(f domain.Fingerprint) string {
		var out []string
		for _, x := range validation.Lint(f) {
			out = append(out, x.Code)
		}
		return strings.Join(out, ",")
	}
	for name, tc := range map[string]struct {
		f    domain.Fingerprint
		want string
	}{
		"matches empty":         {rule(domain.ObsHTML, "", domain.OpRegex, "(?:foo)?"), validation.RegexMatchesEmpty},
		"anchor only":           {rule(domain.ObsHTML, "", domain.OpRegex, "^"), validation.RegexMatchesEmpty + "," + validation.PatternTooShort},
		"too short":             {rule(domain.ObsHTML, "", domain.OpContains, "ab"), validation.PatternTooShort},
		"ubiquitous header":     {rule(domain.ObsHTTPHeader, "Server", domain.OpExists, ""), validation.UbiquitousHeader},
		"ubiquitous meta":       {rule(domain.ObsMetaTag, "viewport", domain.OpExists, ""), validation.UbiquitousMeta},
		"good regex":            {rule(domain.ObsHTTPHeader, "Server", domain.OpRegex, `^nginx/([\d.]+)`), ""},
		"specific header":       {rule(domain.ObsHTTPHeader, "CF-Ray", domain.OpExists, ""), ""},
		"short hash is fine":    {rule(domain.ObsFaviconHash, "", domain.OpHashEquals, "1"), ""},
		"ecmascript not tested": {domain.Fingerprint{Observation: domain.ObsHTML, Operator: domain.OpRegex, RegexFlavor: domain.FlavorECMAScript, Pattern: "(?!x)y?"}, ""},
	} {
		if got := codes(tc.f); got != tc.want {
			t.Errorf("%s: got %q, want %q", name, got, tc.want)
		}
	}
	recs := domain.Records{Fingerprints: []domain.Fingerprint{rule(domain.ObsHTML, "", domain.OpRegex, "^"), rule(domain.ObsHTML, "", domain.OpRegex, "wp-content")}}
	if n := len(validation.LintAll(recs)); n != 2 {
		t.Errorf("LintAll = %d findings", n)
	}
}
