// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package domain

import "testing"

func fp(o Observation, target, pattern string) Fingerprint {
	return Fingerprint{
		TechnologyID: "tech_1", Observation: o, Target: target, Operator: OpRegex,
		Pattern: pattern, RegexFlavor: FlavorRE2, VersionExtract: `\1`,
	}
}

func TestSemanticKeyCaseRules(t *testing.T) {
	same := [][2]Fingerprint{
		{fp(ObsHTTPHeader, "X-Powered-By", "^a"), fp(ObsHTTPHeader, "x-powered-by", "^a")},
		{fp(ObsMetaTag, "Generator", "^a"), fp(ObsMetaTag, "generator", "^a")},
		{fp(ObsDNSRecord, "ns", "a"), fp(ObsDNSRecord, "NS", "a")},
	}
	for i, p := range same {
		if p[0].SemanticKey() != p[1].SemanticKey() {
			t.Errorf("case %d: keys must be equal", i)
		}
	}
	different := [][2]Fingerprint{
		{fp(ObsCookie, "PHPSESSID", "a"), fp(ObsCookie, "phpsessid", "a")},
		{fp(ObsJSGlobal, "jQuery", "a"), fp(ObsJSGlobal, "jquery", "a")},
		{fp(ObsHTML, "", "abc"), fp(ObsHTML, "", "ABC")},
		{fp(ObsHTML, "", "a"), fp(ObsScriptURL, "", "a")},
	}
	for i, p := range different {
		if p[0].SemanticKey() == p[1].SemanticKey() {
			t.Errorf("case %d: keys must differ", i)
		}
	}
}

func TestSemanticKeyFields(t *testing.T) {
	base := fp(ObsHTML, "", "a")
	for name, mut := range map[string]func(*Fingerprint){
		"technology": func(f *Fingerprint) { f.TechnologyID = "tech_2" },
		"operator":   func(f *Fingerprint) { f.Operator = OpContains },
		"flavor":     func(f *Fingerprint) { f.RegexFlavor = FlavorECMAScript },
		"version":    func(f *Fingerprint) { f.VersionExtract = `\2` },
		"group":      func(f *Fingerprint) { f.GroupID = "fpg_1" },
	} {
		other := base
		mut(&other)
		if other.SemanticKey() == base.SemanticKey() {
			t.Errorf("%s must change the key", name)
		}
	}
	other := base
	other.Confidence, other.Status, other.Raw = 0.9, StatusDraft, []byte(`{}`)
	if other.SemanticKey() != base.SemanticKey() {
		t.Error("confidence, status and raw must not affect the key")
	}
}
