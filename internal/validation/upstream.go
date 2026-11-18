// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package validation

import (
	"encoding/json"
	"fmt"
	"hash/fnv"
	"sort"

	"github.com/matteoredaelli/open-web-fingerprints/internal/domain"
	"github.com/matteoredaelli/open-web-fingerprints/internal/matcher"
)

// Some sources ship examples with their rules: strings the rule must match,
// often with the version it must read. They are the source's own tests, and a
// rule keeps them in its raw fragment, in a convention this file reads:
//
//	{"file": "...", "matches": "...", "index": 12,
//	 "examples": [{"text": "nginx/1.25.3", "version": "1.25.3"}]}
//
// From them, cases are generated for each rule:
//
//   - positive: the rule's own examples (at most maxPositive), with the
//     expected version when the rule reads one;
//   - negative: examples of rules of other technologies in the same database,
//     which the rule must not match.
//
// Order matters for negatives. The source tries a database's fingerprints in
// order and stops at the first match, but the registry reports every match. An
// example of an earlier rule is never seen by a later one in the source, so it
// is not a fair negative; only examples of later rules are used. That is also the
// case where the rule, applied alone, would claim another product's banner.
//
// Evidence from these cases is marked Origin = "upstream_example". It is real
// data written by the source's maintainers, but it is not independent of the
// rule: the same people wrote both.

const (
	maxPositive = 5 // positive cases kept per rule
	maxNearest  = 3 // negatives taken from the nearest later rules
	maxSpread   = 2 // negatives spread over the other later rules
)

type upstreamRaw struct {
	File     string `json:"file"`
	Matches  string `json:"matches"`
	Index    int    `json:"index"`
	Examples []struct {
		Text    string `json:"text"`
		Version string `json:"version"`
	} `json:"examples"`
}

// UpstreamStats says what the generator did.
type UpstreamStats struct {
	Rules          int            // rules with at least one usable example
	Positive       int            // positive cases generated
	Negative       int            // negative cases generated
	NegativeChecks int            // negatives evaluated, including those not kept
	Skipped        map[string]int // rules left out, by reason
}

type candidate struct {
	rule domain.Fingerprint
	raw  upstreamRaw
}

// FromUpstreamExamples generates cases from the examples kept in the rules'
// raw fragments. It evaluates every possible negative to find the rules that
// match another product's banner; a sample of the passing negatives and all of
// the failing ones become cases.
func FromUpstreamExamples(recs domain.Records) ([]Loaded, UpstreamStats) {
	st := UpstreamStats{Skipped: map[string]int{}}
	// Group by database: the file and what it matches.
	dbs := map[string][]candidate{}
	var order []string
	for _, f := range recs.Fingerprints {
		if len(f.Raw) == 0 {
			continue
		}
		var raw upstreamRaw
		if json.Unmarshal(f.Raw, &raw) != nil || len(raw.Examples) == 0 {
			continue
		}
		switch {
		case f.Operator != domain.OpRegex && f.Operator != domain.OpEquals && f.Operator != domain.OpContains:
			st.Skipped["operator not testable offline"]++
			continue
		case f.Operator == domain.OpRegex && f.RegexFlavor != domain.FlavorRE2:
			st.Skipped["pattern needs a backtracking engine"]++
			continue
		}
		if observationFor(f, "x") == nil {
			st.Skipped["observation type not supported"]++
			continue
		}
		key := raw.File + "\x00" + raw.Matches
		if _, seen := dbs[key]; !seen {
			order = append(order, key)
		}
		dbs[key] = append(dbs[key], candidate{rule: f, raw: raw})
	}
	sort.Strings(order)

	var out []Loaded
	for _, key := range order {
		db := dbs[key]
		sort.SliceStable(db, func(i, j int) bool { return db[i].raw.Index < db[j].raw.Index })
		for i, c := range db {
			st.Rules++
			own := map[string]bool{}
			for _, e := range c.raw.Examples {
				own[e.Text] = true
			}
			// Positives.
			for n, e := range c.raw.Examples {
				if n == maxPositive {
					break
				}
				exp := Expect{Match: true}
				if e.Version != "" && c.rule.VersionExtract != "" {
					exp.Version = e.Version
				}
				out = append(out, generated(c.rule, fmt.Sprintf("ex%d", n+1), e.Text, exp))
				st.Positive++
			}
			// Negatives: an exact digest cannot be "over-broad", so a negative
			// against other hashes would prove nothing.
			if c.rule.Observation == domain.ObsFaviconHash {
				continue
			}
			var fails, passes []Loaded
			for _, o := range db[i+1:] {
				if o.rule.TechnologyID == c.rule.TechnologyID || len(o.raw.Examples) == 0 {
					continue
				}
				text := o.raw.Examples[0].Text
				if own[text] {
					continue // the same banner is an example of both rules
				}
				st.NegativeChecks++
				l := generated(c.rule, fmt.Sprintf("neg:%s:1", o.rule.ID), text, Expect{Match: false})
				got, err := matcher.Evaluate(c.rule, &l.Case.Input)
				if err == nil && got.Matched {
					fails = append(fails, l)
				} else {
					passes = append(passes, l)
				}
			}
			kept := sampleNegatives(c.rule.ID, passes)
			out = append(out, fails...)
			out = append(out, kept...)
			st.Negative += len(fails) + len(kept)
		}
	}
	return out, st
}

// sampleNegatives keeps the nearest later rules, which give the most similar
// banners, and a few spread over the rest, chosen by a stable hash.
func sampleNegatives(id domain.FingerprintID, passes []Loaded) []Loaded {
	if len(passes) <= maxNearest+maxSpread {
		return passes
	}
	out := append([]Loaded(nil), passes[:maxNearest]...)
	rest := append([]Loaded(nil), passes[maxNearest:]...)
	sort.Slice(rest, func(i, j int) bool { return hash(string(id), rest[i].Case.ID) < hash(string(id), rest[j].Case.ID) })
	return append(out, rest[:maxSpread]...)
}

func hash(a, b string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(a + "\x00" + b))
	return h.Sum64()
}

func generated(rule domain.Fingerprint, id, text string, exp Expect) Loaded {
	return Loaded{
		File: "upstream", RuleID: rule.ID, Origin: OriginUpstream,
		Case: Case{ID: id, Input: *observationFor(rule, text), Expect: exp},
	}
}

// observationFor builds the observation a banner stands for, as the rule's own
// observation type sees it. It returns nil for observations that cannot be
// reconstructed from a single string.
func observationFor(f domain.Fingerprint, text string) *matcher.Observation {
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
	return nil
}
