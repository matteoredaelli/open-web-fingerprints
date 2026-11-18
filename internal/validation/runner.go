// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package validation

import (
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/matteoredaelli/open-web-fingerprints/internal/domain"
	"github.com/matteoredaelli/open-web-fingerprints/internal/matcher"
)

// Status of one case.
type Status string

// Case statuses.
const (
	Pass        Status = "pass"
	Fail        Status = "fail"
	Error       Status = "error"       // the case does not fit the registry (no rule, ambiguous, broken pattern)
	Unsupported Status = "unsupported" // the rule cannot be evaluated offline yet
)

// Result is the outcome of one case.
type Result struct {
	Loaded
	Status  Status
	Message string
	// RuleID is set when the selector resolved to exactly one rule.
	RuleID domain.FingerprintID
}

// Run evaluates every case against the registry. It never changes it.
func Run(cases []Loaded, recs domain.Records) []Result {
	slug := map[domain.TechnologyID]string{}
	for _, t := range recs.Technologies {
		slug[t.ID] = t.Slug
	}
	byTech := map[string][]domain.Fingerprint{}
	byID := make(map[domain.FingerprintID]domain.Fingerprint, len(recs.Fingerprints))
	for _, f := range recs.Fingerprints {
		byTech[slug[f.TechnologyID]] = append(byTech[slug[f.TechnologyID]], f)
		byID[f.ID] = f
	}

	out := make([]Result, 0, len(cases))
	for _, l := range cases {
		r := Result{Loaded: l}
		var rule domain.Fingerprint
		var err error
		if l.RuleID != "" {
			var ok bool
			if rule, ok = byID[l.RuleID]; !ok {
				err = fmt.Errorf("rule %s is not in the registry", l.RuleID)
			}
		} else {
			rule, err = resolve(l.Case.Rule, byTech[l.Case.Rule.Technology])
		}
		if err != nil {
			r.Status, r.Message = Error, err.Error()
			out = append(out, r)
			continue
		}
		r.RuleID = rule.ID
		got, err := matcher.Evaluate(rule, &l.Case.Input)
		switch {
		case errors.Is(err, matcher.ErrUnsupported):
			r.Status, r.Message = Unsupported, err.Error()
		case err != nil:
			r.Status, r.Message = Error, err.Error()
		case got.Matched != l.Case.Expect.Match:
			r.Status, r.Message = Fail, fmt.Sprintf("expected match=%v, got match=%v", l.Case.Expect.Match, got.Matched)
		case l.Case.Expect.Version != "" && got.Version != l.Case.Expect.Version:
			r.Status, r.Message = Fail, fmt.Sprintf("expected version %q, got %q", l.Case.Expect.Version, got.Version)
		default:
			r.Status = Pass
		}
		out = append(out, r)
	}
	return out
}

// resolve finds the single rule a selector means. Omitted target, operator
// and pattern match anything; the selector must still pick exactly one rule.
func resolve(s Selector, rules []domain.Fingerprint) (domain.Fingerprint, error) {
	if s.Technology == "" || s.Observation == "" {
		return domain.Fingerprint{}, errors.New("selector needs technology and observation")
	}
	if len(rules) == 0 {
		return domain.Fingerprint{}, fmt.Errorf("technology %q has no rules in the registry", s.Technology)
	}
	obs := domain.Observation(s.Observation)
	var found []domain.Fingerprint
	for _, f := range rules {
		if f.Observation != obs ||
			(s.Target != "" && domain.NormalizeTarget(obs, f.Target) != domain.NormalizeTarget(obs, s.Target)) ||
			(s.Operator != "" && string(f.Operator) != s.Operator) ||
			(s.Pattern != "" && f.Pattern != s.Pattern) {
			continue
		}
		found = append(found, f)
	}
	switch len(found) {
	case 0:
		return domain.Fingerprint{}, fmt.Errorf("no rule of %q matches the selector (observation %s, target %q, pattern %q): the fixture may be stale",
			s.Technology, s.Observation, s.Target, s.Pattern)
	case 1:
		return found[0], nil
	}
	return domain.Fingerprint{}, fmt.Errorf("selector matches %d rules of %q; add operator or pattern", len(found), s.Technology)
}

// Summary counts results by status.
type Summary map[Status]int

// Summarize counts the results.
func Summarize(rs []Result) Summary {
	s := Summary{}
	for _, r := range rs {
		s[r.Status]++
	}
	return s
}

// Apply records the results as test evidence on the rules and returns the
// updated fingerprints. Only passing and failing cases are evidence; errors
// and unsupported cases say nothing about a rule.
//
// Health is computed over all of a rule's recorded test runs:
//
//	broken  at least one test fails
//	ok      at least one passing positive and one passing negative test
//	unknown anything less
//
// A rule's reviewed status, probe review and other fields are not touched.
func Apply(results []Result, recs domain.Records, now time.Time) []domain.Fingerprint {
	byID := map[domain.FingerprintID]domain.Fingerprint{}
	for _, f := range recs.Fingerprints {
		byID[f.ID] = f
	}
	touched := map[domain.FingerprintID]bool{}
	cleared := map[domain.FingerprintID]bool{}
	for _, r := range results {
		if r.RuleID == "" || (r.Status != Pass && r.Status != Fail) {
			continue
		}
		f := byID[r.RuleID]
		v := domain.Validation{Health: "unknown"}
		if f.Validation != nil {
			v = *f.Validation
			v.TestRuns = append([]domain.TestRun(nil), v.TestRuns...)
		}
		// Generated cases are recomputed as a set, so the previous set goes: a
		// source that changes an example must not leave stale evidence behind.
		if r.Origin == OriginUpstream && !cleared[f.ID] {
			cleared[f.ID] = true
			kept := v.TestRuns[:0]
			for _, tr := range v.TestRuns {
				if tr.Origin != OriginUpstream {
					kept = append(kept, tr)
				}
			}
			v.TestRuns = kept
		}
		run := domain.TestRun{Result: string(r.Status), FixtureRef: r.Ref(), At: now, Origin: r.Origin}
		run.Expect = "no_match"
		if r.Case.Expect.Match {
			run.Expect = "match"
		}
		replaced := false
		for i := range v.TestRuns {
			if v.TestRuns[i].FixtureRef == run.FixtureRef {
				v.TestRuns[i], replaced = run, true
			}
		}
		if !replaced {
			v.TestRuns = append(v.TestRuns, run)
		}
		f.Validation = &v
		byID[f.ID] = f
		touched[f.ID] = true
	}
	var out []domain.Fingerprint
	for id := range touched {
		f := byID[id]
		t := now
		f.Validation.LastValidatedAt = &t
		f.Validation.Health = health(f.Validation.TestRuns)
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func health(runs []domain.TestRun) string {
	var pos, neg bool
	for _, r := range runs {
		if r.Result == string(Fail) {
			return "broken"
		}
		if r.Result == string(Pass) {
			pos = pos || r.Expect == "match"
			neg = neg || r.Expect == "no_match"
		}
	}
	if pos && neg {
		return "ok"
	}
	return "unknown"
}
