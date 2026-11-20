// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package validation

import (
	"errors"
	"fmt"

	"github.com/matteoredaelli/open-web-fingerprints/internal/domain"
	"github.com/matteoredaelli/open-web-fingerprints/internal/matcher"
)

// runGroup evaluates a case that names a group of rules. The selectors must
// list every member: a case that names part of a group would test a different,
// weaker rule. Rules of different groups can look alike (many templates repeat
// "status is 200"), so the group is found by what it contains, and exactly one
// group of the technology must fit.
func runGroup(l Loaded, rules []domain.Fingerprint) Result {
	r := Result{Loaded: l}
	fail := func(status Status, format string, a ...any) Result {
		r.Status, r.Message = status, fmt.Sprintf(format, a...)
		return r
	}
	byGroup := map[domain.GroupID][]domain.Fingerprint{}
	var order []domain.GroupID
	for _, f := range rules {
		if f.GroupID == "" {
			continue
		}
		if _, ok := byGroup[f.GroupID]; !ok {
			order = append(order, f.GroupID)
		}
		byGroup[f.GroupID] = append(byGroup[f.GroupID], f)
	}
	sel := l.Case.Group
	var found [][]domain.Fingerprint
	for _, id := range order {
		if members, ok := assign(sel, byGroup[id]); ok {
			found = append(found, members)
		}
	}
	switch len(found) {
	case 0:
		return fail(Error, "no group of %q has exactly these %d members: the fixture may be stale", sel[0].Technology, len(sel))
	case 1:
	default:
		return fail(Error, "%d groups of %q have these members; add a pattern or target to tell them apart", len(found), sel[0].Technology)
	}
	members := found[0]
	for _, m := range members {
		r.RuleIDs = append(r.RuleIDs, m.ID)
	}
	r.RuleID = members[0].ID
	got, err := matcher.EvaluateGroup(members, &l.Case.Input)
	switch {
	case errors.Is(err, matcher.ErrUnsupported):
		return fail(Unsupported, "%v", err)
	case err != nil:
		return fail(Error, "%v", err)
	case got.Matched != l.Case.Expect.Match:
		return fail(Fail, "expected match=%v, got match=%v", l.Case.Expect.Match, got.Matched)
	case l.Case.Expect.Version != "" && got.Version != l.Case.Expect.Version:
		return fail(Fail, "expected version %q, got %q", l.Case.Expect.Version, got.Version)
	}
	r.Status = Pass
	return r
}

// assign matches each selector to a distinct member, using every member. It
// reports false unless the selectors and the members correspond one to one.
func assign(sel []Selector, members []domain.Fingerprint) ([]domain.Fingerprint, bool) {
	if len(sel) != len(members) {
		return nil, false
	}
	used := make([]bool, len(members))
	var try func(i int) bool
	try = func(i int) bool {
		if i == len(sel) {
			return true
		}
		for j, m := range members {
			if !used[j] && selects(sel[i], m) {
				used[j] = true
				if try(i + 1) {
					return true
				}
				used[j] = false
			}
		}
		return false
	}
	if !try(0) {
		return nil, false
	}
	return members, true
}

// selects reports whether a selector describes a rule (technology aside).
func selects(s Selector, f domain.Fingerprint) bool {
	obs := domain.Observation(s.Observation)
	return f.Observation == obs && f.Role == s.Role &&
		(s.Target == "" || domain.NormalizeTarget(obs, f.Target) == domain.NormalizeTarget(obs, s.Target)) &&
		(s.Operator == "" || string(f.Operator) == s.Operator) &&
		(s.Pattern == "" || f.Pattern == s.Pattern) &&
		(s.ProbePath == "" || (f.Probe != nil && f.Probe.Path == s.ProbePath))
}
