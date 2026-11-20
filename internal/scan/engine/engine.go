// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

// Package engine applies the rules of a registry export to an observation and
// reports the technologies that match, with the evidence, and how much of the
// registry could be applied.
//
// What it does not do: it makes no request, executes no script and runs no probe.
// A rule that needs something the observation does not have is not evaluated, and
// is counted in the coverage with the reason, never treated as a miss.
package engine

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/matteoredaelli/open-web-fingerprints/internal/domain"
	"github.com/matteoredaelli/open-web-fingerprints/internal/matcher"
	"github.com/matteoredaelli/open-web-fingerprints/scan"
)

// Reasons a rule is not evaluated. They appear in the coverage of the result.
const (
	ReasonProbe      = "probe disabled"
	ReasonBrowser    = "needs a browser"
	ReasonRobots     = "robots.txt not fetched"
	ReasonNoDNS      = "no DNS data"
	ReasonNoTLS      = "no TLS data"
	ReasonNoFavicon  = "favicon not fetched"
	ReasonFlavor     = "pattern needs a backtracking engine"
	ReasonHealth     = "below the minimum health"
	ReasonDeprecated = "deprecated"
	ReasonOther      = "not supported by the matcher"
	ReasonInvalid    = "invalid rule"
	ReasonInert      = "cookie name is a pattern (inert upstream too)"
)

// Health levels, from worst to best.
var healthRank = map[string]int{"broken": 0, "degraded": 1, "unknown": 2, "ok": 3}

// ValidHealth reports whether s is a health level.
func ValidHealth(s string) bool { _, ok := healthRank[s]; return ok }

// Options configure a run.
type Options struct {
	// MinHealth is the lowest health a rule may have to be used: broken (every
	// rule, the default), degraded, unknown or ok.
	MinHealth string
	// MaxEvidence bounds the evidence listed for one technology (default 50).
	MaxEvidence int
}

// Input is what the rules are applied to.
type Input struct {
	Observation *matcher.Observation
	// Page is the URL the observation comes from.
	Page string
	// DNSLooked, HasTLS and FaviconTried tell which observations were attempted.
	DNSLooked, HasTLS, FaviconTried bool
}

// Output is the outcome of a run.
type Output struct {
	Technologies []scan.Technology
	Coverage     scan.Coverage
	Warnings     []scan.Warning
}

// Engine holds an indexed registry. It is built once and can serve many runs.
type Engine struct {
	reg        *domain.Registry
	techs      []domain.Technology
	vendors    map[domain.VendorID]string
	categories map[domain.CategoryID]string
	sources    map[domain.SourceID]string
	rules      map[domain.TechnologyID]*techRules
}

type techRules struct {
	singles  []domain.Fingerprint
	groups   map[domain.GroupID][]domain.Fingerprint
	groupIDs []domain.GroupID
	versions []domain.Fingerprint
}

// New indexes a registry.
func New(reg *domain.Registry) *Engine {
	e := &Engine{
		reg: reg, vendors: map[domain.VendorID]string{}, categories: map[domain.CategoryID]string{},
		sources: map[domain.SourceID]string{}, rules: map[domain.TechnologyID]*techRules{},
	}
	for _, v := range reg.Vendors {
		e.vendors[v.ID] = v.Name
	}
	for _, c := range reg.Categories {
		e.categories[c.ID] = c.Name
	}
	for _, s := range reg.Sources {
		e.sources[s.ID] = s.Slug
	}
	e.techs = append(e.techs, reg.Technologies...)
	sort.Slice(e.techs, func(i, j int) bool { return e.techs[i].ID < e.techs[j].ID })
	for _, f := range reg.Fingerprints {
		r := e.rules[f.TechnologyID]
		if r == nil {
			r = &techRules{groups: map[domain.GroupID][]domain.Fingerprint{}}
			e.rules[f.TechnologyID] = r
		}
		switch {
		case f.Role == domain.RoleVersion:
			r.versions = append(r.versions, f)
		case f.GroupID != "":
			if _, ok := r.groups[f.GroupID]; !ok {
				r.groupIDs = append(r.groupIDs, f.GroupID)
			}
			r.groups[f.GroupID] = append(r.groups[f.GroupID], f)
		default:
			r.singles = append(r.singles, f)
		}
	}
	return e
}

// Rules returns the number of rules of the registry.
func (e *Engine) Rules() int { return len(e.reg.Fingerprints) }

type run struct {
	e        *Engine
	in       Input
	opt      Options
	p        *matcher.Prepared
	skipped  map[string]int
	evaluate int
	invalid  int
}

// Run applies the registry to the input.
func (e *Engine) Run(in Input, opt Options) Output {
	if opt.MaxEvidence <= 0 {
		opt.MaxEvidence = 50
	}
	if opt.MinHealth == "" {
		opt.MinHealth = "broken"
	}
	r := &run{e: e, in: in, opt: opt, p: matcher.Prepare(in.Observation), skipped: map[string]int{}}
	var out Output
	for _, t := range e.techs {
		rules := e.rules[t.ID]
		if rules == nil {
			continue
		}
		if t.Status == domain.StatusDeprecated {
			r.skipped[ReasonDeprecated] += rules.count()
			continue
		}
		if tech, ok := r.technology(t, rules, &out); ok {
			out.Technologies = append(out.Technologies, tech)
		}
	}
	sort.SliceStable(out.Technologies, func(i, j int) bool {
		a, b := out.Technologies[i], out.Technologies[j]
		if la, lb := strings.ToLower(a.Name), strings.ToLower(b.Name); la != lb {
			return la < lb
		}
		return a.Slug < b.Slug
	})
	if out.Technologies == nil {
		out.Technologies = []scan.Technology{}
	}
	unsupported := 0
	for _, n := range r.skipped {
		unsupported += n
	}
	out.Coverage = scan.Coverage{
		RulesTotal: e.Rules(), RulesEvaluated: r.evaluate, RulesUnsupported: unsupported, Skipped: r.skipped,
	}
	if len(r.skipped) == 0 {
		out.Coverage.Skipped = nil
	}
	if r.invalid > 0 {
		out.Warnings = append(out.Warnings, scan.Warning{Code: "invalid_rules",
			Message: fmt.Sprintf("%d rules of the registry could not be evaluated (a pattern does not compile); they were skipped", r.invalid), Ref: ReasonInvalid})
	}
	return out
}

func (t *techRules) count() int {
	n := len(t.singles) + len(t.versions)
	for _, g := range t.groups {
		n += len(g)
	}
	return n
}

// reason says why a rule is not evaluated for this input, or "".
func (r *run) reason(f domain.Fingerprint) string {
	switch {
	case f.Probe != nil || f.Observation == domain.ObsProbeResponse:
		return ReasonProbe
	case f.Status == domain.StatusDeprecated:
		return ReasonDeprecated
	case matcher.InertReason(f) != "":
		return ReasonInert
	case rankOf(f) < healthRank[r.opt.MinHealth]:
		return ReasonHealth
	case f.Operator == domain.OpRegex && f.RegexFlavor != domain.FlavorRE2:
		return ReasonFlavor
	}
	switch f.Observation {
	case domain.ObsJSGlobal, domain.ObsXHR:
		return ReasonBrowser
	case domain.ObsRobots:
		return ReasonRobots
	case domain.ObsDNSRecord:
		if !r.in.DNSLooked {
			return ReasonNoDNS
		}
	case domain.ObsTLSCert:
		if !r.in.HasTLS {
			return ReasonNoTLS
		}
	case domain.ObsFaviconHash:
		if !r.in.FaviconTried {
			return ReasonNoFavicon
		}
	}
	return ""
}

func rankOf(f domain.Fingerprint) int {
	if f.Validation != nil {
		if rk, ok := healthRank[f.Validation.Health]; ok {
			return rk
		}
	}
	return healthRank["unknown"]
}

// eval evaluates one rule that has no reason to be skipped. skipReason is set when
// the matcher cannot evaluate it after all.
func (r *run) eval(f domain.Fingerprint) (out matcher.Outcome, skipReason string) {
	out, err := r.p.Evaluate(f)
	switch {
	case err == nil:
		return out, ""
	case errors.Is(err, matcher.ErrUnsupported):
		if strings.Contains(err.Error(), "needs a browser") {
			return out, ReasonBrowser
		}
		return out, ReasonOther
	default:
		r.invalid++
		return out, ReasonInvalid
	}
}

type hit struct {
	rule  domain.Fingerprint
	out   matcher.Outcome
	group string
}

// technology evaluates the rules of one technology.
func (r *run) technology(t domain.Technology, rules *techRules, o *Output) (scan.Technology, bool) {
	var hits []hit
	for _, f := range rules.singles {
		if why := r.reason(f); why != "" {
			r.skipped[why]++
			continue
		}
		out, why := r.eval(f)
		if why != "" {
			r.skipped[why]++
			continue
		}
		r.evaluate++
		if out.Matched {
			hits = append(hits, hit{rule: f, out: out})
		}
	}
	for _, gid := range rules.groupIDs {
		members := rules.groups[gid]
		if g, matched := r.group(members); matched {
			for i, m := range g {
				hits = append(hits, hit{rule: members[i], out: m, group: string(gid)})
			}
		}
	}
	if len(hits) == 0 {
		// Version rules only read a version of something that was detected.
		return scan.Technology{}, false
	}
	// Version rules apply to the page the detection came from.
	for _, f := range rules.versions {
		if why := r.reason(f); why != "" {
			r.skipped[why]++
			continue
		}
		out, why := r.eval(f)
		if why != "" {
			r.skipped[why]++
			continue
		}
		r.evaluate++
		if out.Matched && out.Version != "" {
			hits = append(hits, hit{rule: f, out: out})
		}
	}
	return r.build(t, hits, o), true
}

// group evaluates the members of a group. It returns the outcome of each member
// and whether all matched. A member that cannot be evaluated makes the whole
// group unsupported; every member is then counted under the reason.
func (r *run) group(members []domain.Fingerprint) ([]matcher.Outcome, bool) {
	for _, f := range members {
		if why := r.reason(f); why != "" {
			r.skipped[why] += len(members)
			return nil, false
		}
	}
	outs := make([]matcher.Outcome, len(members))
	all := true
	for i, f := range members {
		out, why := r.eval(f)
		if why != "" {
			r.skipped[why] += len(members)
			return nil, false
		}
		outs[i] = out
		all = all && out.Matched
	}
	r.evaluate += len(members)
	return outs, all
}

// build turns the matching rules of a technology into the result's record.
func (r *run) build(t domain.Technology, hits []hit, o *Output) scan.Technology {
	e := r.e
	rec := scan.Technology{ID: string(t.ID), Slug: t.Slug, Name: t.Name, Vendor: e.vendors[t.VendorID]}
	for _, c := range t.CategoryIDs {
		if n := e.categories[c]; n != "" {
			rec.Categories = append(rec.Categories, n)
		}
	}
	sort.Strings(rec.Categories)
	sort.SliceStable(hits, func(i, j int) bool { return hits[i].rule.ID < hits[j].rule.ID })

	type vote struct {
		version string
		conf    float64
		health  int
		id      domain.FingerprintID
	}
	var votes []vote
	sources := map[string]bool{}
	for _, h := range hits {
		f := h.rule
		health := "unknown"
		if f.Validation != nil && f.Validation.Health != "" {
			health = f.Validation.Health
		}
		src := ""
		for i, p := range f.Provenance {
			name := e.sources[p.SourceID]
			if name == "" {
				name = string(p.SourceID)
			}
			if i == 0 {
				src = name
			}
			sources[name] = true
		}
		if health != "broken" && f.Confidence > rec.Confidence {
			rec.Confidence = f.Confidence
		}
		if h.out.Version != "" {
			votes = append(votes, vote{h.out.Version, f.Confidence, healthRank[health], f.ID})
		}
		if len(rec.Evidence) >= r.opt.MaxEvidence {
			continue
		}
		rec.Evidence = append(rec.Evidence, scan.Evidence{
			RuleID: string(f.ID), Observation: string(f.Observation), Target: f.Target,
			Matched: clip(h.out.Value, 300), Version: h.out.Version, Health: health, Source: src,
			Group: h.group, Page: r.in.Page,
		})
	}
	for s := range sources {
		rec.Sources = append(rec.Sources, s)
	}
	sort.Strings(rec.Sources)
	if len(hits) > len(rec.Evidence) {
		o.Warnings = append(o.Warnings, scan.Warning{Code: "evidence_truncated",
			Message: fmt.Sprintf("%d of %d matching rules are listed", len(rec.Evidence), len(hits)), Ref: t.Slug})
	}
	// The version of the rule with the highest confidence wins, healthier rules
	// first; a disagreement is reported, not hidden.
	if len(votes) > 0 {
		sort.SliceStable(votes, func(i, j int) bool {
			a, b := votes[i], votes[j]
			if a.health != b.health {
				return a.health > b.health
			}
			if a.conf != b.conf {
				return a.conf > b.conf
			}
			return a.id < b.id
		})
		rec.Version = votes[0].version
		distinct := map[string]bool{}
		for _, v := range votes {
			distinct[v.version] = true
		}
		if len(distinct) > 1 {
			var vs []string
			for v := range distinct {
				vs = append(vs, v)
			}
			sort.Strings(vs)
			o.Warnings = append(o.Warnings, scan.Warning{Code: "conflicting_versions",
				Message: fmt.Sprintf("rules give different versions (%s); %s was chosen", strings.Join(vs, ", "), rec.Version), Ref: t.Slug})
		}
	}
	return rec
}

// clip cuts a string to n characters without breaking a UTF-8 sequence.
func clip(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return strings.ToValidUTF8(s, "")
	}
	r := []rune(strings.ToValidUTF8(s, ""))
	return string(r[:n-1]) + "…"
}
