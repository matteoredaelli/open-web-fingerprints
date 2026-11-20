// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package engine

import (
	"strings"
	"testing"

	"github.com/matteoredaelli/open-web-fingerprints/internal/domain"
	"github.com/matteoredaelli/open-web-fingerprints/scan"
)

func rel(id, from, to, typ string) domain.Relationship {
	r := domain.Relationship{ID: domain.RelationshipID(id), FromTechnologyID: domain.TechnologyID(from), Type: typ, Provenance: prov("src_a")}
	if strings.HasPrefix(to, "cat_") {
		r.ToCategoryID = domain.CategoryID(to)
	} else {
		r.ToTechnologyID = domain.TechnologyID(to)
	}
	return r
}

func engineWith(rels ...domain.Relationship) *Engine {
	r := reg([]domain.Technology{
		tech("t_lodash", "Lodash"), tech("t_under", "Underscore.js"), tech("t_wp", "WordPress"), tech("t_woo", "WooCommerce"),
		tech("t_back", "Backbone.js"), tech("t_plugin", "Plugin"), tech("t_hugo", "Hugo"), tech("t_old", "Old"), tech("t_new", "New"),
	})
	r.Relationships = rels
	return New(r)
}

func tc(id, name string, conf float64) scan.Technology {
	return scan.Technology{ID: id, Slug: strings.ToLower(name), Name: name, Confidence: conf, Sources: []string{"a"}, Evidence: []scan.Evidence{{RuleID: "fp_1"}}}
}

func names(o Output) string {
	var n []string
	for _, t := range o.Technologies {
		n = append(n, t.Name)
	}
	return strings.Join(n, ",")
}

func TestMutualExclusionKeepsTheMoreConfident(t *testing.T) {
	e := engineWith(rel("r1", "t_lodash", "t_under", "excludes"), rel("r2", "t_under", "t_lodash", "excludes"))
	out := e.Resolve(Output{Technologies: []scan.Technology{tc("t_lodash", "Lodash", 0.5), tc("t_under", "Underscore.js", 0)}})
	if names(out) != "Lodash" || len(out.Suppressed) != 1 || out.Suppressed[0].Name != "Underscore.js" ||
		out.Suppressed[0].Reason != scan.SuppressedExcluded || out.Suppressed[0].By[0] != "Lodash" {
		t.Fatalf("%s %+v", names(out), out.Suppressed)
	}
	// The other way round.
	out = e.Resolve(Output{Technologies: []scan.Technology{tc("t_lodash", "Lodash", 0.2), tc("t_under", "Underscore.js", 0.5)}})
	if names(out) != "Underscore.js" {
		t.Errorf("the more confident stays: %s", names(out))
	}
	// A tie keeps both and says so, once.
	out = e.Resolve(Output{Technologies: []scan.Technology{tc("t_lodash", "Lodash", 0.5), tc("t_under", "Underscore.js", 0.5)}})
	if names(out) != "Lodash,Underscore.js" || len(out.Suppressed) != 0 || len(out.Warnings) != 1 || out.Warnings[0].Code != "mutual_exclusion_tie" {
		t.Errorf("tie: %s %+v %+v", names(out), out.Suppressed, out.Warnings)
	}
}

func TestOneWayExclusionAndRequirements(t *testing.T) {
	e := engineWith(
		rel("r1", "t_new", "t_old", "excludes"), // New excludes Old, not the reverse
		rel("r2", "t_woo", "t_wp", "requires"),
		rel("r3", "t_plugin", "t_wp", "requires"), rel("r4", "t_plugin", "t_back", "requires"), // needs one of them
		rel("r5", "t_hugo", "cat_2", "requires"), // needs something in category CMS (cat_2)
	)
	cms := tc("t_wp", "WordPress", 0.5)
	cms.Categories = []string{"CMS"}
	// Old is excluded by New whatever their confidence.
	out := e.Resolve(Output{Technologies: []scan.Technology{tc("t_new", "New", 0.1), tc("t_old", "Old", 0.9)}})
	if names(out) != "New" || out.Suppressed[0].Name != "Old" {
		t.Errorf("one-way exclusion: %s %+v", names(out), out.Suppressed)
	}
	// WooCommerce without WordPress is held back, with the reason; with it, kept.
	out = e.Resolve(Output{Technologies: []scan.Technology{tc("t_woo", "WooCommerce", 0.5)}})
	if names(out) != "" || out.Suppressed[0].Reason != scan.SuppressedRequirement || out.Suppressed[0].By[0] != "WordPress" {
		t.Errorf("requirement: %s %+v", names(out), out.Suppressed)
	}
	out = e.Resolve(Output{Technologies: []scan.Technology{tc("t_woo", "WooCommerce", 0.5), cms}})
	if names(out) != "WooCommerce,WordPress" || len(out.Suppressed) != 0 {
		t.Errorf("requirement met: %s %+v", names(out), out.Suppressed)
	}
	// With several requirements, one is enough.
	out = e.Resolve(Output{Technologies: []scan.Technology{tc("t_plugin", "Plugin", 0.5), tc("t_back", "Backbone.js", 0.5)}})
	if names(out) != "Plugin,Backbone.js" {
		t.Errorf("one of several: %s", names(out))
	}
	// A category requirement is met by another detected technology of that category, not by itself.
	out = e.Resolve(Output{Technologies: []scan.Technology{tc("t_hugo", "Hugo", 0.5)}})
	if names(out) != "" || !strings.Contains(strings.Join(out.Suppressed[0].By, ","), "category CMS") {
		t.Errorf("category requirement: %s %+v", names(out), out.Suppressed)
	}
	out = e.Resolve(Output{Technologies: []scan.Technology{tc("t_hugo", "Hugo", 0.5), cms}})
	if names(out) != "Hugo,WordPress" {
		t.Errorf("category requirement met: %s", names(out))
	}
}

func TestImpliedTechnologiesSatisfyRequirementsButAreNotAdded(t *testing.T) {
	// Plugin requires WordPress; Backbone.js implies WordPress here (made up): seeing Backbone.js is enough.
	e := engineWith(rel("r1", "t_plugin", "t_wp", "requires"), rel("r2", "t_back", "t_wp", "implies"))
	out := e.Resolve(Output{Technologies: []scan.Technology{tc("t_plugin", "Plugin", 0.5), tc("t_back", "Backbone.js", 0.5)}})
	if names(out) != "Plugin,Backbone.js" {
		t.Errorf("implied: %s %+v", names(out), out.Suppressed)
	}
	if len(out.Technologies) != 2 {
		t.Error("implied technologies are not added to the result")
	}
}

func TestResolveUsesSameNameRecordsAndIgnoresRemovedRelationships(t *testing.T) {
	rm := rel("r2", "t_new", "t_old", "excludes")
	rm.Provenance[0].State = "removed_upstream"
	e := engineWith(rel("r1", "t_woo", "t_wp", "requires"), rm)
	// WordPress was detected through another record with the same name.
	wp := tc("t_other_wp", "WordPress", 0.5)
	wp.SameName = []string{"t_wp"}
	out := e.Resolve(Output{Technologies: []scan.Technology{tc("t_woo", "WooCommerce", 0.5), wp, tc("t_new", "New", 0.5), tc("t_old", "Old", 0.5)}})
	if !strings.Contains(names(out), "WooCommerce") || !strings.Contains(names(out), "Old") || len(out.Suppressed) != 0 {
		t.Errorf("%s %+v", names(out), out.Suppressed)
	}
	// Nothing to do on an empty result.
	if got := e.Resolve(Output{}); len(got.Technologies) != 0 || got.Suppressed != nil {
		t.Errorf("%+v", got)
	}
}

func TestImpliedTechnologies(t *testing.T) {
	low := 0.3
	rImplies := func(id, from, to string, conf *float64) domain.Relationship {
		r := rel(id, from, to, "implies")
		r.Confidence = conf
		return r
	}
	cat := tech("t_cat", "Cat")
	dep := tech("t_dep", "Dep")
	dep.Status = domain.StatusDeprecated
	r := reg([]domain.Technology{
		tech("t_wp", "WordPress"), tech("t_php", "PHP"), tech("t_mysql", "MySQL"), tech("t_linux", "Linux"), tech("t_back", "Backbone.js"),
		tech("t_under", "Underscore.js"), tech("t_lodash", "Lodash"), cat, dep,
	})
	r.Relationships = []domain.Relationship{
		rImplies("r1", "t_wp", "t_php", nil), rImplies("r2", "t_wp", "t_mysql", &low), rImplies("r3", "t_php", "t_linux", nil),
		rImplies("r4", "t_linux", "t_php", nil),                                                // a cycle
		rImplies("r5", "t_back", "t_under", nil), rel("r6", "t_lodash", "t_under", "excludes"), // Lodash excludes Underscore
		rImplies("r7", "t_wp", "t_dep", nil),   // deprecated: not implied
		rImplies("r8", "t_back", "t_php", nil), // a second implier of PHP
	}
	e := New(r)
	out := e.Resolve(Output{Technologies: []scan.Technology{tc("t_wp", "WordPress", 0.8), tc("t_back", "Backbone.js", 0.6), tc("t_lodash", "Lodash", 0.5)}})
	got := map[string]scan.Implied{}
	for _, i := range out.Implied {
		got[i.Name] = i
	}
	if len(out.Implied) != 3 {
		t.Fatalf("implied: %+v", out.Implied)
	}
	if p := got["PHP"]; strings.Join(p.ImpliedBy, ",") != "Backbone.js,Linux,WordPress" || p.Confidence != 0.8 {
		t.Errorf("PHP is implied by both found ones (and, through the cycle, by Linux), with the better confidence: %+v", p)
	}
	if m := got["MySQL"]; m.Confidence != 0.3 || strings.Join(m.ImpliedBy, ",") != "WordPress" {
		t.Errorf("the relationship's own confidence lowers it: %+v", m)
	}
	if l := got["Linux"]; strings.Join(l.ImpliedBy, ",") != "PHP" || l.Confidence != 0.8 {
		t.Errorf("implied through another implied technology: %+v", l)
	}
	if _, ok := got["Underscore.js"]; ok {
		t.Error("what a found technology excludes is not implied")
	}
	if _, ok := got["Dep"]; ok {
		t.Error("a deprecated technology is not implied")
	}
	// A technology that was found is not also "implied".
	out = e.Resolve(Output{Technologies: []scan.Technology{tc("t_wp", "WordPress", 0.8), tc("t_php", "PHP", 0.5)}})
	for _, i := range out.Implied {
		if i.Name == "PHP" || i.Name == "WordPress" {
			t.Errorf("already found: %+v", i)
		}
	}
	// A suppressed technology implies nothing.
	r2 := reg([]domain.Technology{tech("t_wp", "WordPress"), tech("t_php", "PHP"), tech("t_woo", "WooCommerce")})
	r2.Relationships = []domain.Relationship{rel("r1", "t_woo", "t_wp", "requires"), rel("r2", "t_woo", "t_php", "implies")}
	out = New(r2).Resolve(Output{Technologies: []scan.Technology{tc("t_woo", "WooCommerce", 0.5)}})
	if len(out.Technologies) != 0 || len(out.Implied) != 0 {
		t.Errorf("a technology held back implies nothing: %+v %+v", out.Technologies, out.Implied)
	}
}
