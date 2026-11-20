// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package validation_test

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/matteoredaelli/open-web-fingerprints/internal/domain"
	"github.com/matteoredaelli/open-web-fingerprints/internal/extractor"
	"github.com/matteoredaelli/open-web-fingerprints/internal/extractor/nuclei"
	"github.com/matteoredaelli/open-web-fingerprints/internal/matcher"
	"github.com/matteoredaelli/open-web-fingerprints/internal/pipeline"
	"github.com/matteoredaelli/open-web-fingerprints/internal/repository/memory"
	"github.com/matteoredaelli/open-web-fingerprints/internal/validation"
)

func nucleiRegistry(t *testing.T) domain.Records {
	t.Helper()
	reg := extractor.NewRegistry()
	if err := reg.Register(nuclei.New()); err != nil {
		t.Fatal(err)
	}
	repo := memory.New()
	_, err := pipeline.New(reg, repo).Run(context.Background(), pipeline.Request{
		Source:   domain.Source{Slug: "nuclei", ExtractorID: nuclei.ID, License: "MIT"},
		Revision: "x", FS: os.DirFS("../extractor/nuclei/testdata/snapshot"),
	})
	if err != nil {
		t.Fatal(err)
	}
	recs, _ := repo.AllRecords(context.Background())
	return recs
}

func TestGroupCases(t *testing.T) {
	recs := nucleiRegistry(t)
	cases, err := validation.Load("testdata/groups")
	if err != nil {
		t.Fatal(err)
	}
	rs := validation.Run(cases, recs)
	for _, r := range rs {
		if r.Status != validation.Pass {
			t.Errorf("%s: %s %s", r.Case.ID, r.Status, r.Message)
		}
		if len(r.RuleIDs) != 2 {
			t.Errorf("%s: evidence must cover both members: %v", r.Case.ID, r.RuleIDs)
		}
	}
	// Evidence lands on every member of the group, and only on that group.
	updated := validation.Apply(rs, recs, now)
	health := map[domain.FingerprintID]string{}
	for _, f := range updated {
		health[f.ID] = f.Validation.Health
	}
	var action, other int
	for _, f := range recs.Fingerprints {
		if strings.Contains(f.Pattern, "/4DACTION/") {
			for _, g := range recs.Fingerprints {
				if g.GroupID == f.GroupID && g.TechnologyID == f.TechnologyID {
					if health[g.ID] != "ok" {
						t.Errorf("member %s of the 4DACTION group: %q", g.Pattern, health[g.ID])
					}
					action++
				}
			}
		}
		if strings.Contains(f.Pattern, "/4DSTATS") && health[f.ID] != "" {
			other++
		}
	}
	if action != 2 || other != 0 {
		t.Errorf("members=%d, other groups touched=%d", action, other)
	}
	// The accellion group has a positive and a negative too.
	var ok int
	for id, h := range health {
		_ = id
		if h == "ok" {
			ok++
		}
	}
	if ok != 4 {
		t.Errorf("ok rules = %d, want the 4 members of the two tested groups", ok)
	}
}

func TestGroupSelectorProblems(t *testing.T) {
	recs := nucleiRegistry(t)
	mk := func(sel ...validation.Selector) validation.Loaded {
		return validation.Loaded{File: "g.json", Case: validation.Case{ID: "c", Group: sel, Expect: validation.Expect{Match: false}}}
	}
	st := validation.Selector{Technology: "4d", Observation: "http_status"}
	html := func(p string) validation.Selector {
		return validation.Selector{Technology: "4d", Observation: "html", Pattern: p}
	}
	for name, tc := range map[string]struct {
		c    validation.Loaded
		want string
	}{
		"ambiguous: every group has a status": {mk(st, validation.Selector{Technology: "4d", Observation: "html"}), "groups of"},
		"partial group":                       {mk(html("/4DACTION/"), html("/4DACTION/"), st), "no group"},
		"missing member":                      {mk(html("/4DACTION/")), "no group"},
		"members of two groups":               {mk(html("/4DACTION/"), html("/4DSTATS")), "no group"},
		"unknown technology":                  {mk(validation.Selector{Technology: "nope", Observation: "html"}, validation.Selector{Technology: "nope", Observation: "html"}), "no group"},
		"stale pattern":                       {mk(html("/gone/"), st), "stale"},
	} {
		r := validation.Run([]validation.Loaded{tc.c}, recs)[0]
		if r.Status != validation.Error || !strings.Contains(r.Message, tc.want) {
			t.Errorf("%s: %s %q", name, r.Status, r.Message)
		}
		if up := validation.Apply([]validation.Result{r}, recs, now); len(up) != 0 {
			t.Errorf("%s: an error must not become evidence", name)
		}
	}
}

func TestGroupFailureMakesAllMembersBroken(t *testing.T) {
	recs := nucleiRegistry(t)
	l := validation.Loaded{File: "g.json", Case: validation.Case{
		ID: "wrong",
		Group: []validation.Selector{
			{Technology: "4d", Observation: "html", Pattern: "/4DACTION/"},
			{Technology: "4d", Observation: "http_status"},
		},
		Input:  matcher.Observation{Status: 200, HTML: "/4DACTION/"},
		Expect: validation.Expect{Match: false},
	}}
	rs := validation.Run([]validation.Loaded{l}, recs)
	if rs[0].Status != validation.Fail {
		t.Fatalf("%+v", rs[0])
	}
	up := validation.Apply(rs, recs, now)
	if len(up) != 2 || up[0].Validation.Health != "broken" || up[1].Validation.Health != "broken" {
		t.Errorf("%+v", up)
	}
}

func TestGroupCaseFileRules(t *testing.T) {
	dir := t.TempDir()
	write := func(body string) error {
		if err := os.WriteFile(dir+"/g.json", []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		_, err := validation.Load(dir)
		return err
	}
	sel := `{"technology":"a","observation":"html"}`
	for name, body := range map[string]string{
		"both":       `{"schema_version":"0.1.0","cases":[{"id":"c","rule":` + sel + `,"group":[` + sel + `,` + sel + `],"input":{},"expect":{"match":true}}]}`,
		"neither":    `{"schema_version":"0.1.0","cases":[{"id":"c","input":{},"expect":{"match":true}}]}`,
		"one member": `{"schema_version":"0.1.0","cases":[{"id":"c","group":[` + sel + `],"input":{},"expect":{"match":true}}]}`,
		"two techs":  `{"schema_version":"0.1.0","cases":[{"id":"c","group":[` + sel + `,{"technology":"b","observation":"html"}],"input":{},"expect":{"match":true}}]}`,
	} {
		if err := write(body); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	if err := write(`{"schema_version":"0.1.0","cases":[{"id":"c","group":[` + sel + `,` + sel + `],"input":{},"expect":{"match":true}}]}`); err != nil {
		t.Errorf("a valid group case: %v", err)
	}
}
