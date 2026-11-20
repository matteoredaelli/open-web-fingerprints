// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package pipeline_test

import (
	"context"
	"testing"
	"time"

	"github.com/matteoredaelli/open-web-fingerprints/internal/curate"
	"github.com/matteoredaelli/open-web-fingerprints/internal/domain"
	"github.com/matteoredaelli/open-web-fingerprints/internal/repository"
)

func cookieRule(t *testing.T, repo repository.Repository) domain.Fingerprint {
	t.Helper()
	all, err := repo.AllRecords(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range all.Fingerprints {
		if f.Observation == "cookie" {
			return f
		}
	}
	t.Fatal("no cookie rule")
	return domain.Fingerprint{}
}

func TestCorrectionSurvivesRefreshWhileUpstreamIsUnchanged(t *testing.T) {
	eachBackend(t, func(t *testing.T) {
		p, repo := setup(t)
		ctx := context.Background()
		fsys := mapFS(t)
		editTechFile(t, fsys, "src/technologies/a.json", func(d map[string]map[string]any) {
			d["Zeta"] = map[string]any{"cats": []int{1}, "website": "https://zeta.example", "cookies": map[string]string{`zeta\.sid`: ""}}
		})
		run(t, p, fsys, "r1")
		f := cookieRule(t, repo)
		if f.Target != `zeta\.sid` {
			t.Fatalf("the importer is faithful: %q", f.Target)
		}

		fixed, err := curate.CorrectFingerprint(ctx, repo, f.ID, curate.Correction{Field: "target", Value: "zeta.sid", Reason: "a cookie name is literal"}, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if fixed.Target != "zeta.sid" || fixed.Correction.Original != `zeta\.sid` {
			t.Fatalf("%+v", fixed)
		}

		// Same upstream: nothing changes, the correction stays, and so do the diff and the raw fragment.
		rep := run(t, p, fsys, "r2")
		if len(rep.Diff.Fingerprints.Modified) != 0 {
			t.Errorf("a kept correction is not a change: %+v", rep.Diff.Fingerprints)
		}
		g := cookieRule(t, repo)
		if g.Target != "zeta.sid" || g.Correction == nil || g.Correction.Reason != "a cookie name is literal" || len(g.Raw) == 0 {
			t.Errorf("after refresh: %+v", g)
		}

		// The source changes the very value that was corrected. A rule's identity includes its
		// content, so this is a new rule: it starts clean, and the corrected one stays as
		// removed upstream (never deleted), still carrying the reviewer's record.
		editTechFile(t, fsys, "src/technologies/a.json", func(d map[string]map[string]any) {
			d["Zeta"]["cookies"] = map[string]string{`zeta_session`: ""}
		})
		rep = run(t, p, fsys, "r3")
		if len(rep.Diff.Fingerprints.Added) != 1 || len(rep.Diff.Fingerprints.Removed) != 1 {
			t.Errorf("a new rule and a removed one: %+v", rep.Diff.Fingerprints)
		}
		all, _ := repo.AllRecords(ctx)
		var fresh, old int
		for _, x := range all.Fingerprints {
			switch {
			case x.Observation == "cookie" && x.Target == "zeta_session" && x.Correction == nil:
				fresh++
			case x.Observation == "cookie" && x.Target == "zeta.sid" && x.Correction != nil && x.Provenance[0].State == "removed_upstream":
				old++
			}
		}
		if fresh != 1 || old != 1 {
			t.Errorf("fresh=%d archived corrected=%d", fresh, old)
		}
	})
}
