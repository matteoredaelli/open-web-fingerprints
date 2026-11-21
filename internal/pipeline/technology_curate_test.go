// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package pipeline_test

import (
	"context"
	"errors"
	"testing"

	"github.com/matteoredaelli/open-web-fingerprints/internal/curate"
	"github.com/matteoredaelli/open-web-fingerprints/internal/domain"
)

func zeta(t *testing.T, all domain.Records) domain.Technology {
	t.Helper()
	for _, x := range all.Technologies {
		if x.Name == "Zeta" {
			return x
		}
	}
	t.Fatal("no Zeta")
	return domain.Technology{}
}

func TestCuratedTechnologyFieldsSurviveRefresh(t *testing.T) {
	eachBackend(t, func(t *testing.T) {
		p, repo := setup(t)
		ctx := context.Background()
		fsys := mapFS(t)
		editTechFile(t, fsys, "src/technologies/a.json", func(d map[string]map[string]any) {
			d["Zeta"] = map[string]any{"cats": []int{1}, "website": "https://zeta.example", "description": "old", "html": "zeta"}
		})
		run(t, p, fsys, "r1")

		site, desc := "https://zeta.dev", "Curated text"
		got, err := curate.Technology(ctx, repo, "zeta", curate.TechnologyPatch{Website: &site, Description: &desc})
		if err != nil {
			t.Fatal(err)
		}
		if got.Website != site || len(got.Curated) != 2 {
			t.Fatalf("%+v", got)
		}

		// The source changes both fields: the reviewer's choice stays, the rest follows the source.
		editTechFile(t, fsys, "src/technologies/a.json", func(d map[string]map[string]any) {
			d["Zeta"]["website"] = "https://zeta.io"
			d["Zeta"]["description"] = "newer upstream text"
			d["Zeta"]["saas"] = true
		})
		run(t, p, fsys, "r2")
		all, err := repo.AllRecords(ctx)
		if err != nil {
			t.Fatal(err)
		}
		z := zeta(t, all)
		if z.Website != site || z.Description != desc || len(z.Curated) != 2 {
			t.Errorf("curated fields lost: %+v", z)
		}
		if z.SaaS == nil || !*z.SaaS {
			t.Errorf("an uncurated field must follow the source: %+v", z.SaaS)
		}
	})
}

func TestCurateTechnologyErrors(t *testing.T) {
	_, repo := setup(t)
	ctx := context.Background()
	bad, empty := "zeta.dev", ""
	if _, err := curate.Technology(ctx, repo, "zeta", curate.TechnologyPatch{}); err == nil {
		t.Error("an empty patch must fail")
	}
	if _, err := curate.Technology(ctx, repo, "nope", curate.TechnologyPatch{Website: &empty}); !errors.Is(err, curate.ErrNotFound) {
		t.Errorf("unknown technology: %v", err)
	}
	if _, err := curate.Technology(ctx, repo, "nope", curate.TechnologyPatch{Website: &bad}); err == nil {
		t.Error("a bad website must fail")
	}
	if _, err := curate.Technology(ctx, repo, "nope", curate.TechnologyPatch{VendorSlug: &bad}); err == nil {
		t.Error("an unknown vendor must fail")
	}
}
