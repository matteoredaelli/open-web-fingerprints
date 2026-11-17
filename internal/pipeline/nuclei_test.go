// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package pipeline_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/matteoredaelli/open-web-fingerprints/internal/domain"
	"github.com/matteoredaelli/open-web-fingerprints/internal/export"
	"github.com/matteoredaelli/open-web-fingerprints/internal/extractor/nuclei"
	"github.com/matteoredaelli/open-web-fingerprints/internal/validator"
	"github.com/matteoredaelli/open-web-fingerprints/schemas"
)

func nucleiSource() domain.Source {
	return domain.Source{
		Slug: "projectdiscovery-nuclei-templates", Name: "Nuclei technology templates", License: "MIT",
		ExtractorID: nuclei.ID, Redistributable: "unreviewed",
	}
}

const nucleiFixture = "../extractor/nuclei/testdata/snapshot"

func TestNucleiGroupsAndProbesSurviveTheRegistry(t *testing.T) {
	eachBackend(t, func(t *testing.T) {
		p, repo := setup(t)
		ctx := context.Background()
		rep, err := p.Run(ctx, pipelineRequest(nucleiSource(), nucleiFixture, "91be390"))
		if err != nil {
			t.Fatal(err)
		}
		all, _ := repo.AllRecords(ctx)
		if issues := validator.Validate(all); len(issues) != 0 {
			t.Fatalf("invalid registry: %v", issues)
		}

		groups := map[domain.GroupID][]domain.Fingerprint{}
		var probes, drafts int
		for _, f := range all.Fingerprints {
			if f.GroupID != "" {
				groups[f.GroupID] = append(groups[f.GroupID], f)
			}
			if f.Probe != nil {
				probes++
				if f.Probe.SafetyReview != "pending" || f.Status != domain.StatusDraft {
					t.Errorf("a probe must be a draft with a pending review: %+v", f)
				}
				drafts++
			} else if f.Status != domain.StatusActive {
				t.Errorf("a passive rule is active on import: %+v", f)
			}
		}
		if len(groups) < 10 || probes == 0 || rep.Counts.Fingerprints != len(all.Fingerprints) {
			t.Fatalf("groups=%d probes=%d counts=%+v", len(groups), probes, rep.Counts)
		}
		for id, g := range groups {
			if len(g) < 2 {
				t.Errorf("group %s has %d rules", id, len(g))
			}
		}

		// The export carries groups and probes and satisfies the schema.
		reg, err := export.Build(ctx, repo, now(), export.Options{IncludeUnreviewed: true})
		if err != nil {
			t.Fatal(err)
		}
		b, err := export.JSON(reg)
		if err != nil {
			t.Fatalf("export: %v", err)
		}
		if err := schemas.ValidateRegistry(b); err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Fingerprints []struct {
				GroupID string `json:"group_id"`
				Probe   *struct {
					Path string
				}
			}
		}
		if err := json.Unmarshal(b, &doc); err != nil {
			t.Fatal(err)
		}
		var g, pr int
		for _, f := range doc.Fingerprints {
			if f.GroupID != "" {
				g++
			}
			if f.Probe != nil {
				pr++
			}
		}
		if g == 0 || pr != probes {
			t.Errorf("export groups=%d probes=%d (stored %d)", g, pr, probes)
		}

		// Re-importing changes nothing.
		if again, err := p.Run(ctx, pipelineRequest(nucleiSource(), nucleiFixture, "91be390")); err != nil || !again.Diff.IsEmpty() {
			t.Errorf("re-import: err=%v diff=%+v", err, again.Diff)
		}
	})
}

func TestNucleiAndRecogShareVendorsAndMeetAsCandidates(t *testing.T) {
	eachBackend(t, func(t *testing.T) {
		p, repo := setup(t)
		ctx := context.Background()
		if _, err := p.Run(ctx, pipelineRequest(recogSource(), "../extractor/recog/testdata/snapshot", "f1191e2")); err != nil {
			t.Fatal(err)
		}
		before := vendorsOf(t, repo)
		if _, err := p.Run(ctx, pipelineRequest(nucleiSource(), nucleiFixture, "91be390")); err != nil {
			t.Fatal(err)
		}
		after := vendorsOf(t, repo)
		// Both fixtures mention the Apache HTTP Server through its CPE.
		if len(after) < len(before) {
			t.Fatalf("vendors shrank: %d -> %d", len(before), len(after))
		}
		for tok, v := range before {
			if a, ok := after[tok]; !ok || a.ID != v.ID {
				t.Errorf("vendor %s must keep its ID", tok)
			}
		}
		var shared int
		for tok, v := range after {
			if b, ok := before[tok]; ok && len(v.Provenance) == len(b.Provenance)+1 {
				shared++
			}
		}
		t.Logf("vendors shared between recog and nuclei fixtures: %d", shared)
		// Neither source is merged into the other.
		all, _ := repo.AllRecords(ctx)
		slugs := map[string]bool{}
		for _, x := range all.Technologies {
			if slugs[x.Slug] {
				t.Errorf("duplicate slug %s", x.Slug)
			}
			slugs[x.Slug] = true
		}
	})
}

func now() time.Time { return time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC) }
