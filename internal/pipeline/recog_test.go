// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package pipeline_test

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/matteoredaelli/open-web-fingerprints/internal/domain"
	"github.com/matteoredaelli/open-web-fingerprints/internal/extractor/recog"
	"github.com/matteoredaelli/open-web-fingerprints/internal/pipeline"
	"github.com/matteoredaelli/open-web-fingerprints/internal/validator"
)

func recogSource() domain.Source {
	return domain.Source{
		Slug: "rapid7-recog", Name: "Rapid7 Recog", License: "BSD-2-Clause",
		ExtractorID: recog.ID, Redistributable: "unreviewed",
	}
}

// Two sources with different formats and different kinds of data meet in one
// registry: shared vendors, candidates for the same product, nothing merged.
func TestRecogAndWappalyzerSideBySide(t *testing.T) {
	eachBackend(t, func(t *testing.T) {
		p, repo := setup(t)
		ctx := context.Background()
		run(t, p, mapFS(t), "r1")
		before, _ := repo.AllRecords(ctx)

		rep, err := p.Run(ctx, pipelineRequest(recogSource(), "../extractor/recog/testdata/snapshot", "f1191e2"))
		if err != nil {
			t.Fatal(err)
		}
		all, _ := repo.AllRecords(ctx)
		if issues := validator.Validate(all); len(issues) != 0 {
			t.Fatalf("invalid registry: %v", issues)
		}
		if len(all.Technologies) <= len(before.Technologies) || rep.Counts.Fingerprints == 0 {
			t.Fatalf("recog added nothing: %+v", rep.Counts)
		}

		// Recog's PHP and the Wappalyzer-format PHP share the vendor (same CPE
		// vendor "php") but are not merged: a reviewer decides.
		var php []domain.Technology
		for _, x := range all.Technologies {
			if x.Name == "PHP" {
				php = append(php, x)
			}
		}
		if len(php) != 2 || php[0].VendorID == "" || php[0].VendorID != php[1].VendorID {
			t.Fatalf("PHP: %+v", php)
		}
		var candidate bool
		for _, c := range conflictsOf(t, repo) {
			if c.Kind == domain.ConflictIdentityCandidate && c.Detail["name_a"] == "PHP" && c.Detail["websites"] == "unknown" {
				candidate = true
			}
		}
		if !candidate {
			t.Error("PHP must be an identity candidate, with unknown websites because Recog gives none")
		}

		// Recog brings observation types the other source does not have.
		seen := map[domain.Observation]bool{}
		for _, f := range all.Fingerprints {
			seen[f.Observation] = true
		}
		for _, o := range []domain.Observation{"page_title", "set_cookie", domain.ObsFaviconHash} {
			if !seen[o] {
				t.Errorf("no %s fingerprint", o)
			}
		}
		// Case-sensitive Recog patterns carry an explicit flag.
		var cs bool
		for _, f := range all.Fingerprints {
			if f.Provenance[0].SourceID != php[0].Provenance[0].SourceID && len(f.Pattern) > 5 && f.Pattern[:5] == "(?-i)" {
				cs = true
			}
		}
		if !cs {
			t.Error("recog patterns must be explicitly case-sensitive")
		}

		// Re-importing either changes nothing.
		if again, err := p.Run(ctx, pipelineRequest(recogSource(), "../extractor/recog/testdata/snapshot", "f1191e2")); err != nil || !again.Diff.IsEmpty() {
			t.Errorf("recog re-import: err=%v diff=%+v", err, again.Diff)
		}
		if again := run(t, p, mapFS(t), "r1"); !again.Diff.IsEmpty() {
			t.Errorf("wappalyzer re-import after recog: %+v", again.Diff)
		}
	})
}

func TestRecogUpstreamExamplesAreEvidenceInTheRegistry(t *testing.T) {
	// The stored rule keeps upstream's examples in its raw fragment, so that a
	// later step can turn them into validation cases.
	eachBackend(t, func(t *testing.T) {
		p, repo := setup(t)
		if _, err := p.Run(context.Background(), pipelineRequest(recogSource(), "../extractor/recog/testdata/snapshot", "f1191e2")); err != nil {
			t.Fatal(err)
		}
		all, _ := repo.AllRecords(context.Background())
		var withExamples int
		for _, f := range all.Fingerprints {
			if len(f.Raw) > 0 && strings.Contains(string(f.Raw), `"examples"`) {
				withExamples++
			}
		}
		if withExamples == 0 {
			t.Error("no stored rule has examples in its raw fragment")
		}
	})
}

func pipelineRequest(src domain.Source, dir, rev string) pipeline.Request {
	return pipeline.Request{Source: src, Revision: rev, FS: os.DirFS(dir)}
}
