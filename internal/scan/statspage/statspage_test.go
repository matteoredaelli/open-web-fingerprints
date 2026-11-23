// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package statspage

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/matteoredaelli/open-web-fingerprints/scan"
)

func sample() *scan.Stats {
	return &scan.Stats{
		SchemaVersion: scan.StatsSchemaVersion, GeneratedAt: time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC), Scanner: "owfscan test", List: "sites.txt",
		Registry: scan.StatsSource{ContentSHA256: "sha256:0123456789abcdef0123", Sources: []string{"a"}, Notice: "unreviewed data: internal use only"},
		Filters:  scan.StatsFilter{MinSites: 3, ExcludedTech: []string{"noisy"}},
		Sites:    scan.StatsSites{Listed: 100, Scanned: 90, Reached: 80, Failed: 10},
		Technologies: []scan.StatTech{
			{Name: "<script>alert(1)</script>", Categories: []string{"CMS"}, Sites: 40, Share: 0.5},
			{Name: "nginx", Categories: []string{"Web servers"}, Sites: 20, Share: 0.25},
		},
		Families:      []scan.StatFamily{{Name: "Web servers and proxies", Sites: 20, Share: 0.25, Technologies: []scan.StatTech{{Name: "nginx", Sites: 20, Share: 0.25}}}},
		DomainSignals: []scan.StatTech{{Name: "Google Workspace", Sites: 10, Share: 0.125}},
		Categories:    []scan.StatCount{{Name: "CMS", Sites: 40, Share: 0.5}},
		Headers:       []scan.StatCount{{Name: "strict-transport-security", Sites: 30, Share: 0.375}},
		Pairs:         []scan.StatPair{{A: "nginx", B: "PHP", Sites: 9, Share: 0.11}},
		Coverage:      scan.StatsCoverage{MeanPercent: 61.4, MedianTechs: 3, MeanTechs: 3.2},
		Other:         scan.StatsOther{TechnologiesHidden: 7},
		Notes:         []string{"a note"},
	}
}

func render(t *testing.T, s *scan.Stats) string {
	t.Helper()
	var b bytes.Buffer
	if err := Render(&b, s, Options{}); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func TestRendersTheSections(t *testing.T) {
	out := render(t, sample())
	for _, want := range []string{
		"Web technology statistics", "sites.txt", "Internal use", "Categories", "nginx", "Domain signals", "Google Workspace",
		"By family", "Web servers and proxies", "Seen together", "nginx &#43; PHP", "strict-transport-security", "50.0%", "7 technologies", "noisy", "a note", "How to read this page",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("page lacks %q", want)
		}
	}
}

func TestEscapesAndHasNoScript(t *testing.T) {
	out := render(t, sample())
	if strings.Contains(out, "<script") || strings.Contains(out, "onerror") && strings.Contains(out, "<img") {
		t.Error("unescaped markup in the page")
	}
	if !strings.Contains(out, "&lt;script&gt;") {
		t.Error("the hostile name was not escaped")
	}
	if strings.Contains(out, "http://") || strings.Contains(out, "https://") {
		t.Error("the page refers to the network")
	}
}

func TestDeterministic(t *testing.T) {
	a, b := render(t, sample()), render(t, sample())
	if a != b {
		t.Error("two renders differ")
	}
}

func TestEmptyAndNil(t *testing.T) {
	if err := Render(&bytes.Buffer{}, nil, Options{}); err == nil {
		t.Error("nil statistics must fail")
	}
	out := render(t, &scan.Stats{})
	if !strings.Contains(out, "No technology was seen") {
		t.Error("empty statistics not explained")
	}
}
