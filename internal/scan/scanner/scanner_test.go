// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package scanner

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/fetch"
	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/scantest"
	"github.com/matteoredaelli/open-web-fingerprints/scan"
)

func options(t *testing.T) Options {
	t.Helper()
	reg, err := ParseRegistry(scantest.RegistryJSON(t))
	if err != nil {
		t.Fatal(err)
	}
	return Options{Registry: reg, Fetch: fetch.Options{AllowPrivate: true, Timeout: 3 * time.Second}, NoFavicon: true, Version: "test",
		Now: func() time.Time { return time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC) }}
}

func tech(r *scan.Result, name string) *scan.Technology {
	for i := range r.Technologies {
		if r.Technologies[i].Name == name {
			return &r.Technologies[i]
		}
	}
	return nil
}

func names(r *scan.Result) []string {
	var out []string
	for _, t := range r.Technologies {
		out = append(out, t.Name)
	}
	return out
}

func TestScanEndToEnd(t *testing.T) {
	srv := scantest.Site()
	defer srv.Close()
	opt := options(t)
	res, err := Scan(context.Background(), opt, srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(res); err != nil {
		t.Fatalf("the result must satisfy its schema: %v", err)
	}

	php := tech(res, "PHP")
	if php == nil || php.Version != "8.2.1" || len(php.Evidence) == 0 {
		t.Fatalf("PHP: %+v (have %v)", php, names(res))
	}
	four := tech(res, "4D")
	if four == nil || four.Version != "20.4.1" {
		t.Fatalf("4D: %+v (have %v)", four, names(res))
	}
	var group, version int
	for _, ev := range four.Evidence {
		if ev.Group != "" {
			group++
		}
		if ev.Version == "20.4.1" {
			version++
		}
		if ev.Health != "unknown" || ev.Source != "projectdiscovery-nuclei-templates" || ev.Page != res.Target.URL {
			t.Errorf("evidence: %+v", ev)
		}
	}
	if group < 2 || version == 0 {
		t.Errorf("a group of rules and a version rule: %+v", four.Evidence)
	}
	if tech(res, "A-Frame") == nil {
		t.Errorf("technologies: %v", names(res))
	}

	var li, gh, mast bool
	for _, s := range res.Socials {
		li = li || s.Platform == "linkedin"
		gh = gh || s.Platform == "github"
		mast = mast || s.Platform == "mastodon"
	}
	if !li || !gh || !mast || len(res.Contacts) != 2 || len(res.Links) == 0 || len(res.Domains) == 0 {
		t.Errorf("socials %+v contacts %+v", res.Socials, res.Contacts)
	}

	c := res.Coverage
	if c.RulesTotal == 0 || c.RulesEvaluated == 0 || c.Skipped["needs a browser"] == 0 || c.Skipped["probe disabled"] == 0 ||
		c.RulesUnsupported == 0 || c.RulesEvaluated+c.RulesUnsupported > c.RulesTotal {
		t.Errorf("coverage: %+v", c)
	}
	if c.Skipped["favicon not fetched"] == 0 {
		t.Errorf("the favicon was not fetched, so favicon rules are skipped, not missed: %+v", c.Skipped)
	}

	if !strings.HasPrefix(res.Registry.ContentSHA256, "sha256:") || len(res.Registry.Sources) != 3 || !strings.Contains(res.Registry.Notice, "internal use only") {
		t.Errorf("registry: %+v", res.Registry)
	}
	if res.Scanner != "owfscan test" || res.Target.Host != "127.0.0.1" || res.Pages[0].Status != 200 || res.ScannedAt.IsZero() {
		t.Errorf("result: %+v", res.Target)
	}

	again, err := Scan(context.Background(), opt, srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if len(again.Technologies) != len(res.Technologies) || again.Coverage.RulesEvaluated != res.Coverage.RulesEvaluated {
		t.Error("two scans of the same page must agree")
	}
}

// The export is made with --include-unreviewed: the scanner uses it and says so.
func TestUnreviewedSourcesAreNotRefused(t *testing.T) {
	reg, err := ParseRegistry(scantest.RegistryJSON(t))
	if err != nil || reg.Ref.Notice == "" {
		t.Fatalf("err=%v", err)
	}
}

func TestMinHealth(t *testing.T) {
	srv := scantest.Site()
	defer srv.Close()
	opt := options(t)
	opt.MinHealth = "ok"
	res, err := Scan(context.Background(), opt, srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	// Nothing in the fixtures has test evidence, so no rule is healthy enough.
	if len(res.Technologies) != 0 || res.Coverage.Skipped["below the minimum health"] == 0 {
		t.Errorf("%v %+v", names(res), res.Coverage)
	}
	if err := Validate(res); err != nil {
		t.Fatal(err)
	}
	opt.MinHealth = "great"
	if _, err := Scan(context.Background(), opt, srv.URL); err == nil {
		t.Error("an unknown health level must be refused")
	}
}

func TestRegistryIsVerified(t *testing.T) {
	good := scantest.RegistryJSON(t)
	for name, b := range map[string][]byte{
		"edited":  []byte(strings.Replace(string(good), `"name": "PHP"`, `"name": "PHPX"`, 1)),
		"garbage": []byte("{"),
		"empty":   nil,
	} {
		if _, err := ParseRegistry(b); err == nil {
			t.Errorf("%s: a damaged export must be refused", name)
		}
	}
	if _, err := LoadRegistry("/nonexistent/registry.json"); err == nil {
		t.Error("a missing file must fail")
	}
	if _, err := Scan(context.Background(), Options{}, "x"); err == nil {
		t.Error("no registry must fail")
	}
}

func TestScanRefusesLocalAddressesByDefault(t *testing.T) {
	opt := options(t)
	opt.Fetch = fetch.Options{Timeout: time.Second}
	srv := scantest.Site()
	defer srv.Close()
	if _, err := Scan(context.Background(), opt, srv.URL); err == nil {
		t.Error("a local address is refused by default")
	}
}
