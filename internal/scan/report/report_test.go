// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/matteoredaelli/open-web-fingerprints/scan"
)

func sample() *scan.Result {
	return &scan.Result{
		SchemaVersion: scan.SchemaVersion, ScannedAt: time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC), Scanner: "owfscan test",
		Target: scan.Target{Input: "x.example", URL: "https://www.x.example/", Host: "www.x.example", RegistrableDomain: "x.example"},
		Pages: []scan.Page{{FinalURL: "https://www.x.example/", Status: 200, Bytes: 1000, HeadersFiltered: true,
			Headers: map[string]string{"strict-transport-security": "max-age=63072000", "server": "nginx"}}},
		Technologies: []scan.Technology{
			{Name: "WordPress", Version: "6.4", Vendor: "Automattic", Categories: []string{"CMS", "Blogs"}, Confidence: 0.8, Sources: []string{"a"},
				Evidence: []scan.Evidence{{Observation: "meta_tag", Target: "generator", Matched: "WordPress 6.4", Health: "ok", Source: "a"}}},
			{Name: "<img src=x onerror=alert(1)>", Categories: []string{"Analytics"}, Confidence: 0.5, Sources: []string{"b"},
				Evidence: []scan.Evidence{{Observation: "html", Matched: `"><script>alert(2)</script>`, Health: "unknown", Source: "b"}}},
		},
		Implied:    []scan.Implied{{Name: "PHP", ImpliedBy: []string{"WordPress"}, Confidence: 0.5}},
		Suppressed: []scan.Suppressed{{Name: "Underscore.js", Reason: scan.SuppressedExcluded, By: []string{"Lodash"}}},
		Socials: []scan.Social{
			{Platform: "linkedin", Handle: "x-co", URL: "https://www.linkedin.com/company/x-co"},
			{Platform: "evil", Handle: "h", URL: "javascript:alert(3)"},
		},
		Contacts: []scan.Contact{{Kind: "email", Value: "info@x.example"}, {Kind: "phone", Value: "+390212345678"}},
		Domains:  []scan.Domain{{Domain: "x.example", Internal: true, Links: 50}, {Domain: "google.com", Links: 3}},
		Host: &scan.Host{IPs: []string{"203.0.113.9"}, DNS: map[string][]string{"NS": {"ns1.x.example"}},
			TLS: &scan.TLS{Issuer: "CN=R3", NotAfter: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)}},
		Related: &scan.Related{Candidates: 2, Checked: 2, Probable: []string{"x.org"}, Domains: []scan.RelatedDomain{
			{Domain: "x.org", Level: scan.RelatedProbable, Evidence: []scan.RelatedEvidence{{Kind: "cert_org", Strength: "strong"}}},
			{Domain: "x.net", Level: scan.RelatedCandidate},
		}},
		Friends:  &scan.Friends{Candidates: 1, Checked: 1, Domains: []scan.Friend{{Domain: "friend.example", Status: scan.FriendYes}}},
		Coverage: scan.Coverage{RulesTotal: 100, RulesEvaluated: 60, RulesUnsupported: 40, Skipped: map[string]int{"needs a browser": 30, "probe disabled": 10}},
		Registry: scan.RegistryRef{ContentSHA256: "sha256:0123456789abcdef0123", Sources: []string{"a", "b"}, Notice: "unreviewed data: internal use only"},
	}
}

func render(t *testing.T, r *scan.Result) string {
	t.Helper()
	var b bytes.Buffer
	if err := Render(&b, r, Options{}); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func TestRendersTheSections(t *testing.T) {
	out := render(t, sample())
	for _, want := range []string{
		"x.example", "HTTP 200", "WordPress", "6.4", "Automattic", "CMS", "Implied", "PHP", "Matched but not reported", "Underscore.js",
		"203.0.113.9", "ns1.x.example", "CN=R3", "days left", "1 of 6 present", "not a security assessment",
		"linkedin", "mailto:info@x.example", "tel:&#43;390212345678", "google.com", "friend.example", "x.org", "cert org",
		"60%", "needs a browser", "What was not seen", "unreviewed data: internal use only", "sha256:0123456789ab",
		"Content-Security-Policy", "<svg",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report lacks %q", want)
		}
	}
	if strings.Contains(out, "<script") {
		t.Error("the page must contain no script")
	}
}

func TestHostileValuesAreEscaped(t *testing.T) {
	out := render(t, sample())
	for _, bad := range []string{"<img src=x", "onerror=alert(1)>", `"><script>`, "javascript:"} {
		if strings.Contains(out, bad) {
			t.Errorf("unescaped or unsafe content %q reached the page", bad)
		}
	}
	if !strings.Contains(out, "&lt;img src=x onerror=alert(1)&gt;") {
		t.Error("the hostile name must appear as text")
	}
}

func TestSameResultSamePage(t *testing.T) {
	a, b := render(t, sample()), render(t, sample())
	if a != b {
		t.Error("the page must be a function of the result")
	}
}

func TestEmptyResultStillRenders(t *testing.T) {
	out := render(t, &scan.Result{SchemaVersion: scan.SchemaVersion, Target: scan.Target{Host: "h.example"}})
	if !strings.Contains(out, "No technology matched") || !strings.Contains(out, "h.example") {
		t.Errorf("empty result:\n%s", out[:min(len(out), 400)])
	}
	if err := Render(&bytes.Buffer{}, nil, Options{}); err == nil {
		t.Error("a nil result is an error")
	}
}

func TestTitleOption(t *testing.T) {
	var b bytes.Buffer
	if err := Render(&b, sample(), Options{Title: "Client <A>"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "Client &lt;A&gt;") {
		t.Error("title")
	}
}

func TestPrimaryCategory(t *testing.T) {
	if got := primary([]string{"Miscellaneous", "CMS", "Blogs"}); got != "CMS" {
		t.Errorf("%s", got)
	}
	if got := primary(nil); got != "Other" {
		t.Errorf("%s", got)
	}
	if safeURL("javascript:alert(1)") != "" || safeURL("data:text/html,x") != "" || safeURL("https://a.example/x") == "" {
		t.Error("safeURL")
	}
}
