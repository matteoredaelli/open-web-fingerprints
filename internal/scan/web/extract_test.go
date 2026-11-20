// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package web

import (
	"os"
	"strings"
	"testing"

	"github.com/matteoredaelli/open-web-fingerprints/scan"
)

func home(t *testing.T) Extraction {
	t.Helper()
	b, err := os.ReadFile("testdata/home.html")
	if err != nil {
		t.Fatal(err)
	}
	return Extract([]Page{{URL: "https://www.tyres.example/en/", Body: b}}, "www.tyres.example")
}

func findLink(ex Extraction, url, kind string) *scan.Link {
	for i := range ex.Links {
		if ex.Links[i].URL == url && ex.Links[i].Kind == kind {
			return &ex.Links[i]
		}
	}
	return nil
}

func TestLinks(t *testing.T) {
	ex := home(t)
	for _, tc := range []struct {
		url, kind string
		internal  bool
		domain    string
	}{
		{"https://www.tyres.example/en/tyres/", "a", true, "tyres.example"},                 // relative to <base>
		{"https://www.tyres.example/careers/", "a", true, "tyres.example"},                  // .. and no fragment
		{"https://www.tyres.example/press/", "a", true, "tyres.example"},                    // upper case host, default port
		{"https://shop.tyres-direct.example/?ref=home", "a", false, "tyres-direct.example"}, // query is kept
		{"https://www.tyres.example/etc.clientlibs/site.min.css", "link", true, "tyres.example"},
		{"https://www.tyres.example/en/app.js?v=3", "script", true, "tyres.example"},
		{"https://www.googletagmanager.com/gtm.js?id=GTM-XXXX", "script", false, "googletagmanager.com"},
		{"https://www.tyres.example/it/", "link", true, "tyres.example"},
		{"https://www.tyres.example/img/logo.svg", "img", true, "tyres.example"},
		{"https://www.tyres.example/img/logo@2x.png", "img", true, "tyres.example"}, // srcset
		{"https://www.tyres.example/img/hero-lg.webp", "source", true, "tyres.example"},
		{"https://www.youtube.com/embed/xyz", "iframe", false, "youtube.com"},
		{"https://www.tyres.example/search", "form", true, "tyres.example"},
	} {
		l := findLink(ex, tc.url, tc.kind)
		if l == nil {
			t.Errorf("missing %s link %s", tc.kind, tc.url)
			continue
		}
		if l.Internal != tc.internal || l.Domain != tc.domain || l.FoundIn != "https://www.tyres.example/en/" {
			t.Errorf("%+v", *l)
		}
	}
	// Not links: javascript, fragments, empty, mailto, tel, CSS url().
	for _, l := range ex.Links {
		if strings.HasPrefix(l.URL, "mailto:") || strings.HasPrefix(l.URL, "tel:") || strings.Contains(l.URL, "javascript") ||
			strings.Contains(l.URL, "#") || strings.Contains(l.URL, "not-a-link") {
			t.Errorf("not a link: %+v", l)
		}
	}
	if l := findLink(ex, "https://www.tyres.example/en/", "link"); l == nil || l.Rel != "canonical" {
		t.Errorf("canonical: %+v", l)
	}
	seen := map[string]bool{}
	for _, l := range ex.Links {
		k := l.Kind + l.URL
		if seen[k] {
			t.Errorf("duplicate link %s %s", l.Kind, l.URL)
		}
		seen[k] = true
	}
}

func TestDomains(t *testing.T) {
	ex := home(t)
	if len(ex.Domains) == 0 || ex.Domains[0].Domain != "tyres.example" || !ex.Domains[0].Internal {
		t.Fatalf("the target's domain comes first: %+v", ex.Domains)
	}
	byName := map[string]scan.Domain{}
	var total int
	for _, d := range ex.Domains {
		byName[d.Domain] = d
		total += d.Links
		if len(d.Examples) == 0 || len(d.Examples) > 3 {
			t.Errorf("examples: %+v", d)
		}
	}
	if total != len(ex.Links) {
		t.Errorf("domains count %d links, there are %d", total, len(ex.Links))
	}
	if byName["linkedin.com"].Internal || byName["linkedin.com"].Links != 1 || byName["youtube.com"].Links != 1 {
		t.Errorf("%+v %+v", byName["linkedin.com"], byName["youtube.com"])
	}
	if _, ok := byName["www.tyres.example"]; ok {
		t.Error("domains are registrable domains, not hosts")
	}
}

func TestSocials(t *testing.T) {
	ex := home(t)
	by := map[string]scan.Social{}
	for _, s := range ex.Socials {
		by[s.Platform+":"+s.Handle] = s
	}
	vias := func(s scan.Social) string {
		var v []string
		for _, f := range s.Found {
			v = append(v, f.Via)
		}
		return strings.Join(v, ",")
	}
	want := map[string]string{
		"linkedin:example-tyres":                  "a,jsonld",
		"facebook:exampletyres":                   "a,jsonld",
		"x:exampletyres":                          "meta,rel-me,jsonld",
		"instagram:exampletyres":                  "a",
		"tiktok:exampletyres":                     "a",
		"github:example-tyres":                    "a",
		"telegram:exampletyres":                   "a",
		"whatsapp:390212345678":                   "a",
		"youtube:@exampletyres":                   "jsonld",
		"mastodon:@exampletyres@mastodon.example": "rel-me",
	}
	for k, v := range want {
		s, ok := by[k]
		if !ok {
			t.Errorf("missing %s", k)
			continue
		}
		got := map[string]bool{}
		for _, f := range s.Found {
			got[f.Via] = true
			if f.Page != "https://www.tyres.example/en/" {
				t.Errorf("%s found on %s", k, f.Page)
			}
		}
		for _, via := range strings.Split(v, ",") {
			if !got[via] {
				t.Errorf("%s: found via %s, want %s", k, vias(s), via)
			}
		}
	}
	for _, bad := range []string{"facebook:sharer", "x:intent", "github:features", "instagram:p"} {
		if _, ok := by[bad]; ok {
			t.Errorf("%s is not a profile", bad)
		}
	}
	if len(ex.Socials) != len(want) {
		t.Errorf("%d profiles, want %d: %v", len(ex.Socials), len(want), keys(by))
	}
	// The same account found three ways is one profile.
	if s := by["x:exampletyres"]; s.URL != "https://x.com/exampletyres" {
		t.Errorf("%+v", s)
	}
}

func keys[V any](m map[string]V) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestContacts(t *testing.T) {
	ex := home(t)
	got := map[string]string{}
	for _, c := range ex.Contacts {
		var vias []string
		for _, f := range c.Found {
			vias = append(vias, f.Via)
		}
		got[c.Kind+" "+c.Value] = strings.Join(vias, ",")
	}
	want := map[string]string{
		"email info@tyres.example":    "a",
		"email press@tyres.example":   "jsonld,text",
		"email sales@tyres.example":   "a",
		"email support@tyres.example": "a",
		"phone +390212345678":         "a,jsonld",
	}
	for k, v := range want {
		g, ok := got[k]
		if !ok {
			t.Errorf("missing %s (have %v)", k, got)
			continue
		}
		for _, via := range strings.Split(v, ",") {
			if !strings.Contains(g, via) {
				t.Errorf("%s found via %q, want %s", k, g, via)
			}
		}
	}
	for k := range got {
		if _, ok := want[k]; !ok {
			t.Errorf("unexpected contact %s", k)
		}
	}
	// "hello [at] tyres.example" and "logo@2x.png" are not addresses.
	if _, ok := got["email hello@tyres.example"]; ok {
		t.Error("obfuscated addresses are not guessed")
	}
}

func TestWarningsAndTolerance(t *testing.T) {
	ex := home(t)
	if len(ex.Warnings) != 1 || ex.Warnings[0].Code != "invalid_jsonld" {
		t.Errorf("warnings: %+v", ex.Warnings)
	}
	// Broken HTML, no body, a bad page URL: no panic, sensible output.
	for _, p := range []Page{
		{URL: "https://a.example/", Body: []byte("<a href='/x'>")},
		{URL: "https://a.example/", Body: nil},
		{URL: "https://a.example/", Body: []byte("\x00\xff<<<>>>")},
		{URL: "not a url", Body: []byte("<a href='/x'>")},
	} {
		_ = Extract([]Page{p}, "a.example")
	}
	if ex := Extract([]Page{{URL: "not a url", Body: []byte("x")}}, "a.example"); len(ex.Warnings) != 1 || ex.Warnings[0].Code != "invalid_page_url" {
		t.Errorf("bad page URL: %+v", ex.Warnings)
	}
	empty := Extract(nil, "a.example")
	if empty.Links == nil || empty.Domains == nil || empty.Socials == nil || empty.Contacts == nil {
		t.Error("collections must be empty, not nil, so that they encode as []")
	}
	if !strings.Contains(ex.String(), "links") {
		t.Error(ex.String())
	}
}

func TestSeveralPagesMerge(t *testing.T) {
	a := Page{URL: "https://www.example.org/", Body: []byte(`<a href="https://github.com/example">gh</a><a href="/about">about</a>`)}
	b := Page{URL: "https://www.example.org/about", Body: []byte(`<a href="https://github.com/example">gh</a><a href="mailto:a@example.org">m</a>`)}
	ex := Extract([]Page{a, b}, "example.org")
	if len(ex.Socials) != 1 || len(ex.Socials[0].Found) != 2 {
		t.Errorf("one profile found on two pages: %+v", ex.Socials)
	}
	if len(ex.Contacts) != 1 || ex.Contacts[0].Found[0].Page != "https://www.example.org/about" {
		t.Errorf("%+v", ex.Contacts)
	}
	// The same URL on two pages is two links: it says where it was found.
	n := 0
	for _, l := range ex.Links {
		if l.URL == "https://github.com/example" {
			n++
		}
	}
	if n != 2 {
		t.Errorf("links to github = %d", n)
	}
}

func TestNormalizeURL(t *testing.T) {
	base, _ := NormalizeURL(nil, "https://www.example.org/a/b/")
	for in, want := range map[string]string{
		"c":                             "https://www.example.org/a/b/c",
		"../c#x":                        "https://www.example.org/a/c",
		"//cdn.example.org/x":           "https://cdn.example.org/x",
		"HTTP://EXAMPLE.ORG:80":         "http://example.org/",
		"https://example.org:443/p?q=1": "https://example.org/p?q=1",
		"https://example.org:8443/":     "https://example.org:8443/",
		"https://user:pw@example.org/":  "https://example.org/",
		"https://example.org./":         "https://example.org/",
		"https://[2001:db8::1]/x":       "https://[2001:db8::1]/x",
	} {
		u, ok := NormalizeURL(base, in)
		if !ok || u.String() != want {
			t.Errorf("%q -> %v ok=%v, want %s", in, u, ok, want)
		}
	}
	for _, bad := range []string{"", "  ", "javascript:x", "data:text/html,x", "mailto:a@b.example", "ftp://x.example/", "http://", "%zz"} {
		if u, ok := NormalizeURL(base, bad); ok {
			t.Errorf("%q must be rejected, got %v", bad, u)
		}
	}
}

func TestRegistrableDomain(t *testing.T) {
	for in, want := range map[string]string{
		"www.pirelli.com": "pirelli.com", "blog.example.co.uk": "example.co.uk", "a.b.github.io": "b.github.io",
		"localhost": "localhost", "192.0.2.1": "192.0.2.1", "co.uk": "co.uk", "WWW.Example.ORG.": "example.org", "tyres.example": "tyres.example",
	} {
		if got := RegistrableDomain(in); got != want {
			t.Errorf("RegistrableDomain(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestEmailAndPhone(t *testing.T) {
	for in, want := range map[string]string{"Info@Example.ORG": "info@example.org", " a.b+c@sub.example.co.uk ": "a.b+c@sub.example.co.uk"} {
		if got, ok := NormalizeEmail(in); !ok || got != want {
			t.Errorf("email %q -> %q %v", in, got, ok)
		}
	}
	for _, bad := range []string{"", "a@b", "a@b.c", "@x.example", "a b@x.example", "logo@2x.png", "a@x.example..com", "a@-x.example"} {
		if got, ok := NormalizeEmail(bad); ok {
			t.Errorf("email %q accepted as %q", bad, got)
		}
	}
	for in, want := range map[string]string{
		"+39 02 1234 5678": "+390212345678", "0039-02-1234-5678": "+390212345678", "(02) 1234 5678": "0212345678",
		"+39 02 1234 5678;ext=12": "+390212345678", "+1 (555) 010-9999": "+15550109999",
	} {
		if got, ok := NormalizePhone(in); !ok || got != want {
			t.Errorf("phone %q -> %q %v, want %q", in, got, ok, want)
		}
	}
	for _, bad := range []string{"", "12345", "+1234567890123456", "abc", "000000", "+"} {
		if got, ok := NormalizePhone(bad); ok {
			t.Errorf("phone %q accepted as %q", bad, got)
		}
	}
}
