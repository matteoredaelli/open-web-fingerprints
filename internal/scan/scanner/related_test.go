// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package scanner

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/fetch"
	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/web"
	"github.com/matteoredaelli/open-web-fingerprints/scan"
)

const targetHome = `<html><head>
<meta name="google-site-verification" content="TOKEN-OWNER-1">
<link rel="alternate" hreflang="it" href="https://alpha.it/">
<script src="https://www.googletagmanager.com/gtm.js?id=GTM-OWNER1"></script>
</head><body>
<a href="https://shared-token.example/">a</a> <a href="https://same-gtm.example/">b</a> <a href="https://mutual.example/">c</a>
<a href="https://just-linked.example/">d</a> <a href="https://shy.example/">e</a> <a href="https://www.linkedin.com/company/alpha">in</a>
</body></html>`

func relatedWeb() *virtualWeb {
	return &virtualWeb{hits: map[string][]string{}, sites: map[string]http.HandlerFunc{
		"shared-token.example": page(`<meta name="google-site-verification" content="TOKEN-OWNER-1">`),
		"same-gtm.example":     page(`<script src="https://www.googletagmanager.com/gtm.js?id=GTM-OWNER1"></script><script src="x.js?id=GTM-OTHER99"></script>`),
		"mutual.example":       page(`<a href="https://www.alpha.example/">alpha</a>`),
		"just-linked.example":  page(`<p>nothing about alpha, a different token <meta name="google-site-verification" content="TOKEN-OTHER"></p>`),
		"alpha.it":             page(`<link rel="alternate" hreflang="en" href="https://www.alpha.example/">`),
		"san.example":          page(`<p>named in the certificate</p>`),
		"shy.example": func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/robots.txt" {
				_, _ = fmt.Fprint(w, "User-agent: *\nDisallow: /\n")
				return
			}
			_, _ = fmt.Fprint(w, `<meta name="google-site-verification" content="TOKEN-OWNER-1">`)
		},
	}}
}

func homeFor(links ...string) HomeInfo {
	return HomeInfo{
		Domain: "alpha.example", URL: "https://www.alpha.example/", HTML: []byte(targetHome),
		Links: links0(targetHome), TLS: &scan.TLS{Subject: "CN=www.alpha.example,O=Alpha Holding SA,C=FR", DNSNames: []string{"www.alpha.example", "alpha.example", "*.san.example", "san.example"}},
	}
}

func links0(html string) []scan.Link {
	return web.Extract([]web.Page{{URL: "https://www.alpha.example/", Body: []byte(html)}}, "www.alpha.example").Links
}

func TestFindRelated(t *testing.T) {
	vw := relatedWeb()
	got := FindRelated(context.Background(), RelatedOptions{Fetch: fetch.Options{Transport: vw, Timeout: time.Second}, Delay: time.Millisecond}, homeFor())
	by := map[string]scan.RelatedDomain{}
	for _, d := range got.Domains {
		by[d.Domain] = d
	}
	kinds := func(d string) string {
		var k []string
		for _, e := range by[d].Evidence {
			k = append(k, e.Kind)
		}
		return strings.Join(k, ",")
	}
	want := map[string][2]string{ // level, evidence kinds
		"shared-token.example": {"probable", "linked_from_home,site_verification"},
		"same-gtm.example":     {"probable", "linked_from_home,analytics_id"},
		"mutual.example":       {"probable", "linked_from_home,links_back"},
		"alpha.it":             {"probable", "hreflang_home,hreflang_back"},
		"san.example":          {"probable", "cert_san"},
		"just-linked.example":  {"candidate", "linked_from_home"},
	}
	for d, w := range want {
		if by[d].Level != w[0] || kinds(d) != w[1] {
			t.Errorf("%s: %s [%s], want %s [%s]", d, by[d].Level, kinds(d), w[0], w[1])
		}
	}
	// A page that shares a token but disallows crawlers is not read, so its token is not used.
	if s := by["shy.example"]; s.Status != "not_allowed" || s.Level != "candidate" || kinds("shy.example") != "linked_from_home" {
		t.Errorf("shy: %+v", s)
	}
	for _, p := range vw.hits["shy.example"] {
		if p != "/robots.txt" {
			t.Errorf("shy.example: %q requested although robots.txt disallows it", p)
		}
	}
	if _, ok := by["linkedin.com"]; ok || len(vw.hits["www.linkedin.com"]) != 0 {
		t.Error("a social platform is neither a candidate nor contacted")
	}
	if got.Candidates != 7 || got.Checked != 7 {
		t.Errorf("candidates=%d checked=%d", got.Candidates, got.Checked)
	}
	// The order: probable first, the strongest first.
	for i := 1; i < len(got.Domains); i++ {
		a, b := got.Domains[i-1], got.Domains[i]
		if a.Level == "candidate" && b.Level == "probable" {
			t.Errorf("order: %s before %s", a.Domain, b.Domain)
		}
	}
	for _, e := range by["shared-token.example"].Evidence {
		if e.Kind == scan.RelEvSiteVerification && (strings.Contains(e.Detail, "OWNER-1") || e.Strength != "strong") {
			t.Errorf("the token is shortened in the output: %+v", e)
		}
	}
}

func TestFindRelatedLimitAndCancel(t *testing.T) {
	vw := relatedWeb()
	opt := RelatedOptions{Fetch: fetch.Options{Transport: vw, Timeout: time.Second}, Delay: time.Millisecond, Max: 2}
	got := FindRelated(context.Background(), opt, homeFor())
	if got.Checked != 2 {
		t.Fatalf("checked %d", got.Checked)
	}
	// With a low limit the candidates that already have strong signals are read first.
	for _, d := range got.Domains[:2] {
		if d.Status == "not_checked" {
			t.Errorf("a strong candidate was left unread: %+v", d)
		}
	}
	var unread int
	for _, d := range got.Domains {
		if d.Status == "not_checked" {
			unread++
		}
	}
	if unread != got.Candidates-2 {
		t.Errorf("the rest are listed as not_checked: %d", unread)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if g := FindRelated(ctx, opt, homeFor()); g.Checked != 0 {
		t.Errorf("a cancelled run reads nothing: %d", g.Checked)
	}
	if g := FindRelated(context.Background(), opt, HomeInfo{Domain: "alpha.example", URL: "https://www.alpha.example/", HTML: []byte("<p>x</p>")}); g.Candidates != 0 || g.Domains == nil {
		t.Errorf("nothing found: %+v", g)
	}
}

func TestFindRelatedUsesTheCertificateOrganization(t *testing.T) {
	// Two servers share a certificate whose organization is "Acme Co": the same verified organization.
	a := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/robots.txt" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<p>other site</p>"))
	}))
	defer a.Close()
	host := strings.Replace(a.URL, "127.0.0.1", "localhost", 1)
	home := HomeInfo{
		Domain: "alpha.example", URL: "https://www.alpha.example/", HTML: []byte(`<a href="` + host + `/">x</a>`),
		TLS: &scan.TLS{Subject: "CN=example.com,O=Acme Co,C=US"},
	}
	home.Links = web.Extract([]web.Page{{URL: home.URL, Body: home.HTML}}, "www.alpha.example").Links
	got := FindRelated(context.Background(), RelatedOptions{Fetch: fetch.Options{AllowPrivate: true, Insecure: true, Timeout: 3 * time.Second}, Delay: time.Millisecond}, home)
	if len(got.Domains) != 1 || got.Domains[0].Level != "probable" {
		t.Fatalf("%+v", got)
	}
	var org bool
	for _, e := range got.Domains[0].Evidence {
		org = org || (e.Kind == scan.RelEvCertOrg && e.Detail == "Acme Co")
	}
	if !org {
		t.Errorf("the organization in the certificate matched: %+v", got.Domains[0].Evidence)
	}
	// A different organization is no evidence.
	home.TLS.Subject = "CN=example.com,O=Someone Else,C=US"
	got = FindRelated(context.Background(), RelatedOptions{Fetch: fetch.Options{AllowPrivate: true, Insecure: true, Timeout: 3 * time.Second}, Delay: time.Millisecond}, home)
	if got.Domains[0].Level != "candidate" {
		t.Errorf("%+v", got.Domains[0])
	}
}

func TestScanWithRelated(t *testing.T) {
	vw := relatedWeb()
	vw.sites["www.alpha.example"] = page(`<a href="https://mutual.example/">m</a><a href="https://just-linked.example/">j</a>`)
	opt := options(t)
	opt.Fetch = fetch.Options{Transport: vw, Timeout: time.Second}
	opt.Related, opt.Delay = true, time.Millisecond
	res, err := Scan(context.Background(), opt, "https://www.alpha.example/")
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(res); err != nil {
		t.Fatalf("the result must satisfy the schema: %v", err)
	}
	if res.Related == nil || res.Related.Domains[0].Domain != "mutual.example" || res.Related.Domains[0].Level != "probable" {
		t.Errorf("%+v", res.Related)
	}
	opt.Related = false
	if res, err = Scan(context.Background(), opt, "https://www.alpha.example/"); err != nil || res.Related != nil {
		t.Errorf("not asked for, not there: %v %+v", err, res.Related)
	}
}
