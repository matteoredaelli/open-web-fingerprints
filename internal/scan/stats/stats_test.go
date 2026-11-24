// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package stats

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/batch"
	"github.com/matteoredaelli/open-web-fingerprints/scan"
	"github.com/matteoredaelli/open-web-fingerprints/schemas"
)

func tech(name, version string, conf float64, obs string, cats ...string) scan.Technology {
	return scan.Technology{Name: name, Version: version, Confidence: conf, Categories: cats, Evidence: []scan.Evidence{{Observation: obs}}}
}

func result(status int, techs ...scan.Technology) []byte {
	at := time.Date(2026, 11, 22, 0, 0, 0, 0, time.UTC)
	r := scan.Result{
		SchemaVersion: scan.SchemaVersion, ScannedAt: at,
		Pages:        []scan.Page{{Status: status, Headers: map[string]string{"strict-transport-security": "x"}}},
		Technologies: techs, Socials: []scan.Social{{Platform: "linkedin", Handle: "secret-handle"}},
		Contacts: []scan.Contact{{Kind: "email", Value: "private@x.example"}},
		Host:     &scan.Host{TLS: &scan.TLS{Issuer: "CN=R3,O=Let's Encrypt", NotAfter: at.Add(45 * 24 * time.Hour)}},
		Coverage: scan.Coverage{RulesTotal: 10, RulesEvaluated: 6},
		Registry: scan.RegistryRef{ContentSHA256: "sha256:abc", Sources: []string{"s"}},
	}
	b, _ := json.Marshal(r)
	return b
}

func TestCompute(t *testing.T) {
	ctx := context.Background()
	st, err := batch.Open(ctx, filepath.Join(t.TempDir(), "b.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	var sites []batch.Site
	for i, d := range []string{"a.example", "b.example", "c.example", "d.example", "e.example", "f.example"} {
		sites = append(sites, batch.Site{Domain: d, Rank: i + 1})
	}
	_, _ = st.Add(ctx, sites)
	_ = st.SetMeta(ctx, "list", "top.txt")
	now := time.Now()
	wp := func(v string) []scan.Technology {
		return []scan.Technology{tech("WordPress", v, 0.8, "html", "CMS"), tech("PHP", "", 0.7, "http_header", "Programming languages"), tech("Anthropic", "", 0.5, "dns_record", "Security")}
	}
	_ = st.SaveDone(ctx, "a.example", 200, result(200, wp("6.4")...), now)
	_ = st.SaveDone(ctx, "b.example", 200, result(200, wp("6.4")...), now)
	_ = st.SaveDone(ctx, "c.example", 200, result(200, append(wp("6.5"), tech("Rare", "", 0.9, "html", "Misc"), tech("Weak", "", 0.2, "html", "Misc"))...), now)
	_ = st.SaveDone(ctx, "d.example", 403, result(403, wp("1")...), now) // scanned, not reached
	_ = st.SaveFailed(ctx, "e.example", "dns: no such host", now)

	s, err := Compute(ctx, st, Options{MinConfidence: 0.3, MinSites: 2, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if s.Sites.Listed != 6 || s.Sites.Scanned != 4 || s.Sites.Reached != 3 || s.Sites.Failed != 1 || s.Sites.Pending != 1 {
		t.Errorf("sites %+v", s.Sites)
	}
	if len(s.Technologies) < 2 || s.Technologies[0].Name != "PHP" && s.Technologies[0].Name != "WordPress" || s.Technologies[0].Sites != 3 || s.Technologies[0].Share != 1 {
		t.Errorf("technologies %+v", s.Technologies)
	}
	var cms *scan.StatFamily
	for i := range s.Families {
		if s.Families[i].Name == FamilyCMS {
			cms = &s.Families[i]
		}
	}
	if cms == nil || cms.Sites != 3 || len(cms.Technologies) != 1 || cms.Technologies[0].Name != "WordPress" {
		t.Errorf("CMS family %+v (3 sites show WordPress)", cms)
	}
	var wpv []scan.StatCount
	for _, x := range s.Technologies {
		if x.Name == "WordPress" {
			wpv = x.Versions
		}
		if x.Name == "Rare" || x.Name == "Weak" || x.Name == "Anthropic" {
			t.Errorf("%s must not be a web technology listed here", x.Name)
		}
	}
	if len(wpv) != 1 || wpv[0].Name != "6.4" || wpv[0].Sites != 2 {
		t.Errorf("versions %+v (6.5 is on one site, under min_sites)", wpv)
	}
	if len(s.DomainSignals) != 1 || s.DomainSignals[0].Name != "Anthropic" {
		t.Errorf("domain signals %+v", s.DomainSignals)
	}
	if s.Other.TechnologiesHidden != 1 { // Rare: one site; Weak is under the confidence filter and not counted
		t.Errorf("hidden %d", s.Other.TechnologiesHidden)
	}
	if s.Headers[0].Name != "strict-transport-security" || s.Headers[0].Sites != 3 {
		t.Errorf("headers %+v", s.Headers)
	}
	if s.TLS.WithCertificate != 3 || s.TLS.DaysLeft[0].Name != "30 to 59 days" || s.TLS.Issuers[0].Name != "Let's Encrypt" {
		t.Errorf("tls %+v", s.TLS)
	}
	if len(s.Pairs) == 0 || s.Pairs[0].Sites != 3 {
		t.Errorf("pairs %+v", s.Pairs)
	}
	b, _ := json.Marshal(s)
	if err := schemas.ValidateStats(b); err != nil {
		t.Errorf("schema: %v", err)
	}
	for _, leak := range []string{"secret-handle", "private@x.example", "a.example", "b.example"} {
		if strings.Contains(string(b), leak) {
			t.Errorf("site-level data %q leaked into the statistics", leak)
		}
	}
	// Excluding a technology removes it.
	s2, _ := Compute(ctx, st, Options{MinSites: 2, Exclude: []string{"php"}})
	for _, x := range s2.Technologies {
		if x.Name == "PHP" {
			t.Error("excluded technology listed")
		}
	}
}

func TestFamilyOf(t *testing.T) {
	for _, c := range []struct {
		name string
		cats []string
		want string
	}{
		{"WordPress", []string{"Blogs", "CMS", "Platform"}, FamilyCMS},
		{"Next.js", []string{"JavaScript frameworks", "Static site generator", "Web servers"}, FamilyFramework},
		{"Nginx", []string{"Reverse proxies", "Web servers"}, FamilyServers},
		{"Varnish", []string{"CDN", "Caching", "Web servers"}, FamilyInfra},
		{"Cloudflare", []string{"CDN", "Security"}, FamilyInfra},
		{"HSTS", []string{"Security"}, FamilySignals},
		{"HTML5", nil, FamilySignals},
		{"Open Graph", []string{"Miscellaneous"}, FamilySignals},
		{"Cart Functionality", []string{"Ecommerce"}, FamilySignals},
		{"Intercom", []string{"Live chat"}, FamilyBusiness},
		{"Something", nil, FamilyOther},
		{"Odd", []string{"Unmapped category"}, FamilyOther},
	} {
		if got := FamilyOf(c.name, c.cats); got != c.want {
			t.Errorf("FamilyOf(%q, %v) = %q, want %q", c.name, c.cats, got, c.want)
		}
	}
}

func TestComputeLeavesOutGeneric(t *testing.T) {
	ctx := context.Background()
	st, err := batch.Open(ctx, filepath.Join(t.TempDir(), "b.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	_, _ = st.Add(ctx, []batch.Site{{Domain: "a.example", Rank: 1}})
	g := tech("Cart Functionality", "", 0.5, "dom", "Ecommerce")
	g.Generic = true
	_ = st.SaveDone(ctx, "a.example", 200, result(200, g, tech("PHP", "", 0.7, "http_header")), time.Now())
	names := func(opt Options) []string {
		s, err := Compute(ctx, st, opt)
		if err != nil {
			t.Fatal(err)
		}
		var n []string
		for _, x := range s.Technologies {
			n = append(n, x.Name)
		}
		return n
	}
	if got := names(Options{MinSites: 1}); len(got) != 1 || got[0] != "PHP" {
		t.Errorf("default: %v", got)
	}
	if got := names(Options{MinSites: 1, IncludeGeneric: true}); len(got) != 2 {
		t.Errorf("included: %v", got)
	}
}

func checkedResult(c *scan.Checks) []byte {
	var r scan.Result
	_ = json.Unmarshal(result(200), &r)
	r.Checks = c
	b, _ := json.Marshal(r)
	return b
}

func TestComputeChecks(t *testing.T) {
	ctx := context.Background()
	st, err := batch.Open(ctx, filepath.Join(t.TempDir(), "b.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	_, _ = st.Add(ctx, []batch.Site{{Domain: "a.example", Rank: 1}, {Domain: "b.example", Rank: 2}, {Domain: "c.example", Rank: 3}, {Domain: "d.example", Rank: 4}})
	now := time.Now()
	mk := func(hsts string, dmarc string, bots bool) *scan.Checks {
		c := &scan.Checks{
			Headers:   &scan.HeaderChecks{Headers: []scan.HeaderCheck{{Name: "strict-transport-security", Status: hsts}}, Cookies: []scan.CookieCheck{{Name: "sid", Issues: []string{"no_httponly"}}}},
			Transport: &scan.TransportCheck{HTTPS: true, HTTP2: true, TLSVersion: "TLS 1.3", HTTP3Advertised: bots},
			Policies:  &scan.Policies{Robots: &scan.RobotsCheck{Present: true, AIBots: []scan.AIBot{{Name: "GPTBot", Named: bots, Blocked: bots}, {Name: "CCBot", Blocked: true}}}, SecurityTxt: &scan.SecurityTxt{Present: bots, Status: scan.CheckOK}},
			Mail: &scan.MailChecks{Domain: "x", MX: []string{"1 aspmx.l.google.com."},
				Providers: []scan.Provider{{Name: "Google Workspace", Role: scan.RoleMailbox}, {Name: "Cloudflare", Role: scan.RoleDNS}},
				SPF:       &scan.SPF{Record: "v=spf1 -all", All: "-all", TotalLookups: 12}, DMARC: &scan.DMARC{Policy: dmarc}, DKIM: []scan.DKIM{{Selector: "google"}}},
		}
		return c
	}
	_ = st.SaveDone(ctx, "a.example", 200, checkedResult(mk(scan.CheckOK, "reject", true)), now)
	_ = st.SaveDone(ctx, "b.example", 200, checkedResult(mk(scan.CheckMissing, "none", false)), now)
	nomail := mk(scan.CheckOK, "", false)
	nomail.Mail.MX = nil
	_ = st.SaveDone(ctx, "c.example", 200, checkedResult(nomail), now)
	_ = st.SaveDone(ctx, "d.example", 200, result(200), now) // scanned without --checks

	s, err := Compute(ctx, st, Options{MinSites: 2, Top: 30, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	c := s.Checks
	if c == nil || c.Sites != 3 || c.MailReviewed != 3 || c.MailSites != 2 {
		t.Fatalf("%+v", c)
	}
	h := c.Headers[0]
	if h.OK != 2 || h.Missing != 1 {
		t.Errorf("hsts %+v", h)
	}
	get := func(l []scan.StatCount, name string) scan.StatCount {
		for _, x := range l {
			if x.Name == name {
				return x
			}
		}
		return scan.StatCount{}
	}
	if x := get(c.DMARC, "p=reject"); x.Sites != 1 || x.Share != 0.5 {
		t.Errorf("dmarc %+v", c.DMARC)
	}
	if x := get(c.SPF, "-all"); x.Sites != 2 || x.Share != 1 {
		t.Errorf("spf %+v", c.SPF)
	}
	if get(c.Mail, "SPF tree over 10 lookups").Sites != 2 || get(c.Mail, "DKIM: a common selector found").Sites != 2 {
		t.Errorf("mail %+v", c.Mail)
	}
	if get(c.MailProviders, "Google Workspace").Sites != 2 || get(c.DNSProviders, "Cloudflare").Sites != 3 {
		t.Errorf("providers %+v %+v", c.MailProviders, c.DNSProviders)
	}
	// Only a ban by name counts: CCBot is blocked under "*" only, and GPTBot is named once.
	if len(c.AIBots) != 0 || get(c.Policies, "bans at least one AI crawler by name").Sites != 1 {
		t.Errorf("bots %+v policies %+v", c.AIBots, c.Policies)
	}
	if c.Cookies.Sites != 3 || c.Cookies.NoHTTPOnly != 3 || c.Cookies.NoSecure != 0 {
		t.Errorf("cookies %+v", c.Cookies)
	}
	if get(c.Connection, "HTTP/2").Sites != 3 || get(c.Connection, "TLS 1.3").Sites != 3 {
		t.Errorf("connection %+v", c.Connection)
	}
	b, _ := json.Marshal(s)
	if err := schemas.ValidateStats(b); err != nil {
		t.Fatalf("statistics with checks must satisfy the schema: %v", err)
	}
	if strings.Contains(string(b), "a.example") {
		t.Error("no site name in the statistics")
	}
}
