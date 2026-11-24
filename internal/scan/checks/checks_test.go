// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package checks

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/matteoredaelli/open-web-fingerprints/scan"
)

func byName(h *scan.HeaderChecks, name string) scan.HeaderCheck {
	for _, c := range h.Headers {
		if c.Name == name {
			return c
		}
	}
	return scan.HeaderCheck{}
}

func TestHeadersGood(t *testing.T) {
	h := Headers("https://a.example/", map[string]string{
		"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
		"Content-Security-Policy":   "default-src 'self'; script-src 'self' 'nonce-abc' 'unsafe-inline'; frame-ancestors 'none'",
		"X-Content-Type-Options":    "nosniff",
		"Referrer-Policy":           "strict-origin-when-cross-origin",
		"Server":                    "nginx",
	}, nil)
	for name, want := range map[string]string{
		"strict-transport-security": scan.CheckOK,
		"content-security-policy":   scan.CheckOK, // unsafe-inline is ignored beside a nonce
		"x-frame-options":           scan.CheckOK, // frame-ancestors
		"x-content-type-options":    scan.CheckOK,
		"referrer-policy":           scan.CheckOK,
		"server":                    scan.CheckInfo,
		"x-powered-by":              scan.CheckOK,
		"permissions-policy":        scan.CheckInfo,
	} {
		if got := byName(h, name); got.Status != want {
			t.Errorf("%s: %s (%s), want %s", name, got.Status, got.Note, want)
		}
	}
	if h.Missing != 0 || h.Weak != 0 {
		t.Errorf("missing=%d weak=%d", h.Missing, h.Weak)
	}
}

func TestHeadersBad(t *testing.T) {
	h := Headers("https://a.example/", map[string]string{
		"strict-transport-security": "max-age=100",
		"content-security-policy":   "script-src 'unsafe-inline' https://x.example",
		"x-frame-options":           "ALLOW-FROM https://x.example",
		"x-content-type-options":    "sniff",
		"referrer-policy":           "unsafe-url",
		"x-powered-by":              "PHP/8.1.2",
	}, nil)
	for _, n := range []string{"strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options", "referrer-policy", "x-powered-by"} {
		if got := byName(h, n); got.Status != scan.CheckWeak {
			t.Errorf("%s: %s, want weak", n, got.Status)
		}
	}
	if m := Headers("https://a.example/", nil, nil); m.Missing != 4 {
		t.Errorf("empty answer: missing=%d, want 4 (hsts, csp, xfo, xcto)", m.Missing)
	}
}

func TestHeadersHTTPAndReportOnly(t *testing.T) {
	h := Headers("http://a.example/", map[string]string{"Content-Security-Policy-Report-Only": "default-src 'self'"}, nil)
	if got := byName(h, "strict-transport-security"); got.Status != scan.CheckInfo {
		t.Errorf("hsts over http: %s", got.Status)
	}
	if got := byName(h, "content-security-policy"); got.Status != scan.CheckInfo || got.Present {
		t.Errorf("report-only: %+v", got)
	}
}

func TestCookies(t *testing.T) {
	h := Headers("https://a.example/", nil, []string{
		"sid=SECRET; Path=/; Secure; HttpOnly; SameSite=Lax",
		"pref=dark; Path=/",
		"x=1; SameSite=None; HttpOnly",
	})
	if len(h.Cookies) != 3 {
		t.Fatalf("%+v", h.Cookies)
	}
	if len(h.Cookies[0].Issues) != 0 || h.Cookies[0].SameSite != "lax" {
		t.Errorf("sid: %+v", h.Cookies[0])
	}
	if got := strings.Join(h.Cookies[1].Issues, ","); got != "no_secure,no_httponly,no_samesite" {
		t.Errorf("pref: %s", got)
	}
	if got := strings.Join(h.Cookies[2].Issues, ","); got != "no_secure,samesite_none_without_secure" {
		t.Errorf("x: %s", got)
	}
}

type fakeDNS struct {
	txt map[string][]string
	mx  []string
	ns  []string
	err map[string]error
}

func (f fakeDNS) LookupMX(context.Context, string) ([]string, error) { return f.mx, nil }
func (f fakeDNS) LookupNS(context.Context, string) ([]string, error) { return f.ns, nil }
func (f fakeDNS) LookupTXT(_ context.Context, n string) ([]string, error) {
	if e := f.err[n]; e != nil {
		return nil, e
	}
	if v, ok := f.txt[n]; ok {
		return v, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: n, IsNotFound: true}
}

func TestMail(t *testing.T) {
	m, warns := Mail(context.Background(), fakeDNS{
		mx: []string{"1 aspmx.l.google.com.", "5 alt1.aspmx.l.google.com."},
		ns: []string{"ns-1.awsdns-01.org.", "ns-2.awsdns-02.co.uk."},
		txt: map[string][]string{
			"a.example":                      {"google-site-verification=x", "v=spf1 include:_spf.google.com include:sendgrid.net ip4:1.2.3.4 -all"},
			"_dmarc.a.example":               {"v=DMARC1; p=reject; sp=none; pct=50; rua=mailto:r@a.example"},
			"google._domainkey.a.example":    {"v=DKIM1; k=rsa; p=MIIB"},
			"selector1._domainkey.a.example": {"v=DKIM1; p="},
			"_mta-sts.a.example":             {"v=STSv1; id=1"},
		},
	}, "a.example")
	if len(warns) != 0 {
		t.Fatalf("%v", warns)
	}
	if m.SPF.Status != scan.CheckOK || m.SPF.All != "-all" || m.SPF.Lookups != 2 || len(m.SPF.Includes) != 2 {
		t.Errorf("spf %+v", m.SPF)
	}
	d := m.DMARC
	if d.Status != scan.CheckOK || d.Policy != "reject" || d.SubdomainPolicy != "none" || d.Pct != 50 || len(d.Rua) != 1 || d.Note == "" {
		t.Errorf("dmarc %+v", d)
	}
	if len(m.DKIM) != 2 || m.DKIM[0].Selector != "google" || !m.DKIM[1].Revoked {
		t.Errorf("dkim %+v", m.DKIM)
	}
	if m.MTASTS == nil || !m.MTASTS.Present || m.TLSRPT == nil || m.TLSRPT.Present {
		t.Errorf("tags %+v %+v", m.MTASTS, m.TLSRPT)
	}
	got := map[string]bool{}
	for _, p := range m.Providers {
		got[p.Role+":"+p.Name] = true
	}
	for _, w := range []string{"mailbox:Google Workspace", "sending:Google Workspace", "sending:SendGrid", "dns:Amazon Route 53"} {
		if !got[w] {
			t.Errorf("provider %s missing in %v", w, m.Providers)
		}
	}
	if len(m.Providers) != 4 {
		t.Errorf("duplicates: %v", m.Providers)
	}
}

func TestMailMissingAndNoMail(t *testing.T) {
	m, _ := Mail(context.Background(), fakeDNS{mx: []string{"1 mx.a.example."}}, "a.example")
	if m.SPF.Status != scan.CheckMissing || m.DMARC.Status != scan.CheckMissing {
		t.Errorf("%+v %+v", m.SPF, m.DMARC)
	}
	if m.DKIMSelTried == 0 {
		t.Error("selectors not tried")
	}
	n, _ := Mail(context.Background(), fakeDNS{mx: []string{"0 ."}}, "a.example")
	if !n.NullMX || len(n.MX) != 0 || n.SPF.Status != scan.CheckInfo || n.DMARC.Status != scan.CheckInfo || n.DKIMSelTried != 0 {
		t.Errorf("null mx: %+v %+v %+v", n, n.SPF, n.DMARC)
	}
}

func TestMailLookupFailureIsNotMissing(t *testing.T) {
	m, warns := Mail(context.Background(), fakeDNS{
		mx:  []string{"1 mx.a.example."},
		err: map[string]error{"_dmarc.a.example": &net.DNSError{Err: "server misbehaving", IsTemporary: true}},
	}, "a.example")
	if m.DMARC != nil || len(warns) != 1 || warns[0].Code != "check_dns_txt" {
		t.Errorf("%+v %v", m.DMARC, warns)
	}
}

func TestSPFWeak(t *testing.T) {
	for rec, why := range map[string]string{
		"v=spf1 +all":                       "+all",
		"v=spf1 mx":                         "all",
		"v=spf1 ptr -all":                   "ptr",
		"v=spf1 a a a a a a a a a a a -all": "10",
	} {
		if s := spf([]string{rec}); s.Status != scan.CheckWeak || !strings.Contains(s.Note, why) {
			t.Errorf("%s: %+v", rec, s)
		}
	}
	if s := spf([]string{"v=spf1 -all", "v=spf1 -all"}); s.Status != scan.CheckWeak {
		t.Errorf("two records: %+v", s)
	}
	if s := spf([]string{"v=spf1 redirect=_spf.b.example"}); s.Status != scan.CheckOK || s.Lookups != 1 {
		t.Errorf("redirect: %+v", s)
	}
}

func TestRobots(t *testing.T) {
	text := "User-agent: GPTBot\nDisallow: /\n\nUser-agent: CCBot\nAllow: /\n\nUser-agent: *\nDisallow: /private/\nSitemap: https://a.example/s1.xml\nSitemap: https://a.example/s2.xml\n"
	r := Robots(text, true)
	if !r.Present || r.SitemapCount != 2 || len(r.Sitemaps) != 2 {
		t.Errorf("%+v", r)
	}
	by := map[string]scan.AIBot{}
	for _, b := range r.AIBots {
		by[b.Name] = b
	}
	if !by["GPTBot"].Blocked || !by["GPTBot"].Named || by["CCBot"].Blocked || !by["CCBot"].Named || by["ClaudeBot"].Blocked || by["ClaudeBot"].Named {
		t.Errorf("%+v", by)
	}
	if r.AIBlocked != 1 || r.AINamed != 2 {
		t.Errorf("blocked=%d named=%d", r.AIBlocked, r.AINamed)
	}
	// A blanket ban catches every AI crawler without naming any.
	all := Robots("User-agent: *\nDisallow: /\n", true)
	if all.AIBlocked != len(AIBots) || all.AINamed != 0 {
		t.Errorf("blanket: %+v", all)
	}
	if Robots("", false).Present {
		t.Error("absent")
	}
}

func TestSecurityTxt(t *testing.T) {
	now := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	good := "Contact: mailto:sec@a.example\nContact: https://a.example/report\nExpires: 2027-01-01T00:00:00Z\nPolicy: https://a.example/p\n"
	s := SecurityTxt(200, "text/plain; charset=utf-8", []byte(good), "https://a.example/.well-known/security.txt", now)
	if !s.Present || s.Status != scan.CheckOK || s.Contacts != 2 || !s.HasPolicy || s.HasEncryption || s.Expired {
		t.Errorf("%+v", s)
	}
	if e := SecurityTxt(200, "text/plain", []byte(strings.Replace(good, "2027", "2026", 1)), "u", now); !e.Expired || e.Status != scan.CheckWeak {
		t.Errorf("expired: %+v", e)
	}
	if n := SecurityTxt(200, "text/plain", []byte("Contact: x\n"), "u", now); n.Status != scan.CheckWeak {
		t.Errorf("no expires: %+v", n)
	}
	// A home page served for every path is not a security.txt.
	if h := SecurityTxt(200, "text/html", []byte("<html>Contact: us</html>"), "u", now); h.Present || h.Status != scan.CheckInfo {
		t.Errorf("html: %+v", h)
	}
	if h := SecurityTxt(404, "text/plain", []byte(good), "u", now); h.Present {
		t.Errorf("404: %+v", h)
	}
}

func TestTransport(t *testing.T) {
	now := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	tr := Transport(scan.Page{FinalURL: "https://a.example/", Proto: "HTTP/2.0", Headers: map[string]string{"alt-svc": `h3=":443"; ma=86400, h2=":443"`}},
		&scan.TLS{Version: "TLS 1.3", ALPN: "h2", NotAfter: now.Add(30 * 24 * time.Hour)}, now)
	if !tr.HTTP2 || !tr.HTTP3Advertised || tr.TLSStatus != scan.CheckOK || tr.CertDaysLeft == nil || *tr.CertDaysLeft != 30 {
		t.Errorf("%+v", tr)
	}
	old := Transport(scan.Page{FinalURL: "https://a.example/"}, &scan.TLS{Version: "TLS 1.0", NotAfter: now.Add(-time.Hour)}, now)
	if old.TLSStatus != scan.CheckWeak || old.HTTP2 || old.HTTP3Advertised {
		t.Errorf("%+v", old)
	}
	if h := Transport(scan.Page{FinalURL: "http://a.example/"}, nil, now); h.HTTPS || h.TLSStatus != scan.CheckWeak {
		t.Errorf("%+v", h)
	}
}

func TestSPFTree(t *testing.T) {
	m, warns := Mail(context.Background(), fakeDNS{
		mx: []string{"1 mx.a.example."},
		txt: map[string][]string{
			"a.example":       {"v=spf1 include:_spf.x.example include:b.example -all"},
			"_spf.x.example":  {"v=spf1 include:_spf.google.com a mx -all"},
			"_spf.google.com": {"v=spf1 ip4:1.1.1.1 a:x.example ~all"},
			"b.example":       {"v=spf1 include:loop.example -all"},
			"loop.example":    {"v=spf1 include:b.example -all"},
		},
	}, "a.example")
	if len(warns) != 0 {
		t.Fatal(warns)
	}
	s := m.SPF
	// a.example: 2 includes; x: include + a + mx = 3; google: a = 1; b: 1; loop: 1 -> 8
	if s.TotalLookups != 8 || !s.TreeComplete || len(s.Nested) != 4 || s.Status != scan.CheckOK {
		t.Errorf("%+v", s)
	}
	found := false
	for _, p := range m.Providers {
		found = found || (p.Name == "Google Workspace" && p.Role == scan.RoleSending)
	}
	if !found {
		t.Errorf("the sender behind a nested include is recognised: %v", m.Providers)
	}
	// Past ten, the record fails.
	var inc, recs = "v=spf1", map[string][]string{}
	for i := 0; i < 11; i++ {
		inc += " include:n" + string(rune('a'+i)) + ".example"
		recs["n"+string(rune('a'+i))+".example"] = []string{"v=spf1 -all"}
	}
	recs["a.example"] = []string{inc + " -all"}
	big, _ := Mail(context.Background(), fakeDNS{mx: []string{"1 mx.a.example."}, txt: recs}, "a.example")
	if big.SPF.Status != scan.CheckWeak || big.SPF.TotalLookups != 11 {
		t.Errorf("%+v", big.SPF)
	}
}

// flaky answers "no such host" the first time for each name, as a rushed resolver can.
type flaky struct {
	fakeDNS
	mu   sync.Mutex
	seen map[string]bool
}

func (f *flaky) LookupTXT(ctx context.Context, n string) ([]string, error) {
	f.mu.Lock()
	first := !f.seen[n]
	f.seen[n] = true
	f.mu.Unlock()
	if first {
		return nil, &net.DNSError{Err: "no such host", Name: n, IsNotFound: true}
	}
	return f.fakeDNS.LookupTXT(ctx, n)
}

func TestEmptyAnswerIsAskedAgain(t *testing.T) {
	f := &flaky{seen: map[string]bool{}, fakeDNS: fakeDNS{mx: []string{"1 mx.a.example."}, txt: map[string][]string{
		"a.example": {"v=spf1 -all"}, "_dmarc.a.example": {"v=DMARC1; p=reject"}}}}
	m, _ := Mail(context.Background(), f, "a.example")
	if m.SPF.Status != scan.CheckOK || m.DMARC.Policy != "reject" {
		t.Errorf("%+v %+v", m.SPF, m.DMARC)
	}
}

func TestSPFMacroIncludeIsNotFollowed(t *testing.T) {
	m, _ := Mail(context.Background(), fakeDNS{mx: []string{"1 mx.a.example."}, txt: map[string][]string{
		"a.example": {"v=spf1 include:%{ir}.%{v}.%{d}.spf.has.pphosted.com ~all"}}}, "a.example")
	if m.SPF.TreeComplete || m.SPF.TotalLookups != 1 || m.SPF.Status != scan.CheckOK {
		t.Errorf("%+v", m.SPF)
	}
	found := false
	for _, p := range m.Providers {
		found = found || p.Name == "Proofpoint"
	}
	if found {
		t.Log("provider recognised from the macro host") // pphosted.com is in the MX list only; fine either way
	}
}
