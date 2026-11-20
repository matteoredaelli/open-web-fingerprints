// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package observe

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/matteoredaelli/open-web-fingerprints/internal/domain"
	"github.com/matteoredaelli/open-web-fingerprints/internal/matcher"
	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/fetch"
)

type fakeResolver struct {
	ips   []string
	cname string
	ns    []string
	mx    []string
	txt   []string
	err   error
	calls atomic.Int32
}

func (f *fakeResolver) LookupIP(context.Context, string) ([]netip.Addr, error) {
	f.calls.Add(1)
	var out []netip.Addr
	for _, s := range f.ips {
		out = append(out, netip.MustParseAddr(s))
	}
	return out, f.err
}
func (f *fakeResolver) LookupCNAME(context.Context, string) (string, error) { return f.cname, nil }
func (f *fakeResolver) LookupNS(context.Context, string) ([]string, error)  { return f.ns, nil }
func (f *fakeResolver) LookupMX(context.Context, string) ([]string, error)  { return f.mx, nil }
func (f *fakeResolver) LookupTXT(context.Context, string) ([]string, error) {
	return f.txt, &net.DNSError{Err: "no such host", IsNotFound: true}
}

var icon = []byte{0x89, 'P', 'N', 'G', 1, 2, 3, 4, 5, 6, 7}

func site(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Server", "nginx/1.25.3")
		w.Header().Set("Content-Type", "text/html; charset=iso-8859-1")
		http.SetCookie(w, &http.Cookie{Name: "PHPSESSID", Value: "abc"})
		http.SetCookie(w, &http.Cookie{Name: "_ga", Value: "GA1.2.3"})
		// "café" in latin-1
		_, _ = w.Write([]byte("<html><head><title>caf\xe9 shop</title><link rel=\"icon\" href=\"/assets/fav.png\"></head><body>hi</body></html>"))
	})
	mux.HandleFunc("/assets/fav.png", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write(icon)
	})
	return httptest.NewServer(mux)
}

func opts(r Resolver) Options {
	return Options{Fetcher: fetch.New(fetch.Options{AllowPrivate: true, Timeout: 3 * time.Second}), Resolver: r}
}

func TestObserveBuildsTheObservation(t *testing.T) {
	srv := site(t)
	defer srv.Close()
	res := &fakeResolver{ips: []string{"192.0.2.10", "2001:db8::1"}, cname: "cdn.example.net.", ns: []string{"ns2.example.net.", "ns1.example.net."}, mx: []string{"10 mx.example.net."}}
	o, err := Observe(context.Background(), opts(res), strings.Replace(srv.URL, "127.0.0.1", "localhost", 1))
	if err != nil {
		t.Fatal(err)
	}
	obs := o.Observation
	if obs.Status != 200 || obs.Headers["Server"] != "nginx/1.25.3" || obs.Cookies["PHPSESSID"] != "abc" || len(obs.SetCookies) != 2 {
		t.Errorf("observation: %+v", obs)
	}
	if _, ok := obs.Headers["Set-Cookie"]; ok {
		t.Error("set-cookie lives in SetCookies, not in Headers")
	}
	// The page is decoded to UTF-8 and the title derives from it.
	if !strings.Contains(obs.HTML, "café shop") || !strings.Contains(string(o.HTML), "café") {
		t.Errorf("html is not decoded: %q", obs.HTML)
	}
	h := obs.FaviconHashes
	if h["md5"] == "" || h["mmh3"] == "" || obs.FaviconHash != h["mmh3"] || h["md5"] != FaviconHashes(icon)["md5"] {
		t.Errorf("favicon: %+v", h)
	}
	if obs.DNS["NS"][0] != "ns1.example.net." || obs.DNS["CNAME"][0] != "cdn.example.net." || obs.DNS["MX"][0] != "10 mx.example.net." {
		t.Errorf("dns: %+v", obs.DNS)
	}
	if len(o.Host.IPs) != 2 || o.Host.DNS["NS"] == nil {
		t.Errorf("host: %+v", o.Host)
	}
	if o.Page.Status != 200 || o.Page.Headers["server"] == "" {
		t.Errorf("page: %+v", o.Page)
	}
	for _, w := range o.Warnings {
		t.Errorf("unexpected warning: %+v", w)
	}
}

// What the observation says must be what the registry's rules read.
func TestObservationFeedsTheMatcher(t *testing.T) {
	srv := site(t)
	defer srv.Close()
	o, err := Observe(context.Background(), opts(nil), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	hashes := FaviconHashes(icon)
	rules := map[string]domain.Fingerprint{
		"header":      {Observation: domain.ObsHTTPHeader, Target: "Server", Operator: domain.OpRegex, Pattern: `^nginx/([\d.]+)`, RegexFlavor: domain.FlavorRE2, VersionExtract: `\1`},
		"cookie":      {Observation: domain.ObsCookie, Target: "PHPSESSID", Operator: domain.OpExists},
		"title":       {Observation: "page_title", Operator: domain.OpRegex, Pattern: `^café shop$`, RegexFlavor: domain.FlavorRE2},
		"set cookie":  {Observation: "set_cookie", Operator: domain.OpRegex, Pattern: `^_ga=`, RegexFlavor: domain.FlavorRE2},
		"nuclei mmh3": {Observation: domain.ObsFaviconHash, Target: "mmh3", Operator: domain.OpHashEquals, Pattern: hashes["mmh3"]},
		"recog md5":   {Observation: domain.ObsFaviconHash, Target: "md5", Operator: domain.OpRegex, Pattern: "^" + hashes["md5"] + "$", RegexFlavor: domain.FlavorRE2},
		"status":      {Observation: "http_status", Operator: domain.OpEquals, Pattern: "200"},
		"html":        {Observation: domain.ObsHTML, Operator: domain.OpContains, Pattern: "café"},
	}
	for name, r := range rules {
		got, err := matcher.Evaluate(r, &o.Observation)
		if err != nil || !got.Matched {
			t.Errorf("%s: matched=%v err=%v", name, got.Matched, err)
		}
	}
	if got, _ := matcher.Evaluate(rules["header"], &o.Observation); got.Version != "1.25.3" {
		t.Errorf("version = %q", got.Version)
	}
	// A rule on the raw header block sees the names as sent ("Server: nginx/..").
	block := domain.Fingerprint{Observation: "response_headers", Operator: domain.OpRegex, RegexFlavor: domain.FlavorRE2, Pattern: `(?-i)Server:\s+nginx/([\d.]+)`, VersionExtract: `\1`}
	if got, err := matcher.Evaluate(block, &o.Observation); err != nil || !got.Matched || got.Version != "1.25.3" {
		t.Errorf("raw header block: %+v %v", got, err)
	}
	// And a wrong hash does not match.
	bad := rules["nuclei mmh3"]
	bad.Pattern = "123"
	if got, _ := matcher.Evaluate(bad, &o.Observation); got.Matched {
		t.Error("a different favicon hash must not match")
	}
}

func TestBareHostTriesHTTPSThenHTTP(t *testing.T) {
	srv := site(t) // plain HTTP only
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	o, err := Observe(context.Background(), opts(nil), host)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(o.Page.FinalURL, "http://") || len(o.Warnings) == 0 || o.Warnings[0].Code != "https_unavailable" {
		t.Errorf("final %s warnings %+v", o.Page.FinalURL, o.Warnings)
	}
	// With an explicit scheme there is no second attempt.
	if _, err := Observe(context.Background(), opts(nil), "https://"+host); err == nil {
		t.Error("an explicit https URL must not fall back to http")
	}
}

func TestBlockedAddressDoesNotFallBack(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer srv.Close()
	o := Options{Fetcher: fetch.New(fetch.Options{Timeout: time.Second})}
	_, err := Observe(context.Background(), o, strings.TrimPrefix(srv.URL, "http://"))
	if !errors.Is(err, fetch.ErrBlockedAddress) || hits.Load() != 0 {
		t.Errorf("err=%v hits=%d", err, hits.Load())
	}
}

func TestFaviconRules(t *testing.T) {
	var asked atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		switch r.URL.Path {
		case "/":
			_, _ = w.Write([]byte(`<html><head><link rel="apple-touch-icon" href="/touch.png"><link rel="icon" href="data:image/png;base64,AAAA"></head></html>`))
		default:
			asked.Add(1)
			_, _ = w.Write([]byte("<html>not found, with a 200</html>")) // a site that serves its home page for any path
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	o, err := Observe(context.Background(), opts(nil), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if o.Observation.FaviconHashes != nil {
		t.Errorf("an HTML answer is not a favicon: %+v", o.Observation.FaviconHashes)
	}
	if asked.Load() != 1 {
		t.Errorf("only /favicon.ico is tried (apple-touch and data: icons are not): %d requests", asked.Load())
	}
	// NoFavicon makes no extra request.
	asked.Store(0)
	n := opts(nil)
	n.NoFavicon = true
	if _, err := Observe(context.Background(), n, srv.URL); err != nil || asked.Load() != 0 {
		t.Errorf("err=%v asked=%d", err, asked.Load())
	}
}

func TestDNSProblemsAreWarnings(t *testing.T) {
	srv := site(t)
	defer srv.Close()
	res := &fakeResolver{err: errors.New("server failure")}
	o, err := Observe(context.Background(), opts(res), strings.Replace(srv.URL, "127.0.0.1", "localhost", 1))
	if err != nil {
		t.Fatalf("a DNS failure must not fail the scan: %v", err)
	}
	var w bool
	for _, x := range o.Warnings {
		if x.Code == "dns_ip" {
			w = true
		}
		if x.Code == "dns_txt" {
			t.Error("a name that does not exist is not a warning")
		}
	}
	if !w || o.Observation.DNS != nil {
		t.Errorf("warnings %+v dns %+v", o.Warnings, o.Observation.DNS)
	}
	// An IP literal is not looked up.
	res = &fakeResolver{}
	o, err = Observe(context.Background(), opts(res), srv.URL) // http://127.0.0.1:port
	if err != nil || res.calls.Load() != 0 || len(o.Host.IPs) != 1 || o.Host.IPs[0] != "127.0.0.1" {
		t.Errorf("err=%v calls=%d host=%+v", err, res.calls.Load(), o.Host)
	}
}

func TestNonHTMLAndErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/missing" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/pdf")
		_, _ = w.Write([]byte("%PDF-1.7 binary"))
	}))
	defer srv.Close()
	o, err := Observe(context.Background(), opts(nil), srv.URL)
	if err != nil || len(o.HTML) != 0 || o.Observation.HTML != "" || o.Observation.Status != 200 {
		t.Errorf("a PDF is not HTML: %+v err=%v", o.Observation.Status, err)
	}
	// A 404 page is still observed: error pages carry information.
	o, err = Observe(context.Background(), opts(nil), srv.URL+"/missing")
	if err != nil || o.Observation.Status != 404 {
		t.Errorf("err=%v", err)
	}
	if _, err := Observe(context.Background(), Options{}, "x"); err == nil {
		t.Error("no fetcher must fail")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Observe(ctx, opts(nil), srv.URL); err == nil {
		t.Error("a cancelled context must fail")
	}
}

func TestTLSIsPartOfTheObservation(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html></html>"))
	}))
	defer srv.Close()
	o := opts(nil)
	o.Fetcher = fetch.New(fetch.Options{AllowPrivate: true, Insecure: true, Timeout: 3 * time.Second})
	got, err := Observe(context.Background(), o, srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if got.Host.TLS == nil || got.Observation.TLS["issuer"] == "" || got.Observation.TLS["version"] == "" {
		t.Errorf("tls: %+v %+v", got.Host.TLS, got.Observation.TLS)
	}
	rule := domain.Fingerprint{Observation: domain.ObsTLSCert, Target: "issuer", Operator: domain.OpContains, Pattern: got.Host.TLS.Issuer}
	if m, err := matcher.Evaluate(rule, &got.Observation); err != nil || !m.Matched {
		t.Errorf("a tls_cert rule must read the issuer: %v %v", m, err)
	}
}
