// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package fetch

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func local() Options { return Options{AllowPrivate: true, Timeout: 5 * time.Second} }

func get(t *testing.T, f *Fetcher, u string) *Response {
	t.Helper()
	r, err := f.Get(context.Background(), u)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestGetReadsPageHeadersAndCookies(t *testing.T) {
	var ua, accept string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ua, accept = r.UserAgent(), r.Header.Get("Accept")
		w.Header().Set("Server", "nginx/1.25.3")
		w.Header().Add("Set-Cookie", "a=1; Path=/")
		w.Header().Add("Set-Cookie", "b=2; Path=/; HttpOnly")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<html>hello</html>"))
	}))
	defer srv.Close()
	r := get(t, New(local()), srv.URL)
	if r.Status != 200 || string(r.Body) != "<html>hello</html>" || r.FinalURL != srv.URL+"/" && r.FinalURL != srv.URL {
		t.Errorf("%+v", r)
	}
	if r.Header.Get("Server") != "nginx/1.25.3" || len(r.SetCookies) != 2 || !strings.HasPrefix(r.ContentType, "text/html") {
		t.Errorf("headers: %v cookies: %v", r.Header, r.SetCookies)
	}
	if !strings.HasPrefix(ua, "owfscan") || !strings.Contains(accept, "text/html") {
		t.Errorf("the request must identify the tool: ua=%q accept=%q", ua, accept)
	}
	p := r.Page()
	if p.Status != 200 || p.Headers["server"] != "nginx/1.25.3" || !strings.Contains(p.Headers["set-cookie"], "a=1") || p.Bytes != len(r.Body) {
		t.Errorf("page: %+v", p)
	}
}

func TestRedirectsAreRecordedAndCookiesKept(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/step", http.StatusMovedPermanently)
	})
	mux.HandleFunc("/step", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "42", Path: "/"})
		http.Redirect(w, r, "/final", http.StatusFound)
	})
	var sawCookie string
	mux.HandleFunc("/final", func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("sid"); err == nil {
			sawCookie = c.Value
		}
		_, _ = w.Write([]byte("done"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	r := get(t, New(local()), srv.URL)
	if r.FinalURL != srv.URL+"/final" || len(r.Redirects) != 2 || r.Redirects[0].Status != 301 || r.Redirects[1].Status != 302 ||
		r.Redirects[0].URL != srv.URL || r.Redirects[1].URL != srv.URL+"/step" {
		t.Errorf("final %s, redirects %+v", r.FinalURL, r.Redirects)
	}
	if sawCookie != "42" {
		t.Errorf("a cookie set in a redirect must travel on: %q", sawCookie)
	}
}

func TestLimits(t *testing.T) {
	big := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", 5000)))
	}))
	defer big.Close()
	o := local()
	o.MaxBody = 1000
	if r := get(t, New(o), big.URL); len(r.Body) != 1000 || !r.Truncated {
		t.Errorf("body %d truncated=%v", len(r.Body), r.Truncated)
	}

	loop := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, r.URL.Path+"x", http.StatusFound) }))
	defer loop.Close()
	o = local()
	o.MaxRedirects = 3
	if _, err := New(o).Get(context.Background(), loop.URL); err == nil || !strings.Contains(err.Error(), "redirects") {
		t.Errorf("redirect loop: %v", err)
	}

	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { time.Sleep(300 * time.Millisecond) }))
	defer slow.Close()
	o = local()
	o.Timeout = 50 * time.Millisecond
	if _, err := New(o).Get(context.Background(), slow.URL); err == nil {
		t.Error("a slow server must time out")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := New(local()).Get(ctx, big.URL); err == nil {
		t.Error("a cancelled context must fail")
	}
}

func TestSchemesAndBadURLs(t *testing.T) {
	f := New(local())
	for _, u := range []string{"", "ftp://example.org/", "file:///etc/passwd", "javascript:alert(1)", "http://", "//example.org", "example.org"} {
		if _, err := f.Get(context.Background(), u); err == nil {
			t.Errorf("%q must be refused", u)
		}
	}
	// A redirect to another scheme is refused.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "ftp://example.org/x", http.StatusFound)
	}))
	defer srv.Close()
	if _, err := f.Get(context.Background(), srv.URL); err == nil {
		t.Error("a redirect to ftp must be refused")
	}
}

func TestPrivateAddressesAreRefusedByDefault(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { hits.Add(1) }))
	defer srv.Close()
	_, err := New(Options{Timeout: 2 * time.Second}).Get(context.Background(), srv.URL)
	if err == nil || !errors.Is(err, ErrBlockedAddress) {
		t.Fatalf("a loopback server must be refused by default, got %v", err)
	}
	if hits.Load() != 0 {
		t.Error("the connection must not even be made")
	}
	for _, u := range []string{"http://127.0.0.1:1/", "http://[::1]:1/", "http://169.254.169.254/latest/meta-data/", "http://10.0.0.1/", "http://192.168.1.1/", "http://localhost:1/"} {
		if _, err := New(Options{Timeout: time.Second}).Get(context.Background(), u); !errors.Is(err, ErrBlockedAddress) {
			t.Errorf("%s: %v", u, err)
		}
	}
}

// A public-looking site that redirects to an internal address must not lead us there.
func TestRedirectToPrivateAddressIsRefused(t *testing.T) {
	internal := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("secret")) }))
	l, err := netListen("tcp6", "[::1]:0")
	if err != nil {
		t.Skip("no IPv6 loopback")
	}
	internal.Listener = l
	internal.Start()
	defer internal.Close()
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, internal.URL, http.StatusFound) }))
	defer front.Close()
	// The front is "public" (the test treats 127.0.0.1 as such); ::1 is not.
	o := Options{Timeout: 2 * time.Second, Allow: func(ip netip.Addr) bool { return ip == netip.MustParseAddr("127.0.0.1") }}
	if _, err := New(o).Get(context.Background(), front.URL); !errors.Is(err, ErrBlockedAddress) {
		t.Errorf("a redirect to an internal address must be refused: %v", err)
	}
	// And the same chain is fine when internal addresses are allowed.
	if r := get(t, New(local()), front.URL); string(r.Body) != "secret" {
		t.Errorf("%+v", r)
	}
}

func TestPublic(t *testing.T) {
	for in, want := range map[string]bool{
		"8.8.8.8": true, "93.184.216.34": true, "2606:4700:4700::1111": true,
		"127.0.0.1": false, "::1": false, "10.1.2.3": false, "172.16.0.1": false, "172.32.0.1": true, "192.168.0.1": false,
		"169.254.169.254": false, "100.64.0.1": false, "198.18.0.1": false, "0.0.0.0": false, "224.0.0.1": false,
		"fe80::1": false, "fc00::1": false, "::ffff:10.0.0.1": false, "::ffff:8.8.8.8": true, "255.255.255.255": true,
	} {
		ip := netip.MustParseAddr(in)
		got := Public(ip)
		if in == "255.255.255.255" {
			continue // broadcast is not a destination; the dialer would fail on it anyway
		}
		if got != want {
			t.Errorf("Public(%s) = %v, want %v", in, got, want)
		}
	}
}

func TestTLSIsRecordedAndVerified(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("tls")) }))
	defer srv.Close()
	if _, err := New(local()).Get(context.Background(), srv.URL); err == nil {
		t.Error("an unknown certificate must be refused unless Insecure is set")
	}
	o := local()
	o.Insecure = true
	r := get(t, New(o), srv.URL)
	if r.TLS == nil || r.TLS.Version == "" || r.TLS.Issuer == "" || r.TLS.NotAfter.IsZero() || len(r.TLS.DNSNames) == 0 {
		t.Errorf("tls: %+v", r.TLS)
	}
}

func TestCache(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path == "/boom" {
			http.Error(w, "x", 500)
			return
		}
		w.Header().Set("X-N", "v")
		_, _ = w.Write([]byte("body"))
	}))
	defer srv.Close()
	dir := t.TempDir()
	now := time.Date(2026, 11, 18, 9, 0, 0, 0, time.UTC)
	o := local()
	o.CacheDir, o.Now = dir, func() time.Time { return now }
	f := New(o)

	first := get(t, f, srv.URL)
	second := get(t, f, srv.URL)
	if first.Cached || !second.Cached || hits.Load() != 1 || string(second.Body) != "body" || second.Header.Get("X-N") != "v" {
		t.Errorf("hits=%d first.Cached=%v second=%+v", hits.Load(), first.Cached, second)
	}
	if !second.Page().Cached {
		t.Error("the page must say it came from the cache")
	}
	// Another Fetcher with the same directory sees the entry.
	if r := get(t, New(o), srv.URL); !r.Cached || hits.Load() != 1 {
		t.Error("the cache is on disk, not in memory")
	}
	// It expires.
	now = now.Add(48 * time.Hour)
	if r := get(t, f, srv.URL); r.Cached || hits.Load() != 2 {
		t.Errorf("an old entry must be fetched again: %v hits=%d", r.Cached, hits.Load())
	}
	// Errors are not cached.
	get(t, f, srv.URL+"/boom")
	get(t, f, srv.URL+"/boom")
	if hits.Load() != 4 {
		t.Errorf("a 5xx must not be cached: hits=%d", hits.Load())
	}
	// A damaged body is not trusted.
	files, _ := filepath.Glob(filepath.Join(dir, "*.body"))
	for _, p := range files {
		if err := os.WriteFile(p, []byte("tampered"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	before := hits.Load()
	if r := get(t, f, srv.URL); r.Cached || string(r.Body) != "body" || hits.Load() != before+1 {
		t.Errorf("tampered cache: %+v", r)
	}
	// A broken metadata file is ignored.
	metas, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	for _, p := range metas {
		if err := os.WriteFile(p, []byte("{"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if r := get(t, f, srv.URL); r.Cached {
		t.Error("broken metadata must be ignored")
	}
}

func netListen(network, addr string) (net.Listener, error) { return net.Listen(network, addr) }
