// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package browser

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func viaProxy(t *testing.T, p *proxy) *http.Client {
	t.Helper()
	u, _ := url.Parse("http://" + p.addr())
	return &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(u), TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec // test server certificate
}

func TestProxyRefusesNonPublicAddresses(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("secret")) }))
	defer backend.Close()
	tlsBackend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("secret")) }))
	defer tlsBackend.Close()

	p, err := newProxy(false, 100)
	if err != nil {
		t.Fatal(err)
	}
	defer p.close()
	c := viaProxy(t, p)
	// Plain http to a loopback address: refused with 403, not forwarded.
	resp, err := c.Get(backend.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || string(body) == "secret" {
		t.Errorf("http: %d %q", resp.StatusCode, body)
	}
	// A CONNECT to a loopback address: refused, so the TLS request fails.
	if resp, err := c.Get(tlsBackend.URL); err == nil {
		_ = resp.Body.Close()
		t.Errorf("a tunnel to a loopback address must fail, got %d", resp.StatusCode)
	}
	if _, blocked := p.stats(); blocked < 2 {
		t.Errorf("refusals are counted: %d", blocked)
	}
}

func TestProxyForwardsWhenAllowed(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Seen-Proxy-Header", r.Header.Get("Proxy-Connection"))
		_, _ = w.Write([]byte("hello"))
	}))
	defer backend.Close()
	tlsBackend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("secure")) }))
	defer tlsBackend.Close()

	p, err := newProxy(true, 100)
	if err != nil {
		t.Fatal(err)
	}
	defer p.close()
	c := viaProxy(t, p)
	for url, want := range map[string]string{backend.URL: "hello", tlsBackend.URL: "secure"} {
		resp, err := c.Get(url)
		if err != nil {
			t.Fatalf("%s: %v", url, err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if string(body) != want {
			t.Errorf("%s: %q", url, body)
		}
		if resp.Header.Get("X-Seen-Proxy-Header") != "" {
			t.Error("hop-by-hop headers are not forwarded")
		}
	}
	if n, _ := p.stats(); n != 2 {
		t.Errorf("requests: %d", n)
	}
}

func TestProxyStopsAtTheRequestLimit(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }))
	defer backend.Close()
	p, err := newProxy(true, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer p.close()
	c := viaProxy(t, p)
	var codes []int
	for range 4 {
		resp, err := c.Get(backend.URL)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		codes = append(codes, resp.StatusCode)
	}
	if codes[0] != 200 || codes[1] != 200 || codes[2] != http.StatusTooManyRequests || codes[3] != http.StatusTooManyRequests {
		t.Errorf("codes: %v", codes)
	}
	if n, _ := p.stats(); n != 2 {
		t.Errorf("the count stops at the limit: %d", n)
	}
	// Anything that is not an absolute http URL is refused.
	req, _ := http.NewRequest(http.MethodGet, "http://"+p.addr()+"/relative", nil)
	p2, _ := newProxy(true, 10)
	defer p2.close()
	req.URL.Host = p2.addr()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("not a proxy request: %d", resp.StatusCode)
	}
}
