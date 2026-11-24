// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

// Package fetch retrieves pages for the scanner, politely and safely.
//
// Limits, all of them settable: a timeout per request, a cap on the body, a cap
// on redirects. Only http and https are followed. Addresses that are not on the
// public internet (loopback, private ranges, link-local, the cloud metadata
// address) are refused, also when a public site redirects to one, unless the
// caller allows them: a scanner must not become a way to reach the network it
// runs in. Proxies from the environment are not used for the same reason.
//
// It makes the requests it is asked for and no others: no crawling, no robots.txt,
// no probes.
package fetch

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/netip"
	"net/url"
	"strings"
	"syscall"
	"time"

	"github.com/matteoredaelli/open-web-fingerprints/scan"
)

// Defaults.
const (
	DefaultTimeout      = 20 * time.Second
	DefaultMaxBody      = 5 << 20
	DefaultMaxRedirects = 10
	DefaultMaxAge       = 24 * time.Hour
)

// Options configure a Fetcher.
type Options struct {
	Timeout      time.Duration
	MaxBody      int64
	MaxRedirects int
	UserAgent    string
	// AllowPrivate lets requests reach private and local addresses. It exists for
	// tests and for scanning your own network.
	AllowPrivate bool
	// Allow decides which addresses may be contacted when AllowPrivate is false.
	// The default is Public.
	Allow func(netip.Addr) bool
	// Insecure accepts any certificate. The certificate is still recorded.
	Insecure bool
	// CacheDir enables the on-disk response cache. Entries older than MaxAge are
	// fetched again. Server errors (5xx) are not cached.
	CacheDir string
	MaxAge   time.Duration
	Now      func() time.Time
	// Transport replaces the network transport (tests).
	Transport http.RoundTripper
}

// DefaultUserAgent identifies the scanner.
const DefaultUserAgent = "owfscan (+https://github.com/matteoredaelli/open-web-fingerprints)"

// Response is what was fetched.
type Response struct {
	URL         string
	FinalURL    string
	Status      int
	Header      http.Header
	SetCookies  []string
	ContentType string
	Body        []byte
	Truncated   bool
	Redirects   []scan.Redirect
	Duration    time.Duration
	FetchedAt   time.Time
	Cached      bool
	TLS         *scan.TLS
	Proto       string // HTTP/1.1, HTTP/2.0
}

// Fetcher fetches pages. It keeps cookies for the duration of a scan, so a
// redirect chain that sets a cookie behaves as in a browser.
type Fetcher struct {
	opt    Options
	client *http.Client
}

// ErrBlockedAddress is returned when a request would reach an address that is
// not allowed.
var ErrBlockedAddress = errors.New("address not allowed")

// New returns a Fetcher.
func New(opt Options) *Fetcher {
	if opt.Timeout <= 0 {
		opt.Timeout = DefaultTimeout
	}
	if opt.MaxBody <= 0 {
		opt.MaxBody = DefaultMaxBody
	}
	if opt.MaxRedirects <= 0 {
		opt.MaxRedirects = DefaultMaxRedirects
	}
	if opt.MaxAge <= 0 {
		opt.MaxAge = DefaultMaxAge
	}
	if opt.UserAgent == "" {
		opt.UserAgent = DefaultUserAgent
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	jar, _ := cookiejar.New(nil)
	rt := opt.Transport
	if rt == nil {
		rt = NewTransport(opt)
	}
	f := &Fetcher{opt: opt}
	f.client = &http.Client{Transport: rt, Jar: jar, Timeout: opt.Timeout}
	return f
}

// NewTransport returns the network transport New uses: the address guard sits in its
// dialer, so it holds for every connection, redirects included. A caller that wants to
// wrap the transport (rate limits, robots.txt) builds it here and passes the wrapper as
// Options.Transport, so the guard is not lost. One transport can be shared by many
// Fetchers: it is safe for concurrent use and keeps connections alive.
func NewTransport(opt Options) *http.Transport {
	if opt.Timeout <= 0 {
		opt.Timeout = DefaultTimeout
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	if !opt.AllowPrivate {
		allow := opt.Allow
		if allow == nil {
			allow = Public
		}
		dialer.Control = func(_, address string, _ syscall.RawConn) error { return guard(address, allow) }
	}
	return &http.Transport{
		Proxy:                 nil,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: opt.Insecure, MinVersion: tls.VersionTLS10}, //nolint:gosec // opt-in, recorded in the result
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: opt.Timeout,
		MaxIdleConns:          10,
		IdleConnTimeout:       30 * time.Second,
	}
}

// guard refuses connections to addresses that are not on the public internet.
func guard(address string, allow func(netip.Addr) bool) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrBlockedAddress, address)
	}
	if !allow(ip) {
		return fmt.Errorf("%w: %s is not a public address", ErrBlockedAddress, ip)
	}
	return nil
}

var (
	cgnat    = netip.MustParsePrefix("100.64.0.0/10")
	benchmrk = netip.MustParsePrefix("198.18.0.0/15")
	ula      = netip.MustParsePrefix("fc00::/7")
	nat64    = netip.MustParsePrefix("64:ff9b::/96")
)

// Public reports whether an address is a public unicast address a scanner may
// contact. IPv4-mapped IPv6 addresses are judged as their IPv4 form.
func Public(ip netip.Addr) bool {
	ip = ip.Unmap()
	switch {
	case !ip.IsValid(), ip.IsLoopback(), ip.IsPrivate(), ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast(),
		ip.IsMulticast(), ip.IsUnspecified(), ip.IsInterfaceLocalMulticast():
		return false
	}
	for _, p := range []netip.Prefix{cgnat, benchmrk, ula, nat64} {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}

// Get fetches a URL and follows redirects.
func (f *Fetcher) Get(ctx context.Context, rawURL string) (*Response, error) {
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return nil, fmt.Errorf("fetch: %q is not an http(s) URL", rawURL)
	}
	if r := f.fromCache(rawURL); r != nil {
		return r, nil
	}
	var chain []scan.Redirect
	f.client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= f.opt.MaxRedirects {
			return fmt.Errorf("fetch: stopped after %d redirects", f.opt.MaxRedirects)
		}
		if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
			return fmt.Errorf("fetch: redirect to %q refused", req.URL.Scheme)
		}
		if prev := req.Response; prev != nil {
			chain = append(chain, scan.Redirect{URL: via[len(via)-1].URL.String(), Status: prev.StatusCode})
		}
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("fetch: %w", err)
	}
	req.Header.Set("User-Agent", f.opt.UserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en;q=0.8,*;q=0.5")
	start := f.opt.Now()
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", rawURL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, f.opt.MaxBody+1))
	if err != nil {
		return nil, fmt.Errorf("fetch %s: reading the body: %w", rawURL, err)
	}
	r := &Response{
		URL: rawURL, FinalURL: resp.Request.URL.String(), Status: resp.StatusCode, Header: resp.Header.Clone(),
		SetCookies: resp.Header.Values("Set-Cookie"), ContentType: resp.Header.Get("Content-Type"),
		Redirects: chain, FetchedAt: start.UTC(), Duration: f.opt.Now().Sub(start), Proto: resp.Proto,
	}
	if int64(len(body)) > f.opt.MaxBody {
		body, r.Truncated = body[:f.opt.MaxBody], true
	}
	r.Body = body
	if resp.TLS != nil {
		r.TLS = tlsInfo(resp.TLS)
	}
	f.toCache(r)
	return r, nil
}

func tlsInfo(cs *tls.ConnectionState) *scan.TLS {
	t := &scan.TLS{Version: tls.VersionName(cs.Version), ALPN: cs.NegotiatedProtocol}
	if len(cs.PeerCertificates) > 0 {
		c := cs.PeerCertificates[0]
		t.Issuer, t.Subject = c.Issuer.String(), c.Subject.String()
		t.NotBefore, t.NotAfter = c.NotBefore.UTC(), c.NotAfter.UTC()
		t.DNSNames = append([]string(nil), c.DNSNames...)
	}
	return t
}

// Page converts a response into the result's page record.
func (r *Response) Page() scan.Page {
	h := map[string]string{}
	for k, v := range r.Header {
		h[strings.ToLower(k)] = strings.Join(v, "\n")
	}
	return scan.Page{
		URL: r.URL, FinalURL: r.FinalURL, Status: r.Status, ContentType: r.ContentType,
		Bytes: len(r.Body), DurationMS: int(r.Duration.Milliseconds()), Redirects: r.Redirects,
		Headers: h, Cached: r.Cached, Proto: r.Proto,
	}
}
