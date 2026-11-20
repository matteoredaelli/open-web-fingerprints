// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package observe

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/html"
	"golang.org/x/net/html/charset"

	"github.com/matteoredaelli/open-web-fingerprints/internal/matcher"
	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/fetch"
	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/web"
	"github.com/matteoredaelli/open-web-fingerprints/scan"
)

// Resolver looks names up. The real one is net.Resolver; tests replace it.
type Resolver interface {
	LookupIP(ctx context.Context, host string) ([]netip.Addr, error)
	LookupCNAME(ctx context.Context, host string) (string, error)
	LookupNS(ctx context.Context, domain string) ([]string, error)
	LookupMX(ctx context.Context, domain string) ([]string, error)
	LookupTXT(ctx context.Context, domain string) ([]string, error)
}

// SystemResolver resolves with the system's resolver.
type SystemResolver struct{ R *net.Resolver }

func (s SystemResolver) r() *net.Resolver {
	if s.R != nil {
		return s.R
	}
	return net.DefaultResolver
}

// LookupIP implements Resolver.
func (s SystemResolver) LookupIP(ctx context.Context, host string) ([]netip.Addr, error) {
	return s.r().LookupNetIP(ctx, "ip", host)
}

// LookupCNAME implements Resolver.
func (s SystemResolver) LookupCNAME(ctx context.Context, host string) (string, error) {
	return s.r().LookupCNAME(ctx, host)
}

// LookupNS implements Resolver.
func (s SystemResolver) LookupNS(ctx context.Context, d string) ([]string, error) {
	ns, err := s.r().LookupNS(ctx, d)
	var out []string
	for _, n := range ns {
		out = append(out, n.Host)
	}
	return out, err
}

// LookupMX implements Resolver.
func (s SystemResolver) LookupMX(ctx context.Context, d string) ([]string, error) {
	mx, err := s.r().LookupMX(ctx, d)
	var out []string
	for _, m := range mx {
		out = append(out, fmt.Sprintf("%d %s", m.Pref, m.Host))
	}
	return out, err
}

// LookupTXT implements Resolver.
func (s SystemResolver) LookupTXT(ctx context.Context, d string) ([]string, error) {
	return s.r().LookupTXT(ctx, d)
}

// Options control what is observed.
type Options struct {
	Fetcher  *fetch.Fetcher
	Resolver Resolver // nil: no DNS
	// NoFavicon skips the extra request for the favicon.
	NoFavicon bool
	// MaxFavicon bounds the favicon size. Default 256 KiB.
	MaxFavicon int
}

// Observed is a page together with everything derived from it.
type Observed struct {
	Page        scan.Page
	Host        scan.Host
	Observation matcher.Observation
	// HTML is the body decoded to UTF-8 when it is a text page, else empty.
	HTML     []byte
	Warnings []scan.Warning
}

// Observe fetches the target and builds its observation. rawURL may omit the
// scheme: https is tried first and, only if the connection cannot be made, http.
func Observe(ctx context.Context, opt Options, rawURL string) (*Observed, error) {
	if opt.Fetcher == nil {
		return nil, errors.New("observe: no fetcher")
	}
	if opt.MaxFavicon <= 0 {
		opt.MaxFavicon = 256 << 10
	}
	o := &Observed{}
	target := strings.TrimSpace(rawURL)
	bare := !strings.Contains(target, "://")
	if bare {
		target = "https://" + target
	}
	resp, err := opt.Fetcher.Get(ctx, target)
	if err != nil && bare && ctx.Err() == nil && !errors.Is(err, fetch.ErrBlockedAddress) {
		first := err
		alt := "http://" + strings.TrimSpace(rawURL)
		if resp, err = opt.Fetcher.Get(ctx, alt); err == nil {
			o.warn("https_unavailable", "https failed, the page was fetched over http: "+first.Error(), target)
		}
	}
	if err != nil {
		return nil, err
	}
	o.Page = resp.Page()
	if resp.Truncated {
		o.warn("body_truncated", "the page is larger than the limit and was cut", resp.FinalURL)
	}
	final, err := url.Parse(resp.FinalURL)
	if err != nil {
		return nil, fmt.Errorf("observe: %w", err)
	}

	obs := &o.Observation
	obs.URL, obs.Status = resp.FinalURL, resp.Status
	obs.Headers = map[string]string{}
	for k, v := range resp.Header {
		if strings.EqualFold(k, "Set-Cookie") {
			continue
		}
		obs.Headers[strings.ToLower(k)] = strings.Join(v, ", ")
	}
	obs.SetCookies = resp.SetCookies
	obs.Cookies = cookieMap(resp.SetCookies)
	if isText(resp) {
		body, err := toUTF8(resp.Body, resp.ContentType)
		if err != nil {
			o.warn("charset", "the page could not be decoded: "+err.Error(), resp.FinalURL)
			body = resp.Body
		}
		o.HTML, obs.HTML = body, string(body)
	}
	if resp.TLS != nil {
		t := *resp.TLS
		o.Host.TLS = &t
		obs.TLS = map[string]string{"issuer": t.Issuer, "subject": t.Subject, "version": t.Version}
	}
	if opt.Resolver != nil {
		o.dns(ctx, opt.Resolver, final.Hostname(), obs)
	}
	if !opt.NoFavicon && len(o.HTML) > 0 {
		o.favicon(ctx, opt, final, obs)
	}
	return o, nil
}

func (o *Observed) warn(code, msg, ref string) {
	o.Warnings = append(o.Warnings, scan.Warning{Code: code, Message: msg, Ref: ref})
}

func isText(r *fetch.Response) bool {
	ct := strings.ToLower(r.ContentType)
	if strings.Contains(ct, "html") || strings.Contains(ct, "xml") || strings.HasPrefix(ct, "text/") {
		return true
	}
	// A missing or wrong content type: look at the start of the body.
	return ct == "" && strings.Contains(strings.ToLower(http.DetectContentType(r.Body)), "text/html")
}

func toUTF8(b []byte, contentType string) ([]byte, error) {
	r, err := charset.NewReader(bytes.NewReader(b), contentType)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

func cookieMap(lines []string) map[string]string {
	out := map[string]string{}
	for _, l := range lines {
		c, err := http.ParseSetCookie(l)
		if err != nil || c.Name == "" {
			continue
		}
		out[c.Name] = c.Value
	}
	return out
}

// dns collects what is known about the host and its domain. A failing lookup is
// not an error of the scan: it is a warning and the record type is left out.
func (o *Observed) dns(ctx context.Context, r Resolver, host string, obs *matcher.Observation) {
	if _, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		o.Host.IPs = []string{strings.Trim(host, "[]")}
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	domain := web.RegistrableDomain(host)
	o.Host.DNS = map[string][]string{}
	obs.DNS = map[string][]string{}
	set := func(typ string, vals []string, err error, name string) {
		if err != nil {
			var nf *net.DNSError
			if notFound := errors.As(err, &nf) && nf.IsNotFound; !notFound {
				o.warn("dns_"+strings.ToLower(typ), err.Error(), name)
			}
		}
		if len(vals) == 0 {
			return
		}
		sort.Strings(vals)
		o.Host.DNS[typ], obs.DNS[typ] = vals, vals
	}
	ips, err := r.LookupIP(ctx, host)
	if err != nil {
		o.warn("dns_ip", err.Error(), host)
	}
	for _, ip := range ips {
		o.Host.IPs = append(o.Host.IPs, ip.String())
	}
	sort.Strings(o.Host.IPs)
	if c, err := r.LookupCNAME(ctx, host); err == nil && c != "" && !strings.EqualFold(strings.TrimSuffix(c, "."), host) {
		set("CNAME", []string{c}, nil, host)
	}
	ns, err := r.LookupNS(ctx, domain)
	set("NS", ns, err, domain)
	mx, err := r.LookupMX(ctx, domain)
	set("MX", mx, err, domain)
	txt, err := r.LookupTXT(ctx, domain)
	set("TXT", txt, err, domain)
	if len(o.Host.DNS) == 0 {
		o.Host.DNS, obs.DNS = nil, nil
	}
}

// favicon fetches the icon the page declares, or /favicon.ico, and hashes it.
// It is one more request to the same site. A response that is not an image (many
// sites answer a missing favicon with their home page) is not hashed.
func (o *Observed) favicon(ctx context.Context, opt Options, final *url.URL, obs *matcher.Observation) {
	for _, cand := range iconCandidates(o.HTML, final) {
		resp, err := opt.Fetcher.Get(ctx, cand)
		if err != nil {
			o.warn("favicon", err.Error(), cand)
			continue
		}
		ct := strings.ToLower(resp.ContentType)
		if resp.Status != 200 || len(resp.Body) == 0 || len(resp.Body) > opt.MaxFavicon || resp.Truncated ||
			strings.Contains(ct, "html") || strings.HasPrefix(ct, "text/") {
			continue
		}
		h := FaviconHashes(resp.Body)
		obs.FaviconHashes = h
		obs.FaviconHash = h["mmh3"]
		return
	}
}

// iconCandidates lists the URLs to try, in order: the declared icons, then
// /favicon.ico. data: URLs and other schemes are skipped.
func iconCandidates(body []byte, page *url.URL) []string {
	var out []string
	seen := map[string]bool{}
	add := func(raw string) {
		if u, ok := web.NormalizeURL(page, raw); ok && !seen[u.String()] {
			seen[u.String()] = true
			out = append(out, u.String())
		}
	}
	doc, err := html.Parse(bytes.NewReader(body))
	if err == nil {
		base := page
		var walk func(n *html.Node)
		walk = func(n *html.Node) {
			if n.Type == html.ElementNode && n.Data == "link" {
				var rel, href string
				for _, a := range n.Attr {
					switch a.Key {
					case "rel":
						rel = strings.ToLower(a.Val)
					case "href":
						href = a.Val
					}
				}
				if href != "" && (strings.Contains(rel, "icon")) && !strings.Contains(rel, "apple-touch") && !strings.Contains(rel, "mask-icon") {
					if u, ok := web.NormalizeURL(base, href); ok {
						add(u.String())
					}
				}
			}
			for ch := n.FirstChild; ch != nil; ch = ch.NextSibling {
				walk(ch)
			}
		}
		walk(doc)
	}
	add("/favicon.ico")
	if len(out) > 3 {
		out = out[:3]
	}
	return out
}
