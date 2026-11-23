// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package client

import (
	"context"
	"net/url"

	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/engine"
	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/fetch"
	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/observe"
	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/scanner"
	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/web"
	"github.com/matteoredaelli/open-web-fingerprints/scan"
)

// The parts of a scan, each on its own: what `owfscan extract`, `links`, `social`,
// `observe`, `friends` and `related` do. They use the same fields of Options as Scan
// and the same guards.

// ValidHealth reports whether s is a value of Options.MinHealth: broken, degraded,
// unknown or ok.
func ValidHealth(s string) bool { return engine.ValidHealth(s) }

// Extraction is what a set of pages publishes: links, the domains they point to,
// social profiles and contact details.
type Extraction = web.Extraction

// Extract reads saved HTML, fetched from pageURL (relative links are resolved against
// it; links to the same registrable domain are internal). It makes no request.
func Extract(html []byte, pageURL string) (Extraction, error) {
	u, err := url.Parse(pageURL)
	if err != nil || u.Hostname() == "" {
		return Extraction{}, errBadURL
	}
	return web.Extract([]web.Page{{URL: pageURL, Body: html}}, u.Hostname()), nil
}

// RegistrableDomain returns the registrable domain (eTLD+1) of a host name.
func RegistrableDomain(host string) string { return web.RegistrableDomain(host) }

// Site is what the pages of a site publish.
type Site struct {
	URL   string   // final URL of the first page
	Pages []string // final URLs of the pages read, the first included
	Extraction
}

func (o Options) crawl(dns, favicon bool) scanner.CrawlOptions {
	c := scanner.CrawlOptions{
		Fetch: o.fetchOptions(), NoFavicon: !favicon,
		Depth: o.Depth, MaxPages: o.MaxPages, Delay: o.Delay, MaxDelay: o.MaxDelay, IgnoreRobots: o.IgnoreRobots,
	}
	if dns {
		c.Resolver = observe.SystemResolver{}
	}
	return c
}

// ReadSite fetches a page (and with Options.Depth the pages it leads to) and extracts
// links, domains, social profiles and contacts from all of them.
func ReadSite(ctx context.Context, opt Options, target string) (*Site, error) {
	c, err := scanner.Crawl(ctx, opt.crawl(false, false), target)
	if err != nil {
		return nil, err
	}
	var pages []web.Page
	var urls []string
	for _, p := range c.Pages {
		urls = append(urls, p.Page.FinalURL)
		if len(p.HTML) > 0 {
			pages = append(pages, web.Page{URL: p.Page.FinalURL, Body: p.HTML})
		}
	}
	host := ""
	if u, err := url.Parse(c.Main.Page.FinalURL); err == nil {
		host = u.Hostname()
	}
	ex := web.Extract(pages, host)
	ex.Warnings = append(append([]scan.Warning{}, c.Warnings...), ex.Warnings...)
	return &Site{URL: c.Main.Page.FinalURL, Pages: urls, Extraction: ex}, nil
}

// Observed is what the rules are applied to: the page, its host, the observation and
// the body. The body is left out unless Options.KeepHTML is set.
type Observed = observe.Observed

// Observe fetches a page, its favicon (unless Options.NoFavicon) and, with Options.DNS,
// the DNS records of its host, and returns what the rules read. Headers named in
// Options.DropHeaders are left out of the output (the observation too), and the cookie
// values with them when set-cookie is on the list, so two calls in a row agree.
func Observe(ctx context.Context, opt Options, target string) (*Observed, error) {
	o := observe.Options{Fetcher: fetch.New(opt.fetchOptions()), NoFavicon: opt.NoFavicon}
	if opt.DNS {
		o.Resolver = observe.SystemResolver{}
	}
	ob, err := observe.Observe(ctx, o, target)
	if err != nil {
		return nil, err
	}
	if !opt.KeepHTML {
		ob.Observation.HTML = ""
	}
	if drop := opt.DropHeaders; len(drop) > 0 {
		page := ob.Page
		page.Headers, page.HeadersFiltered = observe.FilterHeaders(page.Headers, drop), true
		ob.Page = page
		ob.Observation.Headers = observe.FilterHeaders(ob.Observation.Headers, drop)
		if observe.Dropped("set-cookie", drop) {
			// The cookie names stay (they are what rules look for); the values and the
			// raw lines are what changes.
			ob.Observation.SetCookies = nil
			names := make(map[string]string, len(ob.Observation.Cookies))
			for k := range ob.Observation.Cookies {
				names[k] = ""
			}
			ob.Observation.Cookies = names
		}
	}
	return ob, nil
}

// FriendsResult is the answer of Friends.
type FriendsResult struct {
	URL     string // final URL of the home page
	Friends *scan.Friends
}

// Friends reads a home page and looks for friend domains: linked from it and linking
// back. It reads the home page only, whatever Options.Depth says. It contacts other
// sites: robots.txt is always honoured, Options.Delay separates requests and at most
// Options.FriendsMax sites are contacted.
func Friends(ctx context.Context, opt Options, target string) (*FriendsResult, error) {
	opt.Depth = 0
	c, err := scanner.Crawl(ctx, opt.crawl(false, false), target)
	if err != nil {
		return nil, err
	}
	u, err := url.Parse(c.Main.Page.FinalURL)
	if err != nil {
		return nil, err
	}
	ex := web.Extract([]web.Page{{URL: c.Main.Page.FinalURL, Body: c.Main.HTML}}, u.Hostname())
	fr := scanner.FindFriends(ctx, scanner.FriendsOptions{Fetch: opt.fetchOptions(), Max: opt.FriendsMax, Delay: opt.Delay},
		scanner.Home{Domain: web.RegistrableDomain(u.Hostname()), Links: ex.Links})
	return &FriendsResult{URL: c.Main.Page.FinalURL, Friends: fr}, nil
}

// RelatedResult is the answer of Related.
type RelatedResult struct {
	URL     string // final URL of the home page
	Related *scan.Related
}

// Related reads a home page and looks for domains that may belong to the same owner,
// with the evidence for each. It reads the home page only, looks names up in DNS and
// contacts other sites under the same rules as Friends, at most Options.RelatedMax of
// them. Options.RelatedTLDs also tries the target's name under other TLDs.
func Related(ctx context.Context, opt Options, target string) (*RelatedResult, error) {
	opt.Depth = 0
	c, err := scanner.Crawl(ctx, opt.crawl(true, false), target)
	if err != nil {
		return nil, err
	}
	u, err := url.Parse(c.Main.Page.FinalURL)
	if err != nil {
		return nil, err
	}
	ex := web.Extract([]web.Page{{URL: c.Main.Page.FinalURL, Body: c.Main.HTML}}, u.Hostname())
	r := scanner.FindRelated(ctx, scanner.RelatedOptions{
		Fetch: opt.fetchOptions(), Max: opt.RelatedMax, Delay: opt.Delay, TLDs: opt.RelatedTLDs, Resolver: observe.SystemResolver{},
	}, scanner.HomeInfo{
		Domain: web.RegistrableDomain(u.Hostname()), URL: c.Main.Page.FinalURL, HTML: c.Main.HTML, Links: ex.Links, TLS: c.Main.Host.TLS,
	})
	return &RelatedResult{URL: c.Main.Page.FinalURL, Related: r}, nil
}
