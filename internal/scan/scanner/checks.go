// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package scanner

import (
	"context"
	"net/netip"
	"net/url"
	"time"

	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/checks"
	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/fetch"
	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/observe"
	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/robots"
	"github.com/matteoredaelli/open-web-fingerprints/scan"
)

const securityTxtPath = "/.well-known/security.txt"

// runChecks builds the Checks of a result. The headers, the connection and robots.txt come from
// what the crawl already read; the mail records are DNS queries. It adds at most two requests:
// robots.txt (if the crawl did not read it) and security.txt (skipped if robots.txt asks crawlers
// to stay away from it).
func runChecks(ctx context.Context, opt Options, crawl *Crawled, ob *observe.Observed, final *url.URL, domain string, now time.Time) (*scan.Checks, []scan.Warning) {
	var warns []scan.Warning
	c := &scan.Checks{
		Headers:   checks.Headers(ob.Page.FinalURL, ob.Observation.Headers, ob.Observation.SetCookies),
		Transport: checks.Transport(ob.Page, ob.Host.TLS, now),
		Policies:  &scan.Policies{},
	}
	// A crawl of one page does not read robots.txt; the review needs it, and robots.txt may
	// always be fetched.
	text, fetched := crawl.Robots, crawl.RobotsFetched
	if !fetched {
		origin := (&url.URL{Scheme: final.Scheme, Host: final.Host}).String()
		_, text, fetched = fetchRobots(ctx, fetch.New(opt.Fetch), origin)
	}
	if fetched {
		c.Policies.Robots = checks.Robots(text, text != "")
	}
	allowed := true
	if fetched && !opt.IgnoreRobots {
		allowed = robots.Parse(text, userAgentToken).Allowed(securityTxtPath)
	}
	if allowed {
		u := (&url.URL{Scheme: final.Scheme, Host: final.Host, Path: securityTxtPath}).String()
		resp, err := fetch.New(opt.Fetch).Get(ctx, u)
		switch {
		case err != nil:
			warns = append(warns, scan.Warning{Code: "check_security_txt", Message: err.Error(), Ref: u})
		default:
			c.Policies.SecurityTxt = checks.SecurityTxt(resp.Status, resp.ContentType, resp.Body, resp.FinalURL, now)
		}
	}
	if _, err := netip.ParseAddr(final.Hostname()); err != nil && opt.Resolver != nil && domain != "" {
		mail, w := checks.Mail(ctx, opt.Resolver, domain)
		c.Mail = mail
		warns = append(warns, w...)
	}
	return c, warns
}
