// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package scanner

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/fetch"
	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/web"
	"github.com/matteoredaelli/open-web-fingerprints/scan"
)

// RelatedOptions control the search for related domains.
type RelatedOptions struct {
	Fetch fetch.Options
	// Max is how many candidate domains get their home page read (default DefaultMaxRelated).
	Max int
	// Delay is the pause before each request to another site.
	Delay time.Duration
}

// DefaultMaxRelated bounds how many other sites one scan contacts to look for related domains.
const DefaultMaxRelated = 20

// HomeInfo is what the search needs to know about the target's home page.
type HomeInfo struct {
	Domain string      // registrable domain of the target
	URL    string      // final URL of its home page
	HTML   []byte      // its HTML
	Links  []scan.Link // links found on it
	TLS    *scan.TLS   // the certificate it presented, if any
}

type relCand struct {
	domain string
	origin string // scheme://host to read the home page from
	ev     []scan.RelatedEvidence
}

func strong(kind string) bool {
	switch kind {
	case scan.RelEvHreflangHome, scan.RelEvCertSAN, scan.RelEvCertOrg, scan.RelEvSiteVerification, scan.RelEvAnalyticsID:
		return true
	}
	return false
}

func ev(kind, detail string) scan.RelatedEvidence {
	s := "medium"
	if strong(kind) {
		s = "strong"
	}
	return scan.RelatedEvidence{Kind: kind, Strength: s, Detail: detail}
}

// FindRelated looks for domains that may belong to the same owner as the target.
//
// Candidates come from what the target says about itself: the domains its home page links to,
// the domains it declares as other-language versions (hreflang), and the other names in its
// TLS certificate. Each candidate's home page is then read, within the limits of a crawl
// (robots.txt honoured with no override, a pause, a cap, non-public addresses refused), and
// compared with the target's: the organization in the certificate, the ownership tokens put in
// meta tags for search engines, the tag manager and analytics identifiers, and the links and
// alternates that point back. A domain with at least one strong signal is "probable"; the rest are
// "candidate". Nothing here says who owns a domain.
func FindRelated(ctx context.Context, opt RelatedOptions, home HomeInfo) *scan.Related {
	if opt.Max <= 0 {
		opt.Max = DefaultMaxRelated
	}
	mine := web.ExtractSignals(home.HTML, home.URL)
	myOrg := ""
	if home.TLS != nil {
		myOrg = web.CertOrganization(home.TLS.Subject)
	}

	cands := map[string]*relCand{}
	add := func(domain, origin string, e scan.RelatedEvidence) {
		domain = strings.ToLower(domain)
		if domain == "" || domain == home.Domain || web.IsPlatformHost(domain) {
			return
		}
		c := cands[domain]
		if c == nil {
			c = &relCand{domain: domain, origin: origin}
			cands[domain] = c
		}
		for _, x := range c.ev {
			if x.Kind == e.Kind {
				return
			}
		}
		c.ev = append(c.ev, e)
	}
	for _, l := range home.Links {
		if l.Kind != "a" || l.Internal || l.Domain == "" {
			continue
		}
		if u, err := url.Parse(l.URL); err == nil && (u.Scheme == "http" || u.Scheme == "https") && !web.IsPlatformHost(u.Hostname()) {
			add(l.Domain, u.Scheme+"://"+u.Host, ev(scan.RelEvLinkedFromHome, l.URL))
		}
	}
	for _, a := range mine.Alternates {
		if u, err := url.Parse(a); err == nil && (u.Scheme == "http" || u.Scheme == "https") {
			if d := web.RegistrableDomain(u.Hostname()); d != home.Domain {
				add(d, u.Scheme+"://"+u.Host, ev(scan.RelEvHreflangHome, a))
			}
		}
	}
	if home.TLS != nil {
		for _, n := range home.TLS.DNSNames {
			n = strings.TrimPrefix(strings.ToLower(n), "*.")
			if d := web.RegistrableDomain(n); d != home.Domain && strings.Contains(n, ".") {
				add(d, "https://"+n, ev(scan.RelEvCertSAN, n))
			}
		}
	}

	list := make([]*relCand, 0, len(cands))
	for _, c := range cands {
		list = append(list, c)
	}
	// Candidates with strong signals are read first, so a low limit does not hide them.
	sort.Slice(list, func(i, j int) bool {
		si, sj := strongCount(list[i].ev), strongCount(list[j].ev)
		if si != sj {
			return si > sj
		}
		return list[i].domain < list[j].domain
	})

	out := &scan.Related{Candidates: len(list), Domains: []scan.RelatedDomain{}}
	f := fetch.New(opt.Fetch)
	for i, c := range list {
		d := scan.RelatedDomain{Domain: c.domain, Status: "checked", URL: c.origin + "/", Evidence: append([]scan.RelatedEvidence{}, c.ev...)}
		switch {
		case i >= opt.Max || ctx.Err() != nil:
			d.Status = "not_checked"
		case !sleep(ctx, opt.Delay):
			d.Status = "not_checked"
		default:
			out.Checked++
			rules, _, ok, rerr := fetchRobotsErr(ctx, f, c.origin)
			switch {
			case rerr != nil:
				d.Status, d.Detail = "unreachable", rerr.Error()
			case !ok || !rules.Allowed(c.origin+"/"):
				d.Status, d.Detail = "not_allowed", "robots.txt asks crawlers not to fetch the home page, or could not be read"
			case !sleep(ctx, opt.Delay):
				d.Status = "not_checked"
				out.Checked--
			default:
				compare(ctx, f, &d, home.Domain, mine, myOrg)
			}
		}
		d.Level = scan.RelatedCandidate
		if strongCount(d.Evidence) > 0 || (has(d.Evidence, scan.RelEvLinkedFromHome) && has(d.Evidence, scan.RelEvLinksBack)) {
			d.Level = scan.RelatedProbable
		}
		out.Domains = append(out.Domains, d)
	}
	sort.SliceStable(out.Domains, func(i, j int) bool {
		a, b := out.Domains[i], out.Domains[j]
		if (a.Level == scan.RelatedProbable) != (b.Level == scan.RelatedProbable) {
			return a.Level == scan.RelatedProbable
		}
		if sa, sb := strongCount(a.Evidence), strongCount(b.Evidence); sa != sb {
			return sa > sb
		}
		if len(a.Evidence) != len(b.Evidence) {
			return len(a.Evidence) > len(b.Evidence)
		}
		return a.Domain < b.Domain
	})
	return out
}

// compare reads a candidate's home page and adds what it shares with the target.
func compare(ctx context.Context, f *fetch.Fetcher, d *scan.RelatedDomain, target string, mine web.Signals, myOrg string) {
	resp, err := f.Get(ctx, d.URL)
	if err != nil {
		d.Status, d.Detail = "unreachable", err.Error()
		return
	}
	d.URL = resp.FinalURL
	if resp.TLS != nil && myOrg != "" && strings.EqualFold(web.CertOrganization(resp.TLS.Subject), myOrg) {
		d.Evidence = append(d.Evidence, ev(scan.RelEvCertOrg, myOrg))
	}
	ct := strings.ToLower(resp.ContentType)
	if resp.Status < 200 || resp.Status >= 300 || (ct != "" && !strings.Contains(ct, "html")) {
		d.Status, d.Detail = "unreachable", fmt.Sprintf("status %d, %q", resp.Status, ct)
		return
	}
	final, err := url.Parse(resp.FinalURL)
	if err != nil {
		return
	}
	theirs := web.ExtractSignals(resp.Body, resp.FinalURL)
	names := make([]string, 0, len(mine.Verification))
	for n := range mine.Verification {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if v, ok := theirs.Verification[n]; ok && v == mine.Verification[n] {
			d.Evidence = append(d.Evidence, ev(scan.RelEvSiteVerification, n+" "+short(v)))
		}
	}
	for _, id := range mine.IDs {
		for _, o := range theirs.IDs {
			if id == o {
				d.Evidence = append(d.Evidence, ev(scan.RelEvAnalyticsID, id))
			}
		}
	}
	for _, a := range theirs.Alternates {
		if web.RegistrableDomain(web.HostOf(a)) == target {
			d.Evidence = append(d.Evidence, ev(scan.RelEvHreflangBack, a))
			break
		}
	}
	ex := web.Extract([]web.Page{{URL: resp.FinalURL, Body: resp.Body}}, final.Hostname())
	for _, l := range ex.Links {
		if l.Kind == "a" && l.Domain == target {
			d.Evidence = append(d.Evidence, ev(scan.RelEvLinksBack, l.URL))
			break
		}
	}
}

func short(s string) string {
	if len(s) > 8 {
		return s[:8] + "…"
	}
	return s
}

func strongCount(es []scan.RelatedEvidence) int {
	n := 0
	for _, e := range es {
		if e.Strength == "strong" {
			n++
		}
	}
	return n
}

func has(es []scan.RelatedEvidence, kind string) bool {
	for _, e := range es {
		if e.Kind == kind {
			return true
		}
	}
	return false
}
