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

// FriendsOptions control friend detection.
type FriendsOptions struct {
	Fetch fetch.Options
	// Max is how many candidate domains to look at (default DefaultMaxFriends).
	Max int
	// Delay is the pause before each request to another site.
	Delay time.Duration
}

// DefaultMaxFriends bounds how many other sites one scan contacts.
const DefaultMaxFriends = 20

// FindFriends looks for "friend" domains. A domain is a friend when the target's home
// page links to it and its own home page links back to the target's registrable domain.
//
// Only ordinary links (<a>) count, from the first page's links; social platforms are
// not candidates (their home pages link to everything). Each candidate costs one request
// to a site the user did not name, so it is held to the same rules as a crawl and more:
// its robots.txt must allow "/" for owfscan (no option overrides this), there is a pause
// before each request, the number of sites is bounded, and non-public addresses are
// refused. Candidates are taken by the number of links to them, then by name.
func FindFriends(ctx context.Context, opt FriendsOptions, home Home) *scan.Friends {
	if opt.Max <= 0 {
		opt.Max = DefaultMaxFriends
	}
	type cand struct {
		domain string
		links  []string // links on the home page
		first  *url.URL // first one: where the site's own host is taken from
	}
	byDomain := map[string]*cand{}
	for _, l := range home.Links {
		if l.Kind != "a" || l.Internal || l.Domain == "" || l.Domain == home.Domain {
			continue
		}
		u, err := url.Parse(l.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || web.IsPlatformHost(u.Hostname()) {
			continue
		}
		c := byDomain[l.Domain]
		if c == nil {
			c = &cand{domain: l.Domain, first: u}
			byDomain[l.Domain] = c
		}
		c.links = append(c.links, l.URL)
	}
	cs := make([]*cand, 0, len(byDomain))
	for _, c := range byDomain {
		cs = append(cs, c)
	}
	sort.Slice(cs, func(i, j int) bool {
		if len(cs[i].links) != len(cs[j].links) {
			return len(cs[i].links) > len(cs[j].links)
		}
		return cs[i].domain < cs[j].domain
	})

	out := &scan.Friends{Candidates: len(cs), Domains: []scan.Friend{}}
	f := fetch.New(opt.Fetch)
	for i, c := range cs {
		fr := scan.Friend{Domain: c.domain, LinkedFrom: firstN(c.links, 5)}
		if i >= opt.Max || ctx.Err() != nil {
			fr.Status = scan.FriendNotChecked
			out.Domains = append(out.Domains, fr)
			continue
		}
		out.Checked++
		origin := c.first.Scheme + "://" + c.first.Host
		fr.URL = origin + "/"
		if !sleep(ctx, opt.Delay) {
			fr.Status, fr.Detail = scan.FriendNotChecked, "cancelled"
			out.Checked--
			out.Domains = append(out.Domains, fr)
			continue
		}
		rules, _, ok, rerr := fetchRobotsErr(ctx, f, origin)
		switch {
		case rerr != nil:
			fr.Status, fr.Detail = scan.FriendUnreadable, rerr.Error()
		case !ok:
			fr.Status, fr.Detail = scan.FriendBlocked, "robots.txt could not be read, so the site was not asked"
		case !rules.Allowed(origin + "/"):
			fr.Status, fr.Detail = scan.FriendBlocked, "robots.txt asks crawlers not to fetch the home page"
		default:
			friendCheck(ctx, f, home.Domain, &fr, origin+"/", opt.Delay)
		}
		out.Domains = append(out.Domains, fr)
	}
	return out
}

// Home is what friend detection needs to know about the target.
type Home struct {
	Domain string      // registrable domain of the target
	Links  []scan.Link // links found on the target's home page
}

func friendCheck(ctx context.Context, f *fetch.Fetcher, target string, fr *scan.Friend, homeURL string, delay time.Duration) {
	if !sleep(ctx, delay) {
		fr.Status, fr.Detail = scan.FriendNotChecked, "cancelled"
		return
	}
	resp, err := f.Get(ctx, homeURL)
	if err != nil {
		fr.Status, fr.Detail = scan.FriendUnreadable, err.Error()
		return
	}
	fr.URL = resp.FinalURL
	ct := strings.ToLower(resp.ContentType)
	if resp.Status < 200 || resp.Status >= 300 || (ct != "" && !strings.Contains(ct, "html")) {
		fr.Status = scan.FriendUnreadable
		fr.Detail = fmt.Sprintf("status %d, %q", resp.Status, ct)
		return
	}
	final, err := url.Parse(resp.FinalURL)
	if err != nil {
		fr.Status, fr.Detail = scan.FriendUnreadable, err.Error()
		return
	}
	ex := web.Extract([]web.Page{{URL: resp.FinalURL, Body: resp.Body}}, final.Hostname())
	var back []string
	for _, l := range ex.Links {
		if l.Kind == "a" && l.Domain == target {
			back = append(back, l.URL)
		}
	}
	if len(back) > 0 {
		fr.Status, fr.LinksBack = scan.FriendYes, firstN(dedupe(back), 5)
		return
	}
	fr.Status = scan.FriendNo
	// A redirect to a site of the target itself would be a link of sorts, but not a friend.
	if web.RegistrableDomain(final.Hostname()) == target {
		fr.Detail = "redirects to the target"
	}
}

func firstN(l []string, n int) []string {
	l = dedupe(l)
	if len(l) > n {
		return l[:n]
	}
	return l
}

func dedupe(l []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(l))
	for _, s := range l {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
