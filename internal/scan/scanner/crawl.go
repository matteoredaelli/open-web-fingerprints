// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package scanner

import (
	"context"
	"fmt"
	"net/url"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/fetch"
	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/observe"
	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/robots"
	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/web"
	"github.com/matteoredaelli/open-web-fingerprints/scan"
)

// CrawlOptions control how far a scan goes beyond the page it was asked for.
type CrawlOptions struct {
	Fetch     fetch.Options
	Resolver  observe.Resolver
	NoFavicon bool
	// Depth is how many link levels to follow from the first page (0: only that
	// page). MaxPages bounds the pages fetched in total, the first included.
	Depth, MaxPages int
	// Delay is the pause before each further request. A larger Crawl-delay in
	// robots.txt wins, up to MaxDelay.
	Delay time.Duration
	// IgnoreRobots fetches pages that robots.txt asks crawlers to avoid. The page
	// the user names is always fetched.
	IgnoreRobots bool
}

// Defaults for a crawl.
const (
	DefaultMaxPages = 8
	DefaultDelay    = 500 * time.Millisecond
	MaxDelay        = 10 * time.Second
	userAgentToken  = "owfscan"
)

// Crawled is what a crawl found: the observation of the first page and of each
// page followed.
type Crawled struct {
	Main   *observe.Observed
	Pages  []*observe.Observed // every page, the first one included, in fetch order
	Robots string              // robots.txt of the first page's host, when fetched
	// RobotsFetched is true when the first page's robots.txt was read (it may be
	// absent or empty: Robots is then "").
	RobotsFetched bool
	Warnings      []scan.Warning
}

// Crawl observes a page and, if asked, the pages it links to that are most likely to
// say something about the site: contact, about, press, legal and similar. It stays
// on the registrable domain of the first page, follows only ordinary links, skips
// files and addresses with a query, honours robots.txt, pauses between requests and
// never fetches more than MaxPages pages.
func Crawl(ctx context.Context, opt CrawlOptions, target string) (*Crawled, error) {
	f := fetch.New(opt.Fetch)
	main, err := observe.Observe(ctx, observe.Options{Fetcher: f, Resolver: opt.Resolver, NoFavicon: opt.NoFavicon}, target)
	if err != nil {
		return nil, err
	}
	c := &Crawled{Main: main, Pages: []*observe.Observed{main}, Warnings: append([]scan.Warning{}, main.Warnings...)}
	if opt.Depth <= 0 {
		return c, nil
	}
	if opt.MaxPages <= 0 {
		opt.MaxPages = DefaultMaxPages
	}
	final, err := url.Parse(main.Page.FinalURL)
	if err != nil {
		return nil, fmt.Errorf("crawl: %w", err)
	}
	site := web.RegistrableDomain(final.Hostname())

	// robots.txt is read once per host. A host whose robots.txt cannot be read
	// (server error) is not crawled: the site cannot be asked, so it is not assumed
	// to agree.
	type hostRobots struct {
		rules *robots.Rules
		ok    bool
	}
	hosts := map[string]hostRobots{}
	robotsOf := func(u *url.URL) hostRobots {
		origin := u.Scheme + "://" + u.Host
		if h, seen := hosts[origin]; seen {
			return h
		}
		h := hostRobots{ok: true}
		if !opt.IgnoreRobots {
			r, text, ok := fetchRobots(ctx, f, origin)
			h = hostRobots{rules: r, ok: ok}
			if origin == final.Scheme+"://"+final.Host {
				c.Robots, c.RobotsFetched = text, ok
			}
			if !ok {
				c.Warnings = append(c.Warnings, scan.Warning{Code: "robots_unavailable",
					Message: "robots.txt could not be read, so no further pages of this host are fetched", Ref: origin})
			}
		}
		hosts[origin] = h
		return h
	}
	// The first page's robots.txt is read in any case when crawling: the rules that
	// read it need it, and the crawl depends on it.
	robotsOf(final)

	visited := map[string]bool{key(final): true}
	for _, p := range c.Pages {
		visited[key(mustParse(p.Page.FinalURL))] = true
	}
	prev := c.Pages
	for level := 1; level <= opt.Depth && len(c.Pages) < opt.MaxPages; level++ {
		var pages []web.Page
		for _, p := range prev {
			if len(p.HTML) > 0 {
				pages = append(pages, web.Page{URL: p.Page.FinalURL, Body: p.HTML})
			}
		}
		ex := web.Extract(pages, final.Hostname())
		cands := selectLinks(ex.Links, site, visited)
		var added []*observe.Observed
		for _, cand := range cands {
			if len(c.Pages) >= opt.MaxPages || ctx.Err() != nil {
				break
			}
			u := mustParse(cand)
			h := robotsOf(u)
			if !h.ok || (h.rules != nil && !h.rules.Allowed(cand)) {
				visited[key(u)] = true
				continue
			}
			wait := opt.Delay
			if h.rules != nil && h.rules.CrawlDelay > wait {
				wait = h.rules.CrawlDelay
			}
			if wait > MaxDelay {
				wait = MaxDelay
			}
			if !sleep(ctx, wait) {
				break
			}
			visited[key(u)] = true
			o, err := observe.Observe(ctx, observe.Options{Fetcher: f, NoFavicon: true}, cand)
			if err != nil {
				c.Warnings = append(c.Warnings, scan.Warning{Code: "page_failed", Message: err.Error(), Ref: cand})
				continue
			}
			// A redirect can lead to a page already seen or out of the site.
			fu := mustParse(o.Page.FinalURL)
			if web.RegistrableDomain(fu.Hostname()) != site || (visited[key(fu)] && key(fu) != key(u)) {
				continue
			}
			visited[key(fu)] = true
			c.Warnings = append(c.Warnings, o.Warnings...)
			c.Pages = append(c.Pages, o)
			added = append(added, o)
		}
		if len(added) == 0 {
			break
		}
		prev = added
	}
	if n := len(c.Pages); n >= opt.MaxPages {
		c.Warnings = append(c.Warnings, scan.Warning{Code: "page_limit",
			Message: fmt.Sprintf("stopped at %d pages (--max-pages); other candidate pages were not fetched", n)})
	}
	return c, ctx.Err()
}

func mustParse(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		return &url.URL{}
	}
	return u
}

// key identifies a page for the purpose of not fetching it twice: host, path without
// a trailing slash, no query.
func key(u *url.URL) string {
	p := strings.TrimSuffix(u.EscapedPath(), "/")
	return strings.ToLower(u.Hostname()) + p
}

func sleep(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// fetchRobots reads /robots.txt of an origin. A missing file (4xx) allows everything;
// a server error or a network failure means the site cannot be asked, and ok is false.
func fetchRobots(ctx context.Context, f *fetch.Fetcher, origin string) (rules *robots.Rules, text string, ok bool) {
	resp, err := f.Get(ctx, origin+"/robots.txt")
	switch {
	case err != nil:
		return &robots.Rules{}, "", false
	case resp.Status >= 500:
		return &robots.Rules{}, "", false
	case resp.Status >= 400 || resp.Status < 200:
		return robots.Parse("", userAgentToken), "", true
	}
	body := resp.Body
	if len(body) > 512<<10 {
		body = body[:512<<10]
	}
	text = string(body)
	return robots.Parse(text, userAgentToken), text, true
}

// skipExt are files, not pages.
var skipExt = map[string]bool{
	".pdf": true, ".zip": true, ".gz": true, ".tar": true, ".rar": true, ".7z": true, ".exe": true, ".dmg": true, ".apk": true,
	".jpg": true, ".jpeg": true, ".png": true, ".gif": true, ".svg": true, ".webp": true, ".ico": true, ".avif": true,
	".mp3": true, ".mp4": true, ".mov": true, ".avi": true, ".webm": true, ".wav": true,
	".doc": true, ".docx": true, ".xls": true, ".xlsx": true, ".ppt": true, ".pptx": true, ".csv": true,
	".xml": true, ".json": true, ".rss": true, ".atom": true, ".css": true, ".js": true, ".woff": true, ".woff2": true, ".ttf": true,
}

// keywords score a path segment: the pages that most often list a company's social
// profiles, contact details and legal entity. Matching is on whole words of the path
// (split on / - _ and .), in the languages that appear most on company sites.
var keywords = map[string]int{
	"contact": 10, "contacts": 10, "contacts-us": 10, "contatti": 10, "contatto": 10, "kontakt": 10, "contacto": 10, "contactez": 10, "contato": 10, "contactenos": 10,
	"about": 8, "about-us": 8, "company": 8, "who-we-are": 8, "chi-siamo": 8, "azienda": 8, "ueber-uns": 8, "uber-uns": 8, "a-propos": 8, "quienes-somos": 8, "sobre": 8, "nosotros": 8, "profile": 6,
	"imprint": 7, "impressum": 7, "legal": 7, "legal-notice": 7, "mentions-legales": 7, "note-legali": 7, "aviso-legal": 7,
	"press": 6, "media": 5, "newsroom": 6, "stampa": 6, "presse": 6, "pressemitteilungen": 6, "prensa": 6,
	"social": 6, "follow-us": 6, "community": 4,
	"careers": 5, "career": 5, "jobs": 5, "lavora-con-noi": 5, "karriere": 5, "carrieres": 5, "empleo": 5,
	"team": 5, "people": 4, "leadership": 5, "management": 4,
	"support": 4, "help": 3, "faq": 3, "assistenza": 4, "service": 3,
	"investors": 4, "investor-relations": 4, "sustainability": 3, "esg": 3,
	"privacy": 2, "cookies": 2, "cookie-policy": 2, "terms": 2,
	"locations": 3, "stores": 3, "dealers": 3, "offices": 4, "sedi": 4,
}

// score rates a path: the best keyword it contains, with a small preference for short
// paths. Zero means the page is not worth fetching.
func score(p string) int {
	best := 0
	segs := strings.FieldsFunc(strings.ToLower(p), func(r rune) bool { return r == '/' })
	for _, seg := range segs {
		seg = strings.TrimSuffix(seg, path.Ext(seg))
		if v := keywords[seg]; v > best {
			best = v
		}
		for _, w := range strings.FieldsFunc(seg, func(r rune) bool { return r == '-' || r == '_' || r == '.' }) {
			if v := keywords[w]; v > best {
				best = v
			}
		}
	}
	if best == 0 {
		return 0
	}
	// A page near the root is more likely the page itself than an article about it.
	if d := len(segs); d > 3 {
		best -= d - 3
	}
	if best < 1 {
		best = 1
	}
	return best
}

// selectLinks picks the links to follow: ordinary links (not stylesheets, scripts,
// images) to the same registrable domain, over http or https, without a query,
// that are not files and not seen, ordered by score and then by address. It marks
// nothing visited; the caller does that when it fetches.
func selectLinks(links []scan.Link, site string, visited map[string]bool) []string {
	type cand struct {
		url   string
		score int
	}
	seen := map[string]bool{}
	var cs []cand
	for _, l := range links {
		if l.Kind != "a" || l.Domain != site {
			continue
		}
		u, err := url.Parse(l.URL)
		if err != nil || u.RawQuery != "" || (u.Scheme != "http" && u.Scheme != "https") {
			continue
		}
		if skipExt[strings.ToLower(path.Ext(u.Path))] {
			continue
		}
		k := key(u)
		if visited[k] || seen[k] {
			continue
		}
		seen[k] = true
		if s := score(u.Path); s > 0 {
			cs = append(cs, cand{l.URL, s})
		}
	}
	sort.SliceStable(cs, func(i, j int) bool {
		if cs[i].score != cs[j].score {
			return cs[i].score > cs[j].score
		}
		return cs[i].url < cs[j].url
	})
	out := make([]string, len(cs))
	for i, c := range cs {
		out[i] = c.url
	}
	return out
}
