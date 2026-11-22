// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package scanner

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/fetch"
	"github.com/matteoredaelli/open-web-fingerprints/scan"
)

func TestScore(t *testing.T) {
	for p, positive := range map[string]bool{
		"/contact": true, "/en/contact-us/": true, "/it/contatti": true, "/azienda/chi-siamo": true, "/about.html": true,
		"/legal/imprint": true, "/press": true, "/media/newsroom": true, "/careers/": true, "/de/kontakt": true,
		"/products": false, "/": false, "/blog/2024/05/hello-world": false, "/shop/tyres": false, "/contactless-payments-overview-and-news-2024": false,
	} {
		if got := score(p) > 0; got != positive {
			t.Errorf("score(%q) = %d, want positive=%v", p, score(p), positive)
		}
	}
	if score("/contact") <= score("/privacy") || score("/contact") <= score("/careers") {
		t.Error("contact pages come first")
	}
	if score("/a/b/c/d/e/f/contact") >= score("/contact") || score("/a/b/c/d/e/f/contact") < 1 {
		t.Error("a deep page ranks lower but is still a candidate")
	}
}

func link(u, kind, domain string) scan.Link {
	return scan.Link{URL: u, Kind: kind, Domain: domain, Internal: domain == "example.org", FoundIn: "https://www.example.org/"}
}

func TestSelectLinks(t *testing.T) {
	links := []scan.Link{
		link("https://www.example.org/contact", "a", "example.org"),
		link("https://www.example.org/contact/", "a", "example.org"), // same page
		link("https://www.example.org/about", "a", "example.org"),
		link("https://www.example.org/about?utm=1", "a", "example.org"),      // query
		link("https://www.example.org/press/report.pdf", "a", "example.org"), // a file
		link("https://www.example.org/privacy", "a", "example.org"),
		link("https://www.example.org/products", "a", "example.org"),   // no keyword: followed after the others
		link("https://www.example.org/careers", "link", "example.org"), // not an ordinary link
		link("https://www.example.org/legal", "script", "example.org"),
		link("https://shop.example.org/contact-us", "a", "example.org"), // another host of the same site
		link("https://other.example.net/contact", "a", "example.net"),   // another site
		link("https://www.example.org/seen", "a", "example.org"),
		link("https://www.example.org/seen2", "a", "example.org"), // no keyword: still followed, last
		link("ftp://www.example.org/contact", "a", "example.org"),
	}
	visited := map[string]bool{"www.example.org/seen": true}
	got := selectLinks(links, "example.org", visited)
	want := []string{"https://shop.example.org/contact-us", "https://www.example.org/contact", "https://www.example.org/about", "https://www.example.org/privacy", "https://www.example.org/products", "https://www.example.org/seen2"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("selected\n %v\nwant\n %v", got, want)
	}
	if len(visited) != 1 {
		t.Error("selection marks nothing visited")
	}
	if again := selectLinks(links, "example.org", visited); strings.Join(again, " ") != strings.Join(got, " ") {
		t.Error("selection is deterministic")
	}
}

type multiSite struct {
	*httptest.Server
	mu   sync.Mutex
	hits map[string]int
}

func (m *multiSite) count(path string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.hits[path]
}

// site serves a small company site. /careers is disallowed by robots.txt.
func newSite(t *testing.T, robotsTxt string, robotsStatus int) *multiSite {
	t.Helper()
	m := &multiSite{hits: map[string]int{}}
	page := func(body string) string {
		return "<!doctype html><html><head><title>t</title></head><body>" + body + "</body></html>"
	}
	pages := map[string]string{
		"/": page(`<a href="/contact">Contact</a> <a href="/about">About</a> <a href="/careers">Jobs</a> <a href="/products?id=1">P</a>
			<a href="/brochure.pdf">pdf</a> <a href="https://elsewhere.example.net/contact">ext</a> <a href="/blog/hello">blog</a>`),
		"/contact": page(`<a href="https://www.linkedin.com/company/acme">in</a> <a href="mailto:hello@acme.example">m</a>
			<a href="tel:+39 02 1234 5678">t</a> <a href="/contact/offices">Offices</a>`),
		"/about":           page(`<a href="https://github.com/acme">gh</a> <a href="/">home</a>`),
		"/contact/offices": page(`<a href="https://www.facebook.com/acme">fb</a>`),
		"/careers":         page(`<a href="https://www.instagram.com/acme/">ig</a>`),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		m.hits[r.URL.Path]++
		m.mu.Unlock()
		if r.URL.Path == "/robots.txt" {
			if robotsStatus != 200 {
				http.Error(w, "x", robotsStatus)
				return
			}
			_, _ = w.Write([]byte(robotsTxt))
			return
		}
		body, ok := pages[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(body))
	})
	m.Server = httptest.NewServer(mux)
	t.Cleanup(m.Close)
	return m
}

func copts(depth, max int) CrawlOptions {
	return CrawlOptions{Fetch: fetch.Options{AllowPrivate: true, Timeout: 3 * time.Second}, NoFavicon: true, Depth: depth, MaxPages: max, Delay: time.Millisecond}
}

func paths(c *Crawled) string {
	var out []string
	for _, p := range c.Pages {
		path := mustParse(p.Page.FinalURL).Path
		if path == "" {
			path = "/"
		}
		out = append(out, path)
	}
	return strings.Join(out, " ")
}

func TestCrawlFollowsTheRightPages(t *testing.T) {
	s := newSite(t, "User-agent: *\nDisallow: /careers\n", 200)
	// The links of the test site point to its own host (127.0.0.1), which is the same registrable domain.
	c, err := Crawl(context.Background(), copts(1, 10), s.URL)
	if err != nil {
		t.Fatal(err)
	}
	got := paths(c)
	if got != "/ /contact /about /blog/hello" {
		t.Errorf("pages: %q (careers is disallowed, products has a query, the pdf is a file, elsewhere is another site)", got)
	}
	if s.count("/careers") != 0 || s.count("/products") != 0 || s.count("/brochure.pdf") != 0 {
		t.Errorf("hits: %v", s.hits)
	}
	if s.count("/robots.txt") != 1 || !c.RobotsFetched || !strings.Contains(c.Robots, "Disallow: /careers") {
		t.Errorf("robots.txt is read once and kept: hits=%d fetched=%v %q", s.count("/robots.txt"), c.RobotsFetched, c.Robots)
	}

	// Depth 2 reaches /contact/offices, linked from /contact.
	c, err = Crawl(context.Background(), copts(2, 10), s.URL)
	if err != nil {
		t.Fatal(err)
	}
	if got := paths(c); got != "/ /contact /about /blog/hello /contact/offices" {
		t.Errorf("depth 2: %q", got)
	}
	for path, n := range s.hits {
		if n > 3 && path != "/" { // fetched once per crawl (two crawls) plus nothing else
			t.Errorf("%s fetched %d times", path, n)
		}
	}
}

func TestCrawlLimitsAndDepthZero(t *testing.T) {
	s := newSite(t, "", 404)
	c, err := Crawl(context.Background(), copts(0, 10), s.URL)
	if err != nil || len(c.Pages) != 1 || c.RobotsFetched || s.count("/robots.txt") != 0 {
		t.Errorf("depth 0 reads only the page named and not robots.txt: pages=%d hits=%d err=%v", len(c.Pages), s.count("/robots.txt"), err)
	}
	c, err = Crawl(context.Background(), copts(2, 2), s.URL)
	if err != nil || len(c.Pages) != 2 {
		t.Fatalf("max pages 2: %d pages err=%v", len(c.Pages), err)
	}
	var limit bool
	for _, w := range c.Warnings {
		limit = limit || w.Code == "page_limit"
	}
	if !limit {
		t.Errorf("hitting the limit is reported: %+v", c.Warnings)
	}
	// A missing robots.txt (404) allows everything: careers is fetched.
	c, _ = Crawl(context.Background(), copts(1, 10), s.URL)
	if !strings.Contains(paths(c), "/careers") || !c.RobotsFetched || c.Robots != "" {
		t.Errorf("%q fetched=%v", paths(c), c.RobotsFetched)
	}
}

func TestRobotsHandling(t *testing.T) {
	// A server error means the site cannot be asked: nothing beyond the first page.
	s := newSite(t, "", 503)
	c, err := Crawl(context.Background(), copts(1, 10), s.URL)
	if err != nil || len(c.Pages) != 1 {
		t.Fatalf("pages: %d err=%v", len(c.Pages), err)
	}
	var w bool
	for _, x := range c.Warnings {
		w = w || x.Code == "robots_unavailable"
	}
	if !w || c.RobotsFetched {
		t.Errorf("warnings: %+v", c.Warnings)
	}
	// Disallow everything: the first page is still fetched (the user named it), nothing else is.
	s = newSite(t, "User-agent: *\nDisallow: /\n", 200)
	c, _ = Crawl(context.Background(), copts(1, 10), s.URL)
	if len(c.Pages) != 1 || s.count("/contact") != 0 {
		t.Errorf("disallow all: %q", paths(c))
	}
	// ...unless the user says to ignore robots.txt.
	o := copts(1, 10)
	o.IgnoreRobots = true
	before := s.count("/robots.txt")
	c, _ = Crawl(context.Background(), o, s.URL)
	if len(c.Pages) < 3 || s.count("/robots.txt") != before || c.RobotsFetched {
		t.Errorf("ignore robots: %q robots hits %d", paths(c), s.count("/robots.txt"))
	}
	// Our own group applies in place of "*", and Crawl-delay is honoured (capped).
	s = newSite(t, "User-agent: *\nDisallow: /\nUser-agent: owfscan\nDisallow: /about\nCrawl-delay: 0.05\n", 200)
	start := time.Now()
	c, _ = Crawl(context.Background(), copts(1, 10), s.URL)
	if got := paths(c); got != "/ /contact /careers /blog/hello" {
		t.Errorf("owfscan group: %q", got)
	}
	if time.Since(start) < 100*time.Millisecond {
		t.Errorf("the crawl delay of robots.txt must be respected: %v", time.Since(start))
	}
}

func TestCrawlStopsWhenCancelledAndSurvivesFailures(t *testing.T) {
	s := newSite(t, "", 404)
	ctx, cancel := context.WithCancel(context.Background())
	o := copts(1, 10)
	o.Delay = 50 * time.Millisecond
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	c, err := Crawl(ctx, o, s.URL)
	if err == nil || c == nil || len(c.Pages) >= 4 {
		t.Errorf("a cancelled crawl stops early with an error: pages=%v err=%v", len(c.Pages), err)
	}

	// A page that fails is a warning, not the end of the crawl.
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			_, _ = fmt.Fprint(w, `<a href="/contact">c</a><a href="/about">a</a>`)
		case "/contact":
			hj, _ := w.(http.Hijacker)
			conn, _, _ := hj.Hijack()
			_ = conn.Close() // the connection drops
		case "/about":
			w.Header().Set("Content-Type", "text/html")
			_, _ = fmt.Fprint(w, `<p>about</p>`)
		default:
			http.NotFound(w, r)
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c, err = Crawl(context.Background(), copts(1, 10), srv.URL)
	if err != nil || len(c.Pages) != 2 {
		t.Fatalf("pages=%d err=%v", len(c.Pages), err)
	}
	var failed bool
	for _, w := range c.Warnings {
		failed = failed || (w.Code == "page_failed" && strings.HasSuffix(w.Ref, "/contact"))
	}
	if !failed {
		t.Errorf("warnings: %+v", c.Warnings)
	}
}

func TestCrawlDoesNotLeaveTheSiteOnRedirect(t *testing.T) {
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("<p>other</p>")) }))
	defer other.Close()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			_, _ = fmt.Fprint(w, `<a href="/contact">c</a>`)
		case "/contact":
			http.Redirect(w, r, strings.Replace(other.URL, "127.0.0.1", "localhost", 1), http.StatusFound)
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c, err := Crawl(context.Background(), copts(1, 10), srv.URL)
	if err != nil || len(c.Pages) != 1 {
		t.Errorf("a page that redirects to another site is dropped: pages=%d err=%v", len(c.Pages), err)
	}
}
