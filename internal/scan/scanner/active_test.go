// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/fetch"
	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/scantest"
)

type probeSite struct {
	*httptest.Server
	mu   sync.Mutex
	hits []string
}

func (p *probeSite) paths() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.hits...)
}

func newProbeSite(robots string) *probeSite {
	ps := &probeSite{}
	ps.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ps.mu.Lock()
		ps.hits = append(ps.hits, r.URL.Path)
		ps.mu.Unlock()
		switch r.URL.Path {
		case "/robots.txt":
			if robots == "" {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write([]byte(robots))
		case "/cfadmin/":
			_, _ = w.Write([]byte("<html>This page is secured by accellion</html>"))
		case "/typo3/sysext/core/Resources/Public/Images/typo3_orange.svg":
			w.Header().Set("Content-Type", "image/svg+xml")
			_, _ = w.Write([]byte("<svg/>"))
		default:
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<html><body>home</body></html>"))
		}
	}))
	return ps
}

func activeOptions(t *testing.T, approve ...string) Options {
	t.Helper()
	reg, err := ParseRegistry(scantest.RegistryJSONApproving(t, approve...))
	if err != nil {
		t.Fatal(err)
	}
	return Options{Registry: reg, Fetch: fetch.Options{AllowPrivate: true, Timeout: 5 * time.Second}, NoFavicon: true, Delay: time.Millisecond, Active: true}
}

func TestActiveSendsOnlyApprovedProbes(t *testing.T) {
	site := newProbeSite("")
	defer site.Close()

	// Nothing approved: nothing is sent, and the result says why.
	opt := activeOptions(t)
	res, err := Scan(context.Background(), opt, site.URL)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range site.paths() {
		if p != "/" {
			t.Errorf("an unapproved probe was sent: %s", p)
		}
	}
	var warned bool
	for _, w := range res.Warnings {
		warned = warned || w.Code == "no_approved_probes"
	}
	if !warned || tech(res, "Accellion") != nil {
		t.Errorf("warnings: %+v", res.Warnings)
	}

	// /cfadmin/ approved: that path, and only that, is requested; the rules on it match.
	site2 := newProbeSite("")
	defer site2.Close()
	opt = activeOptions(t, "/cfadmin/")
	res, err = Scan(context.Background(), opt, site2.URL)
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(res); err != nil {
		t.Fatalf("a result with probes must satisfy the schema: %v", err)
	}
	got := map[string]bool{}
	for _, p := range site2.paths() {
		got[p] = true
	}
	if !got["/cfadmin/"] || got["/typo3/sysext/core/Resources/Public/Images/typo3_orange.svg"] {
		t.Errorf("requests: %v", site2.paths())
	}
	if tech(res, "Accellion") == nil {
		t.Fatalf("the approved probe's rules were evaluated: %v", names(res))
	}
	if res.Active == nil || res.Active.Approved != 1 || res.Active.Sent != 1 || res.Active.NotSent != 0 {
		t.Errorf("active: %+v", res.Active)
	}
	if res.Coverage.Skipped["probe not approved"] == 0 || res.Coverage.Skipped["probe disabled"] != 0 {
		t.Errorf("the other probes are 'not approved', not 'disabled': %+v", res.Coverage.Skipped)
	}

	// Without --active nothing is probed even though a probe is approved.
	site3 := newProbeSite("")
	defer site3.Close()
	opt = activeOptions(t, "/cfadmin/")
	opt.Active = false
	res, err = Scan(context.Background(), opt, site3.URL)
	if err != nil || res.Active != nil || tech(res, "Accellion") != nil {
		t.Fatalf("active off: %v %+v", err, res.Active)
	}
	for _, p := range site3.paths() {
		if p != "/" {
			t.Errorf("a probe was sent without --active: %s", p)
		}
	}
	if res.Coverage.Skipped["probe disabled"] == 0 {
		t.Errorf("%+v", res.Coverage.Skipped)
	}
}

func TestActiveHonoursRobotsAndTheLimit(t *testing.T) {
	// robots.txt forbids /cfadmin/: it is not requested, and counted as disallowed.
	site := newProbeSite("User-agent: *\nDisallow: /cfadmin/\n")
	defer site.Close()
	opt := activeOptions(t, "/cfadmin/", "/typo3/sysext/core/Resources/Public/Images/typo3_orange.svg")
	res, err := Scan(context.Background(), opt, site.URL)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range site.paths() {
		if p == "/cfadmin/" {
			t.Error("robots.txt disallows this path")
		}
	}
	if res.Active == nil || res.Active.Disallowed != 1 || res.Active.Sent != 1 || res.Active.NotSent != 1 {
		t.Errorf("active: %+v", res.Active)
	}

	// A limit of one: one request, the other is counted.
	site2 := newProbeSite("")
	defer site2.Close()
	opt = activeOptions(t, "/cfadmin/", "/typo3/sysext/core/Resources/Public/Images/typo3_orange.svg")
	opt.ActiveMax = 1
	res, err = Scan(context.Background(), opt, site2.URL)
	if err != nil || res.Active.Sent != 1 || res.Active.NotSent != 1 {
		t.Fatalf("%v %+v", err, res.Active)
	}

	// A server error on robots.txt: the site cannot be asked, so no probe is sent.
	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/robots.txt" {
			http.Error(w, "x", http.StatusInternalServerError)
			return
		}
		if r.URL.Path != "/" {
			t.Errorf("a probe was sent although robots.txt could not be read: %s", r.URL.Path)
		}
		_, _ = w.Write([]byte("<html>home</html>"))
	}))
	defer broken.Close()
	opt = activeOptions(t, "/cfadmin/")
	res, err = Scan(context.Background(), opt, broken.URL)
	if err != nil || res.Active.Sent != 0 {
		t.Errorf("%v %+v", err, res.Active)
	}
}

func TestActiveDropsAnswersFromAnotherSite(t *testing.T) {
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<html>secured by accellion</html>"))
	}))
	defer other.Close()
	// The probed path redirects to a different site; its answer must not count.
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/cfadmin/":
			http.Redirect(w, r, "http://localhost:"+other.URL[len("http://127.0.0.1:"):]+"/", http.StatusFound)
		case "/robots.txt":
			http.NotFound(w, r)
		default:
			_, _ = w.Write([]byte("<html>home</html>"))
		}
	}))
	defer site.Close()
	opt := activeOptions(t, "/cfadmin/")
	res, err := Scan(context.Background(), opt, site.URL)
	if err != nil {
		t.Fatal(err)
	}
	if tech(res, "Accellion") != nil || res.Active.Failed != 1 {
		t.Errorf("an answer from another domain is thrown away: %v %+v", names(res), res.Active)
	}
}
