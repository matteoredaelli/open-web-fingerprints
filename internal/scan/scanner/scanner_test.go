// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package scanner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/browser"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/fetch"
	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/scantest"
	"github.com/matteoredaelli/open-web-fingerprints/scan"
)

func options(t *testing.T) Options {
	t.Helper()
	reg, err := ParseRegistry(scantest.RegistryJSON(t))
	if err != nil {
		t.Fatal(err)
	}
	return Options{Registry: reg, Fetch: fetch.Options{AllowPrivate: true, Timeout: 3 * time.Second}, NoFavicon: true, Version: "test",
		Now: func() time.Time { return time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC) }}
}

func tech(r *scan.Result, name string) *scan.Technology {
	for i := range r.Technologies {
		if r.Technologies[i].Name == name {
			return &r.Technologies[i]
		}
	}
	return nil
}

func names(r *scan.Result) []string {
	var out []string
	for _, t := range r.Technologies {
		out = append(out, t.Name)
	}
	return out
}

func TestScanEndToEnd(t *testing.T) {
	srv := scantest.Site()
	defer srv.Close()
	opt := options(t)
	res, err := Scan(context.Background(), opt, srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(res); err != nil {
		t.Fatalf("the result must satisfy its schema: %v", err)
	}

	php := tech(res, "PHP")
	if php == nil || php.Version != "8.2.1" || len(php.Evidence) == 0 {
		t.Fatalf("PHP: %+v (have %v)", php, names(res))
	}
	four := tech(res, "4D")
	if four == nil || four.Version != "20.4.1" {
		t.Fatalf("4D: %+v (have %v)", four, names(res))
	}
	var group, version int
	for _, ev := range four.Evidence {
		if ev.Group != "" {
			group++
		}
		if ev.Version == "20.4.1" {
			version++
		}
		if ev.Health != "unknown" || ev.Source != "projectdiscovery-nuclei-templates" || ev.Page != res.Target.URL {
			t.Errorf("evidence: %+v", ev)
		}
	}
	if group < 2 || version == 0 {
		t.Errorf("a group of rules and a version rule: %+v", four.Evidence)
	}
	if tech(res, "A-Frame") == nil {
		t.Errorf("technologies: %v", names(res))
	}

	var li, gh, mast bool
	for _, s := range res.Socials {
		li = li || s.Platform == "linkedin"
		gh = gh || s.Platform == "github"
		mast = mast || s.Platform == "mastodon"
	}
	if !li || !gh || !mast || len(res.Contacts) != 2 || len(res.Links) == 0 || len(res.Domains) == 0 {
		t.Errorf("socials %+v contacts %+v", res.Socials, res.Contacts)
	}

	c := res.Coverage
	if c.RulesTotal == 0 || c.RulesEvaluated == 0 || c.Skipped["needs a browser"] == 0 || c.Skipped["probe disabled"] == 0 ||
		c.RulesUnsupported == 0 || c.RulesEvaluated+c.RulesUnsupported > c.RulesTotal {
		t.Errorf("coverage: %+v", c)
	}
	if c.Skipped["favicon not fetched"] == 0 {
		t.Errorf("the favicon was not fetched, so favicon rules are skipped, not missed: %+v", c.Skipped)
	}

	if !strings.HasPrefix(res.Registry.ContentSHA256, "sha256:") || len(res.Registry.Sources) != 3 || !strings.Contains(res.Registry.Notice, "internal use only") {
		t.Errorf("registry: %+v", res.Registry)
	}
	if res.Scanner != "owfscan test" || res.Target.Host != "127.0.0.1" || res.Pages[0].Status != 200 || res.ScannedAt.IsZero() {
		t.Errorf("result: %+v", res.Target)
	}

	again, err := Scan(context.Background(), opt, srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if len(again.Technologies) != len(res.Technologies) || again.Coverage.RulesEvaluated != res.Coverage.RulesEvaluated {
		t.Error("two scans of the same page must agree")
	}
}

// The export is made with --include-unreviewed: the scanner uses it and says so.
func TestUnreviewedSourcesAreNotRefused(t *testing.T) {
	reg, err := ParseRegistry(scantest.RegistryJSON(t))
	if err != nil || reg.Ref.Notice == "" {
		t.Fatalf("err=%v", err)
	}
}

func TestMinHealth(t *testing.T) {
	srv := scantest.Site()
	defer srv.Close()
	opt := options(t)
	opt.MinHealth = "ok"
	res, err := Scan(context.Background(), opt, srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	// Nothing in the fixtures has test evidence, so no rule is healthy enough.
	if len(res.Technologies) != 0 || res.Coverage.Skipped["below the minimum health"] == 0 {
		t.Errorf("%v %+v", names(res), res.Coverage)
	}
	if err := Validate(res); err != nil {
		t.Fatal(err)
	}
	opt.MinHealth = "great"
	if _, err := Scan(context.Background(), opt, srv.URL); err == nil {
		t.Error("an unknown health level must be refused")
	}
}

func TestRegistryIsVerified(t *testing.T) {
	good := scantest.RegistryJSON(t)
	for name, b := range map[string][]byte{
		"edited":  []byte(strings.Replace(string(good), `"name": "PHP"`, `"name": "PHPX"`, 1)),
		"garbage": []byte("{"),
		"empty":   nil,
	} {
		if _, err := ParseRegistry(b); err == nil {
			t.Errorf("%s: a damaged export must be refused", name)
		}
	}
	if _, err := LoadRegistry("/nonexistent/registry.json"); err == nil {
		t.Error("a missing file must fail")
	}
	if _, err := Scan(context.Background(), Options{}, "x"); err == nil {
		t.Error("no registry must fail")
	}
}

func TestScanRefusesLocalAddressesByDefault(t *testing.T) {
	opt := options(t)
	opt.Fetch = fetch.Options{Timeout: time.Second}
	srv := scantest.Site()
	defer srv.Close()
	if _, err := Scan(context.Background(), opt, srv.URL); err == nil {
		t.Error("a local address is refused by default")
	}
}

// A site whose home page says little: the details are on /contact, and robots.txt
// carries a signature.
func depthSite() *httptest.Server {
	mux := http.NewServeMux()
	html := func(w http.ResponseWriter, body string) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<!doctype html><html><body>" + body + "</body></html>"))
	}
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("User-agent: *\nDisallow: /private\n# Powered by Shoporama\n"))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			html(w, `<a href="/contact">Contact</a> <a href="/private/contact">Private</a>`)
		case "/contact":
			w.Header().Set("X-Powered-By", "PHP/8.2.1")
			html(w, `<a href="https://www.linkedin.com/company/acme">in</a> <a href="mailto:hello@acme.example">m</a> <a href="tel:+39 02 1234 5678">t</a>`)
		default:
			http.NotFound(w, r)
		}
	})
	return httptest.NewServer(mux)
}

func TestScanDepthFindsWhatTheHomePageDoesNot(t *testing.T) {
	srv := depthSite()
	defer srv.Close()
	opt := options(t)

	home, err := Scan(context.Background(), opt, srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if len(home.Pages) != 1 || len(home.Socials) != 0 || len(home.Contacts) != 0 || tech(home, "PHP") != nil {
		t.Fatalf("the home page alone says little: pages=%d socials=%d contacts=%d techs=%v", len(home.Pages), len(home.Socials), len(home.Contacts), names(home))
	}
	if home.Coverage.Skipped["robots.txt not fetched"] == 0 {
		t.Errorf("without a crawl robots.txt is not fetched: %+v", home.Coverage.Skipped)
	}

	opt.Depth, opt.Delay = 1, time.Millisecond
	deep, err := Scan(context.Background(), opt, srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(deep); err != nil {
		t.Fatalf("a crawled result must satisfy the schema: %v", err)
	}
	if len(deep.Pages) != 2 || !strings.HasSuffix(deep.Pages[1].FinalURL, "/contact") {
		t.Fatalf("pages: %+v (the page under /private is disallowed)", deep.Pages)
	}
	if len(deep.Socials) != 1 || deep.Socials[0].Platform != "linkedin" || !strings.HasSuffix(deep.Socials[0].Found[0].Page, "/contact") {
		t.Errorf("socials: %+v", deep.Socials)
	}
	if len(deep.Contacts) != 2 {
		t.Errorf("contacts: %+v", deep.Contacts)
	}
	php := tech(deep, "PHP")
	if php == nil || php.Version != "8.2.1" {
		t.Fatalf("PHP found on the second page: %v", names(deep))
	}
	for _, ev := range php.Evidence {
		if !strings.HasSuffix(ev.Page, "/contact") {
			t.Errorf("each piece of evidence says which page it comes from: %+v", ev)
		}
	}
	// robots.txt is now read, and the rule on it can match.
	if tech(deep, "Shoporama") == nil || deep.Coverage.Skipped["robots.txt not fetched"] != 0 {
		t.Errorf("a rule on robots.txt: %v, skipped %+v", names(deep), deep.Coverage.Skipped)
	}
	// Coverage counts rules, not rules per page.
	if deep.Coverage.RulesTotal != home.Coverage.RulesTotal || deep.Coverage.RulesEvaluated < home.Coverage.RulesEvaluated {
		t.Errorf("coverage: %+v vs %+v", deep.Coverage, home.Coverage)
	}
}

func TestScanDepthRespectsRobotsOnRequest(t *testing.T) {
	srv := depthSite()
	defer srv.Close()
	opt := options(t)
	opt.Depth, opt.Delay, opt.IgnoreRobots = 1, time.Millisecond, true
	res, err := Scan(context.Background(), opt, srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	// Nothing says "private" is off limits any more, but it still has no keyword score
	// ("contact" is the last segment): both pages are candidates.
	if len(res.Pages) != 3 {
		t.Errorf("pages with --ignore-robots: %d", len(res.Pages))
	}
	if tech(res, "Shoporama") != nil || res.Coverage.Skipped["robots.txt not fetched"] == 0 {
		t.Errorf("robots.txt is not read when it is ignored: %v", names(res))
	}
}

func TestLoadRegistryCached(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "registry.json")
	good := scantest.RegistryJSON(t)
	if err := os.WriteFile(file, good, 0o600); err != nil {
		t.Fatal(err)
	}
	stamps := filepath.Join(dir, "stamps", "deep")
	first, err := LoadRegistryCached(file, stamps)
	if err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(stamps)
	if len(entries) != 1 {
		t.Fatalf("one stamp expected: %v", entries)
	}
	second, err := LoadRegistryCached(file, stamps)
	if err != nil || second.Ref.ContentSHA256 != first.Ref.ContentSHA256 || second.Engine.Rules() != first.Engine.Rules() {
		t.Fatalf("a stamped file loads the same: %v", err)
	}

	// The stamp is for these bytes only. Changed content is verified again and refused.
	bad := bytes.Replace(good, []byte(`"slug"`), []byte(`"slugg"`), 1)
	if err := os.WriteFile(file, bad, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRegistryCached(file, stamps); err == nil {
		t.Error("an edited file must not ride on the stamp of the original")
	}
	// A stamp is worth nothing for a file that is not a registry.
	if err := os.WriteFile(file, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRegistryCached(file, stamps); err == nil {
		t.Error("not a registry")
	}
	// A stamp that is present but whose file no longer decodes falls back to full verification.
	sum := sha256.Sum256([]byte("{}"))
	if err := os.WriteFile(filepath.Join(stamps, hex.EncodeToString(sum[:])+"."+verifyRev), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRegistryCached(file, stamps); err == nil {
		t.Error("a forged stamp does not make a bad file good")
	}

	// No stamp directory, or one that cannot be created: still works, nothing stored.
	if err := os.WriteFile(file, good, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRegistryCached(file, ""); err != nil {
		t.Error(err)
	}
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRegistryCached(file, filepath.Join(blocker, "x")); err != nil {
		t.Errorf("an unwritable stamp directory is ignored: %v", err)
	}
	if _, err := LoadRegistryCached(filepath.Join(dir, "missing.json"), stamps); err == nil {
		t.Error("a missing file is an error")
	}
}

// The page builds what the rules look for with JavaScript: a global variable, a link added
// after the load, and a script-inserted social profile.
func jsSite() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!doctype html><html><body><p>hello</p><script>
		  window.AFRAME = {version: '1.4.2'};
		  document.addEventListener('DOMContentLoaded', function () {
		    var a = document.createElement('a'); a.href = 'https://github.com/jsmaker'; a.textContent = 'code';
		    document.body.appendChild(a);
		  });
		</script></body></html>`))
	}))
}

func TestScanWithBrowser(t *testing.T) {
	if os.Getenv("OWF_NO_BROWSER_TESTS") != "" {
		t.Skip("OWF_NO_BROWSER_TESTS is set")
	}
	srv := jsSite()
	defer srv.Close()
	opt := options(t)
	opt.Fetch.AllowPrivate = true

	plain, err := Scan(context.Background(), opt, srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if tech(plain, "A-Frame") != nil || len(plain.Socials) != 0 || plain.Browser != nil || plain.Coverage.Skipped["needs a browser"] == 0 {
		t.Fatalf("without a browser the script's work is not seen: %v %+v", names(plain), plain.Socials)
	}

	opt.Browser, opt.BrowserTimeout = true, 30*time.Second
	res, err := Scan(context.Background(), opt, srv.URL)
	if errors.Is(err, browser.ErrNoChrome) {
		t.Skipf("no Chrome: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(res); err != nil {
		t.Fatalf("a browser result must satisfy the schema: %v", err)
	}
	a := tech(res, "A-Frame")
	if a == nil || a.Version != "1.4.2" {
		t.Fatalf("the global variable is read: %v", names(res))
	}
	if len(res.Socials) != 1 || res.Socials[0].Handle != "jsmaker" {
		t.Errorf("links added by scripts are extracted: %+v", res.Socials)
	}
	if res.Browser == nil || res.Browser.Globals < 1 || res.Browser.Requests < 1 || res.Browser.Blocked != 0 {
		t.Errorf("the browser section says what happened: %+v", res.Browser)
	}
	if res.Coverage.Skipped["needs a browser"] >= plain.Coverage.Skipped["needs a browser"] || res.Coverage.RulesEvaluated <= plain.Coverage.RulesEvaluated {
		t.Errorf("coverage improves: %+v vs %+v", res.Coverage, plain.Coverage)
	}

	// A browser that is not there is an error, not a silent downgrade.
	opt.BrowserPath = "/nonexistent/chrome"
	if _, err := Scan(context.Background(), opt, srv.URL); !errors.Is(err, browser.ErrNoChrome) {
		t.Errorf("--browser without Chrome must fail: %v", err)
	}
}

func TestRedactVolatileEvidence(t *testing.T) {
	techs := []scan.Technology{{Name: "CloudFront", Evidence: []scan.Evidence{
		{Observation: "http_header", Target: "x-amz-cf-id", Matched: "abc123"},
		{Observation: "http_header", Target: "Server", Matched: "nginx"},
		{Observation: "set_cookie", Matched: "sid=1; Path=/"},
		{Observation: "html", Matched: "<b>"},
	}}}
	redactVolatile(techs, []string{"x-amz-*", "set-cookie"})
	m := []string{techs[0].Evidence[0].Matched, techs[0].Evidence[1].Matched, techs[0].Evidence[2].Matched, techs[0].Evidence[3].Matched}
	if m[0] != "" || m[1] != "nginx" || m[2] != "" || m[3] != "<b>" {
		t.Errorf("%q", m)
	}
	techs = []scan.Technology{{Evidence: []scan.Evidence{{Observation: "http_header", Target: "x-amz-cf-id", Matched: "abc"}}}}
	redactVolatile(techs, nil)
	if techs[0].Evidence[0].Matched != "abc" {
		t.Error("an empty list changes nothing")
	}
}
