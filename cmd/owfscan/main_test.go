// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/scantest"
	"github.com/matteoredaelli/open-web-fingerprints/schemas"
)

func run(t *testing.T, stdin string, args ...string) (string, error) {
	t.Helper()
	// Never write verification stamps into the real user cache.
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	cmd := newRootCmd()
	var out, errb bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	cmd.SetIn(strings.NewReader(stdin))
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String() + errb.String(), err
}

const home = "../../internal/scan/web/testdata/home.html"

func TestExtractText(t *testing.T) {
	out, err := run(t, "", "extract", "--url", "https://www.tyres.example/en/", home)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"tyres.example", "linkedin", "example-tyres", "email", "press@tyres.example", "+390212345678", "warning: invalid_jsonld"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

func TestExtractJSONFromStdin(t *testing.T) {
	out, err := run(t, `<a href="https://github.com/example">x</a><a href="/a">y</a>`, "extract", "--json", "--url", "https://example.org/", "-")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Links    []map[string]any
		Socials  []map[string]any
		Contacts []any
		Domains  []map[string]any
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if len(doc.Links) != 2 || len(doc.Socials) != 1 || doc.Socials[0]["platform"] != "github" || doc.Contacts == nil {
		t.Errorf("%+v", doc)
	}
}

func TestExtractErrors(t *testing.T) {
	for name, args := range map[string][]string{
		"no url":       {"extract", home},
		"bad url":      {"extract", "--url", "::", home},
		"no host":      {"extract", "--url", "/path", home},
		"missing file": {"extract", "--url", "https://a.example/", "/nonexistent.html"},
		"no file":      {"extract", "--url", "https://a.example/"},
	} {
		if _, err := run(t, "", args...); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func homepage(t *testing.T) *httptest.Server {
	t.Helper()
	b, err := os.ReadFile(home)
	if err != nil {
		t.Fatal(err)
	}
	var base string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/favicon.ico":
			w.Header().Set("Content-Type", "image/x-icon")
			_, _ = w.Write([]byte{0, 0, 1, 0, 1, 0})
		case "/":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Server", "nginx/1.25.3")
			_, _ = w.Write([]byte(strings.ReplaceAll(string(b), "https://www.tyres.example/en/", base+"/")))
		default:
			http.NotFound(w, r)
		}
	}))
	base = srv.URL
	return srv
}

func TestNetworkCommands(t *testing.T) {
	srv := homepage(t)
	defer srv.Close()
	cache := t.TempDir()

	// Without --allow-private a local server is refused.
	if _, err := run(t, "", "links", srv.URL); err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Errorf("a local address must be refused by default: %v", err)
	}

	out, err := run(t, "", "links", "--allow-private", "--cache-dir", cache, srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"DOMAIN", "linkedin.com", "github.com", "googletagmanager.com"} {
		if !strings.Contains(out, want) {
			t.Errorf("links lacks %q:\n%s", want, out)
		}
	}

	out, err = run(t, "", "social", "--allow-private", "--json", "--cache-dir", cache, srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Socials  []struct{ Platform, Handle string }
		Contacts []struct{ Kind, Value string }
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if len(doc.Socials) < 8 || len(doc.Contacts) != 5 {
		t.Errorf("socials=%d contacts=%d", len(doc.Socials), len(doc.Contacts))
	}

	out, err = run(t, "", "observe", "--allow-private", "--no-dns", "--no-html", "--cache-dir", cache, srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	var ob struct {
		Page struct {
			Status int
			Cached bool
		}
		Observation struct {
			Headers       map[string]string
			HTML          string
			FaviconHashes map[string]string `json:"favicon_hashes"`
		}
	}
	if err := json.Unmarshal([]byte(out), &ob); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if ob.Page.Status != 200 || !ob.Page.Cached || ob.Observation.Headers["Server"] != "nginx/1.25.3" ||
		ob.Observation.HTML != "" || ob.Observation.FaviconHashes["md5"] == "" {
		t.Errorf("observe: %+v", ob)
	}
	// The cache served the second and third command.
	entries, _ := os.ReadDir(cache)
	if len(entries) == 0 {
		t.Error("nothing was cached")
	}

	for name, args := range map[string][]string{
		"no url":      {"links"},
		"bad scheme":  {"social", "--allow-private", "ftp://example.org/"},
		"unreachable": {"links", "--allow-private", "--timeout", "1s", "http://127.0.0.1:1/"},
	} {
		if _, err := run(t, "", args...); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestScanCommand(t *testing.T) {
	srv := scantest.Site()
	defer srv.Close()
	reg := filepath.Join(t.TempDir(), "registry.json")
	if err := os.WriteFile(reg, scantest.RegistryJSON(t), 0o600); err != nil {
		t.Fatal(err)
	}
	base := []string{"scan", "--registry", reg, "--allow-private", "--no-favicon", "--no-dns"}

	out, err := run(t, "", append(base, "-e", srv.URL)...)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"TECHNOLOGIES (", "4D", "20.4.1", "PHP", "8.2.1", "A-Frame", "projectdiscovery-nuclei-templates",
		"NOTICE:", "SOCIAL", "linkedin", "info@acme.example", "+390212345678", "COVERAGE:", "needs a browser", "probe disabled", "[group]"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}

	out, err = run(t, "", append(base, "--json", srv.URL)...)
	if err != nil {
		t.Fatal(err)
	}
	if err := schemas.ValidateScanResult([]byte(out)); err != nil {
		t.Fatalf("--json must print a valid result: %v", err)
	}
	var res struct {
		Technologies []struct {
			Name, Version string
			Evidence      []struct{ Health string }
		}
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil || len(res.Technologies) < 3 {
		t.Fatalf("%v %s", err, out)
	}

	// --min-health ok leaves nothing: no fixture rule has tests.
	out, err = run(t, "", append(base, "--min-health", "ok", srv.URL)...)
	if err != nil || !strings.Contains(out, "TECHNOLOGIES (0)") || !strings.Contains(out, "below the minimum health") {
		t.Errorf("min-health: err=%v\n%s", err, out)
	}

	for name, args := range map[string][]string{
		"no registry":    {"scan", "--allow-private", srv.URL},
		"bad registry":   {"scan", "--registry", "/nonexistent.json", "--allow-private", srv.URL},
		"bad min health": append(append([]string{}, base...), "--min-health", "great", srv.URL),
		"local address":  {"scan", "--registry", reg, srv.URL},
		"no url":         base,
	} {
		if _, err := run(t, "", args...); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	// A damaged export is refused before anything is fetched.
	b := scantest.RegistryJSON(t)
	bad := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(bad, []byte(strings.Replace(string(b), `"name": "PHP"`, `"name": "PHPX"`, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := run(t, "", append([]string{"scan", "--registry", bad, "--allow-private"}, srv.URL)...); err == nil || !strings.Contains(err.Error(), "hash") {
		t.Errorf("a damaged export must be refused: %v", err)
	}
}

func contactSite() *httptest.Server {
	mux := http.NewServeMux()
	page := func(w http.ResponseWriter, body string) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<!doctype html><html><body>" + body + "</body></html>"))
	}
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("User-agent: *\nDisallow: /about\n"))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			page(w, `<a href="/contact">Contact</a> <a href="/about">About</a>`)
		case "/contact":
			w.Header().Set("X-Powered-By", "PHP/8.2.1")
			page(w, `<a href="https://www.linkedin.com/company/acme">in</a> <a href="mailto:hello@acme.example">m</a>`)
		case "/about":
			page(w, `<a href="https://github.com/acme">gh</a>`)
		default:
			http.NotFound(w, r)
		}
	})
	return httptest.NewServer(mux)
}

func TestDepth(t *testing.T) {
	srv := contactSite()
	defer srv.Close()
	reg := filepath.Join(t.TempDir(), "registry.json")
	if err := os.WriteFile(reg, scantest.RegistryJSON(t), 0o600); err != nil {
		t.Fatal(err)
	}
	common := []string{"--allow-private", "--delay", "1ms", srv.URL}

	out, err := run(t, "", append([]string{"social"}, common...)...)
	if err != nil || strings.Contains(out, "linkedin") {
		t.Errorf("without --depth only the home page is read: %v\n%s", err, out)
	}
	out, err = run(t, "", append([]string{"social", "--depth", "1"}, common...)...)
	if err != nil || !strings.Contains(out, "linkedin") || !strings.Contains(out, "hello@acme.example") || strings.Contains(out, "github") {
		t.Errorf("--depth 1 reads /contact and respects robots.txt (no /about): %v\n%s", err, out)
	}
	out, err = run(t, "", append([]string{"social", "--depth", "1", "--ignore-robots"}, common...)...)
	if err != nil || !strings.Contains(out, "github") {
		t.Errorf("--ignore-robots reads /about: %v\n%s", err, out)
	}
	out, err = run(t, "", append([]string{"links", "--depth", "1", "--json"}, common...)...)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct{ Pages []string }
	if err := json.Unmarshal([]byte(out), &doc); err != nil || len(doc.Pages) != 2 {
		t.Errorf("pages: %v %v", doc.Pages, err)
	}

	out, err = run(t, "", append([]string{"scan", "--registry", reg, "--no-dns", "--no-favicon", "--depth", "1", "--max-pages", "2"}, common...)...)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"+ 1 more page(s)", "pages read:", "/contact", "PHP", "8.2.1", "linkedin", "hello@acme.example"} {
		if !strings.Contains(out, want) {
			t.Errorf("scan output lacks %q:\n%s", want, out)
		}
	}
	out, err = run(t, "", append([]string{"scan", "--registry", reg, "--no-dns", "--no-favicon", "--json", "--depth", "1"}, common...)...)
	if err != nil {
		t.Fatal(err)
	}
	if err := schemas.ValidateScanResult([]byte(out)); err != nil {
		t.Errorf("a crawled result must satisfy the schema: %v", err)
	}
}

func TestFriendsCommand(t *testing.T) {
	// A is served on 127.0.0.1, its friend and a stranger on "localhost": different domains.
	var aURL string
	friend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/robots.txt" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<a href="` + aURL + `/about">our partner</a>`))
	}))
	defer friend.Close()
	stranger := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/robots.txt" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<p>nothing</p>`))
	}))
	l6, err := net.Listen("tcp", "[::1]:0") // a third "domain": the IPv6 loopback
	if err != nil {
		t.Skip("no IPv6 loopback")
	}
	stranger.Listener = l6
	stranger.Start()
	defer stranger.Close()
	local := func(u string) string { return strings.Replace(u, "127.0.0.1", "localhost", 1) }
	a := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<a href="` + local(friend.URL) + `/">f</a> <a href="` + stranger.URL + `/">s</a>`))
	}))
	defer a.Close()
	aURL = a.URL

	out, err := run(t, "", "friends", "--allow-private", "--delay", "1ms", a.URL)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !strings.Contains(out, "FRIENDS (1 of 2 checked, 2 candidates)") || !strings.Contains(out, "friend") || !strings.Contains(out, "not_friend") {
		t.Errorf("output:\n%s", out)
	}
	out, err = run(t, "", "friends", "--allow-private", "--delay", "1ms", "--friends-max", "1", "--json", a.URL)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Friends struct {
			Candidates, Checked int
			Domains             []struct{ Domain, Status string }
		}
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil || doc.Friends.Checked != 1 || doc.Friends.Candidates != 2 || len(doc.Friends.Domains) != 2 {
		t.Errorf("%v %+v", err, doc)
	}
	// The private-address guard applies to the friends too: without --allow-private nothing is read.
	if out, err := run(t, "", "friends", a.URL); err == nil {
		t.Errorf("a private target is refused:\n%s", out)
	}
}
