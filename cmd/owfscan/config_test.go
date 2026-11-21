// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/config"
	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/scantest"
)

// withConfig runs a test with a configuration in force, and puts the previous one back.
func withConfig(t *testing.T, c config.Config, path string, err error) {
	t.Helper()
	oc, op, oe := cfg, cfgPath, cfgErr
	cfg, cfgPath, cfgErr = c, path, err
	t.Cleanup(func() { cfg, cfgPath, cfgErr = oc, op, oe })
}

func TestConfigInitStdoutIsTheDefaults(t *testing.T) {
	out, err := run(t, "", "config", "init", "--stdout")
	if err != nil {
		t.Fatal(err)
	}
	var want bytes.Buffer
	if err := config.Write(&want, config.Default()); err != nil {
		t.Fatal(err)
	}
	if out != want.String() {
		t.Errorf("stdout differs from the written defaults:\n%s", out)
	}
	if _, err := config.Parse(strings.NewReader(out)); err != nil {
		t.Errorf("what init writes must parse: %v", err)
	}
	if !strings.Contains(out, "max_pages = 8") || !strings.Contains(out, `tlds = ["com", "org"`) {
		t.Errorf("missing defaults:\n%s", out)
	}
}

func TestConfigInitWritesTheDefaultLocationAndRefusesToOverwrite(t *testing.T) {
	home := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", "")
	// run() sets HOME itself, so write with -o and also check the default path logic.
	target := filepath.Join(home, "sub", "dir", "owfscan.toml")
	out, err := run(t, "", "config", "init", "-o", target)
	if err != nil || !strings.Contains(out, "wrote "+target) {
		t.Fatalf("%v\n%s", err, out)
	}
	st, err := os.Stat(target)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("file: %v %v", err, st)
	}
	if _, err := run(t, "", "config", "init", "-o", target); err == nil || !strings.Contains(err.Error(), "--force") {
		t.Errorf("an existing file must not be overwritten: %v", err)
	}
	if err := os.WriteFile(target, []byte("[friends]\nmax = 3\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := run(t, "", "config", "init", "-o", target, "--force"); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(target)
	if !strings.Contains(string(b), "max = 20") {
		t.Errorf("--force must rewrite the defaults:\n%s", b)
	}
}

func TestConfigDefaultsOfTheFlagsComeFromTheFile(t *testing.T) {
	c := config.Default()
	c.Friends.Max, c.Crawl.MaxPages, c.Browser.MaxRequests = 5, 3, 100
	withConfig(t, c, "/x/owfscan.toml", nil)
	out, err := run(t, "", "scan", "--help")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"--friends-max int", "(default 5)", "--max-pages int", "(default 3)"} {
		if !strings.Contains(out, want) {
			t.Errorf("help lacks %q:\n%s", want, out)
		}
	}
	show, err := run(t, "", "config", "show")
	if err != nil || !strings.Contains(show, "# read from /x/owfscan.toml") || !strings.Contains(show, "max_requests = 100") {
		t.Errorf("%v\n%s", err, show)
	}
	ceil, _ := run(t, "", "config", "show", "--ceilings")
	if !strings.Contains(ceil, "crawl.max_pages") || !strings.Contains(ceil, "200") {
		t.Errorf("ceilings:\n%s", ceil)
	}
}

func TestBrokenConfigStopsTheCommandsButNotConfig(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "owfscan.toml")
	if err := os.WriteFile(bad, []byte("[crawl]\nmax_page = 3\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, p, err := loadConfig([]string{"links", "--config", bad})
	if err == nil || !strings.Contains(err.Error(), "max_page") {
		t.Fatalf("a typo in a key must be reported: %v", err)
	}
	withConfig(t, c, p, err)
	if _, err := run(t, "", "links", "https://example.org"); err == nil || !strings.Contains(err.Error(), "max_page") {
		t.Errorf("a command must not run on a broken file: %v", err)
	}
	if out, err := run(t, "", "config", "path", "--config", bad); err != nil || !strings.Contains(out, bad) {
		t.Errorf("config path must still work: %v %q", err, out)
	}
	if _, err := run(t, "", "config", "init", "--stdout"); err != nil {
		t.Errorf("config init must still work: %v", err)
	}
}

func TestConfigArg(t *testing.T) {
	t.Setenv("OWFSCAN_CONFIG", "/env.toml")
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"scan", "--config", "/a.toml", "x"}, "/a.toml"},
		{[]string{"scan", "--config=/b.toml"}, "/b.toml"},
		{[]string{"scan", "x"}, "/env.toml"},
		{[]string{"scan", "--", "--config", "/c.toml"}, "/env.toml"},
	}
	for _, c := range cases {
		if got := configArg(c.args); got != c.want {
			t.Errorf("%v: %q, want %q", c.args, got, c.want)
		}
	}
}

func TestTheFileCannotTurnOnSwitches(t *testing.T) {
	for _, key := range []string{"[scan]\nbrowser = true\n", "[browser]\nenabled = true\n", "[fetch]\nallow_private = true\n", "[crawl]\nignore_robots = true\n", "[friends]\nenabled = true\n"} {
		if _, err := config.Parse(strings.NewReader(key)); err == nil {
			t.Errorf("%q must be refused", key)
		}
	}
}

func volatileServer(t *testing.T) *httptest.Server {
	t.Helper()
	var n atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/favicon.ico" {
			http.NotFound(w, r)
			return
		}
		i := n.Add(1)
		w.Header().Set("Server", "nginx/1.25.3")
		w.Header().Set("X-Powered-By", "Express")
		w.Header().Set("ETag", fmt.Sprintf(`"v%d"`, i))
		w.Header().Set("X-Request-Id", fmt.Sprintf("req-%d", i))
		w.Header().Set("X-Envoy-Upstream-Service-Time", fmt.Sprint(i))
		w.Header().Set("X-Client-IP", "203.0.113.7")
		w.Header().Add("Set-Cookie", fmt.Sprintf("sid=session%d; Path=/", i))
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><head><title>t</title></head><body>hello</body></html>"))
	}))
	t.Cleanup(srv.Close)
	return srv
}

type observed struct {
	Page struct {
		Headers         map[string]string
		HeadersFiltered bool `json:"headers_filtered"`
	}
	Observation struct {
		Headers    map[string]string
		Cookies    map[string]string
		SetCookies []string `json:"set_cookies"`
		HTML       string
	}
}

func observeJSON(t *testing.T, args ...string) observed {
	t.Helper()
	out, err := run(t, "", append([]string{"observe", "--allow-private", "--no-dns", "--no-favicon"}, args...)...)
	if err != nil {
		t.Fatal(err)
	}
	var o observed
	if err := json.Unmarshal([]byte(out), &o); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	return o
}

func TestObserveLeavesOutTheBodyAndTheHeadersThatChange(t *testing.T) {
	srv := volatileServer(t)
	a, b := observeJSON(t, srv.URL), observeJSON(t, srv.URL)
	if !reflect.DeepEqual(a, b) {
		t.Errorf("two calls in a row must give the same headers and cookies:\n%+v\n%+v", a, b)
	}
	if a.Observation.HTML != "" {
		t.Error("the body is left out by default")
	}
	if !a.Page.HeadersFiltered {
		t.Error("the output must say that headers were filtered")
	}
	for _, h := range []string{"date", "etag", "x-request-id", "set-cookie", "x-client-ip", "x-envoy-upstream-service-time"} {
		if _, ok := a.Page.Headers[h]; ok {
			t.Errorf("page.headers still has %s", h)
		}
	}
	if a.Page.Headers["server"] != "nginx/1.25.3" || a.Page.Headers["x-powered-by"] != "Express" {
		t.Errorf("stable headers stay: %v", a.Page.Headers)
	}
	if a.Observation.Headers["Server"] != "nginx/1.25.3" || a.Observation.Headers["Etag"] != "" || a.Observation.Headers["Date"] != "" {
		t.Errorf("observation headers: %v", a.Observation.Headers)
	}
	if v, ok := a.Observation.Cookies["sid"]; !ok || v != "" || len(a.Observation.SetCookies) != 0 {
		t.Errorf("the cookie name stays, its value and the raw line go: %v %v", a.Observation.Cookies, a.Observation.SetCookies)
	}
}

func TestObserveHTMLAndAllHeadersAreOptIn(t *testing.T) {
	srv := volatileServer(t)
	o := observeJSON(t, srv.URL, "--html", "--all-headers")
	if !strings.Contains(o.Observation.HTML, "hello") {
		t.Error("--html includes the body")
	}
	if o.Page.HeadersFiltered || o.Page.Headers["etag"] == "" || o.Page.Headers["date"] == "" || o.Observation.Headers["X-Request-Id"] == "" {
		t.Errorf("--all-headers keeps everything: %+v", o.Page)
	}
	if o.Observation.Cookies["sid"] == "" || len(o.Observation.SetCookies) != 1 {
		t.Errorf("--all-headers keeps the cookies: %+v", o.Observation)
	}
}

func TestTheListComesFromTheConfiguration(t *testing.T) {
	c := config.Default()
	c.Output.DropHeaders = []string{"x-powered-by", "x-env*"}
	withConfig(t, c, "", nil)
	srv := volatileServer(t)
	o := observeJSON(t, srv.URL)
	if _, ok := o.Page.Headers["x-powered-by"]; ok {
		t.Error("x-powered-by is on the list")
	}
	if o.Page.Headers["etag"] == "" || o.Page.Headers["x-request-id"] == "" {
		t.Errorf("only the listed headers go: %v", o.Page.Headers)
	}
	if _, ok := o.Page.Headers["x-envoy-upstream-service-time"]; ok {
		t.Error("a prefix with * must match")
	}
	if len(o.Observation.Cookies) == 0 || o.Observation.Cookies["sid"] == "" {
		t.Errorf("set-cookie is not on this list, so the cookies stay: %v", o.Observation.Cookies)
	}
}

func TestReportFromAScanResult(t *testing.T) {
	dir := t.TempDir()
	srv := volatileServer(t)
	t.Setenv("OWFSCAN_REGISTRY", "")
	reg := filepath.Join(dir, "registry.json")
	if err := os.WriteFile(reg, scantest.RegistryJSON(t), 0o600); err != nil {
		t.Fatal(err)
	}
	js, err := run(t, "", "scan", "--allow-private", "--no-dns", "--no-favicon", "--verify-cache", "off", "--registry", reg, "--json", srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	in := filepath.Join(dir, "r.json")
	if err := os.WriteFile(in, []byte(js), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "r.html")
	if _, err := run(t, "", "report", in, "-o", out); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(out)
	if !strings.HasPrefix(string(b), "<!doctype html>") || !strings.Contains(string(b), "What was not seen") {
		t.Errorf("report:\n%.300s", b)
	}
	// Directly from a scan, and a bad input.
	out2 := filepath.Join(dir, "s.html")
	if _, err := run(t, "", "scan", "--allow-private", "--no-dns", "--no-favicon", "--verify-cache", "off", "--registry", reg, "--html", out2, srv.URL); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(out2); err != nil {
		t.Error("scan --html wrote nothing")
	}
	if _, err := run(t, "", "scan", "--html", "-", "--registry", reg, srv.URL); err == nil {
		t.Error("--html - must be refused on scan")
	}
	if _, err := run(t, "{}", "report", "-", "-o", "-"); err == nil {
		t.Error("a file that is not a scan result must be refused")
	}
}
