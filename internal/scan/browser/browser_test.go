// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package browser

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// needChrome skips a test when no Chrome can be started: the tests run Chrome for real.
func needChrome(t *testing.T) {
	t.Helper()
	if os.Getenv("OWF_NO_BROWSER_TESTS") != "" {
		t.Skip("OWF_NO_BROWSER_TESTS is set")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("<p>x</p>")) }))
	defer srv.Close()
	if _, err := Run(context.Background(), Options{AllowPrivate: true, Timeout: 20 * time.Second, Settle: time.Millisecond}, srv.URL); errors.Is(err, ErrNoChrome) {
		t.Skipf("no Chrome: %v", err)
	}
}

const testPage = `<!doctype html><html><head><title>t</title></head><body>
<div id="static">static</div>
<script>
  window.myLib = {version: '1.2.3', nested: {deep: 'yes'}, fn: function(){}};
  window.simple = 42;
  window.flag = true;
  document.addEventListener('DOMContentLoaded', function () {
    var d = document.createElement('div'); d.id = 'injected'; d.textContent = 'made by script';
    document.body.appendChild(d);
  });
  fetch('/api/data').then(function(r){return r.text()});
  var x = new XMLHttpRequest(); x.open('GET', '/api/old'); x.send();
</script></body></html>`

func TestBrowserSeesWhatScriptsDo(t *testing.T) {
	needChrome(t)
	var api atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(testPage))
		case "/api/data", "/api/old":
			api.Add(1)
			_, _ = w.Write([]byte("{}"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	res, err := Run(context.Background(), Options{
		AllowPrivate: true, Timeout: 30 * time.Second, Settle: 500 * time.Millisecond,
		Paths: []string{"myLib.version", "myLib.nested.deep", "myLib", "myLib.fn", "simple", "flag", "nothing.here", "myLib.nope"},
	}, srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.DOM, `id="injected"`) || !strings.Contains(res.DOM, "made by script") {
		t.Errorf("the DOM after scripts must hold what they added:\n%s", res.DOM)
	}
	want := map[string]string{"myLib.version": "1.2.3", "myLib.nested.deep": "yes", "myLib": "", "myLib.fn": "", "simple": "42", "flag": "true"}
	for k, v := range want {
		if got, ok := res.Globals[k]; !ok || got != v {
			t.Errorf("global %s = %q (present %v), want %q", k, got, ok, v)
		}
	}
	for _, k := range []string{"nothing.here", "myLib.nope"} {
		if _, ok := res.Globals[k]; ok {
			t.Errorf("%s does not exist and must not be reported", k)
		}
	}
	if len(res.XHR) != 2 || api.Load() != 2 {
		t.Errorf("xhr=%v api hits=%d", res.XHR, api.Load())
	}
	if !strings.HasPrefix(res.Version, "Chrome/") && !strings.Contains(res.Version, "Chrom") {
		t.Errorf("version %q", res.Version)
	}
	if res.Requests < 3 || res.TimedOut {
		t.Errorf("requests=%d timedOut=%v", res.Requests, res.TimedOut)
	}
}

func TestBrowserCannotReachPrivateAddresses(t *testing.T) {
	needChrome(t)
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte("<p>private</p>"))
	}))
	defer srv.Close()
	// AllowPrivate is off: the loopback server must not be reached, not even by the browser.
	res, err := Run(context.Background(), Options{Timeout: 20 * time.Second, Settle: time.Millisecond}, srv.URL)
	if hits.Load() != 0 {
		t.Fatalf("the browser reached a loopback address %d time(s)", hits.Load())
	}
	if err == nil && strings.Contains(res.DOM, "private") {
		t.Error("the page content must not be returned")
	}
	if err == nil && res.Blocked == 0 {
		t.Errorf("the refusal is counted: %+v", res)
	}
	t.Logf("outcome: err=%v blocked=%v", err, res != nil && res.Blocked > 0)
}

func TestBrowserStopsATooSlowPage(t *testing.T) {
	needChrome(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			<-r.Context().Done()
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body>fast<script>window.here=1; fetch('/slow')</script></body></html>`))
	}))
	defer srv.Close()
	start := time.Now()
	res, err := Run(context.Background(), Options{AllowPrivate: true, Timeout: 4 * time.Second, Settle: time.Millisecond, Paths: []string{"here"}}, srv.URL)
	if time.Since(start) > 15*time.Second {
		t.Errorf("the run must end near its timeout: %v", time.Since(start))
	}
	if err != nil {
		t.Logf("a page still loading may end in an error: %v", err)
		return
	}
	if res.Globals["here"] != "1" {
		t.Errorf("what was seen is returned: %+v", res.Globals)
	}
}

func TestRunRefusesOtherSchemes(t *testing.T) {
	for _, u := range []string{"file:///etc/passwd", "javascript:alert(1)", "about:blank", "chrome://settings", ""} {
		if _, err := Run(context.Background(), Options{}, u); err == nil {
			t.Errorf("%q must be refused", u)
		}
	}
}

func TestNoChromeIsReported(t *testing.T) {
	_, err := Run(context.Background(), Options{ChromePath: "/nonexistent/chrome", Timeout: 5 * time.Second}, "http://example.org/")
	if !errors.Is(err, ErrNoChrome) {
		t.Errorf("a missing executable must say so: %v", err)
	}
}
