// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func run(t *testing.T, stdin string, args ...string) (string, error) {
	t.Helper()
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
	if ob.Page.Status != 200 || !ob.Page.Cached || ob.Observation.Headers["server"] != "nginx/1.25.3" ||
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
