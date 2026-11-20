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
	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/web"
	"github.com/matteoredaelli/open-web-fingerprints/scan"
)

// virtualWeb answers for several host names without a network.
type virtualWeb struct {
	mu    sync.Mutex
	sites map[string]http.HandlerFunc
	hits  map[string][]string
}

func (v *virtualWeb) RoundTrip(r *http.Request) (*http.Response, error) {
	v.mu.Lock()
	v.hits[r.URL.Hostname()] = append(v.hits[r.URL.Hostname()], r.URL.Path)
	v.mu.Unlock()
	h, ok := v.sites[r.URL.Hostname()]
	if !ok {
		return nil, fmt.Errorf("no such host %s", r.URL.Hostname())
	}
	rec := httptest.NewRecorder()
	h(rec, r)
	resp := rec.Result()
	resp.Request = r
	return resp, nil
}

func page(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/robots.txt" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprint(w, "<html><body>"+body+"</body></html>")
	}
}

func friendsWeb() *virtualWeb {
	return &virtualWeb{hits: map[string][]string{}, sites: map[string]http.HandlerFunc{
		"www.friend.example": page(`<a href="https://www.alpha.example/about">our partner</a>`),
		"notfriend.example":  page(`<a href="https://other.example/">somebody else</a>`),
		"shy.example": func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/robots.txt" {
				_, _ = fmt.Fprint(w, "User-agent: *\nDisallow: /\n")
				return
			}
			_, _ = fmt.Fprint(w, `<a href="https://alpha.example/">alpha</a>`)
		},
		"broken.example": func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/robots.txt" {
				http.NotFound(w, r)
				return
			}
			http.Error(w, "boom", http.StatusInternalServerError)
		},
		"serverr.example": func(w http.ResponseWriter, r *http.Request) { http.Error(w, "x", http.StatusServiceUnavailable) },
		"pdf.example": func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/robots.txt" {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/pdf")
			_, _ = fmt.Fprint(w, `%PDF alpha.example`)
		},
		"alpha.example": page("home"),
		"twin.example":  page(`<img src="https://alpha.example/logo.png"><script src="https://alpha.example/x.js"></script>`),
	}}
}

func links(urls ...string) []scan.Link {
	var out []scan.Link
	for _, u := range urls {
		ex := web.Extract([]web.Page{{URL: "https://www.alpha.example/", Body: []byte(`<a href="` + u + `">x</a>`)}}, "www.alpha.example")
		out = append(out, ex.Links...)
	}
	return out
}

func TestFindFriends(t *testing.T) {
	vw := friendsWeb()
	home := Home{Domain: "alpha.example", Links: links(
		"https://www.friend.example/page", "https://www.friend.example/other", // two links to one domain
		"https://notfriend.example/", "https://shy.example/", "https://broken.example/", "https://serverr.example/",
		"https://pdf.example/", "https://twin.example/", "https://nosuch.example/",
		"https://www.linkedin.com/company/acme", // a platform is not a candidate
		"https://www.alpha.example/team",        // internal
	)}
	got := FindFriends(context.Background(), FriendsOptions{Fetch: fetch.Options{Transport: vw, Timeout: time.Second}, Delay: time.Millisecond}, home)

	if got.Candidates != 8 || got.Checked != 8 || len(got.Domains) != 8 {
		t.Fatalf("candidates=%d checked=%d domains=%d", got.Candidates, got.Checked, len(got.Domains))
	}
	by := map[string]scan.Friend{}
	for _, d := range got.Domains {
		by[d.Domain] = d
	}
	want := map[string]string{
		"friend.example": scan.FriendYes, "notfriend.example": scan.FriendNo, "shy.example": scan.FriendBlocked,
		"broken.example": scan.FriendUnreadable, "serverr.example": scan.FriendBlocked, "pdf.example": scan.FriendUnreadable,
		"twin.example": scan.FriendNo, "nosuch.example": scan.FriendUnreadable,
	}
	for dom, st := range want {
		if by[dom].Status != st {
			t.Errorf("%s: %q (%s), want %q", dom, by[dom].Status, by[dom].Detail, st)
		}
	}
	f := by["friend.example"]
	if f.URL != "https://www.friend.example/" || len(f.LinksBack) != 1 || f.LinksBack[0] != "https://www.alpha.example/about" || len(f.LinkedFrom) != 2 {
		t.Errorf("friend: %+v", f)
	}
	if got.Domains[0].Domain != "friend.example" {
		t.Errorf("the domain linked twice comes first: %v", got.Domains[0].Domain)
	}
	// A link from an image or a script is not a link: twin.example only embeds alpha's files.
	if by["twin.example"].Status != scan.FriendNo {
		t.Error("only ordinary links count")
	}
	// The home page of shy.example was never requested; robots.txt was.
	for _, p := range vw.hits["shy.example"] {
		if p != "/robots.txt" {
			t.Errorf("shy.example: %q was requested although robots.txt disallows it", p)
		}
	}
	if len(vw.hits["www.linkedin.com"]) != 0 {
		t.Error("a social platform is not contacted")
	}
	// Only the home page, once.
	for _, p := range vw.hits["www.friend.example"] {
		if p != "/" && p != "/robots.txt" {
			t.Errorf("unexpected request %q", p)
		}
	}
}

func TestFindFriendsLimitsAndCancel(t *testing.T) {
	vw := friendsWeb()
	home := Home{Domain: "alpha.example", Links: links("https://www.friend.example/", "https://notfriend.example/", "https://twin.example/")}
	opt := FriendsOptions{Fetch: fetch.Options{Transport: vw, Timeout: time.Second}, Delay: time.Millisecond, Max: 2}
	got := FindFriends(context.Background(), opt, home)
	if got.Candidates != 3 || got.Checked != 2 || got.Domains[2].Status != scan.FriendNotChecked {
		t.Errorf("the limit is reported: %+v", got)
	}
	if len(vw.hits["twin.example"]) != 0 {
		t.Error("a candidate over the limit is not contacted")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got = FindFriends(ctx, opt, home)
	if got.Checked != 0 {
		t.Errorf("a cancelled run contacts nobody: %+v", got)
	}
	for _, d := range got.Domains {
		if d.Status != scan.FriendNotChecked {
			t.Errorf("%+v", d)
		}
	}

	empty := FindFriends(context.Background(), opt, Home{Domain: "alpha.example"})
	if empty.Candidates != 0 || empty.Domains == nil || len(empty.Domains) != 0 {
		t.Errorf("no links, no candidates: %+v", empty)
	}
	if !strings.Contains(fmt.Sprint(got), "not_checked") {
		t.Error("statuses are readable")
	}
}

func TestScanWithFriends(t *testing.T) {
	vw := friendsWeb()
	vw.sites["www.alpha.example"] = page(`<a href="https://www.friend.example/">a friend</a> <a href="https://notfriend.example/">n</a>`)
	opt := options(t)
	opt.Fetch = fetch.Options{Transport: vw, Timeout: time.Second}
	opt.Friends, opt.Delay = true, time.Millisecond
	res, err := Scan(context.Background(), opt, "https://www.alpha.example/")
	if err != nil {
		t.Fatal(err)
	}
	if res.Friends == nil || res.Friends.Checked != 2 {
		t.Fatalf("%+v", res.Friends)
	}
	if err := Validate(res); err != nil {
		t.Errorf("the result must satisfy the schema: %v", err)
	}
	var friend bool
	for _, d := range res.Friends.Domains {
		friend = friend || (d.Domain == "friend.example" && d.Status == scan.FriendYes)
	}
	if !friend {
		t.Errorf("%+v", res.Friends.Domains)
	}
	// Not asked for: not there, and nobody else is contacted.
	vw2 := friendsWeb()
	vw2.sites["www.alpha.example"] = vw.sites["www.alpha.example"]
	opt.Fetch.Transport, opt.Friends = vw2, false
	res, err = Scan(context.Background(), opt, "https://www.alpha.example/")
	if err != nil || res.Friends != nil || len(vw2.hits["www.friend.example"]) != 0 {
		t.Errorf("friends=%v hits=%v err=%v", res.Friends, vw2.hits, err)
	}
}
