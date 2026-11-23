// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package bot

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/bot/blocklist"
	"github.com/matteoredaelli/open-web-fingerprints/scan"
)

// site describes what the fake scanner finds on a domain.
type fakeWeb struct {
	mu    sync.Mutex
	links map[string][]string // host -> external domains linked
	errs  map[string]error
	seen  []string
}

func (w *fakeWeb) scan(_ context.Context, target string) (*scan.Result, error) {
	host := strings.TrimPrefix(strings.TrimPrefix(target, "https://"), "www.")
	w.mu.Lock()
	w.seen = append(w.seen, target)
	err := w.errs[target]
	if err == nil {
		err = w.errs[host]
	}
	w.mu.Unlock()
	if err != nil {
		return nil, err
	}
	r := &scan.Result{Target: scan.Target{Host: host, RegistrableDomain: host},
		Pages:        []scan.Page{{Status: 200}},
		Technologies: []scan.Technology{{Slug: "nginx", Version: "1.0"}}}
	r.Contacts = []scan.Contact{{Kind: "email", Value: "someone@" + host}}
	r.Domains = append(r.Domains, scan.Domain{Domain: host, Internal: true, Links: 9})
	for i, d := range w.links[host] {
		r.Domains = append(r.Domains, scan.Domain{Domain: d, Links: len(w.links[host]) - i})
	}
	return r, nil
}

func runOpts(w *fakeWeb) RunOptions {
	return RunOptions{Workers: 3, Scan: w.scan, MaxNewPerSite: 10, MaxDepth: 2, Idle: 5 * time.Millisecond,
		Revisit: 24 * time.Hour, LeaseTTL: time.Minute}
}

func openReal(t *testing.T) *Store {
	t.Helper()
	s, err := Open(context.Background(), filepath.Join(t.TempDir(), "bot.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestRunDiscoversAndStops(t *testing.T) {
	ctx := context.Background()
	s := openReal(t)
	w := &fakeWeb{links: map[string][]string{
		"a.com": {"b.com", "c.org", "www.b.com"}, // www.b.com is the same registrable domain
		"b.com": {"d.net"},
		"d.net": {"e.io"}, // depth 2: scanned, its links are not added
	}}
	_, _ = s.Add(ctx, []Seed{{Host: "a.com", Rank: 1}})
	sum, err := Run(ctx, s, runOpts(w))
	if err != nil {
		t.Fatal(err)
	}
	if sum.Scanned != 4 || sum.StopReason != "empty" { // a, b, c, d
		t.Fatalf("%+v", sum)
	}
	n, _ := s.Counts(ctx)
	if n[StateDone] != 4 || n[StatePending] != 0 {
		t.Errorf("counts %v", n)
	}
	// e.io was never added: d.net is at depth 2 = MaxDepth.
	if n2, _ := s.Add(ctx, []Seed{{Host: "e.io"}}); n2 != 1 {
		t.Error("e.io was already known")
	}
	b, err := s.ResultJSON(ctx, "a.com")
	if err != nil || !json.Valid(b) || !strings.Contains(string(b), "nginx") {
		t.Errorf("result: %v %s", err, b)
	}
	if strings.Contains(string(b), "someone@") {
		t.Error("a contact detail was stored")
	}
	// Run again at once: nothing is due (revisit in a day).
	if sum, _ = Run(ctx, s, runOpts(w)); sum.Scanned != 1 { // e.io, just added
		t.Errorf("second run %+v", sum)
	}
}

func TestRunFilterBlocksAtDiscoveryAndClaim(t *testing.T) {
	ctx := context.Background()
	s := openReal(t)
	f, _ := blocklist.New([]string{"adult"})
	_ = f.Add("l", "adult", blocklist.Rules{Block: []string{"bad.com", "worse.org"}})
	w := &fakeWeb{links: map[string][]string{"a.com": {"bad.com", "ok.com"}}}
	_, _ = s.Add(ctx, []Seed{{Host: "a.com"}, {Host: "www.worse.org"}})
	o := runOpts(w)
	o.Filter = f
	sum, err := Run(ctx, s, o)
	if err != nil {
		t.Fatal(err)
	}
	n, _ := s.Counts(ctx)
	if n[StateBlocked] != 2 || n[StateDone] != 2 || sum.Blocked != 1 { // bad.com blocked at discovery, worse.org at claim
		t.Errorf("counts %v, %+v", n, sum)
	}
	for _, seen := range w.seen {
		if strings.Contains(seen, "bad.com") {
			t.Errorf("a blocked domain was scanned: %s", seen)
		}
	}
	st, _ := s.Status(ctx)
	if st.BlockedBy["l"] != 2 {
		t.Errorf("blocked by %v", st.BlockedBy)
	}
}

func TestRunBlocksARedirectToABlockedSite(t *testing.T) {
	ctx := context.Background()
	s := openReal(t)
	f, _ := blocklist.New([]string{"adult"})
	_ = f.Add("l", "adult", blocklist.Rules{Block: []string{"bad.com"}})
	o := runOpts(&fakeWeb{})
	o.Filter = f
	o.Scan = func(context.Context, string) (*scan.Result, error) {
		return &scan.Result{Target: scan.Target{Host: "www.bad.com", RegistrableDomain: "bad.com"}}, nil
	}
	_, _ = s.Add(ctx, []Seed{{Host: "innocent.com"}})
	if _, err := Run(ctx, s, o); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.Counts(ctx); n[StateBlocked] != 1 || n[StateDone] != 0 {
		t.Errorf("counts %v", n)
	}
	if b, _ := s.ResultJSON(ctx, "innocent.com"); b != nil {
		t.Error("the page of a blocked site was kept")
	}
}

func TestRunBudgetAndKillSwitch(t *testing.T) {
	ctx := context.Background()
	s := openReal(t)
	w := &fakeWeb{}
	var seeds []Seed
	for i := 0; i < 10; i++ {
		seeds = append(seeds, Seed{Host: fmt.Sprintf("s%d.com", i), Rank: i + 1})
	}
	_, _ = s.Add(ctx, seeds)
	o := runOpts(w)
	o.Budget = 4
	sum, _ := Run(ctx, s, o)
	if sum.Scanned != 4 || sum.StopReason != "budget" {
		t.Errorf("%+v", sum)
	}
	o = runOpts(w)
	o.ShouldStop = func() bool { return true }
	sum, _ = Run(ctx, s, o)
	if sum.Scanned != 0 || sum.StopReason != "kill switch" {
		t.Errorf("%+v", sum)
	}
}

func TestRunInterruptReleasesWork(t *testing.T) {
	ctx, stop := context.WithCancel(context.Background())
	s := openReal(t)
	_, _ = s.Add(ctx, []Seed{{Host: "slow.com"}})
	started := make(chan struct{})
	o := runOpts(&fakeWeb{})
	o.Scan = func(c context.Context, _ string) (*scan.Result, error) {
		close(started)
		<-c.Done()
		return nil, c.Err()
	}
	done := make(chan Summary)
	go func() { sum, _ := Run(ctx, s, o); done <- sum }()
	<-started
	stop()
	sum := <-done
	if sum.Released != 1 || sum.StopReason != "interrupted" {
		t.Fatalf("%+v", sum)
	}
	n, _ := s.Counts(context.Background())
	if n[StatePending] != 1 || n[StateLeased] != 0 {
		t.Errorf("counts %v", n)
	}
	// The next run does it, at once (no waiting for a lease to expire).
	sum, _ = Run(context.Background(), s, runOpts(&fakeWeb{}))
	if sum.Scanned != 1 {
		t.Errorf("next run %+v", sum)
	}
}

func TestOnlyOneRun(t *testing.T) {
	ctx := context.Background()
	s := openReal(t)
	if ok, _ := s.AcquireRun(ctx, "other", time.Hour); !ok {
		t.Fatal("lock refused")
	}
	_, err := Run(ctx, s, runOpts(&fakeWeb{}))
	if !errors.Is(err, ErrAlreadyRunning) {
		t.Fatalf("%v", err)
	}
	if err := s.ReleaseRun(ctx, "other"); err != nil {
		t.Fatal(err)
	}
	if _, err := Run(ctx, s, runOpts(&fakeWeb{})); err != nil {
		t.Fatal(err)
	}
	if o, _, _ := s.RunLock(ctx); o != "" {
		t.Errorf("lock left behind by %q", o)
	}
}

func TestRunRecordsFailuresAndTriesWWW(t *testing.T) {
	ctx := context.Background()
	s := openReal(t)
	w := &fakeWeb{errs: map[string]error{
		"nodns.com":   errors.New("dial: lookup nodns.com: no such host"),
		"robots.com":  fmt.Errorf("x: %w", ErrRobots),
		"onlywww.com": nil,
	}}
	w.errs["https://onlywww.com"] = errors.New("lookup onlywww.com: no such host")
	_, _ = s.Add(ctx, []Seed{{Host: "nodns.com"}, {Host: "robots.com"}, {Host: "onlywww.com"}})
	sum, err := Run(ctx, s, runOpts(w))
	if err != nil {
		t.Fatal(err)
	}
	if sum.Scanned != 1 || sum.Failed != 2 {
		t.Errorf("%+v", sum)
	}
	found := false
	for _, u := range w.seen {
		found = found || u == "https://www.onlywww.com"
	}
	if !found {
		t.Errorf("no www. retry: %v", w.seen)
	}
	var class string
	_ = s.db.QueryRow(`SELECT last_error_class FROM domains WHERE domain='nodns.com'`).Scan(&class)
	if class != "dns" {
		t.Errorf("class %q", class)
	}
	_ = s.db.QueryRow(`SELECT last_error_class FROM domains WHERE domain='robots.com'`).Scan(&class)
	if class != "robots" {
		t.Errorf("class %q", class)
	}
}

func TestReapplyFilter(t *testing.T) {
	ctx := context.Background()
	s := openReal(t)
	_ = s.Block(ctx, "was.com", "category adult", "old")
	_ = s.Block(ctx, "still.com", "category adult", "old")
	_ = s.Block(ctx, "mine.com", "asked to be left out", OptOutList)
	f, _ := blocklist.New([]string{"adult"})
	_ = f.Add("new", "adult", blocklist.Rules{Block: []string{"still.com"}})
	n, err := s.ReapplyFilter(ctx, func(d string) (string, string, bool) {
		v := f.Check(d)
		return v.List, v.Category, v.Blocked
	})
	if err != nil || n != 1 {
		t.Fatalf("released %d, %v", n, err)
	}
	c, _ := s.Counts(ctx)
	if c[StateBlocked] != 2 || c[StatePending] != 1 {
		t.Errorf("counts %v", c)
	}
	st, _ := s.Status(ctx)
	if st.BlockedBy["new"] != 1 || st.BlockedBy[OptOutList] != 1 {
		t.Errorf("blocked by %v", st.BlockedBy)
	}
}

func TestHashIgnoresNoise(t *testing.T) {
	a := &scan.Result{Technologies: []scan.Technology{{Slug: "x", Version: "1"}}, Domains: []scan.Domain{{Domain: "d.com", Links: 1}}}
	b := &scan.Result{Technologies: []scan.Technology{{Slug: "x", Version: "1"}}, Domains: []scan.Domain{{Domain: "d.com", Links: 7}}, ScannedAt: time.Now()}
	c := &scan.Result{Technologies: []scan.Technology{{Slug: "x", Version: "2"}}, Domains: a.Domains}
	if Hash(a) != Hash(b) || Hash(a) == Hash(c) {
		t.Error("hash")
	}
}
