// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package bot

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func open(t *testing.T, path string, c *clock) *Store {
	t.Helper()
	s, err := Open(context.Background(), path, c.now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestRegistrable(t *testing.T) {
	for in, want := range map[string]string{
		"WWW.Example.com":   "example.com",
		"a.b.example.co.uk": "example.co.uk",
		"example.com.":      "example.com",
		"example.com:8080":  "example.com",
	} {
		if got, err := Registrable(in); err != nil || got != want {
			t.Errorf("%q: %q %v, want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "10.0.0.1", "co.uk", "localhost"} {
		if d, err := Registrable(bad); err == nil {
			t.Errorf("%q accepted as %q", bad, d)
		}
	}
}

func TestAddDedups(t *testing.T) {
	ctx := context.Background()
	c := &clock{time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	s := open(t, filepath.Join(t.TempDir(), "bot.db"), c)
	n, err := s.Add(ctx, []Seed{{Host: "www.a.com"}, {Host: "a.com"}, {Host: "b.org"}, {Host: "1.2.3.4"}})
	if err != nil || n != 2 {
		t.Fatalf("added %d, %v; want 2", n, err)
	}
	if n, _ := s.Add(ctx, []Seed{{Host: "x.a.com"}}); n != 0 {
		t.Fatalf("known domain added again")
	}
}

// A run killed in the middle: the lease expires and the domain is claimed again; the
// result of the dead worker is refused; nothing is lost or scanned twice by two owners.
func TestKillAndResume(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "bot.db")
	c := &clock{time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	s := open(t, path, c)
	if _, err := s.Add(ctx, []Seed{{Host: "a.com", Rank: 1}, {Host: "b.com", Rank: 2}}); err != nil {
		t.Fatal(err)
	}
	a, _ := claim(s, "w1")
	b, _ := claim(s, "w2")
	if a != "a.com" || b != "b.com" {
		t.Fatalf("claims %q %q", a, b)
	}
	if d, _ := claim(s, "w3"); d != "" {
		t.Fatalf("claimed %q while all leased", d)
	}
	// "kill -9": w1 and w2 vanish, the file is reopened later.
	_ = s.Close()
	c.t = c.t.Add(2 * time.Minute)
	s = open(t, path, c)
	if n, _ := s.Counts(ctx); n[StatePending] != 2 {
		t.Fatalf("counts %v", n)
	}
	d, _ := claim(s, "w3")
	if d != "a.com" {
		t.Fatalf("resumed on %q", d)
	}
	if err := s.Complete(ctx, "a.com", "w1", Result{}); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("dead worker wrote: %v", err)
	}
	err := s.Complete(ctx, "a.com", "w3", Result{Status: 200, JSON: []byte(`{}`), Hash: "h1",
		Discovered: []Seed{{Host: "c.com", Depth: 1, DiscoveredFrom: "a.com"}, {Host: "b.com", Depth: 1}},
		Revisit:    RevisitPolicy{Base: 24 * time.Hour, Jitter: 0.01}})
	if err != nil {
		t.Fatal(err)
	}
	n, _ := s.Counts(ctx)
	if n[StateDone] != 1 || n[StatePending] != 2 { // b.com (expired lease) and c.com
		t.Fatalf("counts %v", n)
	}
	// a.com is not due for a day; then it comes back after the others.
	var got []string
	for i := 0; i < 3; i++ {
		d, _ := claim(s, "w3")
		got = append(got, d)
	}
	if got[0] != "b.com" || got[1] != "c.com" || got[2] != "" {
		t.Fatalf("order %v", got)
	}
	c.t = c.t.Add(48 * time.Hour)
	if d, _ := claim(s, "w3"); d == "" {
		t.Fatal("revisit not due")
	}
}

func TestFailBlockHeartbeat(t *testing.T) {
	ctx := context.Background()
	c := &clock{time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	s := open(t, filepath.Join(t.TempDir(), "bot.db"), c)
	_, _ = s.Add(ctx, []Seed{{Host: "a.com"}})
	_ = s.Block(ctx, "evil.example", "adult", "list1")
	d, _ := claim(s, "w")
	if d != "a.com" {
		t.Fatalf("claimed %q (blocked must be skipped)", d)
	}
	c.t = c.t.Add(50 * time.Second)
	if err := s.Heartbeat(ctx, d, "w", time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := s.Heartbeat(ctx, d, "other", time.Minute); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("heartbeat by non-owner: %v", err)
	}
	if err := s.Fail(ctx, d, "w", "dns", 0, time.Hour, FailPolicy{}); err != nil {
		t.Fatal(err)
	}
	if d, _ := claim(s, "w"); d != "" {
		t.Fatalf("retry too early: %q", d)
	}
	n, _ := s.Counts(ctx)
	if n[StateFailed] != 1 || n[StateBlocked] != 1 {
		t.Fatalf("counts %v", n)
	}
}

// claim returns the domain name of the next job, "" when none is due.
func claim(s *Store, owner string) (string, error) {
	j, err := s.Claim(context.Background(), owner, time.Minute)
	return j.Domain, err
}

func TestRevisitPolicy(t *testing.T) {
	day := 24 * time.Hour
	p := RevisitPolicy{Base: 30 * day, Max: 100 * day, Min: day, Jitter: 0.1}
	for _, c := range []struct {
		stable         int
		changed, first bool
		unit           float64
		want           time.Duration
	}{
		{0, false, true, 0, 30 * day},
		{0, true, false, 0, 15 * day},
		{1, false, false, 0, 60 * day},
		{2, false, false, 0, 100 * day}, // 120 days, capped
		{9, false, false, 1, 100 * day},
		{0, false, true, 1, 33 * day},  // jitter up by 10%
		{0, false, true, -1, 27 * day}, // and down
		{0, false, true, 99, 33 * day}, // unit out of range is clamped
	} {
		if got := p.Next(c.stable, c.changed, c.first, c.unit); got != c.want {
			t.Errorf("%+v: %s, want %s", c, got, c.want)
		}
	}
	if d := (RevisitPolicy{Base: time.Hour}).Next(0, true, false, -1); d < day {
		t.Errorf("below the minimum: %s", d)
	}
	if u := jitterUnit("a.com", "x"); u < -1 || u > 1 || u != jitterUnit("a.com", "x") {
		t.Errorf("jitter %v", u)
	}
}

func TestRevisitAdaptsToChanges(t *testing.T) {
	ctx := context.Background()
	c := &clock{time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	s := open(t, filepath.Join(t.TempDir(), "bot.db"), c)
	_, _ = s.Add(ctx, []Seed{{Host: "a.com"}})
	pol := RevisitPolicy{Base: 10 * 24 * time.Hour, Max: 40 * 24 * time.Hour, Jitter: 0.001}
	scan := func(hash string) time.Duration {
		t.Helper()
		j, _ := s.Claim(ctx, "w", time.Minute)
		if j.Domain != "a.com" {
			t.Fatalf("claimed %q", j.Domain)
		}
		if err := s.Complete(ctx, "a.com", "w", Result{Hash: hash, Revisit: pol}); err != nil {
			t.Fatal(err)
		}
		var next string
		_ = s.db.QueryRow(`SELECT next_visit_at FROM domains WHERE domain='a.com'`).Scan(&next)
		at, _ := time.Parse(time.RFC3339, next)
		d := at.Sub(c.t).Round(24 * time.Hour)
		c.t = at.Add(time.Minute)
		return d
	}
	day := 24 * time.Hour
	for i, want := range []struct {
		hash string
		d    time.Duration
	}{{"h1", 10 * day}, {"h1", 20 * day}, {"h1", 40 * day}, {"h1", 40 * day}, {"h2", 5 * day}, {"h2", 20 * day}} {
		if got := scan(want.hash); got != want.d {
			t.Errorf("scan %d: next visit in %s, want %s", i+1, got, want.d)
		}
	}
}

func TestFailuresBackOffAndDNSBlocks(t *testing.T) {
	ctx := context.Background()
	c := &clock{time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	day := 24 * time.Hour
	p := FailPolicy{BlockAfterDNS: 3, MaxRetry: 5 * day}

	// Timeouts double the wait and are capped; they never block.
	s2 := open(t, filepath.Join(t.TempDir(), "two.db"), c)
	_, _ = s2.Add(ctx, []Seed{{Host: "b.com"}})
	for i, want := range []time.Duration{day, 2 * day, 4 * day, 5 * day} {
		c.t = c.t.Add(6 * day)
		j, _ := s2.Claim(ctx, "w", time.Minute)
		if err := s2.Fail(ctx, j.Domain, "w", "timeout", 0, day, p); err != nil {
			t.Fatal(err)
		}
		var n string
		_ = s2.db.QueryRow(`SELECT next_visit_at FROM domains WHERE domain='b.com'`).Scan(&n)
		at, _ := time.Parse(time.RFC3339, n)
		if got := at.Sub(c.t); got != want {
			t.Errorf("failure %d: retry in %s, want %s", i+1, got, want)
		}
	}

	// c.com: three DNS failures in a row block it for good; a timeout in between resets the count.
	s3 := open(t, filepath.Join(t.TempDir(), "three.db"), c)
	_, _ = s3.Add(ctx, []Seed{{Host: "c.com"}})
	seq := []struct {
		class   string
		blocked bool
	}{{"dns", false}, {"dns", false}, {"timeout", false}, {"dns", false}, {"dns", false}, {"dns", true}}
	for i, st := range seq {
		c.t = c.t.Add(200 * day)
		j, _ := s3.Claim(ctx, "w", time.Minute)
		if j.Domain != "c.com" {
			t.Fatalf("step %d: claimed %q", i, j.Domain)
		}
		if err := s3.Fail(ctx, "c.com", "w", st.class, 0, day, p); err != nil {
			t.Fatal(err)
		}
		n, _ := s3.Counts(ctx)
		if (n[StateBlocked] == 1) != st.blocked {
			t.Fatalf("step %d (%s): counts %v", i, st.class, n)
		}
	}
	if j, _ := s3.Claim(ctx, "w", time.Minute); j.Domain != "" {
		t.Error("a blocked domain was claimed")
	}
	// A filter refresh must not release it.
	if n, _ := s3.ReapplyFilter(ctx, func(string) (string, string, bool) { return "", "", false }); n != 0 {
		t.Error("the dns block was lifted by a filter refresh")
	}
	if st, _ := s3.Status(ctx); st.BlockedBy[DNSList] != 1 {
		t.Errorf("%v", st.BlockedBy)
	}
}

func TestOpenUpgradesAnOlderFile(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "old.db")
	c := &clock{time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	s := open(t, path, c)
	for _, col := range []string{"stable_count", "fail_streak", "dns_failures"} {
		if _, err := s.db.Exec("ALTER TABLE domains DROP COLUMN " + col); err != nil {
			t.Fatal(err)
		}
	}
	_, _ = s.Add(ctx, []Seed{{Host: "a.com"}})
	_ = s.Close()
	s = open(t, path, c)
	if j, err := s.Claim(ctx, "w", time.Minute); err != nil || j.Domain != "a.com" {
		t.Fatalf("%v %v", j, err)
	}
	if err := s.Complete(ctx, "a.com", "w", Result{Hash: "h"}); err != nil {
		t.Fatal(err)
	}
}
