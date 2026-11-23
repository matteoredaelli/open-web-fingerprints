// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package bot

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/fetch"
)

// virtual is a clock that moves only when someone sleeps, so the tests are instant and exact.
type virtual struct {
	mu sync.Mutex
	t  time.Time
}

func newVirtual() *virtual { return &virtual{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)} }
func (v *virtual) Now() time.Time {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.t
}
func (v *virtual) Sleep(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if d > 0 {
		v.t = v.t.Add(d)
	}
	return nil
}
func (v *virtual) advance(d time.Duration) {
	v.mu.Lock()
	v.t = v.t.Add(d)
	v.mu.Unlock()
}

type site struct {
	*httptest.Server
	robotsHits, pageHits atomic.Int32
	robots               string
	robotsStatus         int
	pageStatus           int
	retryAfter           string
}

func newSite(t *testing.T, robots string) *site {
	t.Helper()
	s := &site{robots: robots, robotsStatus: 200, pageStatus: 200}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/robots.txt" {
			s.robotsHits.Add(1)
			if s.robotsStatus != 200 {
				w.WriteHeader(s.robotsStatus)
				return
			}
			_, _ = w.Write([]byte(s.robots))
			return
		}
		s.pageHits.Add(1)
		if s.retryAfter != "" {
			w.Header().Set("Retry-After", s.retryAfter)
		}
		w.WriteHeader(s.pageStatus)
		_, _ = w.Write([]byte("page"))
	}))
	t.Cleanup(s.Close)
	return s
}

func newTestPool(v *virtual, o PoolOptions) *Pool {
	if o.Base == nil {
		o.Base = &http.Transport{}
	}
	o.Now, o.Sleep = v.Now, v.Sleep
	return NewPool(o)
}

func get(p *Pool, url string) (*http.Response, error) {
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	resp, err := p.RoundTripper().RoundTrip(req)
	if err == nil {
		_ = resp.Body.Close()
	}
	return resp, err
}

func TestRobotsAreHonouredAndCached(t *testing.T) {
	s := newSite(t, "User-agent: *\nDisallow: /private\n")
	p := newTestPool(newVirtual(), PoolOptions{})
	if _, err := get(p, s.URL+"/ok"); err != nil {
		t.Fatal(err)
	}
	if _, err := get(p, s.URL+"/private/x"); !errors.Is(err, ErrRobots) {
		t.Fatalf("private: %v", err)
	}
	if _, err := get(p, s.URL+"/also-ok"); err != nil {
		t.Fatal(err)
	}
	if s.robotsHits.Load() != 1 || s.pageHits.Load() != 2 {
		t.Errorf("robots %d pages %d", s.robotsHits.Load(), s.pageHits.Load())
	}
}

func TestRobotsTTL(t *testing.T) {
	v := newVirtual()
	s := newSite(t, "")
	p := newTestPool(v, PoolOptions{RobotsTTL: time.Hour})
	_, _ = get(p, s.URL+"/a")
	v.advance(2 * time.Hour)
	_, _ = get(p, s.URL+"/b")
	if s.robotsHits.Load() != 2 {
		t.Errorf("robots read %d times, want 2", s.robotsHits.Load())
	}
}

func TestMissingRobotsAllowsAndBrokenRobotsForbids(t *testing.T) {
	v := newVirtual()
	s := newSite(t, "")
	s.robotsStatus = 404
	p := newTestPool(v, PoolOptions{})
	if _, err := get(p, s.URL+"/a"); err != nil {
		t.Fatalf("404 robots: %v", err)
	}

	b := newSite(t, "")
	b.robotsStatus = 500
	p = newTestPool(v, PoolOptions{RobotsRetry: 10 * time.Minute})
	if _, err := get(p, b.URL+"/a"); !errors.Is(err, ErrRobotsUnavailable) {
		t.Fatalf("500 robots: %v", err)
	}
	if b.pageHits.Load() != 0 {
		t.Error("page fetched although robots.txt could not be read")
	}
}

func TestCrawlDelayAndHostDelay(t *testing.T) {
	v := newVirtual()
	s := newSite(t, "User-agent: *\nCrawl-delay: 20\n")
	p := newTestPool(v, PoolOptions{PerHostDelay: time.Second, MaxCrawlDelay: 30 * time.Second, Rate: 1000})
	_, _ = get(p, s.URL+"/a")
	t1 := v.Now()
	_, _ = get(p, s.URL+"/b")
	if d := v.Now().Sub(t1); d < 20*time.Second {
		t.Errorf("second request after %s, want at least the 20s Crawl-delay", d)
	}

	// The cap: a Crawl-delay of 20s is cut to 5s.
	v2 := newVirtual()
	s2 := newSite(t, "User-agent: *\nCrawl-delay: 20\n")
	p2 := newTestPool(v2, PoolOptions{PerHostDelay: time.Second, MaxCrawlDelay: 5 * time.Second, Rate: 1000})
	_, _ = get(p2, s2.URL+"/a")
	t2 := v2.Now()
	_, _ = get(p2, s2.URL+"/b")
	if d := v2.Now().Sub(t2); d < 5*time.Second || d >= 20*time.Second {
		t.Errorf("capped delay: %s", d)
	}
}

func TestGlobalRateAcrossHosts(t *testing.T) {
	v := newVirtual()
	a, b := newSite(t, ""), newSite(t, "")
	p := newTestPool(v, PoolOptions{Rate: 1, PerHostDelay: time.Second})
	start := v.Now()
	for _, u := range []string{a.URL, b.URL, a.URL, b.URL} {
		_, _ = get(p, u+"/x")
	}
	// 2 robots + 4 pages = 6 requests at 1 per second: at least 5 seconds.
	if d := v.Now().Sub(start); d < 5*time.Second {
		t.Errorf("6 requests in %s, rate is 1/s", d)
	}
}

func TestBackoffOn5xxAndRetryAfter(t *testing.T) {
	v := newVirtual()
	s := newSite(t, "")
	s.pageStatus, s.retryAfter = 503, "600"
	p := newTestPool(v, PoolOptions{BackoffBase: time.Minute, BackoffMax: time.Hour})
	if resp, err := get(p, s.URL+"/a"); err != nil || resp.StatusCode != 503 {
		t.Fatalf("%v %v", resp, err)
	}
	hits := s.pageHits.Load()
	if _, err := get(p, s.URL+"/a"); !errors.Is(err, ErrBackoff) {
		t.Fatalf("in backoff: %v", err)
	}
	if s.pageHits.Load() != hits {
		t.Error("request sent during backoff")
	}
	v.advance(5 * time.Minute) // Retry-After said 10 minutes
	if _, err := get(p, s.URL+"/a"); !errors.Is(err, ErrBackoff) {
		t.Fatalf("Retry-After not honoured: %v", err)
	}
	v.advance(6 * time.Minute)
	s.pageStatus, s.retryAfter = 200, ""
	if resp, err := get(p, s.URL+"/a"); err != nil || resp.StatusCode != 200 {
		t.Fatalf("after backoff: %v %v", resp, err)
	}
	if _, err := get(p, s.URL+"/a"); err != nil {
		t.Fatalf("backoff not cleared by a good answer: %v", err)
	}
}

func TestBackoffGrowsAndIsCapped(t *testing.T) {
	v := newVirtual()
	s := newSite(t, "")
	s.pageStatus = 500
	p := newTestPool(v, PoolOptions{BackoffBase: time.Minute, BackoffMax: 3 * time.Minute})
	var last time.Duration
	for i := 0; i < 5; i++ {
		_, _ = get(p, s.URL+"/a")
		e, _ := p.entry(context.Background(), hostKey(s.URL))
		last = e.st.BackoffUntil.Sub(v.Now())
		e.mu.Unlock()
		v.advance(last + time.Second)
	}
	if last > 3*time.Minute+time.Second {
		t.Errorf("backoff %s exceeds the cap", last)
	}
}

func hostKey(u string) string { return u[len("http://"):] }

func TestHostStateSurvivesARestart(t *testing.T) {
	ctx := context.Background()
	v := newVirtual()
	path := filepath.Join(t.TempDir(), "bot.db")
	st, err := Open(ctx, path, v.Now)
	if err != nil {
		t.Fatal(err)
	}
	s := newSite(t, "User-agent: *\nCrawl-delay: 7\n")
	s.pageStatus = 429
	p := newTestPool(v, PoolOptions{Store: st})
	_, _ = get(p, s.URL+"/a")
	_ = st.Close()

	st, err = Open(ctx, path, v.Now)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	p = newTestPool(v, PoolOptions{Store: st})
	if _, err := get(p, s.URL+"/a"); !errors.Is(err, ErrBackoff) {
		t.Fatalf("backoff lost across restart: %v", err)
	}
	h, ok, _ := st.LoadHost(ctx, hostKey(s.URL))
	if !ok || h.CrawlDelay != 7*time.Second || h.FailCount != 1 {
		t.Errorf("saved state %+v", h)
	}
}

// The guard sits in the transport underneath: wrapping it does not remove it.
func TestGuardSurvivesTheWrapper(t *testing.T) {
	s := newSite(t, "")
	p := newTestPool(newVirtual(), PoolOptions{Base: fetch.NewTransport(fetch.Options{})})
	_, err := get(p, s.URL+"/a") // 127.0.0.1 is not a public address
	if !errors.Is(err, fetch.ErrBlockedAddress) {
		t.Fatalf("loopback reached: %v", err)
	}
	if s.robotsHits.Load()+s.pageHits.Load() != 0 {
		t.Error("the server was contacted")
	}
}

func TestFetcherThroughThePool(t *testing.T) {
	s := newSite(t, "User-agent: *\nDisallow: /no\n")
	p := newTestPool(newVirtual(), PoolOptions{})
	f := fetch.New(fetch.Options{Transport: p.RoundTripper()})
	r, err := f.Get(context.Background(), s.URL+"/yes")
	if err != nil || r.Status != 200 {
		t.Fatalf("%v %v", r, err)
	}
	if _, err := f.Get(context.Background(), s.URL+"/no"); !errors.Is(err, ErrRobots) {
		t.Fatalf("disallowed page fetched: %v", err)
	}
}

func TestCancelledWhileWaiting(t *testing.T) {
	s := newSite(t, "")
	p := NewPool(PoolOptions{Base: &http.Transport{}, PerHostDelay: time.Hour, Rate: 1000})
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, s.URL+"/a", nil)
	start := time.Now()
	// robots.txt is the host's first request; the page then waits an hour, and the context ends it.
	if _, err := p.RoundTripper().RoundTrip(req); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("%v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Error("the wait did not end with the context")
	}
}
