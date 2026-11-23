// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package bot

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/fetch"
	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/robots"
)

// Errors a polite transport returns instead of sending a request.
var (
	// ErrRobots: robots.txt asks crawlers to stay away from this URL.
	ErrRobots = errors.New("bot: disallowed by robots.txt")
	// ErrRobotsUnavailable: robots.txt could not be read (server error, 429 or no answer),
	// so nothing is fetched from the host for now (RFC 9309: unreachable means disallowed).
	ErrRobotsUnavailable = errors.New("bot: robots.txt could not be read")
	// ErrBackoff: the host answered 429 or 5xx, or failed, and is being left alone.
	ErrBackoff = errors.New("bot: host is in backoff")
)

// HostStore keeps the state of hosts between runs. *Store implements it.
type HostStore interface {
	LoadHost(ctx context.Context, host string) (HostState, bool, error)
	SaveHost(ctx context.Context, st HostState) error
}

// PoolOptions configure a Pool. Zero values mean the defaults.
type PoolOptions struct {
	// Base sends the requests. Nil builds fetch.NewTransport(Timeout): the address guard
	// is then in the dialer and holds for every connection, redirects included. A Base of
	// your own must keep that guard.
	Base http.RoundTripper
	// Timeout is the time a server may take to answer (default fetch.DefaultTimeout).
	Timeout time.Duration
	// Store keeps crawl delays and backoffs across runs; nil keeps them in memory only.
	Store HostStore

	UserAgent string  // sent when robots.txt is read (default fetch.DefaultUserAgent)
	Agent     string  // product token matched in robots.txt (default "owfscan")
	Rate      float64 // requests per second over all hosts (default 2)

	PerHostDelay  time.Duration // pause between two requests to one host (default 10s)
	MaxCrawlDelay time.Duration // cap on a Crawl-delay read from robots.txt (default 30s)
	RobotsTTL     time.Duration // how long robots.txt is trusted (default 24h)
	RobotsRetry   time.Duration // how long an unreadable robots.txt is not asked again (default 10m)
	BackoffBase   time.Duration // first backoff after a 429, 5xx or failure (default 1m)
	BackoffMax    time.Duration // longest backoff, Retry-After included (default 6h)

	Now   func() time.Time
	Sleep func(ctx context.Context, d time.Duration) error
}

const (
	maxRobotsBytes = 512 << 10
	maxRobotsHops  = 5
	maxEntries     = 20000
)

// Pool makes the crawler's requests polite and shared: one transport for all workers, a
// global rate, a pause per host that follows Crawl-delay, a backoff on 429 and 5xx, and
// a robots.txt cache. It is used through RoundTripper, so everything a scan fetches
// (redirects, favicon, other pages) goes through it.
type Pool struct {
	o PoolOptions

	mu       sync.Mutex
	entries  map[string]*hostEntry
	hostNext map[string]time.Time
	global   time.Time
}

type hostEntry struct {
	mu        sync.Mutex
	loaded    bool
	st        HostState
	rules     *robots.Rules
	rulesAt   time.Time
	robotsErr time.Time // when robots.txt last failed; zero if it did not
}

// NewPool returns a Pool.
func NewPool(o PoolOptions) *Pool {
	if o.Base == nil {
		o.Base = fetch.NewTransport(fetch.Options{Timeout: o.Timeout})
	}
	if o.UserAgent == "" {
		o.UserAgent = fetch.DefaultUserAgent
	}
	if o.Agent == "" {
		o.Agent = "owfscan"
	}
	if o.Rate <= 0 {
		o.Rate = 2
	}
	def := func(d *time.Duration, v time.Duration) {
		if *d <= 0 {
			*d = v
		}
	}
	def(&o.PerHostDelay, 10*time.Second)
	def(&o.MaxCrawlDelay, 30*time.Second)
	def(&o.RobotsTTL, 24*time.Hour)
	def(&o.RobotsRetry, 10*time.Minute)
	def(&o.BackoffBase, time.Minute)
	def(&o.BackoffMax, 6*time.Hour)
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Sleep == nil {
		o.Sleep = sleep
	}
	return &Pool{o: o, entries: map[string]*hostEntry{}, hostNext: map[string]time.Time{}}
}

func sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// RoundTripper returns the polite transport; pass it as fetch.Options.Transport.
func (p *Pool) RoundTripper() http.RoundTripper { return politeTransport{p} }

type politeTransport struct{ p *Pool }

func (t politeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return t.p.roundTrip(req)
}

func (p *Pool) entry(ctx context.Context, key string) (*hostEntry, error) {
	p.mu.Lock()
	e := p.entries[key]
	if e == nil {
		if len(p.entries) >= maxEntries {
			p.sweepLocked()
		}
		e = &hostEntry{}
		p.entries[key] = e
	}
	p.mu.Unlock()
	e.mu.Lock() // the caller unlocks
	if !e.loaded {
		e.st = HostState{Host: key}
		if p.o.Store != nil {
			if st, ok, err := p.o.Store.LoadHost(ctx, key); err != nil {
				e.mu.Unlock()
				return nil, err
			} else if ok {
				e.st = st
			}
		}
		e.loaded = true
	}
	return e, nil
}

// sweepLocked forgets hosts with nothing worth remembering in memory (the store keeps
// their state), so a crawl over millions of hosts does not grow without bound.
func (p *Pool) sweepLocked() {
	now := p.o.Now()
	for k, e := range p.entries {
		if e.mu.TryLock() {
			idle := now.After(e.st.BackoffUntil) && now.Sub(e.rulesAt) > p.o.RobotsTTL
			e.mu.Unlock()
			if idle {
				delete(p.entries, k)
			}
		}
	}
	for k, t := range p.hostNext {
		if now.After(t) {
			delete(p.hostNext, k)
		}
	}
	// Still full of live hosts: forget the rest rather than refuse to work.
	for k := range p.entries {
		if len(p.entries) < maxEntries/2 {
			break
		}
		delete(p.entries, k)
	}
}

func (p *Pool) delay(e *hostEntry) time.Duration {
	d := p.o.PerHostDelay
	if cd := min(e.st.CrawlDelay, p.o.MaxCrawlDelay); cd > d {
		d = cd
	}
	return d
}

// wait takes the next free slot of the host and then of the global rate. The host's slot
// is reserved first and slept alone, so a slow host does not hold back the others.
func (p *Pool) wait(ctx context.Context, key string, hostDelay time.Duration) error {
	p.mu.Lock()
	now := p.o.Now()
	s1 := now
	if t := p.hostNext[key]; t.After(s1) {
		s1 = t
	}
	p.hostNext[key] = s1.Add(hostDelay)
	p.mu.Unlock()
	if err := p.o.Sleep(ctx, s1.Sub(now)); err != nil {
		return err
	}
	p.mu.Lock()
	now = p.o.Now()
	s2 := now
	if p.global.After(s2) {
		s2 = p.global
	}
	p.global = s2.Add(time.Duration(float64(time.Second) / p.o.Rate))
	p.mu.Unlock()
	return p.o.Sleep(ctx, s2.Sub(now))
}

func (p *Pool) roundTrip(req *http.Request) (*http.Response, error) {
	ctx := req.Context()
	key := strings.ToLower(req.URL.Host)
	e, err := p.entry(ctx, key)
	if err != nil {
		return nil, err
	}
	if until := e.st.BackoffUntil; p.o.Now().Before(until) {
		e.mu.Unlock()
		return nil, fmt.Errorf("%w until %s", ErrBackoff, until.UTC().Format(time.RFC3339))
	}
	if req.URL.Path != "/robots.txt" {
		rules, err := p.rulesLocked(ctx, e, key, req.URL)
		if err != nil {
			e.mu.Unlock()
			return nil, err
		}
		if !rules.Allowed(req.URL.String()) {
			e.mu.Unlock()
			return nil, ErrRobots
		}
	}
	hostDelay := p.delay(e)
	e.mu.Unlock()
	if err := p.wait(ctx, key, hostDelay); err != nil {
		return nil, err
	}
	resp, err := p.o.Base.RoundTrip(req)
	p.record(ctx, e, resp, err)
	return resp, err
}

// rulesLocked returns the host's robots.txt rules, reading the file when the copy is
// missing or old. e.mu is held by the caller.
func (p *Pool) rulesLocked(ctx context.Context, e *hostEntry, key string, u *url.URL) (*robots.Rules, error) {
	now := p.o.Now()
	if e.rules != nil && now.Sub(e.rulesAt) < p.o.RobotsTTL {
		return e.rules, nil
	}
	if !e.robotsErr.IsZero() && now.Sub(e.robotsErr) < p.o.RobotsRetry {
		return nil, ErrRobotsUnavailable
	}
	rules, _, err := p.fetchRobots(ctx, e, key, u)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		e.robotsErr = now
		p.failLocked(ctx, e, nil)
		return nil, fmt.Errorf("%w: %w", ErrRobotsUnavailable, err)
	}
	e.rules, e.rulesAt, e.robotsErr = rules, now, time.Time{}
	e.st.CrawlDelay, e.st.RobotsFetchedAt = rules.CrawlDelay, now
	p.saveLocked(ctx, e)
	return rules, nil
}

// fetchRobots reads /robots.txt. 4xx means there is none (everything allowed); 5xx, 429
// and network errors mean it cannot be read. It follows a few redirects.
func (p *Pool) fetchRobots(ctx context.Context, e *hostEntry, key string, u *url.URL) (*robots.Rules, int, error) {
	target := &url.URL{Scheme: u.Scheme, Host: u.Host, Path: "/robots.txt"}
	for hop := 0; hop < maxRobotsHops; hop++ {
		if err := p.wait(ctx, strings.ToLower(target.Host), p.delay(e)); err != nil {
			return nil, 0, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
		if err != nil {
			return nil, 0, err
		}
		req.Header.Set("User-Agent", p.o.UserAgent)
		resp, err := p.o.Base.RoundTrip(req)
		if err != nil {
			return nil, 0, err
		}
		status := resp.StatusCode
		switch {
		case status >= 300 && status < 400 && resp.Header.Get("Location") != "":
			next, perr := target.Parse(resp.Header.Get("Location"))
			_ = resp.Body.Close()
			if perr != nil || (next.Scheme != "http" && next.Scheme != "https") {
				return nil, status, errors.New("bad redirect")
			}
			target = next
		case status >= 200 && status < 300:
			b, rerr := io.ReadAll(io.LimitReader(resp.Body, maxRobotsBytes))
			_ = resp.Body.Close()
			if rerr != nil {
				return nil, status, rerr
			}
			return robots.Parse(string(b), p.o.Agent), status, nil
		case status == http.StatusTooManyRequests || status >= 500:
			_ = resp.Body.Close()
			return nil, status, fmt.Errorf("status %d", status)
		default: // 4xx, or a redirect with no place to go: no robots.txt
			_ = resp.Body.Close()
			return robots.Parse("", p.o.Agent), status, nil
		}
	}
	return nil, 0, errors.New("too many redirects")
}

// record learns from an answer: a 429, a 5xx or a failure starts or lengthens a backoff;
// a good answer ends it.
func (p *Pool) record(ctx context.Context, e *hostEntry, resp *http.Response, err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	switch {
	case err != nil:
		if ctx.Err() != nil || errors.Is(err, fetch.ErrBlockedAddress) {
			return // our own doing, not the host's
		}
		p.failLocked(ctx, e, nil)
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
		p.failLocked(ctx, e, resp.Header)
	case e.st.FailCount > 0 || !e.st.BackoffUntil.IsZero():
		e.st.FailCount, e.st.BackoffUntil = 0, time.Time{}
		p.saveLocked(ctx, e)
	}
}

func (p *Pool) failLocked(ctx context.Context, e *hostEntry, h http.Header) {
	e.st.FailCount++
	d := p.o.BackoffBase
	for i := 1; i < e.st.FailCount && d < p.o.BackoffMax; i++ {
		d *= 2
	}
	if h != nil {
		if ra := retryAfter(h.Get("Retry-After"), p.o.Now()); ra > d {
			d = ra
		}
	}
	d = min(d, p.o.BackoffMax)
	e.st.BackoffUntil = p.o.Now().Add(d)
	p.saveLocked(ctx, e)
}

func (p *Pool) saveLocked(ctx context.Context, e *hostEntry) {
	if p.o.Store != nil {
		_ = p.o.Store.SaveHost(ctx, e.st) // the state is also in memory; a failed save loses only the next run's memory
	}
}

// retryAfter reads a Retry-After header: seconds or an HTTP date.
func retryAfter(v string, now time.Time) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	if n, err := strconv.Atoi(v); err == nil && n > 0 {
		return time.Duration(n) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil && t.After(now) {
		return t.Sub(now)
	}
	return 0
}
