// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package bot

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/batch"
	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/bot/blocklist"
	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/fetch"
	"github.com/matteoredaelli/open-web-fingerprints/scan"
)

// ScanFunc scans one target (a URL) and returns the result.
type ScanFunc func(ctx context.Context, target string) (*scan.Result, error)

// ErrAlreadyRunning is returned when another bot holds the run lock of the file.
var ErrAlreadyRunning = errors.New("bot: another run holds this crawl")

// RunOptions configure Run. Limits that the configuration bounds (workers, rate, delays)
// are checked there; Run trusts them.
type RunOptions struct {
	Workers  int
	Owner    string        // names this run in leases; default host-pid
	LeaseTTL time.Duration // default 10m
	Timeout  time.Duration // time allowed to one domain, the www. retry included (default 90s)
	// Budget is the most domains claimed in this run (0: no limit); Until stops the run
	// after this long (0: no limit).
	Budget int
	Until  time.Duration
	// MaxNewPerSite and MaxDepth bound discovery: a page adds at most MaxNewPerSite new
	// domains, and a domain MaxDepth hops from a seed adds none.
	MaxNewPerSite, MaxDepth int
	// Revisit is when a scanned domain comes back; RevisitMax is the longest, for a domain
	// that does not change.
	Revisit, RevisitMax time.Duration
	// DNSFailures blocks a domain for good after this many "no such host" in a row (0: never).
	DNSFailures int
	// Filter blocks domains; nil blocks none (the caller decided it, see --no-filter).
	Filter *blocklist.Filter
	Scan   ScanFunc
	// ShouldStop is the kill switch, asked before every claim.
	ShouldStop func() bool
	// Progress is called after each domain with done, failed, blocked or released.
	Progress func(domain, outcome string)
	// Idle is how long a worker waits when nothing is due but others are working (default 1s).
	Idle time.Duration
	Now  func() time.Time
}

// Summary of a run.
type Summary struct {
	Scanned, Failed, Blocked, Released, Discovered int
	StopReason                                     string // "empty", "budget", "until", "kill switch" or "interrupted"
}

func (o *RunOptions) defaults() {
	if o.Workers <= 0 {
		o.Workers = 4
	}
	if o.LeaseTTL <= 0 {
		o.LeaseTTL = 10 * time.Minute
	}
	if o.Timeout <= 0 {
		o.Timeout = 90 * time.Second
	}
	if o.Revisit <= 0 {
		o.Revisit = 30 * 24 * time.Hour
	}
	if o.RevisitMax < o.Revisit {
		o.RevisitMax = max(o.Revisit, 180*24*time.Hour)
	}
	if o.Idle <= 0 {
		o.Idle = time.Second
	}
	if o.Owner == "" {
		h, _ := os.Hostname()
		o.Owner = fmt.Sprintf("%s-%d", h, os.Getpid())
	}
	if o.ShouldStop == nil {
		o.ShouldStop = func() bool { return false }
	}
}

// Run scans the frontier until nothing is due, the budget or time is spent, the kill
// switch is set or ctx ends. Stopping, even by a signal, releases the domains in flight so
// the next run does them first; a run killed outright loses nothing either, because their
// leases expire.
func Run(ctx context.Context, st *Store, o RunOptions) (Summary, error) {
	o.defaults()
	if o.Scan == nil {
		return Summary{}, errors.New("bot: no scan function")
	}
	ok, err := st.AcquireRun(ctx, o.Owner, o.LeaseTTL)
	if err != nil {
		return Summary{}, err
	}
	if !ok {
		holder, until, _ := st.RunLock(ctx)
		return Summary{}, fmt.Errorf("%w (held by %s until %s)", ErrAlreadyRunning, holder, until.UTC().Format(time.RFC3339))
	}
	defer func() { _ = st.ReleaseRun(context.WithoutCancel(ctx), o.Owner) }()

	var cancelRun context.CancelFunc
	ctx, cancelRun = context.WithCancel(ctx)
	defer cancelRun()
	var reason atomic.Value
	setReason := func(r string) { reason.CompareAndSwap(nil, r) }
	if o.Until > 0 {
		time.AfterFunc(o.Until, func() { setReason("until"); cancelRun() })
	}
	go func() { // keep the run lock alive
		t := time.NewTicker(o.LeaseTTL / 3)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := st.RenewRun(ctx, o.Owner, o.LeaseTTL); errors.Is(err, ErrLeaseLost) {
					setReason("run lock lost")
					cancelRun()
					return
				}
			}
		}
	}()

	r := &runner{st: st, o: o}
	var wg sync.WaitGroup
	for i := 0; i < o.Workers; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); r.worker(ctx, setReason, cancelRun) }()
	}
	wg.Wait()
	sum := Summary{Scanned: int(r.scanned.Load()), Failed: int(r.failed.Load()), Blocked: int(r.blocked.Load()),
		Released: int(r.released.Load()), Discovered: int(r.discovered.Load())}
	if v, ok := reason.Load().(string); ok {
		sum.StopReason = v
	} else if ctx.Err() != nil {
		sum.StopReason = "interrupted"
	} else {
		sum.StopReason = "empty"
	}
	return sum, r.firstErr()
}

type runner struct {
	st *Store
	o  RunOptions

	claimed, inflight                              atomic.Int64
	scanned, failed, blocked, released, discovered atomic.Int64
	mu                                             sync.Mutex
	err                                            error
}

func (r *runner) failPolicy() FailPolicy {
	return FailPolicy{BlockAfterDNS: r.o.DNSFailures, MaxRetry: r.o.RevisitMax}
}

func (r *runner) firstErr() error { r.mu.Lock(); defer r.mu.Unlock(); return r.err }
func (r *runner) fail(err error, cancel context.CancelFunc) {
	r.mu.Lock()
	if r.err == nil {
		r.err = err
	}
	r.mu.Unlock()
	cancel()
}

func (r *runner) worker(ctx context.Context, setReason func(string), cancel context.CancelFunc) {
	for {
		if ctx.Err() != nil {
			return
		}
		if r.o.ShouldStop() {
			setReason("kill switch")
			cancel()
			return
		}
		if r.o.Budget > 0 && r.claimed.Add(1) > int64(r.o.Budget) {
			r.claimed.Add(-1)
			setReason("budget")
			return
		}
		r.inflight.Add(1)
		job, err := r.st.Claim(ctx, r.o.Owner, r.o.LeaseTTL)
		if err != nil {
			r.inflight.Add(-1)
			if ctx.Err() == nil {
				r.fail(err, cancel)
			}
			return
		}
		if job.Domain == "" {
			r.claimed.Add(-1)
			if r.inflight.Add(-1) == 0 {
				return // nothing due and nobody who could add something
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(r.o.Idle):
			}
			continue
		}
		outcome, err := r.process(ctx, job)
		r.inflight.Add(-1)
		if err != nil {
			r.fail(err, cancel)
			return
		}
		switch outcome {
		case "done":
			r.scanned.Add(1)
		case "failed":
			r.failed.Add(1)
		case "blocked":
			r.blocked.Add(1)
			r.claimed.Add(-1) // not scanned: does not use the budget
		case "released":
			r.released.Add(1)
		}
		if r.o.Progress != nil && outcome != "" {
			r.o.Progress(job.Domain, outcome)
		}
	}
}

// process scans one claimed domain. The error is a storage error; a domain that cannot be
// scanned is a normal outcome, recorded as failed.
func (r *runner) process(ctx context.Context, job Job) (string, error) {
	d, o := job.Domain, r.o
	if o.Filter != nil {
		if v := o.Filter.Check(d); v.Blocked {
			return "blocked", r.st.Block(ctx, d, "category "+v.Category, v.List)
		}
	}
	sctx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()
	hbDone := make(chan struct{})
	var lost atomic.Bool
	go func() {
		defer close(hbDone)
		t := time.NewTicker(o.LeaseTTL / 3)
		defer t.Stop()
		for {
			select {
			case <-sctx.Done():
				return
			case <-t.C:
				if err := r.st.Heartbeat(sctx, d, o.Owner, o.LeaseTTL); errors.Is(err, ErrLeaseLost) {
					lost.Store(true)
					cancel()
					return
				}
			}
		}
	}()
	res, err := o.Scan(sctx, "https://"+d)
	if err != nil && strings.Contains(err.Error(), "no such host") && !strings.HasPrefix(d, "www.") {
		res, err = o.Scan(sctx, "https://www."+d)
	}
	cancel()
	<-hbDone
	if lost.Load() {
		return "", nil // someone else owns it now; write nothing
	}
	if ctx.Err() != nil { // stopping: give it back
		return "released", r.st.Release(context.WithoutCancel(ctx), d, o.Owner)
	}
	if err != nil {
		class, retry := classify(err, o.Revisit)
		return "failed", r.st.Fail(ctx, d, o.Owner, class, 0, retry, r.failPolicy())
	}
	if o.Filter != nil {
		for _, h := range []string{res.Target.Host, res.Target.RegistrableDomain} {
			if v := o.Filter.Check(h); h != "" && v.Blocked {
				return "blocked", r.st.Block(ctx, d, "redirects to "+h+", category "+v.Category, v.List)
			}
		}
	}
	// The crawler stores no personal contact details: the scan finds e-mail addresses and
	// telephone numbers on a page, and they are dropped here, before anything is saved.
	res.Contacts = []scan.Contact{}
	zipped, err := gzipJSON(res)
	if err != nil {
		return "failed", r.st.Fail(ctx, d, o.Owner, "result", 0, o.Revisit, r.failPolicy())
	}
	status := 0
	if len(res.Pages) > 0 {
		status = res.Pages[0].Status
	}
	found := r.discover(job, res)
	err = r.st.Complete(ctx, d, o.Owner, Result{Status: status, JSON: zipped, Hash: Hash(res), Discovered: found, Revisit: RevisitPolicy{Base: o.Revisit, Max: o.RevisitMax}})
	if errors.Is(err, ErrLeaseLost) {
		return "", nil
	}
	r.discovered.Add(int64(len(found)))
	return "done", err
}

// discover turns the external domains of a result into frontier entries, deepest cap first.
func (r *runner) discover(job Job, res *scan.Result) []Seed {
	o := r.o
	if job.Depth >= o.MaxDepth || o.MaxNewPerSite <= 0 {
		return nil
	}
	var ext []scan.Domain
	for _, dom := range res.Domains {
		if !dom.Internal {
			ext = append(ext, dom)
		}
	}
	sort.SliceStable(ext, func(i, j int) bool {
		if ext[i].Links != ext[j].Links {
			return ext[i].Links > ext[j].Links
		}
		return ext[i].Domain < ext[j].Domain
	})
	var out []Seed
	for _, dom := range ext {
		if len(out) >= o.MaxNewPerSite {
			break
		}
		sd := Seed{Host: dom.Domain, Source: "discovered", DiscoveredFrom: job.Domain, Depth: job.Depth + 1}
		if o.Filter != nil {
			if v := o.Filter.Check(dom.Domain); v.Blocked {
				sd.BlockedList, sd.BlockedReason = v.List, "category "+v.Category
			}
		}
		out = append(out, sd)
	}
	return out
}

// classify names a failure with a short stable word and says when to try again.
func classify(err error, revisit time.Duration) (string, time.Duration) {
	switch {
	case errors.Is(err, ErrRobots):
		return "robots", revisit
	case errors.Is(err, ErrRobotsUnavailable):
		return "robots_unavailable", time.Hour
	case errors.Is(err, ErrBackoff):
		return "backoff", time.Hour
	case errors.Is(err, fetch.ErrBlockedAddress):
		return "refused_address", 30 * 24 * time.Hour
	}
	reason := batch.Reason(err)
	switch {
	case strings.HasPrefix(reason, "dns: no such host"):
		return "dns", 7 * 24 * time.Hour
	case strings.HasPrefix(reason, "other:"):
		return "other", 24 * time.Hour // the message may hold data: it is not kept
	}
	return strings.NewReplacer(": ", "_", " ", "_").Replace(reason), 24 * time.Hour
}

// Hash is a fingerprint of what a scan found that matters: technologies with versions and
// the external domains linked. It leaves out times, headers and counts, so an unchanged
// site gives the same hash.
func Hash(res *scan.Result) string {
	var lines []string
	for _, t := range res.Technologies {
		lines = append(lines, "t|"+t.Slug+"|"+t.Version)
	}
	for _, d := range res.Domains {
		if !d.Internal {
			lines = append(lines, "d|"+d.Domain)
		}
	}
	sort.Strings(lines)
	sum := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return hex.EncodeToString(sum[:])
}

func gzipJSON(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(b); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
