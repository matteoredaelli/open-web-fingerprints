// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package batch

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/matteoredaelli/open-web-fingerprints/scan"
)

// ScanFunc scans one target URL. The scanner's Scan, with its options, is wrapped in one.
type ScanFunc func(ctx context.Context, target string) (*scan.Result, error)

// ParseList reads a list of sites: one domain per line, or "rank,domain" as Tranco writes
// it. Blank lines and lines starting with # are ignored, a trailing CR is removed, names
// are lower-cased and a duplicate keeps its first place. A line that is not a plausible
// host name is counted and skipped, never scanned: the list may come from anywhere.
func ParseList(r io.Reader) (sites []Site, skipped int, err error) {
	seen := map[string]bool{}
	sc := bufio.NewScanner(io.LimitReader(r, 256<<20))
	n := 0
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		n++
		rank, dom := n, line
		if a, b, ok := strings.Cut(line, ","); ok {
			if v, err := strconv.Atoi(strings.TrimSpace(a)); err == nil {
				rank, dom = v, strings.TrimSpace(b)
			}
		}
		dom = strings.ToLower(strings.TrimSuffix(dom, "."))
		if !validHost(dom) {
			skipped++
			continue
		}
		if seen[dom] {
			continue
		}
		seen[dom] = true
		sites = append(sites, Site{Domain: dom, Rank: rank})
	}
	return sites, skipped, sc.Err()
}

func validHost(h string) bool {
	if len(h) < 3 || len(h) > 253 || !strings.Contains(h, ".") || net.ParseIP(h) != nil {
		return false
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return false
			}
		}
	}
	return true
}

// Reason shortens a scan error to a stable label, so failures can be counted.
func Reason(err error) string {
	s := err.Error()
	switch {
	case strings.Contains(s, "no such host"):
		return "dns: no such host"
	case strings.Contains(s, "lookup") && strings.Contains(s, "timeout"):
		return "dns: timeout"
	case strings.Contains(s, "not a public address"):
		return "refused: not a public address"
	case strings.Contains(s, "certificate"):
		return "tls: certificate"
	case strings.Contains(s, "connection refused"):
		return "connection refused"
	case strings.Contains(s, "connection reset"):
		return "connection reset"
	case errors.Is(err, context.DeadlineExceeded) || strings.Contains(s, "timeout") || strings.Contains(s, "deadline"):
		return "timeout"
	case strings.Contains(s, "not an HTML") || strings.Contains(s, "not a page"):
		return "not a web page"
	}
	return "other: " + short(s, 80)
}

func short(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// Options of a run.
type Options struct {
	// Workers is how many sites are scanned at once; Rate is how many scans may start per
	// second at most, whatever the number of workers. The list holds distinct sites, so
	// no host is asked twice at the same time.
	Workers int
	Rate    float64
	// Timeout bounds one site, the www. retry included.
	Timeout time.Duration
	// Limit stops after this many sites (0: all).
	Limit       int
	RetryFailed bool
	// Progress, if set, is called after each site.
	Progress func(done, total int, domain, outcome string)
	Now      func() time.Time
}

// Summary of a run.
type Summary struct {
	Scanned, Failed, Remaining int
	Interrupted                bool
}

// Run scans the sites still to do. A site is tried as https://domain and, when the name
// does not exist, as https://www.domain. Cancelling ctx stops cleanly: sites in flight
// stay pending and are done at the next run.
func Run(ctx context.Context, st *Store, scanFn ScanFunc, opt Options) (Summary, error) {
	if opt.Workers <= 0 {
		opt.Workers = 4
	}
	if opt.Rate <= 0 {
		opt.Rate = 2
	}
	if opt.Timeout <= 0 {
		opt.Timeout = 60 * time.Second
	}
	now := opt.Now
	if now == nil {
		now = time.Now
	}
	todo, err := st.Todo(ctx, opt.RetryFailed, opt.Limit)
	if err != nil {
		return Summary{}, err
	}
	var sum Summary
	var scanned, failed atomic.Int64
	jobs := make(chan Site)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var firstErr error
	var finished int
	interval := time.Duration(float64(time.Second) / opt.Rate)

	for i := 0; i < opt.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for s := range jobs {
				outcome, err := scanOne(ctx, st, scanFn, s, opt.Timeout, now)
				if ctx.Err() != nil {
					return // in flight when interrupted: stays pending
				}
				mu.Lock()
				finished++
				if err != nil && firstErr == nil {
					firstErr = err
				}
				n := finished
				mu.Unlock()
				if outcome == StateDone {
					scanned.Add(1)
				} else {
					failed.Add(1)
				}
				if opt.Progress != nil {
					opt.Progress(n, len(todo), s.Domain, outcome)
				}
			}
		}()
	}
	tick := time.NewTicker(interval)
	defer tick.Stop()
feed:
	for i, s := range todo {
		if i > 0 {
			select {
			case <-tick.C:
			case <-ctx.Done():
				break feed
			}
		}
		select {
		case jobs <- s:
		case <-ctx.Done():
			break feed
		}
	}
	close(jobs)
	wg.Wait()
	sum.Scanned, sum.Failed = int(scanned.Load()), int(failed.Load())
	sum.Interrupted = ctx.Err() != nil
	sum.Remaining = len(todo) - sum.Scanned - sum.Failed
	if firstErr != nil {
		return sum, firstErr
	}
	return sum, nil
}

// scanOne scans a site and records the outcome. The error is a storage error: a site
// that cannot be scanned is a normal outcome, recorded as failed.
func scanOne(ctx context.Context, st *Store, scanFn ScanFunc, s Site, timeout time.Duration, now func() time.Time) (string, error) {
	sctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	res, err := scanFn(sctx, "https://"+s.Domain)
	if err != nil && strings.Contains(err.Error(), "no such host") && !strings.HasPrefix(s.Domain, "www.") {
		res, err = scanFn(sctx, "https://www."+s.Domain)
	}
	if ctx.Err() != nil {
		return "", nil
	}
	if err != nil {
		return StateFailed, st.SaveFailed(ctx, s.Domain, Reason(err), now())
	}
	b, err := json.Marshal(res)
	if err != nil {
		return StateFailed, st.SaveFailed(ctx, s.Domain, "result: "+err.Error(), now())
	}
	status := 0
	if len(res.Pages) > 0 {
		status = res.Pages[0].Status
	}
	return StateDone, st.SaveDone(ctx, s.Domain, status, b, now())
}

// Describe is a one-line summary of the counts.
func (c Counts) Describe() string {
	return fmt.Sprintf("%d sites: %d done, %d failed, %d pending", c.Total, c.Done, c.Failed, c.Pending)
}
