// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package batch

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/matteoredaelli/open-web-fingerprints/scan"
)

func TestParseList(t *testing.T) {
	in := "# list\r\n1,Google.com\r\n2,cloudflare.com.\r\n\r\n3,google.com\r\nlocalhost\r\n4,10.0.0.1\r\n5,bad_name.com\r\n6,-x.com\r\nexample.org\r\n"
	got, skipped, err := ParseList(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, s := range got {
		names = append(names, s.Domain)
	}
	if strings.Join(names, ",") != "google.com,cloudflare.com,example.org" || skipped != 4 {
		t.Errorf("%v skipped %d", names, skipped)
	}
	if got[0].Rank != 1 || got[1].Rank != 2 {
		t.Errorf("ranks %+v", got)
	}
}

func TestReason(t *testing.T) {
	for in, want := range map[string]string{
		`dial tcp: lookup x.example: no such host`:           "dns: no such host",
		`lookup x: i/o timeout`:                              "dns: timeout",
		`tls: failed to verify certificate: x509`:            "tls: certificate",
		`10.0.0.1 address not allowed: not a public address`: "refused: not a public address",
	} {
		if got := Reason(errors.New(in)); got != want {
			t.Errorf("%q -> %q", in, got)
		}
	}
	if Reason(context.DeadlineExceeded) != "timeout" {
		t.Error("deadline")
	}
}

func fake(calls *[]string, fail map[string]string, slow time.Duration) ScanFunc {
	var mu sync.Mutex
	return func(ctx context.Context, target string) (*scan.Result, error) {
		mu.Lock()
		*calls = append(*calls, target)
		mu.Unlock()
		if slow > 0 {
			select {
			case <-time.After(slow):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		for k, v := range fail {
			if target == k {
				return nil, errors.New(v)
			}
		}
		return &scan.Result{SchemaVersion: scan.SchemaVersion, Target: scan.Target{URL: target}, Pages: []scan.Page{{Status: 200}}}, nil
	}
}

func open(t *testing.T) *Store {
	t.Helper()
	st, err := Open(context.Background(), filepath.Join(t.TempDir(), "b.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestRunStoresResumesAndRetriesWww(t *testing.T) {
	ctx := context.Background()
	st := open(t)
	if n, _ := st.Add(ctx, []Site{{"a.example", 1}, {"b.example", 2}, {"c.example", 3}}); n != 3 {
		t.Fatal(n)
	}
	if n, _ := st.Add(ctx, []Site{{"a.example", 9}}); n != 0 {
		t.Error("a site already listed is not added again")
	}
	var calls []string
	f := fake(&calls, map[string]string{
		"https://b.example":     "dial tcp: lookup b.example: no such host",
		"https://www.b.example": "dial tcp: lookup www.b.example: no such host",
		"https://c.example":     "dial tcp: lookup c.example: no such host",
	}, 0)
	sum, err := Run(ctx, st, f, Options{Workers: 1, Rate: 1000})
	if err != nil || sum.Scanned != 2 || sum.Failed != 1 {
		t.Fatalf("%+v %v", sum, err)
	}
	c, _ := st.Counts(ctx)
	if c.Done != 2 || c.Failed != 1 || c.ByStatus[200] != 2 || c.ByError["dns: no such host"] != 1 {
		t.Errorf("%+v", c)
	}
	// c.example answered on www.
	b, err := st.Result(ctx, "c.example")
	if err != nil || !strings.Contains(string(b), "https://www.c.example") {
		t.Errorf("www retry: %v %s", err, b)
	}
	// A second run has nothing to do; --retry-failed tries the failed one again.
	calls = nil
	if sum, _ := Run(ctx, st, f, Options{Workers: 1, Rate: 1000}); sum.Scanned+sum.Failed != 0 || len(calls) != 0 {
		t.Errorf("resume must skip finished sites: %+v %v", sum, calls)
	}
	if sum, _ := Run(ctx, st, f, Options{Workers: 1, Rate: 1000, RetryFailed: true}); sum.Failed != 1 {
		t.Errorf("retry: %+v", sum)
	}
}

func TestInterruptedSitesStayPending(t *testing.T) {
	st := open(t)
	_, _ = st.Add(context.Background(), []Site{{"a.example", 1}, {"b.example", 2}, {"c.example", 3}})
	ctx, cancel := context.WithCancel(context.Background())
	var calls []string
	f := fake(&calls, nil, 200*time.Millisecond)
	go func() { time.Sleep(50 * time.Millisecond); cancel() }()
	sum, _ := Run(ctx, st, f, Options{Workers: 1, Rate: 1000})
	if !sum.Interrupted {
		t.Error("interrupted")
	}
	c, _ := st.Counts(context.Background())
	if c.Pending != 3 || c.Done != 0 || c.Failed != 0 {
		t.Errorf("an interrupted site must not be recorded as failed: %+v", c)
	}
}

func TestLimitAndRateOrder(t *testing.T) {
	st := open(t)
	ctx := context.Background()
	_, _ = st.Add(ctx, []Site{{"c.example", 3}, {"a.example", 1}, {"b.example", 2}})
	var calls []string
	if _, err := Run(ctx, st, fake(&calls, nil, 0), Options{Workers: 1, Rate: 1000, Limit: 2}); err != nil {
		t.Fatal(err)
	}
	if strings.Join(calls, " ") != "https://a.example https://b.example" {
		t.Errorf("rank order and limit: %v", calls)
	}
	start := time.Now()
	st2 := open(t)
	_, _ = st2.Add(ctx, []Site{{"a.example", 1}, {"b.example", 2}, {"c.example", 3}})
	var c2 []string
	_, _ = Run(ctx, st2, fake(&c2, nil, 0), Options{Workers: 3, Rate: 20})
	if time.Since(start) < 90*time.Millisecond {
		t.Errorf("the rate limit (20/s: 2 gaps of 50 ms) was not applied: %v", time.Since(start))
	}
}
