// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package bot

import (
	"hash/fnv"
	"math"
	"time"
)

// RevisitPolicy decides when a scanned domain comes back. A site that does not change is
// visited less and less often; one that changes is visited sooner. Jitter spreads the visits
// so that domains found together are not all due on the same day.
type RevisitPolicy struct {
	Base time.Duration // first revisit (default 30 days)
	Max  time.Duration // longest revisit (default 180 days)
	Min  time.Duration // shortest revisit (default 24 hours)
	// Jitter is the fraction the interval may be moved by, up or down (default 0.1).
	Jitter float64
}

func (p RevisitPolicy) withDefaults() RevisitPolicy {
	if p.Base <= 0 {
		p.Base = 30 * 24 * time.Hour
	}
	if p.Max <= 0 {
		p.Max = 180 * 24 * time.Hour
	}
	if p.Min <= 0 {
		p.Min = 24 * time.Hour
	}
	if p.Jitter <= 0 || p.Jitter >= 1 {
		p.Jitter = 0.1
	}
	if p.Max < p.Base {
		p.Max = p.Base
	}
	return p
}

// Next returns the time until the next visit.
//
//   - first: no earlier result to compare with: Base.
//   - changed: the result differs from the last one: half of Base.
//   - otherwise stable is the number of scans in a row that found the same thing, and the
//     interval doubles with each: Base, 2 Base, 4 Base... up to Max.
//
// unit is a number in [-1, 1] that places the interval inside the jitter band. The result
// is kept between Min and Max.
func (p RevisitPolicy) Next(stable int, changed, first bool, unit float64) time.Duration {
	p = p.withDefaults()
	d := float64(p.Base)
	switch {
	case first:
	case changed:
		d /= 2
	default:
		d *= math.Pow(2, float64(min(stable, 20)))
	}
	d *= 1 + p.Jitter*math.Max(-1, math.Min(1, unit))
	return max(p.Min, min(p.Max, time.Duration(d)))
}

// jitterUnit gives a stable pseudo-random number in [-1, 1] for a domain and a moment.
func jitterUnit(domain, stamp string) float64 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(domain + "|" + stamp))
	return float64(h.Sum32())/float64(math.MaxUint32)*2 - 1
}

// FailPolicy decides what a failure costs.
type FailPolicy struct {
	// BlockAfterDNS blocks a domain for good after this many DNS failures in a row
	// ("no such host"); 0 never blocks.
	BlockAfterDNS int
	// MaxRetry caps the wait before a retry, which doubles with each failure in a row
	// (default 180 days).
	MaxRetry time.Duration
}

// DNSList is the name recorded for domains blocked after repeated DNS failures.
const DNSList = "dns"

// retryAfter doubles retryIn for each failure in a row after the first, up to max.
func retryDelay(retryIn time.Duration, streak int, max time.Duration) time.Duration {
	d := retryIn
	for i := 1; i < streak && d < max; i++ {
		d *= 2
	}
	if d > max {
		d = max
	}
	return d
}
