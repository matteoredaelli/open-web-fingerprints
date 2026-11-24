// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

// Package dnslimit caps the DNS queries in flight in the whole process. A batch scans several
// sites at once and each scan with --checks asks dozens of names (SPF tree, DKIM selectors,
// CAA, DNSSEC); without a cap a home router used as the resolver is overwhelmed and every
// lookup, the site's own included, times out.
package dnslimit

import "context"

// Default is the number of queries allowed at once.
const Default = 6

var sem = make(chan struct{}, Default)

// Acquire waits for a free slot and returns the function that frees it. It returns an error
// if ctx ends first.
func Acquire(ctx context.Context) (release func(), err error) {
	select {
	case sem <- struct{}{}:
		return func() { <-sem }, nil
	case <-ctx.Done():
		return func() {}, ctx.Err()
	}
}
