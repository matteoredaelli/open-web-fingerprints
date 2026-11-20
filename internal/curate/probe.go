// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package curate

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/matteoredaelli/open-web-fingerprints/internal/domain"
	"github.com/matteoredaelli/open-web-fingerprints/internal/repository"
)

// Probe review decisions.
const (
	ProbeApproved = "approved"
	ProbeRejected = "rejected"
	ProbePending  = "pending"
)

// ProbeReview is a decision about the probes that request some paths.
type ProbeReview struct {
	// Paths are the probe paths the decision covers; every rule that probes one of them is
	// affected (rules that share a path share a request).
	Paths    []string
	Decision string // approved, rejected or pending
	Note     string // the reviewer's basis; required for approved and rejected
}

// ProbeReviewResult counts what a decision changed.
type ProbeReviewResult struct {
	Rules   int            // rules whose review changed
	Paths   map[string]int // rules per path covered by the decision
	Updated []domain.Fingerprint
}

// SafePath reports whether a probe path is acceptable to approve: an absolute path on the
// target's own host, short, with no way to reach another host or to inject a header. It is
// checked again by the scanner before every request; this is the reviewer-side check.
func SafePath(p string) error {
	switch {
	case p == "" || p[0] != '/':
		return errors.New("a probe path must start with /")
	case strings.HasPrefix(p, "//"):
		return errors.New("a path that starts with // would name another host")
	case len(p) > 512:
		return errors.New("a path of more than 512 characters")
	case strings.ContainsAny(p, "\r\n\x00 \t\\"):
		return errors.New("a path with a control character, space or backslash")
	case strings.Contains(p, "://"):
		return errors.New("a path that contains a URL")
	}
	return nil
}

// ReviewProbes records a reviewer's decision on probes. Approving makes the rules active (a
// probe cannot be active before it is approved); rejecting or resetting makes them drafts
// again. Only GET probes can be approved: that is the only method the scanner sends. Probe
// paths that are not acceptable (see SafePath) cannot be approved. Run it when no import is
// running.
func ReviewProbes(ctx context.Context, repo repository.Repository, r ProbeReview, now time.Time) (ProbeReviewResult, error) {
	res := ProbeReviewResult{Paths: map[string]int{}}
	switch r.Decision {
	case ProbeApproved, ProbeRejected, ProbePending:
	default:
		return res, fmt.Errorf("curate: decision must be %s, %s or %s", ProbeApproved, ProbeRejected, ProbePending)
	}
	if r.Decision != ProbePending && strings.TrimSpace(r.Note) == "" {
		return res, errors.New("curate: a note naming the basis of the decision is required")
	}
	if len(r.Paths) == 0 {
		return res, errors.New("curate: no probe path given")
	}
	want := map[string]bool{}
	for _, p := range r.Paths {
		if r.Decision == ProbeApproved {
			if err := SafePath(p); err != nil {
				return res, fmt.Errorf("curate: %q: %w", p, err)
			}
		}
		want[p] = true
	}
	all, err := repo.AllRecords(ctx)
	if err != nil {
		return res, fmt.Errorf("curate: %w", err)
	}
	var upsert []domain.Fingerprint
	found := map[string]bool{}
	for _, f := range all.Fingerprints {
		if f.Probe == nil || !want[f.Probe.Path] {
			continue
		}
		found[f.Probe.Path] = true
		if r.Decision == ProbeApproved && f.Probe.Method != "GET" {
			return res, fmt.Errorf("curate: %q is probed with %s; only GET can be approved", f.Probe.Path, f.Probe.Method)
		}
		if f.Probe.SafetyReview == r.Decision && f.Probe.ReviewNote == strings.TrimSpace(r.Note) {
			continue
		}
		p := *f.Probe
		p.SafetyReview = r.Decision
		if r.Decision == ProbePending {
			p.ReviewedAt, p.ReviewNote = nil, ""
		} else {
			t := now.UTC()
			p.ReviewedAt, p.ReviewNote = &t, strings.TrimSpace(r.Note)
		}
		f.Probe = &p
		if r.Decision == ProbeApproved {
			f.Status = domain.StatusActive
		} else if f.Status == domain.StatusActive {
			f.Status = domain.StatusDraft
		}
		upsert = append(upsert, f)
		res.Paths[p.Path]++
	}
	for p := range want {
		if !found[p] {
			return res, fmt.Errorf("curate: no rule probes %q", p)
		}
	}
	res.Rules, res.Updated = len(upsert), upsert
	if len(upsert) == 0 {
		return res, nil
	}
	if err := repo.Apply(ctx, repository.ChangeSet{Upsert: domain.Records{Fingerprints: upsert}}); err != nil {
		return res, fmt.Errorf("curate: %w", err)
	}
	return res, nil
}
