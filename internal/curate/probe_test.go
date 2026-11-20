// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package curate

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/matteoredaelli/open-web-fingerprints/internal/domain"
	"github.com/matteoredaelli/open-web-fingerprints/internal/repository"
	"github.com/matteoredaelli/open-web-fingerprints/internal/repository/memory"
)

func probeRule(id, path, method string) domain.Fingerprint {
	return domain.Fingerprint{
		ID: domain.FingerprintID(id), Observation: domain.ObsProbeResponse, Target: "status", Operator: domain.OpEquals, Pattern: "200",
		Status: domain.StatusDraft, Probe: &domain.Probe{Method: method, Path: path, RateLimitClass: "low", SafetyReview: ProbePending},
	}
}

func probeRepo(t *testing.T) *memory.Repo {
	t.Helper()
	r := memory.New()
	err := r.Apply(context.Background(), repository.ChangeSet{Upsert: domain.Records{Fingerprints: []domain.Fingerprint{
		probeRule("fp_1", "/robots.txt", "GET"), probeRule("fp_2", "/robots.txt", "GET"), probeRule("fp_3", "/admin", "GET"),
		probeRule("fp_4", "/opts", "OPTIONS"),
	}}})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestReviewProbes(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	r := probeRepo(t)
	res, err := ReviewProbes(ctx, r, ProbeReview{Paths: []string{"/robots.txt"}, Decision: ProbeApproved, Note: " static file, read-only "}, now)
	if err != nil || res.Rules != 2 || res.Paths["/robots.txt"] != 2 {
		t.Fatalf("%+v %v", res, err)
	}
	all, _ := r.AllRecords(ctx)
	by := map[domain.FingerprintID]domain.Fingerprint{}
	for _, f := range all.Fingerprints {
		by[f.ID] = f
	}
	f := by["fp_1"]
	if f.Probe.SafetyReview != ProbeApproved || f.Status != domain.StatusActive || f.Probe.ReviewNote != "static file, read-only" || !f.Probe.ReviewedAt.Equal(now) {
		t.Errorf("approved: %+v %+v", f, f.Probe)
	}
	if by["fp_3"].Probe.SafetyReview != ProbePending || by["fp_3"].Status != domain.StatusDraft {
		t.Error("other paths are untouched")
	}
	// The same decision again changes nothing.
	if res, _ := ReviewProbes(ctx, r, ProbeReview{Paths: []string{"/robots.txt"}, Decision: ProbeApproved, Note: "static file, read-only"}, now); res.Rules != 0 {
		t.Errorf("idempotent: %+v", res)
	}
	// Rejecting makes them drafts again; resetting clears the record.
	if res, err := ReviewProbes(ctx, r, ProbeReview{Paths: []string{"/robots.txt"}, Decision: ProbeRejected, Note: "changed my mind"}, now); err != nil || res.Rules != 2 {
		t.Fatalf("%+v %v", res, err)
	}
	all, _ = r.AllRecords(ctx)
	for _, f := range all.Fingerprints {
		if f.ID == "fp_1" && (f.Status != domain.StatusDraft || f.Probe.SafetyReview != ProbeRejected) {
			t.Errorf("rejected: %+v", f)
		}
	}
	if _, err := ReviewProbes(ctx, r, ProbeReview{Paths: []string{"/robots.txt"}, Decision: ProbePending}, now); err != nil {
		t.Fatal(err)
	}
	all, _ = r.AllRecords(ctx)
	for _, f := range all.Fingerprints {
		if f.ID == "fp_1" && (f.Probe.ReviewedAt != nil || f.Probe.ReviewNote != "") {
			t.Errorf("reset: %+v", f.Probe)
		}
	}
}

func TestReviewProbesRefusals(t *testing.T) {
	ctx := context.Background()
	r := probeRepo(t)
	for name, tc := range map[string]struct {
		rv   ProbeReview
		want string
	}{
		"no note":       {ProbeReview{Paths: []string{"/admin"}, Decision: ProbeApproved}, "note"},
		"bad decision":  {ProbeReview{Paths: []string{"/admin"}, Decision: "maybe", Note: "n"}, "decision"},
		"no path":       {ProbeReview{Decision: ProbeApproved, Note: "n"}, "no probe path"},
		"unknown path":  {ProbeReview{Paths: []string{"/nope"}, Decision: ProbeRejected, Note: "n"}, "no rule probes"},
		"other host":    {ProbeReview{Paths: []string{"//evil.example/x"}, Decision: ProbeApproved, Note: "n"}, "another host"},
		"not absolute":  {ProbeReview{Paths: []string{"admin"}, Decision: ProbeApproved, Note: "n"}, "start with /"},
		"header inject": {ProbeReview{Paths: []string{"/a\r\nX: y"}, Decision: ProbeApproved, Note: "n"}, "control character"},
		"a url":         {ProbeReview{Paths: []string{"/redirect?u=http://x"}, Decision: ProbeApproved, Note: "n"}, "contains a URL"},
		"not GET":       {ProbeReview{Paths: []string{"/opts"}, Decision: ProbeApproved, Note: "n"}, "only GET"},
	} {
		if _, err := ReviewProbes(ctx, r, tc.rv, time.Now()); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	all, _ := r.AllRecords(ctx)
	for _, f := range all.Fingerprints {
		if f.Probe.SafetyReview != ProbePending {
			t.Errorf("a refused decision changes nothing: %+v", f.Probe)
		}
	}
	// One bad path in a batch refuses the batch.
	if _, err := ReviewProbes(ctx, r, ProbeReview{Paths: []string{"/admin", "admin"}, Decision: ProbeApproved, Note: "n"}, time.Now()); err == nil {
		t.Error("a batch with a bad path is refused whole")
	}
	all, _ = r.AllRecords(ctx)
	for _, f := range all.Fingerprints {
		if f.ID == "fp_3" && f.Probe.SafetyReview != ProbePending {
			t.Error("/admin must not have been approved by a refused batch")
		}
	}
}
