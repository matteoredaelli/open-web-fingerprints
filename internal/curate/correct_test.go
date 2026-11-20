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

func repoWithRule(t *testing.T, f domain.Fingerprint) *memory.Repo {
	t.Helper()
	r := memory.New()
	if err := r.Apply(context.Background(), repository.ChangeSet{Upsert: domain.Records{Fingerprints: []domain.Fingerprint{f}}}); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestCorrectAndRevert(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	r := repoWithRule(t, domain.Fingerprint{
		ID: "fp_1", Observation: "cookie", Target: `connect\.sid`, Operator: domain.OpExists, Status: domain.StatusActive,
		Validation: &domain.Validation{Health: "ok"},
	})
	f, err := CorrectFingerprint(ctx, r, "fp_1", Correction{Field: "target", Value: "connect.sid", Reason: " cookie names are literal "}, now)
	if err != nil {
		t.Fatal(err)
	}
	c := f.Correction
	if f.Target != "connect.sid" || c.Original != `connect\.sid` || c.Value != "connect.sid" || c.Reason != "cookie names are literal" || !c.At.Equal(now) {
		t.Errorf("%+v", f)
	}
	if f.Validation.Health != "unknown" {
		t.Errorf("evidence belongs to the old rule: %+v", f.Validation)
	}

	// Correcting again keeps the source's value as the original.
	f, err = CorrectFingerprint(ctx, r, "fp_1", Correction{Field: "target", Value: "connect.sid2", Reason: "again"}, now)
	if err != nil || f.Correction.Original != `connect\.sid` || f.Target != "connect.sid2" {
		t.Fatalf("%+v %v", f, err)
	}
	// Another field cannot be corrected on top; revert first.
	if _, err = CorrectFingerprint(ctx, r, "fp_1", Correction{Field: "pattern", Value: "x", Reason: "r"}, now); err == nil || !strings.Contains(err.Error(), "revert") {
		t.Errorf("two fields at once: %v", err)
	}

	f, err = RevertFingerprint(ctx, r, "fp_1")
	if err != nil || f.Target != `connect\.sid` || f.Correction != nil {
		t.Fatalf("%+v %v", f, err)
	}
	all, _ := r.AllRecords(ctx)
	if all.Fingerprints[0].Target != `connect\.sid` || all.Fingerprints[0].Correction != nil {
		t.Errorf("stored: %+v", all.Fingerprints[0])
	}
	if _, err = RevertFingerprint(ctx, r, "fp_1"); err == nil {
		t.Error("nothing to revert")
	}
}

func TestCorrectErrors(t *testing.T) {
	ctx := context.Background()
	r := repoWithRule(t, domain.Fingerprint{ID: "fp_1", Observation: "html", Operator: domain.OpRegex, Pattern: "abc", Status: domain.StatusActive})
	now := time.Now()
	for name, tc := range map[string]struct {
		id   domain.FingerprintID
		c    Correction
		want string
	}{
		"unknown field": {"fp_1", Correction{Field: "confidence", Value: "x", Reason: "r"}, "field must be"},
		"no reason":     {"fp_1", Correction{Field: "pattern", Value: "x"}, "reason"},
		"blank reason":  {"fp_1", Correction{Field: "pattern", Value: "x", Reason: "  "}, "reason"},
		"empty value":   {"fp_1", Correction{Field: "pattern", Value: " ", Reason: "r"}, "empty"},
		"same value":    {"fp_1", Correction{Field: "pattern", Value: "abc", Reason: "r"}, "already"},
		"bad regex":     {"fp_1", Correction{Field: "pattern", Value: "(", Reason: "r"}, "regular expression"},
		"unknown rule":  {"fp_9", Correction{Field: "pattern", Value: "x", Reason: "r"}, "not found"},
	} {
		if _, err := CorrectFingerprint(ctx, r, tc.id, tc.c, now); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	all, _ := r.AllRecords(ctx)
	if all.Fingerprints[0].Pattern != "abc" || all.Fingerprints[0].Correction != nil {
		t.Error("a refused correction changes nothing")
	}
}
