// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package curate

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/matteoredaelli/open-web-fingerprints/internal/domain"
	"github.com/matteoredaelli/open-web-fingerprints/internal/repository"
)

// Correction describes a reviewer's change to one field of a rule.
type Correction struct {
	Field  string // "target", "pattern" or "version_extract" (empty: read no version)
	Value  string
	Reason string
}

// CorrectFingerprint changes one field of a rule and records who gave what: the value
// the source had, the new value, the reason and the time. The rule's test evidence is
// cleared (it was gathered on the old rule), and its health goes back to unknown. A
// rule can have one correction; correcting again replaces the new value but keeps the
// source's original. A refresh keeps the correction as long as the source still says
// what it said; see domain.Correction. Run it when no import is running.
func CorrectFingerprint(ctx context.Context, repo repository.Repository, id domain.FingerprintID, c Correction, now time.Time) (domain.Fingerprint, error) {
	if !slices.Contains(domain.CorrectableFields, c.Field) {
		return domain.Fingerprint{}, fmt.Errorf("curate: field must be one of %s", strings.Join(domain.CorrectableFields, ", "))
	}
	if strings.TrimSpace(c.Reason) == "" {
		return domain.Fingerprint{}, errors.New("curate: a reason is required")
	}
	if strings.TrimSpace(c.Value) == "" && c.Field != "version_extract" {
		return domain.Fingerprint{}, errors.New("curate: the new value is empty")
	}
	f, err := findFingerprint(ctx, repo, id)
	if err != nil {
		return domain.Fingerprint{}, err
	}
	field := fieldPtr(&f, c.Field)
	original := *field
	if f.Correction != nil && f.Correction.Field == c.Field {
		original = f.Correction.Original
	} else if f.Correction != nil {
		return domain.Fingerprint{}, fmt.Errorf("curate: %s already has a correction of %s; revert it first", id, f.Correction.Field)
	}
	if c.Value == *field {
		return domain.Fingerprint{}, errors.New("curate: the value is already what the rule has")
	}
	if c.Field == "pattern" && f.Operator == domain.OpRegex {
		if _, err := regexp.Compile(c.Value); err != nil {
			return domain.Fingerprint{}, fmt.Errorf("curate: the new pattern is not a valid regular expression: %w", err)
		}
	}
	*field = c.Value
	f.Correction = &domain.Correction{Field: c.Field, Original: original, Value: c.Value, Reason: strings.TrimSpace(c.Reason), At: now.UTC()}
	f.Validation = &domain.Validation{Health: "unknown"}
	if err := repo.Apply(ctx, repository.ChangeSet{Upsert: domain.Records{Fingerprints: []domain.Fingerprint{f}}}); err != nil {
		return domain.Fingerprint{}, fmt.Errorf("curate: %w", err)
	}
	return f, nil
}

// RevertFingerprint puts back the value the source gave and removes the correction.
// Test evidence is cleared for the same reason as when correcting.
func RevertFingerprint(ctx context.Context, repo repository.Repository, id domain.FingerprintID) (domain.Fingerprint, error) {
	f, err := findFingerprint(ctx, repo, id)
	if err != nil {
		return domain.Fingerprint{}, err
	}
	if f.Correction == nil {
		return domain.Fingerprint{}, fmt.Errorf("curate: %s has no correction", id)
	}
	*fieldPtr(&f, f.Correction.Field) = f.Correction.Original
	f.Correction = nil
	f.Validation = &domain.Validation{Health: "unknown"}
	if err := repo.Apply(ctx, repository.ChangeSet{Upsert: domain.Records{Fingerprints: []domain.Fingerprint{f}}}); err != nil {
		return domain.Fingerprint{}, fmt.Errorf("curate: %w", err)
	}
	return f, nil
}

func findFingerprint(ctx context.Context, repo repository.Repository, id domain.FingerprintID) (domain.Fingerprint, error) {
	all, err := repo.AllRecords(ctx)
	if err != nil {
		return domain.Fingerprint{}, fmt.Errorf("curate: %w", err)
	}
	for _, f := range all.Fingerprints {
		if f.ID == id {
			return f, nil
		}
	}
	return domain.Fingerprint{}, fmt.Errorf("curate: fingerprint %q: %w", id, ErrNotFound)
}

func fieldPtr(f *domain.Fingerprint, name string) *string {
	switch name {
	case "target":
		return &f.Target
	case "version_extract":
		return &f.VersionExtract
	}
	return &f.Pattern
}
