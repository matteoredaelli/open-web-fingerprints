// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

// Package export builds the public JSON registry document from a repository
// and checks it against the published JSON Schema.
package export

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/matteoredaelli/open-web-fingerprints/internal/domain"
	"github.com/matteoredaelli/open-web-fingerprints/internal/repository"
	"github.com/matteoredaelli/open-web-fingerprints/schemas"
)

// SchemaVersion is the version of the export format written by this build.
const SchemaVersion = "0.1.0"

// SchemaURL identifies the schema in exported documents.
const SchemaURL = "https://github.com/matteoredaelli/open-web-fingerprints/schemas/registry.schema.json"

// Options control what an export may contain.
type Options struct {
	// IncludeUnreviewed lets the export contain data from sources whose
	// redistribution status is "unreviewed". Sources marked "no" are never
	// exported.
	IncludeUnreviewed bool
}

// BlockedError means the export was refused because some sources have
// records but their redistribution has not been reviewed.
type BlockedError struct {
	Sources []string // slugs
}

func (e *BlockedError) Error() string {
	return fmt.Sprintf("export refused: redistribution of %s has not been reviewed "+
		"(record the decision with `owf source review`, or pass --include-unreviewed for internal use)",
		strings.Join(e.Sources, ", "))
}

// Build assembles the registry document. Output is sorted so that exports of
// the same data are byte-identical apart from generated_at.
//
// Data is only exported if every source that contributed to a record allows
// it: "yes", or "unreviewed" with IncludeUnreviewed. A record that any
// disallowed source contributed to is left out, together with whatever depends
// on it, and references to left-out records are removed from what remains.
func Build(ctx context.Context, repo repository.Repository, now time.Time, opt Options) (domain.Registry, error) {
	srcs, err := repo.Sources(ctx)
	if err != nil {
		return domain.Registry{}, fmt.Errorf("export: sources: %w", err)
	}
	recs, err := repo.AllRecords(ctx)
	if err != nil {
		return domain.Registry{}, fmt.Errorf("export: records: %w", err)
	}
	f, err := filter(srcs, recs, opt)
	if err != nil {
		return domain.Registry{}, err
	}
	now = now.UTC()
	reg := domain.Registry{
		Schema: SchemaURL, SchemaVersion: SchemaVersion, GeneratedAt: &now,
		Sources: f.sources, Vendors: f.recs.Vendors, Categories: f.recs.Categories,
		Technologies: f.recs.Technologies, Fingerprints: f.recs.Fingerprints,
		Relationships: f.recs.Relationships, Export: f.info,
	}
	if reg.Sources == nil {
		reg.Sources = []domain.Source{}
	}
	if reg.Technologies == nil {
		reg.Technologies = []domain.Technology{}
	}
	if reg.Fingerprints == nil {
		reg.Fingerprints = []domain.Fingerprint{}
	}
	for _, s := range reg.Sources {
		snaps, err := repo.Snapshots(ctx, s.ID)
		if err != nil {
			return domain.Registry{}, fmt.Errorf("export: snapshots: %w", err)
		}
		reg.Snapshots = append(reg.Snapshots, snaps...)
	}
	sort.SliceStable(reg.Snapshots, func(i, j int) bool {
		a, b := reg.Snapshots[i], reg.Snapshots[j]
		if a.SourceID != b.SourceID {
			return a.SourceID < b.SourceID
		}
		return a.RetrievedAt.Before(b.RetrievedAt)
	})
	return reg, nil
}

// JSON renders the registry as indented JSON and validates it against the
// schema. Invalid documents are never returned.
func JSON(reg domain.Registry) ([]byte, error) {
	b, err := json.MarshalIndent(reg, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("export: marshal: %w", err)
	}
	if err := schemas.ValidateRegistry(b); err != nil {
		return nil, fmt.Errorf("export: document violates schema: %w", err)
	}
	return append(b, '\n'), nil
}
