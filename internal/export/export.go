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
	"time"

	"github.com/matteoredaelli/open-web-fingerprints/internal/domain"
	"github.com/matteoredaelli/open-web-fingerprints/internal/repository"
	"github.com/matteoredaelli/open-web-fingerprints/schemas"
)

// SchemaVersion is the version of the export format written by this build.
const SchemaVersion = "0.1.0"

// SchemaURL identifies the schema in exported documents.
const SchemaURL = "https://github.com/matteoredaelli/open-web-fingerprints/schemas/registry.schema.json"

// Build assembles the registry document. Output is sorted so that exports of
// the same data are byte-identical apart from generated_at.
func Build(ctx context.Context, repo repository.Repository, now time.Time) (domain.Registry, error) {
	srcs, err := repo.Sources(ctx)
	if err != nil {
		return domain.Registry{}, fmt.Errorf("export: sources: %w", err)
	}
	recs, err := repo.AllRecords(ctx)
	if err != nil {
		return domain.Registry{}, fmt.Errorf("export: records: %w", err)
	}
	now = now.UTC()
	reg := domain.Registry{
		Schema: SchemaURL, SchemaVersion: SchemaVersion, GeneratedAt: &now,
		Sources: srcs, Vendors: recs.Vendors, Categories: recs.Categories, Technologies: recs.Technologies,
		Fingerprints: recs.Fingerprints, Relationships: recs.Relationships,
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
	for _, s := range srcs {
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
