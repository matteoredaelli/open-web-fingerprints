// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

// Package repository defines storage for canonical records. It is
// independent of SQLite or any other backend.
package repository

import (
	"context"

	"github.com/matteoredaelli/open-web-fingerprints/internal/domain"
)

// Repository stores canonical records, sources and snapshots.
// Implementations must make Apply atomic.
type Repository interface {
	// Allocate returns the canonical ID for an upstream record, creating it
	// on first use. It satisfies normalizer.IDAllocator.
	Allocate(kind domain.Kind, sourceID, key string) (string, error)

	// GetSourceBySlug returns the source with the given slug, if any.
	GetSourceBySlug(ctx context.Context, slug string) (domain.Source, bool, error)
	// UpsertSource inserts or updates a source by ID.
	UpsertSource(ctx context.Context, s domain.Source) error
	// PutSnapshot records a snapshot. Putting the same revision with the
	// same checksum again is a no-op. The same revision with a different
	// checksum is an error.
	PutSnapshot(ctx context.Context, s domain.Snapshot) error
	// Snapshots lists the snapshots of a source, oldest first.
	Snapshots(ctx context.Context, id domain.SourceID) ([]domain.Snapshot, error)

	// SourceRecords returns records that carry provenance from the source,
	// including provenance entries of other sources.
	SourceRecords(ctx context.Context, id domain.SourceID) (domain.Records, error)
	// AllRecords returns every canonical record.
	AllRecords(ctx context.Context) (domain.Records, error)

	// Apply atomically stores a change set.
	Apply(ctx context.Context, cs ChangeSet) error
}

// ChangeSet is a reviewable set of changes produced by one import.
type ChangeSet struct {
	// Upsert holds complete records, replacing any record with the same ID.
	Upsert domain.Records
	// RemovedUpstream lists records whose provenance from SourceID must be
	// marked "removed_upstream". Records are never deleted.
	SourceID        domain.SourceID
	RemovedUpstream RecordIDs
}

// RecordIDs lists record IDs by kind.
type RecordIDs struct {
	Categories    []string
	Technologies  []string
	Fingerprints  []string
	Relationships []string
}

// Len returns the total number of IDs.
func (r RecordIDs) Len() int {
	return len(r.Categories) + len(r.Technologies) + len(r.Fingerprints) + len(r.Relationships)
}
