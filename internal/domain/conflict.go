// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package domain

import "time"

// ConflictID identifies a stored conflict.
type ConflictID string

// KindConflict is the ID prefix of conflicts.
const KindConflict Kind = "cfl"

// Conflict kinds.
const (
	ConflictIdentityCandidate = "identity_candidate"
	ConflictCategoryCandidate = "category_candidate"
)

// Conflict states.
const (
	ConflictOpen     = "open"
	ConflictResolved = "resolved"
	ConflictIgnored  = "ignored"
)

// Conflict is something a reviewer must look at. It never changes canonical
// records by itself.
type Conflict struct {
	ID         ConflictID        `json:"id"`
	Kind       string            `json:"kind"`
	State      string            `json:"state"`
	RecordIDs  []string          `json:"record_ids"`
	SourceIDs  []SourceID        `json:"source_ids"`
	Detail     map[string]string `json:"detail"`
	Resolution string            `json:"resolution,omitempty"`
	CreatedAt  time.Time         `json:"created_at"`
	UpdatedAt  time.Time         `json:"updated_at"`
}

// Alias maps the ID of a record that was merged away to the surviving record.
// Later imports translate the old ID, so a merge is never undone by a
// refresh.
type Alias struct {
	Kind  Kind   `json:"kind"`
	OldID string `json:"old_id"`
	NewID string `json:"new_id"`
}

// Additional conflict kinds raised by merges.
const (
	ConflictMetadata   = "metadata_conflict"
	ConflictConfidence = "confidence_disagreement"
)
