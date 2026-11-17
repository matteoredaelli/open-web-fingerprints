// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

// Package domain holds the canonical, source-independent registry model.
// Its JSON form is the public contract described by schemas/registry.schema.json.
package domain

import (
	"fmt"

	"github.com/google/uuid"
)

// Kind is the prefix of a canonical ID.
type Kind string

// ID kinds.
const (
	KindSource       Kind = "src"
	KindVendor       Kind = "vnd"
	KindCategory     Kind = "cat"
	KindTechnology   Kind = "tech"
	KindFingerprint  Kind = "fp"
	KindGroup        Kind = "fpg"
	KindRelationship Kind = "rel"
)

// Typed IDs. They are plain strings in JSON.
type (
	SourceID       string
	VendorID       string
	CategoryID     string
	TechnologyID   string
	FingerprintID  string
	GroupID        string
	RelationshipID string
)

// NewID returns a new time-ordered ID such as "tech_<uuidv7>".
func NewID(k Kind) (string, error) {
	u, err := uuid.NewV7()
	if err != nil {
		return "", fmt.Errorf("generate uuidv7: %w", err)
	}
	return string(k) + "_" + u.String(), nil
}
