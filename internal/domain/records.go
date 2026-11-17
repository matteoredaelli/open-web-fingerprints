// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package domain

// Records is a set of canonical records, without the source and snapshot
// bookkeeping entries. It is the unit exchanged between pipeline stages.
type Records struct {
	Vendors       []Vendor
	Categories    []Category
	Technologies  []Technology
	Fingerprints  []Fingerprint
	Relationships []Relationship
}
