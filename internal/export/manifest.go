// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package export

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/matteoredaelli/open-web-fingerprints/internal/domain"
	"github.com/matteoredaelli/open-web-fingerprints/schemas"
)

// ContentHash returns the hash of a registry document without its
// generated_at time and its manifest. Collections are written in a stable
// order and JSON object keys are sorted, so the same data always has the same
// hash, whenever and by whomever it is exported.
func ContentHash(reg domain.Registry) (string, error) {
	reg.GeneratedAt, reg.Manifest = nil, nil
	b, err := json.Marshal(reg)
	if err != nil {
		return "", fmt.Errorf("export: hash: %w", err)
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func buildManifest(reg domain.Registry, generator string) (*domain.Manifest, error) {
	h, err := ContentHash(reg)
	if err != nil {
		return nil, err
	}
	if generator == "" {
		generator = "owf"
	}
	m := &domain.Manifest{
		Generator: generator, ContentSHA256: h,
		Counts: domain.ManifestCounts{
			Sources: len(reg.Sources), Vendors: len(reg.Vendors), Categories: len(reg.Categories),
			Technologies: len(reg.Technologies), Fingerprints: len(reg.Fingerprints), Relationships: len(reg.Relationships),
		},
	}
	// The latest snapshot of a source is the one its records come from.
	latest := map[domain.SourceID]domain.Snapshot{}
	for _, sn := range reg.Snapshots {
		if cur, ok := latest[sn.SourceID]; !ok || sn.RetrievedAt.After(cur.RetrievedAt) {
			latest[sn.SourceID] = sn
		}
	}
	for _, s := range reg.Sources {
		ms := domain.ManifestSource{Slug: s.Slug, License: s.License, Redistributable: s.Redistributable}
		if sn, ok := latest[s.ID]; ok {
			ms.Revision, ms.SnapshotChecksum = sn.Revision, sn.Checksum
		}
		m.Sources = append(m.Sources, ms)
	}
	sort.Slice(m.Sources, func(i, j int) bool { return m.Sources[i].Slug < m.Sources[j].Slug })
	if m.Sources == nil {
		m.Sources = []domain.ManifestSource{}
	}
	return m, nil
}

// Verify checks an exported document: it must satisfy the schema, decode
// without unknown fields, and its manifest must match its content. It returns
// the decoded registry.
func Verify(doc []byte) (domain.Registry, error) {
	var reg domain.Registry
	if err := schemas.ValidateRegistry(doc); err != nil {
		return reg, fmt.Errorf("verify: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&reg); err != nil {
		return reg, fmt.Errorf("verify: %w", err)
	}
	if reg.Manifest == nil {
		return reg, fmt.Errorf("verify: the document has no manifest (exports before schema 0.2.0 cannot be verified)")
	}
	h, err := ContentHash(reg)
	if err != nil {
		return reg, err
	}
	if h != reg.Manifest.ContentSHA256 {
		return reg, fmt.Errorf("verify: content hash is %s, the manifest says %s: the file was changed or damaged", h, reg.Manifest.ContentSHA256)
	}
	want, err := buildManifest(reg, reg.Manifest.Generator)
	if err != nil {
		return reg, err
	}
	if want.Counts != reg.Manifest.Counts {
		return reg, fmt.Errorf("verify: counts in the manifest %+v do not match the content %+v", reg.Manifest.Counts, want.Counts)
	}
	return reg, nil
}
