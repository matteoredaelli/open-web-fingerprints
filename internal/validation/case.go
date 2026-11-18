// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

// Package validation checks fingerprints against recorded observations and
// against static quality rules. A fingerprint only becomes healthy with test
// evidence: at least one passing positive case and one passing negative case.
package validation

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/matteoredaelli/open-web-fingerprints/internal/domain"
	"github.com/matteoredaelli/open-web-fingerprints/internal/matcher"
	"github.com/matteoredaelli/open-web-fingerprints/schemas"
)

// File is one fixture file.
type File struct {
	SchemaVersion string `json:"schema_version"`
	Cases         []Case `json:"cases"`
}

// Case is one assertion: when the rule sees Input, does it match?
type Case struct {
	ID          string              `json:"id"`
	Description string              `json:"description,omitempty"`
	Rule        Selector            `json:"rule"`
	Input       matcher.Observation `json:"input"`
	Expect      Expect              `json:"expect"`
}

// Selector identifies a canonical rule by what it means, not by an ID that
// differs between registries. Target, operator and pattern are optional
// filters; the selector must resolve to exactly one rule.
type Selector struct {
	Technology  string `json:"technology"` // slug
	Observation string `json:"observation"`
	Target      string `json:"target,omitempty"`
	Operator    string `json:"operator,omitempty"`
	Pattern     string `json:"pattern,omitempty"`
}

// Expect is the asserted outcome.
type Expect struct {
	Match   bool   `json:"match"`
	Version string `json:"version,omitempty"`
}

// Loaded is a case with the file it came from.
type Loaded struct {
	File string // slash-separated path relative to the loaded root
	Case Case
	// RuleID names the rule directly. It is set for cases generated from a
	// source's own examples, which do not need a selector.
	RuleID domain.FingerprintID
	// Origin is "" for case files and OriginUpstream for generated cases.
	Origin string
}

// OriginUpstream marks evidence that comes from examples shipped by the source
// of a rule, not from a case written for this registry.
const OriginUpstream = "upstream_example"

// Ref is the stable reference stored in a rule's test runs.
func (l Loaded) Ref() string { return l.File + "#" + l.Case.ID }

var idRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)

// Load reads fixture files from a file or a directory (recursively, *.json).
// Files are validated against the fixture schema, decoded strictly, and case
// IDs must be unique across all files.
func Load(root string) ([]Loaded, error) {
	st, err := os.Stat(root)
	if err != nil {
		return nil, fmt.Errorf("validation: %w", err)
	}
	var paths []string
	base := root
	if st.IsDir() {
		err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() && strings.HasSuffix(p, ".json") {
				paths = append(paths, p)
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("validation: %w", err)
		}
	} else {
		paths, base = []string{root}, filepath.Dir(root)
	}
	sort.Strings(paths)

	var out []Loaded
	seen := map[string]string{}
	for _, p := range paths {
		rel, _ := filepath.Rel(base, p)
		rel = path.Clean(filepath.ToSlash(rel))
		b, err := os.ReadFile(p) //nolint:gosec // user-supplied fixture path
		if err != nil {
			return nil, fmt.Errorf("validation: %w", err)
		}
		if err := schemas.ValidateCases(b); err != nil {
			return nil, fmt.Errorf("validation: %s: %w", rel, err)
		}
		dec := json.NewDecoder(bytes.NewReader(b))
		dec.DisallowUnknownFields()
		var f File
		if err := dec.Decode(&f); err != nil {
			return nil, fmt.Errorf("validation: %s: %w", rel, err)
		}
		for _, c := range f.Cases {
			if !idRE.MatchString(c.ID) {
				return nil, fmt.Errorf("validation: %s: invalid case ID %q", rel, c.ID)
			}
			if prev, dup := seen[c.ID]; dup {
				return nil, fmt.Errorf("validation: case ID %q is used in %s and %s", c.ID, prev, rel)
			}
			seen[c.ID] = rel
			if !c.Expect.Match && c.Expect.Version != "" {
				return nil, fmt.Errorf("validation: %s: case %s expects a version but no match", rel, c.ID)
			}
			out = append(out, Loaded{File: rel, Case: c})
		}
	}
	return out, nil
}
