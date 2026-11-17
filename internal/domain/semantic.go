// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// NormalizeTarget applies the case rules of the observation type: header and
// meta names are case-insensitive, DNS record types are upper case, and
// everything else (cookies, JS globals, selectors) is case-sensitive.
func NormalizeTarget(o Observation, target string) string {
	switch o {
	case ObsHTTPHeader, ObsMetaTag:
		return strings.ToLower(target)
	case ObsDNSRecord:
		return strings.ToUpper(target)
	}
	return target
}

// SemanticKey identifies what a rule means, independently of names, wording
// or source. Two fingerprints of the same technology with equal keys are the
// same rule. Patterns are compared as strings: no regex rewriting is done,
// so different strings are never assumed equivalent. A rule that is part of a
// group (rules that must hold together) is a different rule from the same
// condition on its own, so the group is part of the key.
func (f Fingerprint) SemanticKey() string {
	h := sha256.New()
	h.Write([]byte(strings.Join([]string{
		string(f.TechnologyID), string(f.Observation), NormalizeTarget(f.Observation, f.Target),
		string(f.Operator), f.Pattern, string(f.RegexFlavor), f.VersionExtract, string(f.GroupID),
	}, "\x1f")))
	return hex.EncodeToString(h.Sum(nil))[:32]
}

// UnionProvenance appends the entries of b that a does not already have. An
// entry is identified by (source, original ID).
func UnionProvenance(a, b []Provenance) []Provenance {
	out := append([]Provenance(nil), a...)
	seen := map[string]bool{}
	for _, p := range out {
		seen[string(p.SourceID)+"\x00"+p.OriginalID] = true
	}
	for _, p := range b {
		k := string(p.SourceID) + "\x00" + p.OriginalID
		if !seen[k] {
			seen[k] = true
			out = append(out, p)
		}
	}
	return out
}

// LowestExplicitConfidence returns the lowest confidence a source stated
// explicitly, or fallback when none did. Agreement between sources never
// raises confidence.
func LowestExplicitConfidence(p []Provenance, fallback float64) float64 {
	found := false
	lowest := 0.0
	for _, x := range p {
		if x.OriginalConfidence == nil {
			continue
		}
		if !found || *x.OriginalConfidence < lowest {
			lowest, found = *x.OriginalConfidence, true
		}
	}
	if !found {
		return fallback
	}
	return lowest
}
