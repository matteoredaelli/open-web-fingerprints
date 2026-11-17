// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// normalizeTarget applies the case rules of the observation type: header and
// meta names are case-insensitive, DNS record types are upper case, and
// everything else (cookies, JS globals, selectors) is case-sensitive.
func normalizeTarget(o Observation, target string) string {
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
// so different strings are never assumed equivalent.
func (f Fingerprint) SemanticKey() string {
	h := sha256.New()
	h.Write([]byte(strings.Join([]string{
		string(f.TechnologyID), string(f.Observation), normalizeTarget(f.Observation, f.Target),
		string(f.Operator), f.Pattern, string(f.RegexFlavor), f.VersionExtract,
	}, "\x1f")))
	return hex.EncodeToString(h.Sum(nil))[:32]
}
