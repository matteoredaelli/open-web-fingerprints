// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package enthec

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/matteoredaelli/open-web-fingerprints/internal/domain"
)

// parsedPattern is a Wappalyzer pattern string split into the regular
// expression and its inline "\;key:value" modifiers.
type parsedPattern struct {
	Regex      string
	Version    string   // value of \;version:, usually "\1"
	Confidence *float64 // value of \;confidence: scaled to 0..1
	Unknown    []string // modifiers that are not understood
}

// parsePattern splits a pattern on the literal two-character sequence `\;`.
func parsePattern(s string) parsedPattern {
	parts := strings.Split(s, `\;`)
	p := parsedPattern{Regex: parts[0]}
	for _, m := range parts[1:] {
		k, v, ok := strings.Cut(m, ":")
		switch {
		case ok && k == "version":
			p.Version = v
		case ok && k == "confidence":
			n, err := strconv.ParseFloat(v, 64)
			if err != nil || n < 0 || n > 100 {
				p.Unknown = append(p.Unknown, m)
				continue
			}
			c := n / 100
			p.Confidence = &c
		default:
			p.Unknown = append(p.Unknown, m)
		}
	}
	return p
}

// flavorFor reports which regex dialect can run the pattern. Wappalyzer
// patterns are case-insensitive, so (?i) is applied for the check.
func flavorFor(re string) domain.RegexFlavor {
	if _, err := regexp.Compile("(?i)" + re); err != nil {
		return domain.FlavorECMAScript
	}
	return domain.FlavorRE2
}
