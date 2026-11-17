// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package validation

import (
	"regexp"
	"strings"

	"github.com/matteoredaelli/open-web-fingerprints/internal/domain"
)

// Finding is a static quality problem of a rule. It is a warning about
// likely false positives, not a test result.
type Finding struct {
	RuleID  domain.FingerprintID
	Code    string
	Message string
}

// Finding codes.
const (
	RegexMatchesEmpty = "regex_matches_empty"
	PatternTooShort   = "pattern_too_short"
	UbiquitousHeader  = "ubiquitous_header"
	UbiquitousMeta    = "ubiquitous_meta"
)

// Headers and meta names that almost every site has: an "exists" rule on
// them identifies nothing.
var (
	commonHeaders = set("date", "content-type", "content-length", "connection", "server", "vary",
		"cache-control", "etag", "last-modified", "expires", "content-encoding", "accept-ranges",
		"transfer-encoding", "set-cookie", "location", "pragma", "age", "via", "keep-alive")
	commonMeta = set("viewport", "description", "robots", "keywords", "author", "charset", "theme-color")
)

func set(v ...string) map[string]bool {
	m := make(map[string]bool, len(v))
	for _, s := range v {
		m[s] = true
	}
	return m
}

// Lint reports static problems of one rule.
func Lint(f domain.Fingerprint) []Finding {
	var out []Finding
	add := func(code, msg string) { out = append(out, Finding{RuleID: f.ID, Code: code, Message: msg}) }

	if f.Operator == domain.OpRegex && f.RegexFlavor == domain.FlavorRE2 {
		if re, err := regexp.Compile("(?i)" + f.Pattern); err == nil && re.MatchString("") {
			add(RegexMatchesEmpty, "the pattern matches the empty string, so it matches anything")
		}
	}
	if f.Operator != domain.OpExists && f.Operator != domain.OpHashEquals {
		if p := strings.TrimSpace(f.Pattern); p != "" && len(p) < 3 {
			add(PatternTooShort, "a pattern under 3 characters is very likely to match unrelated sites")
		}
	}
	if f.Operator == domain.OpExists {
		switch f.Observation {
		case domain.ObsHTTPHeader:
			if commonHeaders[strings.ToLower(f.Target)] {
				add(UbiquitousHeader, "header "+f.Target+" is present on almost every site")
			}
		case domain.ObsMetaTag:
			if commonMeta[strings.ToLower(f.Target)] {
				add(UbiquitousMeta, "meta "+f.Target+" is present on almost every site")
			}
		}
	}
	return out
}

// LintAll lints every fingerprint.
func LintAll(recs domain.Records) []Finding {
	var out []Finding
	for _, f := range recs.Fingerprints {
		out = append(out, Lint(f)...)
	}
	return out
}
