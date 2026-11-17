// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package nuclei

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// The DSL of a nuclei matcher is a full expression language. Technology
// templates use a small part of it, and only that part is read: a conjunction
// (&&) of the terms below. Anything else makes the matcher unsupported, and the
// template is skipped and counted, never guessed.
//
//	status_code == 200
//	regex("pattern", body|header)
//	contains(body|header|content_type, "text")
//	contains(to_lower(body|header), "text")        (also tolower)
//	contains_any(body|to_lower(body), "a", "b")    contains_all(...) likewise
//	"hash" == mmh3(base64_py(body))                (favicon hash)

// dslTerm is one parsed term.
type dslTerm struct {
	kind   string   // status, regex, contains, any, all, mmh3
	part   string   // body, header, content_type
	args   []string // strings: pattern, text(s) or hash
	status int
	lower  bool // the part is lower-cased first: a case-insensitive match
}

var (
	statusRE = regexp.MustCompile(`^status_code\s*==\s*(\d+)$`)
	regexRE  = regexp.MustCompile(`^regex\(\s*("(?:[^"\\]|\\.)*")\s*,\s*(body|header)\s*\)$`)
	callRE   = regexp.MustCompile(`^(contains|contains_any|contains_all)\(\s*(?:(?:to_lower|tolower)\(\s*(body|header|content_type)\s*\)|(body|header|content_type))\s*,\s*(.+)\)$`)
	mmh3RE   = regexp.MustCompile(`^("(?:[^"\\]|\\.)*")\s*==\s*mmh3\(\s*base64_py\(\s*body\s*\)\s*\)$`)
	strRE    = regexp.MustCompile(`"(?:[^"\\]|\\.)*"`)
)

// parseDSL parses one dsl expression into its && terms.
func parseDSL(expr string) ([]dslTerm, error) {
	var out []dslTerm
	for _, raw := range splitAnd(expr) {
		t, err := parseTerm(strings.TrimSpace(raw))
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("empty expression")
	}
	return out, nil
}

// splitAnd splits on && outside of quotes and parentheses.
func splitAnd(s string) []string {
	var parts []string
	depth, start := 0, 0
	inStr := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inStr {
			switch c {
			case '\\':
				i++
			case '"':
				inStr = false
			}
			continue
		}
		switch c {
		case '"':
			inStr = true
		case '(':
			depth++
		case ')':
			depth--
		case '&':
			if depth == 0 && i+1 < len(s) && s[i+1] == '&' {
				parts = append(parts, s[start:i])
				start = i + 2
				i++
			}
		}
	}
	return append(parts, s[start:])
}

// unwrap removes parentheses that enclose the whole term.
func unwrap(s string) string {
	for strings.HasPrefix(s, "(") && strings.HasSuffix(s, ")") && balanced(s[1:len(s)-1]) {
		s = strings.TrimSpace(s[1 : len(s)-1])
	}
	return s
}

func balanced(s string) bool {
	depth, inStr := 0, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inStr {
			switch c {
			case '\\':
				i++
			case '"':
				inStr = false
			}
			continue
		}
		switch c {
		case '"':
			inStr = true
		case '(':
			depth++
		case ')':
			depth--
			if depth < 0 {
				return false
			}
		}
	}
	return depth == 0
}

func parseTerm(s string) (dslTerm, error) {
	s = unwrap(s)
	if strings.HasPrefix(s, "!") {
		return dslTerm{}, fmt.Errorf("negation is not supported: %s", s)
	}
	if m := statusRE.FindStringSubmatch(s); m != nil {
		n, _ := strconv.Atoi(m[1])
		return dslTerm{kind: "status", status: n}, nil
	}
	if m := regexRE.FindStringSubmatch(s); m != nil {
		re, err := strconv.Unquote(m[1])
		if err != nil {
			return dslTerm{}, fmt.Errorf("bad string %s: %w", m[1], err)
		}
		return dslTerm{kind: "regex", part: m[2], args: []string{re}}, nil
	}
	if m := mmh3RE.FindStringSubmatch(s); m != nil {
		h, err := strconv.Unquote(m[1])
		if err != nil {
			return dslTerm{}, fmt.Errorf("bad string %s: %w", m[1], err)
		}
		return dslTerm{kind: "mmh3", part: "body", args: []string{h}}, nil
	}
	if m := callRE.FindStringSubmatch(s); m != nil {
		part, lower := m[3], false
		if m[2] != "" {
			part, lower = m[2], true
		}
		// Only string literals may follow the part, separated by commas.
		rest := m[4]
		lits := strRE.FindAllString(rest, -1)
		if len(lits) == 0 || !onlyCommas(strRE.ReplaceAllString(rest, "")) {
			return dslTerm{}, fmt.Errorf("unsupported arguments: %s", s)
		}
		var args []string
		for _, l := range lits {
			v, err := strconv.Unquote(l)
			if err != nil {
				return dslTerm{}, fmt.Errorf("bad string %s: %w", l, err)
			}
			args = append(args, v)
		}
		kind := map[string]string{"contains": "contains", "contains_any": "any", "contains_all": "all"}[m[1]]
		if kind == "contains" && len(args) != 1 {
			return dslTerm{}, fmt.Errorf("contains takes one string: %s", s)
		}
		return dslTerm{kind: kind, part: part, args: args, lower: lower}, nil
	}
	return dslTerm{}, fmt.Errorf("outside the supported subset: %s", s)
}

func onlyCommas(s string) bool {
	return strings.Trim(s, ", ") == ""
}
