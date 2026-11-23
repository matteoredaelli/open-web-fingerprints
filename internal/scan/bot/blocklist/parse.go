// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

// Package blocklist reads domain block lists and answers whether a host is on one.
//
// It is pure: it reads from an io.Reader and keeps everything in memory. It does no
// network I/O and knows nothing about the crawler's database.
//
// A list is a hint made by someone else, usually about names. It has false positives
// (a harmless site on a shared name) and false negatives (most of the web is on no
// list), so it is no guarantee about the content of a site. What the parsers cannot
// represent as a whole domain (regular expressions, paths, options, cosmetic rules) is
// skipped and counted, never turned into a weaker rule that would block more.
package blocklist

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"
)

// Formats the parsers read.
const (
	FormatHosts   = "hosts"   // "0.0.0.0 example.com", as in a hosts file
	FormatDomains = "domains" // one domain per line
	FormatAdblock = "adblock" // AdGuard / Adblock Plus: "||example.com^", "@@||example.com^"
)

// Rules is what a list says: domains to block and exceptions to its own blocks.
type Rules struct {
	Block []string // a domain here blocks it and its subdomains
	Allow []string // an exception: cancels this list's blocks on it and its subdomains
}

// Stats counts what the parser saw, so nothing is dropped silently.
type Stats struct {
	Lines   int            // lines read
	Blocked int            // block entries kept
	Allowed int            // exceptions kept
	Skipped map[string]int // reason -> lines not representable ("regex", "options", ...)
}

func (s *Stats) skip(reason string) {
	if s.Skipped == nil {
		s.Skipped = map[string]int{}
	}
	s.Skipped[reason]++
}

// maxLine is the longest line read; a longer one is skipped, so a binary file cannot
// make the parser allocate without limit.
const maxLine = 64 << 10

// Parse reads a list in the given format.
func Parse(format string, r io.Reader) (Rules, Stats, error) {
	var line func(string, *Rules, *Stats)
	switch format {
	case FormatHosts:
		line = hostsLine
	case FormatDomains:
		line = domainsLine
	case FormatAdblock:
		line = adblockLine
	default:
		return Rules{}, Stats{}, fmt.Errorf("blocklist: unknown format %q", format)
	}
	var rules Rules
	var st Stats
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 4096), maxLine)
	for sc.Scan() {
		st.Lines++
		line(strings.TrimSpace(sc.Text()), &rules, &st)
	}
	if err := sc.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			return rules, st, fmt.Errorf("blocklist: a line is longer than %d bytes: not a text list", maxLine)
		}
		return rules, st, fmt.Errorf("blocklist: %w", err)
	}
	st.Blocked, st.Allowed = len(rules.Block), len(rules.Allow)
	return rules, st, nil
}

// Normalize returns the domain in lower case without a trailing dot, or false when it
// is not a plausible domain name (no dot, bad characters, IP address, wildcard).
func Normalize(s string) (string, bool) {
	d := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
	if d == "" || len(d) > 253 || !strings.Contains(d, ".") {
		return "", false
	}
	if _, err := netip.ParseAddr(d); err == nil {
		return "", false
	}
	for _, label := range strings.Split(d, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", false
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' && r != '_' {
				return "", false
			}
		}
	}
	return d, true
}

func stripComment(s string) string {
	if i := strings.Index(s, "#"); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

func hostsLine(l string, r *Rules, st *Stats) {
	l = stripComment(l)
	if l == "" {
		return
	}
	f := strings.Fields(l)
	if _, err := netip.ParseAddr(f[0]); err != nil || len(f) < 2 {
		st.skip("not a hosts line")
		return
	}
	for _, h := range f[1:] {
		if d, ok := Normalize(h); ok {
			r.Block = append(r.Block, d)
		} else {
			st.skip("not a domain") // localhost, broadcasthost, IPs...
		}
	}
}

func domainsLine(l string, r *Rules, st *Stats) {
	if strings.HasPrefix(l, "!") {
		return
	}
	l = stripComment(l)
	if l == "" {
		return
	}
	if strings.ContainsAny(l, " \t") {
		st.skip("not a domain")
		return
	}
	if d, ok := Normalize(strings.TrimPrefix(l, "*.")); ok {
		r.Block = append(r.Block, d)
	} else {
		st.skip("not a domain")
	}
}

func adblockLine(l string, r *Rules, st *Stats) {
	if l == "" || strings.HasPrefix(l, "!") || strings.HasPrefix(l, "[") || strings.HasPrefix(l, "# ") || l == "#" {
		return
	}
	if strings.Contains(l, "##") || strings.Contains(l, "#@#") || strings.Contains(l, "#?#") || strings.Contains(l, "#$#") {
		st.skip("cosmetic")
		return
	}
	allow := strings.HasPrefix(l, "@@")
	l = strings.TrimPrefix(l, "@@")
	if strings.HasPrefix(l, "/") && strings.HasSuffix(l, "/") {
		st.skip("regex")
		return
	}
	if !strings.HasPrefix(l, "||") {
		st.skip("not a domain rule")
		return
	}
	l = l[2:]
	if i := strings.Index(l, "$"); i >= 0 {
		// "important" only raises the rule's priority; any other option narrows the rule
		// (a type, a third party, a client), and keeping it whole would block more.
		if l[i+1:] != "important" {
			st.skip("options")
			return
		}
		l = l[:i]
	}
	l = strings.TrimSuffix(l, "^")
	if strings.ContainsAny(l, "/^*|?:") {
		st.skip("path or pattern")
		return
	}
	d, ok := Normalize(l)
	if !ok {
		st.skip("not a domain")
		return
	}
	if allow {
		r.Allow = append(r.Allow, d)
	} else {
		r.Block = append(r.Block, d)
	}
}
