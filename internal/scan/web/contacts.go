// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package web

import (
	"net/url"
	"regexp"
	"strings"
)

var (
	emailRE     = regexp.MustCompile(`^[a-z0-9][a-z0-9._%+\-]*@[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?)*\.[a-z]{2,24}$`)
	emailInText = regexp.MustCompile(`[A-Za-z0-9][A-Za-z0-9._%+\-]*@[A-Za-z0-9](?:[A-Za-z0-9\-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-]*[A-Za-z0-9])?)*\.[A-Za-z]{2,24}`)
	// File names such as logo@2x.png look like addresses.
	notTLD = map[string]bool{"png": true, "jpg": true, "jpeg": true, "gif": true, "svg": true, "webp": true,
		"css": true, "js": true, "ico": true, "avif": true, "woff": true, "woff2": true, "ttf": true, "map": true}
)

// NormalizeEmail lower-cases an address and checks its shape. ok is false for
// anything that is not a plausible address.
func NormalizeEmail(s string) (string, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	if !emailRE.MatchString(s) {
		return "", false
	}
	tld := s[strings.LastIndex(s, ".")+1:]
	if notTLD[tld] || strings.Contains(s, "..") {
		return "", false
	}
	return s, true
}

// NormalizePhone keeps the digits and a leading plus. "00" is read as the
// international prefix. Numbers without a plus keep their national form, since
// the country cannot be known. It rejects strings with too few or too many
// digits for a telephone number (6 to 15).
func NormalizePhone(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, ";,"); i >= 0 { // extensions: tel:+39021234;ext=5
		s = s[:i]
	}
	var b strings.Builder
	plus := strings.HasPrefix(s, "+")
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	d := b.String()
	if !plus && strings.HasPrefix(d, "00") {
		plus, d = true, d[2:]
	}
	if len(d) < 6 || len(d) > 15 || strings.Trim(d, "0") == "" {
		return "", false
	}
	if plus {
		return "+" + d, true
	}
	return d, true
}

// mailtoAddresses returns the addresses of a mailto: URL (it may list several,
// separated by commas, and carry ?subject=...).
func mailtoAddresses(raw string) []string {
	rest := strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(raw), "mailto:"), "MAILTO:")
	if i := strings.IndexByte(rest, '?'); i >= 0 {
		rest = rest[:i]
	}
	dec, err := url.PathUnescape(rest)
	if err != nil {
		return nil
	}
	var out []string
	for _, a := range strings.Split(dec, ",") {
		if e, ok := NormalizeEmail(a); ok {
			out = append(out, e)
		}
	}
	return out
}

func telNumber(raw string) (string, bool) {
	rest := strings.TrimSpace(raw)
	if len(rest) < 4 || !strings.EqualFold(rest[:4], "tel:") {
		return "", false
	}
	dec, err := url.PathUnescape(rest[4:])
	if err != nil {
		return "", false
	}
	return NormalizePhone(dec)
}
