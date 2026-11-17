// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package normalizer

import (
	"strconv"
	"strings"
	"unicode"

	"golang.org/x/text/unicode/norm"
)

// slugify turns a display name into a lower-case ASCII slug that matches
// ^[a-z0-9]+(-[a-z0-9]+)*$. Letters outside ASCII are reduced to their base
// letter when they have one and dropped otherwise.
func slugify(name string) string {
	r := strings.NewReplacer("+", " plus ", "#", " sharp ", "&", " and ")
	var b strings.Builder
	dash := true // suppress leading dash
	for _, c := range norm.NFD.String(r.Replace(name)) {
		switch {
		case unicode.Is(unicode.Mn, c):
			continue
		case c < unicode.MaxASCII && (unicode.IsLower(c) || unicode.IsDigit(c)):
			b.WriteRune(c)
			dash = false
		case c < unicode.MaxASCII && unicode.IsUpper(c):
			b.WriteRune(unicode.ToLower(c))
			dash = false
		default:
			if !dash {
				b.WriteByte('-')
				dash = true
			}
		}
	}
	return strings.Trim(b.String(), "-")
}

// slugSet hands out unique slugs, adding -2, -3, ... on collision.
type slugSet struct {
	used     map[string]bool
	fallback string
}

func newSlugSet(fallback string) *slugSet {
	return &slugSet{used: map[string]bool{}, fallback: fallback}
}

func (s *slugSet) unique(name string) string {
	base := slugify(name)
	if base == "" {
		base = s.fallback
	}
	slug := base
	for n := 2; s.used[slug]; n++ {
		slug = base + "-" + strconv.Itoa(n)
	}
	s.used[slug] = true
	return slug
}
