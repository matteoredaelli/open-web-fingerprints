// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package normalizer

import "testing"

func TestSlugify(t *testing.T) {
	for in, want := range map[string]string{
		"A-Frame": "a-frame", "Next.js": "next-js", "C++": "c-plus-plus", "C#": "c-sharp",
		"AT&T": "at-and-t", "  Spaced  Out ": "spaced-out", "Café": "cafe", "日本語": "", "--x--": "x",
		"1 & 1": "1-and-1",
	} {
		if got := slugify(in); got != want {
			t.Errorf("slugify(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSlugSetFallbackAndCollisions(t *testing.T) {
	s := newSlugSet("tech")
	got := []string{s.unique("日本"), s.unique("日本"), s.unique("X"), s.unique("x"), s.unique("x")}
	want := []string{"tech", "tech-2", "x", "x-2", "x-3"}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got %v want %v", got, want)
			break
		}
	}
}
