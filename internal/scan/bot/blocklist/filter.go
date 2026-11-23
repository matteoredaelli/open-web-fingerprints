// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package blocklist

import (
	"fmt"
	"slices"
	"strings"
)

// Categories a list may have.
var Categories = []string{"adult", "gambling", "malware", "phishing", "ads", "tracking", "other"}

// maxLists is the most lists one Filter holds (a bit per list in the trie).
const maxLists = 64

type node struct {
	kids  map[string]*node
	block uint64 // lists that block this domain and its subdomains
	allow uint64 // lists whose exception cancels their own blocks here and below
}

// Filter holds several lists in one trie of reversed labels ("com" -> "example").
// Build it with New, add lists with Add, then call Check; it is safe for concurrent
// Check calls once the last Add has returned.
type Filter struct {
	root    node
	lists   []listInfo
	exclude map[string]bool
}

type listInfo struct{ name, category string }

// New returns an empty filter that blocks the given categories. A list of another
// category is accepted by Add but never blocks: ads and tracking lists, for instance,
// are only used when asked for.
func New(excludeCategories []string) (*Filter, error) {
	f := &Filter{exclude: map[string]bool{}}
	for _, c := range excludeCategories {
		if !slices.Contains(Categories, c) {
			return nil, fmt.Errorf("blocklist: unknown category %q", c)
		}
		f.exclude[c] = true
	}
	return f, nil
}

// Add puts a list in the filter. Names must be unique.
func (f *Filter) Add(name, category string, r Rules) error {
	if !slices.Contains(Categories, category) {
		return fmt.Errorf("blocklist: unknown category %q", category)
	}
	if len(f.lists) >= maxLists {
		return fmt.Errorf("blocklist: more than %d lists", maxLists)
	}
	for _, l := range f.lists {
		if l.name == name {
			return fmt.Errorf("blocklist: list %q added twice", name)
		}
	}
	bit := uint64(1) << len(f.lists)
	f.lists = append(f.lists, listInfo{name, category})
	for _, d := range r.Block {
		f.walk(d).block |= bit
	}
	for _, d := range r.Allow {
		f.walk(d).allow |= bit
	}
	return nil
}

func (f *Filter) walk(domain string) *node {
	n := &f.root
	labels := strings.Split(domain, ".")
	for i := len(labels) - 1; i >= 0; i-- {
		if n.kids == nil {
			n.kids = map[string]*node{}
		}
		k := n.kids[labels[i]]
		if k == nil {
			k = &node{}
			n.kids[labels[i]] = k
		}
		n = k
	}
	return n
}

// Verdict is the answer of Check.
type Verdict struct {
	Blocked  bool
	List     string // the list that blocks, the first added when several do
	Category string
	Entry    string // the list entry that matched (the host itself or a parent domain)
}

// Check says whether host, or a parent domain of it, is blocked by a list of an excluded
// category. An exception of a list cancels that list's blocks, wherever on the path they
// are; it does not cancel another list's.
func (f *Filter) Check(host string) Verdict {
	d := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if d == "" {
		return Verdict{}
	}
	labels := strings.Split(d, ".")
	type hit struct {
		bits  uint64
		entry string
	}
	var hits []hit
	var allow uint64
	n := &f.root
	for i := len(labels) - 1; i >= 0; i-- {
		n = n.kids[labels[i]]
		if n == nil {
			break
		}
		allow |= n.allow
		if n.block != 0 {
			hits = append(hits, hit{n.block, strings.Join(labels[i:], ".")})
		}
	}
	for _, h := range hits { // the shortest entry first: the widest rule
		live := h.bits &^ allow
		for i, l := range f.lists {
			if live&(1<<i) != 0 && f.exclude[l.category] {
				return Verdict{Blocked: true, List: l.name, Category: l.category, Entry: h.entry}
			}
		}
	}
	return Verdict{}
}

// Len returns the number of lists in the filter.
func (f *Filter) Len() int { return len(f.lists) }
