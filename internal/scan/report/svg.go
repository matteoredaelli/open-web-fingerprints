// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package report

import (
	"fmt"
	"html"
	"html/template"
	"math"
	"strings"
)

// donut draws the technologies by category as a ring. Every number and every piece of
// text is escaped here: the SVG is inserted as trusted markup afterwards.
func donut(groups []group) template.HTML {
	total := 0
	for _, g := range groups {
		total += g.Count
	}
	if total == 0 {
		return ""
	}
	const r, cx, cy = 70.0, 100.0, 100.0
	circ := 2 * math.Pi * r
	var b strings.Builder
	b.WriteString(`<svg class="donut" viewBox="0 0 200 200" role="img" aria-label="Technologies by category">`)
	fmt.Fprintf(&b, `<circle cx="%.0f" cy="%.0f" r="%.0f" fill="none" stroke="var(--track)" stroke-width="26"/>`, cx, cy, r)
	offset := 0.0
	for _, g := range groups {
		l := circ * float64(g.Count) / float64(total)
		gap := 0.0
		if len(groups) > 1 && l > 3 {
			gap = 1.5
		}
		fmt.Fprintf(&b, `<circle cx="%.0f" cy="%.0f" r="%.0f" fill="none" stroke="hsl(%d 65%% 52%%)" stroke-width="26" stroke-dasharray="%.2f %.2f" stroke-dashoffset="%.2f" transform="rotate(-90 %.0f %.0f)"><title>%s: %d</title></circle>`,
			cx, cy, r, hue(g.Name), l-gap, circ-l+gap, -offset, cx, cy, html.EscapeString(g.Name), g.Count)
		offset += l
	}
	fmt.Fprintf(&b, `<text x="100" y="98" text-anchor="middle" class="donut-n">%d</text><text x="100" y="118" text-anchor="middle" class="donut-l">technologies</text></svg>`, total)
	return template.HTML(b.String()) //nolint:gosec // built above from numbers and escaped text
}

// graph draws the target in the middle and the friend and related domains around it.
func graph(center string, friends, related []netItem) template.HTML {
	type node struct{ name, class string }
	seen := map[string]bool{center: true}
	var nodes []node
	add := func(name, class string) {
		if !seen[name] && len(nodes) < 24 {
			seen[name] = true
			nodes = append(nodes, node{name, class})
		}
	}
	for _, f := range friends {
		add(f.Domain, "friend")
	}
	for _, r := range related {
		if r.Level == "probable" {
			add(r.Domain, "probable")
		}
	}
	for _, r := range related {
		add(r.Domain, "candidate")
	}
	if len(nodes) == 0 {
		return ""
	}
	const w, h = 760.0, 440.0
	cx, cy := w/2, h/2
	rx, ry := 290.0, 160.0
	var b strings.Builder
	fmt.Fprintf(&b, `<svg class="graph" viewBox="0 0 %.0f %.0f" role="img" aria-label="Domains connected to %s">`, w, h, html.EscapeString(center))
	pos := make([][2]float64, len(nodes))
	for i := range nodes {
		a := -math.Pi/2 + 2*math.Pi*float64(i)/float64(len(nodes))
		pos[i] = [2]float64{cx + rx*math.Cos(a), cy + ry*math.Sin(a)}
		fmt.Fprintf(&b, `<line x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f" class="edge %s"/>`, cx, cy, pos[i][0], pos[i][1], nodes[i].class)
	}
	fmt.Fprintf(&b, `<g class="node center"><circle cx="%.1f" cy="%.1f" r="30"/><text x="%.1f" y="%.1f" text-anchor="middle">%s</text></g>`, cx, cy, cx, cy+4, html.EscapeString(short(center, 18)))
	for i, n := range nodes {
		anchor := "middle"
		dy := -14.0
		if pos[i][1] > cy {
			dy = 24
		}
		fmt.Fprintf(&b, `<g class="node %s"><circle cx="%.1f" cy="%.1f" r="9"/><text x="%.1f" y="%.1f" text-anchor="%s">%s</text></g>`,
			n.class, pos[i][0], pos[i][1], pos[i][0], pos[i][1]+dy, anchor, html.EscapeString(short(n.name, 24)))
	}
	b.WriteString(`</svg>`)
	return template.HTML(b.String()) //nolint:gosec // built above from numbers and escaped text
}
