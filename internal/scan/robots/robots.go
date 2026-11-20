// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

// Package robots reads robots.txt, the file by which a site says which paths
// crawlers should not fetch. The scanner uses it for the pages it follows on its
// own; the page the user names is fetched regardless.
//
// It follows RFC 9309: the group for the most specific matching user agent (else
// "*") applies, the longest matching rule wins, Allow wins a tie, "*" and a final
// "$" are the only pattern characters, and matching is on the path with its query.
package robots

import (
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Rules are the rules that apply to one user agent.
type Rules struct {
	rules []rule
	// CrawlDelay is the pause the site asks for between requests (0 if none). It
	// is not part of RFC 9309 but widely published.
	CrawlDelay time.Duration
}

type rule struct {
	allow   bool
	pattern string
}

// Parse reads a robots.txt for the given user agent product token (for example
// "owfscan"). An empty or unreadable file allows everything.
func Parse(text, agent string) *Rules {
	agent = strings.ToLower(agent)
	type group struct {
		agents []string
		rules  []rule
		delay  time.Duration
	}
	var groups []*group
	var cur *group
	inAgents := false
	for _, line := range strings.Split(strings.ReplaceAll(text, "\r", ""), "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		k, v = strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(v)
		switch k {
		case "user-agent":
			if !inAgents || cur == nil {
				cur = &group{}
				groups = append(groups, cur)
			}
			inAgents = true
			cur.agents = append(cur.agents, strings.ToLower(v))
		case "allow", "disallow":
			inAgents = false
			if cur == nil {
				continue
			}
			// An empty Disallow allows everything: no rule.
			if v != "" {
				cur.rules = append(cur.rules, rule{allow: k == "allow", pattern: v})
			}
		case "crawl-delay":
			inAgents = false
			if cur != nil {
				if f, err := strconv.ParseFloat(v, 64); err == nil && f > 0 && f < 3600 {
					cur.delay = time.Duration(f * float64(time.Second))
				}
			}
		default:
			inAgents = false
		}
	}
	// The group whose agent token is the longest one contained in ours wins, else "*".
	var best *group
	bestLen := -1
	for _, g := range groups {
		for _, a := range g.agents {
			switch {
			case a == "*":
				if bestLen < 0 {
					best, bestLen = g, 0
				}
			case a != "" && strings.Contains(agent, a) && len(a) > bestLen:
				best, bestLen = g, len(a)
			}
		}
	}
	r := &Rules{}
	if best != nil {
		r.rules, r.CrawlDelay = best.rules, best.delay
	}
	return r
}

// Allowed reports whether the path (with its query) may be fetched.
func (r *Rules) Allowed(rawURL string) bool {
	if r == nil {
		return true
	}
	p := pathOf(rawURL)
	if p == "/robots.txt" {
		return true
	}
	bestLen, allow := -1, true
	for _, ru := range r.rules {
		if !match(ru.pattern, p) {
			continue
		}
		n := len(ru.pattern)
		if n > bestLen || (n == bestLen && ru.allow) {
			bestLen, allow = n, ru.allow
		}
	}
	return allow
}

func pathOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "/"
	}
	p := u.EscapedPath()
	if p == "" {
		p = "/"
	}
	if u.RawQuery != "" {
		p += "?" + u.RawQuery
	}
	return p
}

// match reports whether a robots.txt pattern matches the start of a path.
func match(pattern, path string) bool {
	anchored := strings.HasSuffix(pattern, "$")
	pattern = strings.TrimSuffix(pattern, "$")
	parts := strings.Split(pattern, "*")
	pos := 0
	for i, part := range parts {
		if i == 0 {
			if !strings.HasPrefix(path, part) {
				return false
			}
			pos = len(part)
			continue
		}
		j := strings.Index(path[pos:], part)
		if j < 0 {
			return false
		}
		pos += j + len(part)
	}
	if anchored {
		// The last part must end the path; with a trailing "*" anything does.
		if strings.HasSuffix(pattern, "*") {
			return true
		}
		last := parts[len(parts)-1]
		return strings.HasSuffix(path, last) && (len(parts) > 1 || path == last)
	}
	return true
}
