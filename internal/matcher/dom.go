// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package matcher

import (
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/andybalholm/cascadia"
	"golang.org/x/net/html"
)

// A dom rule's target is a CSS selector with an optional suffix:
//
//	sel               an element matching sel exists
//	sel::text         the element's text content
//	sel::attr(name)   the value of an attribute (exists: the attribute is set)
//	sel::prop(name)   a JavaScript property: needs a browser, unsupported
var domTargetRE = regexp.MustCompile(`(?s)^(.*?)(?:::(text)|::attr\((.+)\)|::(prop)\((.+)\))?$`)

var selectorCache sync.Map // selector -> cascadia.SelectorGroup

func parseSelector(sel string) (cascadia.SelectorGroup, error) {
	if v, ok := selectorCache.Load(sel); ok {
		return v.(cascadia.SelectorGroup), nil
	}
	g, err := cascadia.ParseGroup(sel)
	if err != nil {
		return nil, fmt.Errorf("selector %q does not parse: %w", sel, err)
	}
	selectorCache.Store(sel, g)
	return g, nil
}

// domValues evaluates the selector on the page and returns the values a rule
// looks at, and whether the observed thing exists.
func domValues(target, page string) (vals []string, present bool, err error) {
	m := domTargetRE.FindStringSubmatch(target)
	sel, text, attr, prop := m[1], m[2] != "", m[3], m[4] != ""
	if prop {
		return nil, false, fmt.Errorf("%w: JavaScript property %q needs a browser", ErrUnsupported, m[5])
	}
	group, err := parseSelector(sel)
	if err != nil {
		return nil, false, err
	}
	if page == "" {
		return nil, false, nil
	}
	root, err := html.Parse(strings.NewReader(page))
	if err != nil {
		return nil, false, fmt.Errorf("parse html: %w", err)
	}
	nodes := cascadia.QueryAll(root, group)
	switch {
	case attr != "":
		for _, n := range nodes {
			for _, a := range n.Attr {
				if strings.EqualFold(a.Key, attr) {
					vals = append(vals, a.Val)
					present = true
					break
				}
			}
		}
	case text:
		for _, n := range nodes {
			if t := nodeText(n); t != "" {
				vals = append(vals, t)
			}
		}
		present = len(vals) > 0
	default:
		// A bare selector looks at the element's text for regex rules.
		present = len(nodes) > 0
		for _, n := range nodes {
			vals = append(vals, nodeText(n))
		}
	}
	return vals, present, nil
}

func nodeText(n *html.Node) string {
	var b strings.Builder
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.TextNode {
			b.WriteString(n.Data)
			b.WriteByte(' ')
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(n)
	return strings.Join(strings.Fields(b.String()), " ")
}
