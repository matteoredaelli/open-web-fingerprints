// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

// Package matcher evaluates one fingerprint against one recorded observation.
// It is the offline engine behind rule validation. It is deliberately small
// and does no network access; the runtime detection engine is a separate
// project (AGENTS.md).
//
// Matching semantics, fixed here so that they are explicit and testable:
//   - regex patterns are unanchored and case-insensitive, as in the
//     Wappalyzer-style sources;
//   - equals and contains are case-sensitive;
//   - header and meta names are case-insensitive, cookie names and JS paths
//     are case-sensitive, DNS record types are upper case;
//   - only RE2 regexes are evaluated. A rule flagged ecmascript is reported as
//     unsupported instead of being run with different semantics.
package matcher

import (
	"sort"
	"strings"

	"golang.org/x/net/html"
)

// Observation is what was seen on one target. Every field is optional; a rule
// whose input is absent simply does not match.
type Observation struct {
	URL     string            `json:"url,omitempty"`
	Status  int               `json:"status,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	Cookies map[string]string `json:"cookies,omitempty"`
	// HTML is the page source. Meta tags, script URLs, inline scripts,
	// stylesheet URLs, CSS and text are derived from it unless given.
	HTML string `json:"html,omitempty"`
	// Scripts, Stylesheets, InlineScripts, CSS and Text override what is
	// derived from HTML.
	Scripts       []string `json:"scripts,omitempty"`
	Stylesheets   []string `json:"stylesheets,omitempty"`
	InlineScripts []string `json:"inline_scripts,omitempty"`
	CSS           string   `json:"css,omitempty"`
	Text          string   `json:"text,omitempty"`
	// JS maps a global path such as "jQuery.fn.jquery" to its value.
	JS          map[string]string   `json:"js,omitempty"`
	DNS         map[string][]string `json:"dns,omitempty"`
	TLS         map[string]string   `json:"tls,omitempty"`
	XHR         []string            `json:"xhr,omitempty"`
	Robots      string              `json:"robots,omitempty"`
	FaviconHash string              `json:"favicon_hash,omitempty"`
	// FaviconHashes holds hashes by algorithm ("md5"); a rule's target names
	// the algorithm. FaviconHash is used when the target is empty.
	FaviconHashes map[string]string `json:"favicon_hashes,omitempty"`
	// SetCookies are the raw Set-Cookie header lines, one per cookie.
	SetCookies []string `json:"set_cookies,omitempty"`
	// Title is the page title, derived from the HTML unless given.
	Title string `json:"title,omitempty"`
	// Probes holds recorded answers to active probes, by path. Nothing is
	// ever requested: these come from fixtures.
	Probes map[string]ProbeResponse `json:"probes,omitempty"`
}

// ProbeResponse is a recorded answer to a probe.
type ProbeResponse struct {
	Status  int               `json:"status"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body,omitempty"`
}

// headerBlock renders headers as "Name: value" lines sorted by name, the form
// that rules on the raw header block (word matchers, for example) read.
func headerBlock(h map[string]string) string {
	names := make([]string, 0, len(h))
	for k := range h {
		names = append(names, k)
	}
	sort.Slice(names, func(i, j int) bool { return strings.ToLower(names[i]) < strings.ToLower(names[j]) })
	var b strings.Builder
	for _, k := range names {
		b.WriteString(k + ": " + h[k] + "\n")
	}
	return strings.TrimSuffix(b.String(), "\n")
}

func headerValue(h map[string]string, name string) (string, bool) {
	for k, v := range h {
		if strings.EqualFold(k, name) {
			return v, true
		}
	}
	return "", false
}

// derived holds values extracted from the HTML once.
type derived struct {
	meta          map[string]string
	scripts       []string
	inlineScripts []string
	stylesheets   []string
	css           string
	text          string
	title         string
	headers       string // the raw header block, see headerBlock
}

func derive(o *Observation) derived {
	d := derived{meta: map[string]string{}, headers: headerBlock(o.Headers)}
	if o.HTML != "" {
		parseHTML(o.HTML, &d)
	}
	if o.Scripts != nil {
		d.scripts = o.Scripts
	}
	if o.Stylesheets != nil {
		d.stylesheets = o.Stylesheets
	}
	if o.InlineScripts != nil {
		d.inlineScripts = o.InlineScripts
	}
	if o.CSS != "" {
		d.css = o.CSS
	}
	if o.Text != "" {
		d.text = o.Text
	}
	if o.Title != "" {
		d.title = o.Title
	}
	return d
}

func parseHTML(src string, d *derived) {
	z := html.NewTokenizer(strings.NewReader(src))
	var raw string // element whose text content we collect: script or style
	var text strings.Builder
	for {
		switch z.Next() {
		case html.ErrorToken:
			d.text = strings.Join(strings.Fields(text.String()), " ")
			return
		case html.StartTagToken, html.SelfClosingTagToken:
			tok := z.Token()
			attrs := map[string]string{}
			for _, a := range tok.Attr {
				attrs[strings.ToLower(a.Key)] = a.Val
			}
			switch tok.Data {
			case "meta":
				name := strings.ToLower(attrs["name"])
				if name == "" {
					name = strings.ToLower(attrs["property"])
				}
				if name != "" {
					d.meta[name] = attrs["content"]
				}
			case "script":
				if src, ok := attrs["src"]; ok {
					d.scripts = append(d.scripts, src)
				} else {
					raw = "script"
				}
			case "link":
				if strings.Contains(strings.ToLower(attrs["rel"]), "stylesheet") && attrs["href"] != "" {
					d.stylesheets = append(d.stylesheets, attrs["href"])
				}
			case "style":
				raw = "style"
			case "title":
				if d.title == "" {
					raw = "title"
				}
			}
		case html.EndTagToken:
			raw = ""
		case html.TextToken:
			t := string(z.Text())
			switch raw {
			case "script":
				d.inlineScripts = append(d.inlineScripts, t)
			case "style":
				d.css += t
			case "title":
				d.title = strings.Join(strings.Fields(t), " ")
			default:
				text.WriteString(t)
				text.WriteByte(' ')
			}
		}
	}
}
