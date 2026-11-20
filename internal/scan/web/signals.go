// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package web

import (
	"bytes"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/net/html"
)

// Signals are the things in a page that tie it to an owner rather than to a
// technology: the tokens a site owner puts there to prove ownership to a search engine or
// a social network, the identifiers of the analytics accounts, and the other-language versions
// the page says it has.
type Signals struct {
	// Verification maps the name of a verification meta tag (google-site-verification,
	// msvalidate.01, facebook-domain-verification, ...) to its token.
	Verification map[string]string
	// IDs are analytics and tag manager identifiers (GTM-..., G-..., UA-...), sorted.
	IDs []string
	// Alternates are the absolute URLs of <link rel="alternate" hreflang=...>.
	Alternates []string
}

var (
	verificationNames = map[string]bool{
		"google-site-verification": true, "msvalidate.01": true, "yandex-verification": true,
		"facebook-domain-verification": true, "p:domain_verify": true, "norton-safeweb-site-verification": true,
		"baidu-site-verification": true, "naver-site-verification": true, "ahrefs-site-verification": true,
	}
	idRE = regexp.MustCompile(`\b(GTM-[A-Z0-9]{4,8}|G-[A-Z0-9]{8,12}|UA-\d{4,10}-\d{1,4}|AW-\d{8,12})\b`)
)

// ExtractSignals reads the ownership signals of a page. base is the page's URL, for resolving
// relative alternates.
func ExtractSignals(body []byte, base string) Signals {
	s := Signals{Verification: map[string]string{}}
	doc, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		return s
	}
	bu, _ := NormalizeURL(nil, base)
	ids := map[string]bool{}
	var walk func(n *html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch n.Data {
			case "meta":
				name := strings.ToLower(attr(n, "name"))
				if name == "" {
					name = strings.ToLower(attr(n, "property"))
				}
				if v := strings.TrimSpace(attr(n, "content")); verificationNames[name] && v != "" {
					s.Verification[name] = v
				}
			case "link":
				if hasRel(attr(n, "rel"), "alternate") && attr(n, "hreflang") != "" {
					if u, ok := NormalizeURL(bu, attr(n, "href")); ok {
						s.Alternates = append(s.Alternates, u.String())
					}
				}
			case "script", "iframe", "img", "noscript":
				for _, v := range []string{attr(n, "src"), attr(n, "data-src")} {
					for _, m := range idRE.FindAllString(v, -1) {
						ids[m] = true
					}
				}
				if n.Data == "script" || n.Data == "noscript" {
					for c := n.FirstChild; c != nil; c = c.NextSibling {
						if c.Type == html.TextNode {
							for _, m := range idRE.FindAllString(c.Data, -1) {
								ids[m] = true
							}
						}
					}
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	for id := range ids {
		s.IDs = append(s.IDs, id)
	}
	sort.Strings(s.IDs)
	s.Alternates = dedupeStrings(s.Alternates)
	return s
}

// CertOrganization returns the organization (O=) of a certificate subject written as
// "CN=...,O=...", or "". Escaped commas are honoured.
func CertOrganization(subject string) string {
	var parts []string
	var cur strings.Builder
	esc := false
	for _, r := range subject {
		switch {
		case esc:
			cur.WriteRune(r)
			esc = false
		case r == '\\':
			esc = true
		case r == ',':
			parts = append(parts, cur.String())
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	parts = append(parts, cur.String())
	for _, p := range parts {
		if k, v, ok := strings.Cut(strings.TrimSpace(p), "="); ok && strings.EqualFold(k, "O") {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// HostOf returns the lower-cased host of a URL, "" if it has none.
func HostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

func dedupeStrings(l []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range l {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
