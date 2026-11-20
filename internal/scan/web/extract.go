// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package web

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"golang.org/x/net/html"
	"golang.org/x/net/publicsuffix"

	"github.com/matteoredaelli/open-web-fingerprints/scan"
)

// Page is the HTML of one fetched page.
type Page struct {
	URL  string // final URL of the page; relative links are resolved against it
	Body []byte
}

// Extraction is everything found in the pages of one target.
type Extraction struct {
	Links    []scan.Link
	Domains  []scan.Domain
	Socials  []scan.Social
	Contacts []scan.Contact
	Warnings []scan.Warning
}

// RegistrableDomain returns the registrable domain (eTLD+1) of a host, or the
// host itself for an IP address, a single label or a public suffix.
func RegistrableDomain(host string) string {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if d, err := publicsuffix.EffectiveTLDPlusOne(host); err == nil {
		return d
	}
	return host
}

// NormalizeURL makes a URL absolute against base and comparable: lower-case
// scheme and host, no fragment, no credentials, no default port, a path of at
// least "/". Only http and https URLs are accepted.
func NormalizeURL(base *url.URL, ref string) (*url.URL, bool) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return nil, false
	}
	u, err := url.Parse(ref)
	if err != nil {
		return nil, false
	}
	if base != nil {
		u = base.ResolveReference(u)
	}
	u.Scheme = strings.ToLower(u.Scheme)
	if (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return nil, false
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	port := u.Port()
	if (u.Scheme == "http" && port == "80") || (u.Scheme == "https" && port == "443") {
		port = ""
	}
	if strings.Contains(host, ":") { // IPv6 literal
		host = "[" + host + "]"
	}
	u.Host = host
	if port != "" {
		u.Host = host + ":" + port
	}
	u.Fragment, u.RawFragment, u.User = "", "", nil
	if u.Path == "" {
		u.Path = "/"
	}
	return u, true
}

type collector struct {
	target  string // registrable domain of the target
	links   map[string]*scan.Link
	order   []string
	socials map[string]*scan.Social
	contact map[string]*scan.Contact
	warn    []scan.Warning
}

// Extract reads the pages and returns links, domains, social profiles and
// contacts. target is the host of the scanned site; links to its registrable
// domain are internal.
func Extract(pages []Page, target string) Extraction {
	c := &collector{
		target: RegistrableDomain(target), links: map[string]*scan.Link{},
		socials: map[string]*scan.Social{}, contact: map[string]*scan.Contact{},
	}
	for _, p := range pages {
		c.page(p)
	}
	return c.result()
}

func (c *collector) page(p Page) {
	pageURL, ok := NormalizeURL(nil, p.URL)
	if !ok {
		c.warn = append(c.warn, scan.Warning{Code: "invalid_page_url", Message: "the page URL is not an http(s) URL", Ref: p.URL})
		return
	}
	doc, err := html.Parse(bytes.NewReader(p.Body))
	if err != nil {
		c.warn = append(c.warn, scan.Warning{Code: "invalid_html", Message: err.Error(), Ref: pageURL.String()})
		return
	}
	base := pageURL
	if h := firstBase(doc); h != "" {
		if b, ok := NormalizeURL(pageURL, h); ok {
			base = b
		}
	}
	pg := pageURL.String()
	var text strings.Builder
	var walk func(n *html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.TextNode && !inRawText(n.Parent) {
			text.WriteString(n.Data)
			text.WriteByte(' ')
		}
		if n.Type == html.ElementNode {
			c.element(n, base, pg)
		}
		for ch := n.FirstChild; ch != nil; ch = ch.NextSibling {
			walk(ch)
		}
	}
	walk(doc)
	for _, m := range emailInText.FindAllString(text.String(), -1) {
		if e, ok := NormalizeEmail(m); ok {
			c.addContact("email", e, pg, "text")
		}
	}
}

func inRawText(n *html.Node) bool {
	return n != nil && n.Type == html.ElementNode && (n.Data == "script" || n.Data == "style" || n.Data == "noscript" || n.Data == "template")
}

func firstBase(doc *html.Node) string {
	var out string
	var walk func(n *html.Node)
	walk = func(n *html.Node) {
		if out != "" {
			return
		}
		if n.Type == html.ElementNode && n.Data == "base" {
			if h := attr(n, "href"); h != "" {
				out = h
				return
			}
		}
		for ch := n.FirstChild; ch != nil; ch = ch.NextSibling {
			walk(ch)
		}
	}
	walk(doc)
	return out
}

func attr(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if a.Key == key {
			return a.Val
		}
	}
	return ""
}

func hasRel(rel, want string) bool {
	for _, f := range strings.Fields(strings.ToLower(rel)) {
		if f == want {
			return true
		}
	}
	return false
}

func (c *collector) element(n *html.Node, base *url.URL, page string) {
	switch n.Data {
	case "a", "area":
		c.href(attr(n, "href"), "a", attr(n, "rel"), base, page)
	case "link":
		c.href(attr(n, "href"), "link", attr(n, "rel"), base, page)
	case "script":
		if typ := strings.ToLower(attr(n, "type")); typ == "application/ld+json" {
			c.jsonLD(n, page)
		} else {
			c.href(attr(n, "src"), "script", "", base, page)
		}
	case "iframe":
		c.href(attr(n, "src"), "iframe", "", base, page)
	case "form":
		c.href(attr(n, "action"), "form", "", base, page)
	case "img", "source":
		kind := n.Data
		c.href(attr(n, "src"), kind, "", base, page)
		for _, s := range srcsetURLs(attr(n, "srcset")) {
			c.href(s, kind, "", base, page)
		}
	case "meta":
		c.meta(n, page)
	}
}

func srcsetURLs(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if f := strings.Fields(part); len(f) > 0 {
			out = append(out, f[0])
		}
	}
	return out
}

func (c *collector) href(raw, kind, rel string, base *url.URL, page string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return
	}
	low := strings.ToLower(raw)
	switch {
	case strings.HasPrefix(low, "mailto:"):
		for _, e := range mailtoAddresses(raw) {
			c.addContact("email", e, page, "a")
		}
		return
	case strings.HasPrefix(low, "tel:"):
		if t, ok := telNumber(raw); ok {
			c.addContact("phone", t, page, "a")
		}
		return
	}
	u, ok := NormalizeURL(base, raw)
	if !ok {
		return
	}
	key := kind + "\x00" + u.String() + "\x00" + page
	if _, seen := c.links[key]; !seen {
		d := RegistrableDomain(u.Hostname())
		c.links[key] = &scan.Link{URL: u.String(), Kind: kind, Rel: strings.TrimSpace(rel),
			Internal: d == c.target, Domain: d, FoundIn: page}
		c.order = append(c.order, key)
	}
	if kind != "a" && kind != "link" {
		return
	}
	via := kind
	if hasRel(rel, "me") {
		via = "rel-me"
	}
	if prof, ok := ParseProfile(u.String()); ok {
		c.addSocial(prof, page, via)
	} else if via == "rel-me" {
		if prof, ok := mastodonProfile(u.String()); ok {
			c.addSocial(prof, page, via)
		}
	}
}

func (c *collector) addSocial(p Profile, page, via string) {
	key := p.Platform + "\x00" + p.Handle
	s, ok := c.socials[key]
	if !ok {
		s = &scan.Social{Platform: p.Platform, Kind: p.Kind, Handle: p.Handle, URL: p.URL}
		c.socials[key] = s
	}
	for _, f := range s.Found {
		if f.Page == page && f.Via == via {
			return
		}
	}
	s.Found = append(s.Found, scan.Find{Page: page, Via: via})
}

func (c *collector) addContact(kind, value, page, via string) {
	key := kind + "\x00" + value
	ct, ok := c.contact[key]
	if !ok {
		ct = &scan.Contact{Kind: kind, Value: value}
		c.contact[key] = ct
	}
	for _, f := range ct.Found {
		if f.Page == page && f.Via == via {
			return
		}
	}
	ct.Found = append(ct.Found, scan.Find{Page: page, Via: via})
}

// meta reads the accounts a page declares about itself.
func (c *collector) meta(n *html.Node, page string) {
	name := strings.ToLower(attr(n, "name"))
	if name == "" {
		name = strings.ToLower(attr(n, "property"))
	}
	content := strings.TrimSpace(attr(n, "content"))
	switch name {
	case "twitter:site", "twitter:creator":
		h := strings.TrimPrefix(content, "@")
		if h != "" && !strings.ContainsAny(h, "/ ") {
			if p, ok := ParseProfile("https://x.com/" + h); ok {
				c.addSocial(p, page, "meta")
			}
		}
	case "og:email":
		if e, ok := NormalizeEmail(content); ok {
			c.addContact("email", e, page, "meta")
		}
	case "og:phone_number":
		if t, ok := NormalizePhone(content); ok {
			c.addContact("phone", t, page, "meta")
		}
	}
}

// jsonLD reads sameAs, telephone and email from structured data.
func (c *collector) jsonLD(n *html.Node, page string) {
	var sb strings.Builder
	for ch := n.FirstChild; ch != nil; ch = ch.NextSibling {
		if ch.Type == html.TextNode {
			sb.WriteString(ch.Data)
		}
	}
	raw := strings.TrimSpace(sb.String())
	if raw == "" {
		return
	}
	var v any
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		c.warn = append(c.warn, scan.Warning{Code: "invalid_jsonld", Message: err.Error(), Ref: page})
		return
	}
	c.walkLD(v, page, 0)
}

func (c *collector) walkLD(v any, page string, depth int) {
	if depth > 12 {
		return
	}
	switch x := v.(type) {
	case []any:
		for _, e := range x {
			c.walkLD(e, page, depth+1)
		}
	case map[string]any:
		for k, e := range x {
			switch k {
			case "sameAs":
				for _, s := range stringsOf(e) {
					if u, ok := NormalizeURL(nil, s); ok {
						if p, ok := ParseProfile(u.String()); ok {
							c.addSocial(p, page, "jsonld")
						}
					}
				}
			case "telephone":
				for _, s := range stringsOf(e) {
					if t, ok := NormalizePhone(s); ok {
						c.addContact("phone", t, page, "jsonld")
					}
				}
			case "email":
				for _, s := range stringsOf(e) {
					if m, ok := NormalizeEmail(strings.TrimPrefix(strings.ToLower(s), "mailto:")); ok {
						c.addContact("email", m, page, "jsonld")
					}
				}
			default:
				c.walkLD(e, page, depth+1)
			}
		}
	}
}

func stringsOf(v any) []string {
	switch x := v.(type) {
	case string:
		return []string{x}
	case []any:
		var out []string
		for _, e := range x {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func (c *collector) result() Extraction {
	var ex Extraction
	ex.Links = make([]scan.Link, 0, len(c.order))
	for _, k := range c.order {
		ex.Links = append(ex.Links, *c.links[k])
	}
	doms := map[string]*scan.Domain{}
	for _, l := range ex.Links {
		d := doms[l.Domain]
		if d == nil {
			d = &scan.Domain{Domain: l.Domain, Internal: l.Internal}
			doms[l.Domain] = d
		}
		d.Links++
		if len(d.Examples) < 3 {
			d.Examples = append(d.Examples, l.URL)
		}
	}
	ex.Domains = make([]scan.Domain, 0, len(doms))
	for _, d := range doms {
		ex.Domains = append(ex.Domains, *d)
	}
	sort.Slice(ex.Domains, func(i, j int) bool {
		a, b := ex.Domains[i], ex.Domains[j]
		if a.Internal != b.Internal {
			return a.Internal
		}
		if a.Links != b.Links {
			return a.Links > b.Links
		}
		return a.Domain < b.Domain
	})
	ex.Socials = make([]scan.Social, 0, len(c.socials))
	for _, s := range c.socials {
		ex.Socials = append(ex.Socials, *s)
	}
	sort.Slice(ex.Socials, func(i, j int) bool {
		a, b := ex.Socials[i], ex.Socials[j]
		if a.Platform != b.Platform {
			return a.Platform < b.Platform
		}
		return a.Handle < b.Handle
	})
	ex.Contacts = make([]scan.Contact, 0, len(c.contact))
	for _, ct := range c.contact {
		ex.Contacts = append(ex.Contacts, *ct)
	}
	sort.Slice(ex.Contacts, func(i, j int) bool {
		a, b := ex.Contacts[i], ex.Contacts[j]
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return a.Value < b.Value
	})
	ex.Warnings = append([]scan.Warning{}, c.warn...)
	return ex
}

// String summarises the extraction in one line.
func (e Extraction) String() string {
	return fmt.Sprintf("%d links, %d domains, %d social profiles, %d contacts", len(e.Links), len(e.Domains), len(e.Socials), len(e.Contacts))
}
