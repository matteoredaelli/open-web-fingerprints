// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package stats

import "strings"

// Family is a coarse group of technologies that answers "what kind of thing is it": a
// CMS, a web server, a CDN. The registry's categories are many and overlap (Next.js is a
// JavaScript framework, a static site generator and a web server), so each technology is
// given one family: the first of this list that one of its categories belongs to.
const (
	FamilyCMS       = "CMS and publishing"
	FamilyCommerce  = "E-commerce and payments"
	FamilyFramework = "Frameworks and languages"
	FamilyLibraries = "Libraries, fonts and media"
	FamilyInfra     = "CDN, hosting and caching"
	FamilyServers   = "Web servers and proxies"
	FamilyAnalytics = "Analytics, tags and advertising"
	FamilySecurity  = "Security, privacy and certificates"
	FamilySignals   = "Standards and page signals"
	FamilyOther     = "Other"
)

// familyOrder is the priority of the families and the order they are listed in.
var familyOrder = []string{
	FamilyCMS, FamilyCommerce, FamilyFramework, FamilyLibraries, FamilyInfra, FamilyServers,
	FamilyAnalytics, FamilySecurity, FamilySignals, FamilyOther,
}

// categoryFamily maps a registry category to a family. Unknown categories fall to Other.
var categoryFamily = map[string]string{
	"CMS": FamilyCMS, "Blogs": FamilyCMS, "Page builders": FamilyCMS, "Wikis": FamilyCMS,
	"Message boards": FamilyCMS, "Documentation": FamilyCMS, "Photo galleries": FamilyCMS,
	"Ecommerce": FamilyCommerce, "Payment processors": FamilyCommerce, "Shopping cart": FamilyCommerce,
	"JavaScript frameworks": FamilyFramework, "Web frameworks": FamilyFramework, "UI frameworks": FamilyFramework,
	"Mobile frameworks": FamilyFramework, "Programming languages": FamilyFramework,
	"Static site generator": FamilyFramework, "Development": FamilyFramework,
	"JavaScript libraries": FamilyLibraries, "Font scripts": FamilyLibraries, "Video players": FamilyLibraries,
	"Livestreaming": FamilyLibraries, "Maps": FamilyLibraries,
	"CDN": FamilyInfra, "Hosting": FamilyInfra, "PaaS": FamilyInfra, "Caching": FamilyInfra,
	"Load balancers": FamilyInfra, "Platform": FamilyInfra,
	"Web servers": FamilyServers, "Reverse proxies": FamilyServers, "Web server extensions": FamilyServers,
	"Analytics": FamilyAnalytics, "Tag managers": FamilyAnalytics, "Advertising": FamilyAnalytics,
	"RUM": FamilyAnalytics, "A/B testing": FamilyAnalytics, "Marketing automation": FamilyAnalytics,
	"Security": FamilySecurity, "Cookie compliance": FamilySecurity, "SSL/TLS certificate authorities": FamilySecurity,
	"Authentication": FamilySecurity,
	"Miscellaneous":  FamilySignals, "Performance": FamilySignals,
}

// signalNames are technologies that describe a page feature or a header, not a product
// somebody chose; a name wins over the categories (HSTS is filed under Security).
var signalNames = map[string]bool{
	"html5": true, "hsts": true, "email": true, "modern-security-headers": true, "x-ua-compatible": true,
	"opensearch": true, "open graph": true, "open-graph-protocol": true, "http/3": true, "pwa": true,
	"rss": true, "priority hints": true, "script": true, "frame": true, "object": true,
}

// FamilyOf gives the family of a technology.
func FamilyOf(name string, categories []string) string {
	if signalNames[strings.ToLower(name)] {
		return FamilySignals
	}
	best := len(familyOrder)
	for _, c := range categories {
		f, ok := categoryFamily[c]
		if !ok {
			f = FamilyOther
		}
		for i, o := range familyOrder {
			if o == f && i < best {
				best = i
			}
		}
	}
	if best == len(familyOrder) {
		return FamilyOther
	}
	return familyOrder[best]
}
