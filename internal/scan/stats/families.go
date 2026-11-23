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
	FamilyBusiness  = "Marketing, support and business tools"
	FamilySignals   = "Standards and page signals"
	FamilyOther     = "Other"
)

// familyOrder is the priority of the families and the order they are listed in.
var familyOrder = []string{
	FamilyCMS, FamilyCommerce, FamilyFramework, FamilyLibraries, FamilyInfra, FamilyServers,
	FamilyAnalytics, FamilyBusiness, FamilySecurity, FamilySignals, FamilyOther,
}

// categoryFamily maps a registry category to a family. Unknown categories fall to Other.
var categoryFamily = map[string]string{
	"CMS": FamilyCMS, "Blogs": FamilyCMS, "Page builders": FamilyCMS, "Wikis": FamilyCMS,
	"WordPress plugins": FamilyCMS, "WordPress themes": FamilyCMS, "Comment systems": FamilyCMS,
	"Editors": FamilyCMS, "Rich text editors": FamilyCMS, "Digital asset management": FamilyCMS,
	"Message boards": FamilyCMS, "Photo galleries": FamilyCMS,
	"Shopify apps": FamilyCommerce, "Shopify themes": FamilyCommerce, "Ecommerce app": FamilyCommerce,
	"Ecommerce frontends": FamilyCommerce, "Shipping carriers": FamilyCommerce, "Buy now pay later": FamilyCommerce,
	"Cart abandonment": FamilyCommerce, "Returns": FamilyCommerce, "Fulfilment": FamilyCommerce,
	"Cross border ecommerce": FamilyCommerce, "Reservations & delivery": FamilyCommerce,
	"Ticket booking": FamilyCommerce, "Loyalty & rewards": FamilyCommerce,
	"Ecommerce": FamilyCommerce, "Payment processors": FamilyCommerce, "Shopping cart": FamilyCommerce,
	"JavaScript frameworks": FamilyFramework, "Web frameworks": FamilyFramework, "UI frameworks": FamilyFramework,
	"Mobile frameworks": FamilyFramework, "Programming languages": FamilyFramework,
	"Static site generator": FamilyFramework, "Devops": FamilyFramework, "Operating systems": FamilyInfra, "Development": FamilyFramework,
	"JavaScript libraries": FamilyLibraries, "Font scripts": FamilyLibraries, "Video players": FamilyLibraries,
	"Livestreaming": FamilyLibraries, "JavaScript graphics": FamilyLibraries, "Widgets": FamilyLibraries,
	"Augmented reality": FamilyLibraries, "Maps": FamilyLibraries,
	"CDN": FamilyInfra, "Hosting": FamilyInfra, "PaaS": FamilyInfra, "Caching": FamilyInfra,
	"Load balancers": FamilyInfra, "IaaS": FamilyInfra, "Containers": FamilyInfra, "Hosting panels": FamilyInfra, "Platform": FamilyInfra,
	"Web servers": FamilyServers, "Reverse proxies": FamilyServers, "Web server extensions": FamilyServers,
	"Analytics": FamilyAnalytics, "Tag managers": FamilyAnalytics, "Advertising": FamilyAnalytics,
	"RUM": FamilyAnalytics, "A/B testing": FamilyAnalytics, "A/B Testing": FamilyAnalytics, "Marketing automation": FamilyAnalytics,
	"Live chat": FamilyBusiness, "CRM": FamilyBusiness, "Appointment scheduling": FamilyBusiness,
	"Personalisation": FamilyBusiness, "Reviews": FamilyBusiness, "Affiliate programs": FamilyBusiness,
	"Customer data platform": FamilyBusiness, "Form builders": FamilyBusiness, "Surveys": FamilyBusiness,
	"Email": FamilyBusiness, "Referral marketing": FamilyBusiness, "Retargeting": FamilyBusiness,
	"Segmentation": FamilyBusiness, "User onboarding": FamilyBusiness, "Support": FamilyBusiness,
	"Recruitment & staffing": FamilyBusiness, "Fundraising & donations": FamilyBusiness, "LMS": FamilyBusiness,
	"SEO": FamilyBusiness, "Issue trackers": FamilyBusiness, "Accounting": FamilyBusiness,
	"Feature management": FamilyBusiness, "Documentation": FamilyBusiness,
	"Search engines": FamilyBusiness, "Translation": FamilyBusiness,
	"Security": FamilySecurity, "Cookie compliance": FamilySecurity, "SSL/TLS certificate authorities": FamilySecurity,
	"Authentication": FamilySecurity,
	"Miscellaneous":  FamilySignals, "Performance": FamilySignals,
}

// signalNames are technologies that describe a page feature or a header, not a product
// somebody chose; a name wins over the categories (HSTS is filed under Security).
var signalNames = map[string]bool{
	"html5": true, "hsts": true, "email": true, "modern-security-headers": true, "x-ua-compatible": true,
	"opensearch": true, "open graph": true, "open-graph-protocol": true, "http/3": true, "pwa": true,
	"rss": true, "priority hints": true, "script": true,
	"cart functionality": true, "frame": true, "object": true,
}

// nameFamily places technologies that have no category (many WhatWeb rules) by name, in
// lower case. Used only when the categories give nothing but Other.
var nameFamily = map[string]string{
	"cloudflare load balancer": FamilyInfra, "cloudfront load balancer": FamilyInfra,
	"application load balancer": FamilyInfra, "s3": FamilyInfra, "alibaba-aliyun": FamilyInfra,
	"google web services": FamilyInfra, "google frontend httpserver": FamilyInfra,
	"apache": FamilyServers, "apache httpd": FamilyServers, "tengine-web-server": FamilyServers,
	"envoy proxy envoy": FamilyServers, "istio envoy": FamilyServers,
	"intercom widget": FamilyBusiness, "sentry instance": FamilyAnalytics,
	"datadog browser rum": FamilyAnalytics, "fullstory rum": FamilyAnalytics,
	"zurb foundation framework": FamilyFramework, "bitrix-site-manager": FamilyCMS,
	"passwordfield": FamilySignals, "dublincore": FamilySignals, "meta-geo": FamilySignals,
	"openid": FamilySignals, "google firebase db url": FamilyInfra,
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
	if best == len(familyOrder) || familyOrder[best] == FamilyOther {
		if f, ok := nameFamily[strings.ToLower(name)]; ok {
			return f
		}
	}
	if best == len(familyOrder) {
		return FamilyOther
	}
	return familyOrder[best]
}
