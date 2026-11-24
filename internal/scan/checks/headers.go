// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

// Package checks makes passive observations about a site and its domain that are not
// registry fingerprints: the security headers and cookie attributes of a response, and the
// mail and name server records of the domain. It reads data the scanner already has, or
// asks DNS; it never sends an HTTP request of its own. It states facts and the usual
// recommendation, with no score and no claim that a site is "secure" or not.
package checks

import (
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/matteoredaelli/open-web-fingerprints/scan"
)

const maxValue = 200

const headersNote = "Only the first page was read, over one request: another page, a browser or a different client " +
	"can receive other headers (a CDN may vary them), and a policy can also be set in a <meta> tag."

// Headers reviews the response headers and cookies of one page. headers is the response
// header map (any case); setCookies are the Set-Cookie lines.
func Headers(page string, headers map[string]string, setCookies []string) *scan.HeaderChecks {
	h := map[string]string{}
	for k, v := range headers {
		h[strings.ToLower(k)] = v
	}
	u, _ := url.Parse(page)
	https := u != nil && u.Scheme == "https"
	out := &scan.HeaderChecks{Page: page, HTTPS: https, Note: headersNote, Headers: []scan.HeaderCheck{}, Cookies: []scan.CookieCheck{}}

	csp, hasCSP := h["content-security-policy"]
	add := func(name string, f func(v string, ok bool) (string, string)) {
		v, ok := h[name]
		st, note := f(v, ok)
		c := scan.HeaderCheck{Name: name, Present: ok, Status: st, Note: note}
		if ok {
			c.Value = cut(v)
		}
		out.Headers = append(out.Headers, c)
		switch st {
		case scan.CheckOK:
			out.OK++
		case scan.CheckWeak:
			out.Weak++
		case scan.CheckMissing:
			out.Missing++
		}
	}

	add("strict-transport-security", func(v string, ok bool) (string, string) {
		switch {
		case !https:
			return scan.CheckInfo, "the page was served over http: browsers ignore the header there"
		case !ok:
			return scan.CheckMissing, "browsers are not told to use https only"
		}
		age := hstsMaxAge(v)
		switch {
		case age < 0:
			return scan.CheckWeak, "no valid max-age"
		case age < 15552000:
			return scan.CheckWeak, "max-age is under 180 days"
		}
		note := ""
		if !strings.Contains(strings.ToLower(v), "includesubdomains") {
			note = "subdomains are not covered (no includeSubDomains)"
		}
		return scan.CheckOK, note
	})
	add("content-security-policy", func(v string, ok bool) (string, string) {
		if !ok {
			if _, has := h["content-security-policy-report-only"]; has {
				return scan.CheckInfo, "only a report-only policy is set: it reports violations but blocks nothing"
			}
			return scan.CheckMissing, "no policy limits where scripts and other content may load from"
		}
		return cspStatus(v)
	})
	add("x-frame-options", func(v string, ok bool) (string, string) {
		if !ok {
			if hasCSP && hasDirective(csp, "frame-ancestors") {
				return scan.CheckOK, "framing is limited by the CSP frame-ancestors directive"
			}
			return scan.CheckMissing, "the page can be framed by other sites (and no CSP frame-ancestors)"
		}
		switch strings.ToUpper(strings.TrimSpace(v)) {
		case "DENY", "SAMEORIGIN":
			return scan.CheckOK, ""
		}
		return scan.CheckWeak, "the value is not DENY or SAMEORIGIN (ALLOW-FROM is obsolete)"
	})
	add("x-content-type-options", func(v string, ok bool) (string, string) {
		switch {
		case !ok:
			return scan.CheckMissing, "browsers may guess content types"
		case strings.EqualFold(strings.TrimSpace(v), "nosniff"):
			return scan.CheckOK, ""
		}
		return scan.CheckWeak, "the only valid value is nosniff"
	})
	add("referrer-policy", func(v string, ok bool) (string, string) {
		if !ok {
			return scan.CheckInfo, "not set: browsers apply their default (strict-origin-when-cross-origin in current ones)"
		}
		for _, p := range strings.Split(strings.ToLower(v), ",") {
			switch strings.TrimSpace(p) {
			case "unsafe-url", "no-referrer-when-downgrade":
				return scan.CheckWeak, "sends the full URL to other sites"
			}
		}
		return scan.CheckOK, ""
	})
	for _, n := range []string{"permissions-policy", "cross-origin-opener-policy", "cross-origin-embedder-policy", "cross-origin-resource-policy"} {
		add(n, func(_ string, ok bool) (string, string) {
			if ok {
				return scan.CheckOK, ""
			}
			return scan.CheckInfo, "optional, not set"
		})
	}
	for _, n := range []string{"server", "x-powered-by", "x-aspnet-version", "x-generator"} {
		add(n, func(v string, ok bool) (string, string) {
			switch {
			case !ok:
				return scan.CheckOK, "not disclosed"
			case hasVersion(v):
				return scan.CheckWeak, "discloses a software version"
			}
			return scan.CheckInfo, "discloses the software, without a version"
		})
	}
	out.Cookies = cookies(setCookies, https)
	return out
}

func cut(s string) string {
	r := []rune(s)
	if len(r) > maxValue {
		return string(r[:maxValue]) + "…"
	}
	return s
}

func hstsMaxAge(v string) int {
	for _, p := range strings.Split(v, ";") {
		k, val, ok := strings.Cut(strings.TrimSpace(p), "=")
		if ok && strings.EqualFold(strings.TrimSpace(k), "max-age") {
			n, err := strconv.Atoi(strings.Trim(strings.TrimSpace(val), `"`))
			if err != nil || n < 0 {
				return -1
			}
			return n
		}
	}
	return -1
}

var versionRe = regexp.MustCompile(`\d+\.\d+|/\d+`)

func hasVersion(v string) bool { return versionRe.MatchString(v) }

// directives parses a CSP into directive -> sources.
func directives(csp string) map[string][]string {
	out := map[string][]string{}
	for _, d := range strings.Split(csp, ";") {
		f := strings.Fields(strings.TrimSpace(d))
		if len(f) == 0 {
			continue
		}
		name := strings.ToLower(f[0])
		if _, dup := out[name]; !dup { // the first occurrence counts
			out[name] = f[1:]
		}
	}
	return out
}

func hasDirective(csp, name string) bool {
	_, ok := directives(csp)[name]
	return ok
}

func cspStatus(csp string) (string, string) {
	d := directives(csp)
	src, ok := d["script-src"]
	which := "script-src"
	if !ok {
		if src, ok = d["default-src"]; ok {
			which = "default-src"
		}
	}
	if !ok {
		return scan.CheckWeak, "no script-src or default-src: scripts are not restricted"
	}
	var nonceOrHash, dynamic bool
	for _, s := range src {
		l := strings.ToLower(strings.Trim(s, "'"))
		if strings.HasPrefix(l, "nonce-") || strings.HasPrefix(l, "sha256-") || strings.HasPrefix(l, "sha384-") || strings.HasPrefix(l, "sha512-") {
			nonceOrHash = true
		}
		if l == "strict-dynamic" {
			dynamic = true
		}
	}
	var issues []string
	for _, s := range src {
		switch l := strings.ToLower(s); {
		case l == "'unsafe-inline'" && !nonceOrHash && !dynamic:
			issues = append(issues, "'unsafe-inline'")
		case l == "'unsafe-eval'":
			issues = append(issues, "'unsafe-eval'")
		case l == "*", l == "data:", l == "http:":
			issues = append(issues, s)
		}
	}
	if len(issues) > 0 {
		return scan.CheckWeak, which + " allows " + strings.Join(issues, ", ")
	}
	return scan.CheckOK, ""
}

func cookies(lines []string, https bool) []scan.CookieCheck {
	out := []scan.CookieCheck{}
	seen := map[string]bool{}
	for _, l := range lines {
		c, err := http.ParseSetCookie(l)
		if err != nil || c.Name == "" || seen[c.Name] {
			continue
		}
		seen[c.Name] = true
		cc := scan.CookieCheck{Name: c.Name, Secure: c.Secure, HTTPOnly: c.HttpOnly}
		switch c.SameSite {
		case http.SameSiteLaxMode:
			cc.SameSite = "lax"
		case http.SameSiteStrictMode:
			cc.SameSite = "strict"
		case http.SameSiteNoneMode:
			cc.SameSite = "none"
		}
		if https && !c.Secure {
			cc.Issues = append(cc.Issues, "no_secure")
		}
		if !c.HttpOnly {
			cc.Issues = append(cc.Issues, "no_httponly")
		}
		if cc.SameSite == "" {
			cc.Issues = append(cc.Issues, "no_samesite")
		}
		if cc.SameSite == "none" && !c.Secure {
			cc.Issues = append(cc.Issues, "samesite_none_without_secure")
		}
		out = append(out, cc)
	}
	return out
}
