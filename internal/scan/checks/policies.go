// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package checks

import (
	"strings"
	"time"

	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/robots"
	"github.com/matteoredaelli/open-web-fingerprints/scan"
)

// AIBots are the user-agent tokens of crawlers that gather content for AI services. The list
// is short and will go out of date; a crawler not in it is not reported.
var AIBots = []string{
	"GPTBot", "ChatGPT-User", "OAI-SearchBot", "ClaudeBot", "Claude-Web", "anthropic-ai",
	"Google-Extended", "PerplexityBot", "CCBot", "Bytespider", "Applebot-Extended",
	"Meta-ExternalAgent", "Amazonbot", "cohere-ai", "Diffbot",
}

const maxSitemaps = 5

// Robots summarises the text of a robots.txt (empty text: the file is not there).
func Robots(text string, present bool) *scan.RobotsCheck {
	r := &scan.RobotsCheck{Present: present}
	if !present {
		return r
	}
	named := map[string]bool{}
	for _, line := range strings.Split(strings.ReplaceAll(text, "\r", ""), "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "sitemap":
			if v = strings.TrimSpace(v); v != "" {
				r.SitemapCount++
				if len(r.Sitemaps) < maxSitemaps {
					r.Sitemaps = append(r.Sitemaps, cut(v))
				}
			}
		case "user-agent":
			named[strings.ToLower(strings.TrimSpace(v))] = true
		}
	}
	for _, b := range AIBots {
		bot := scan.AIBot{Name: b, Named: named[strings.ToLower(b)], Blocked: !robots.Parse(text, b).Allowed("/")}
		if bot.Blocked {
			r.AIBlocked++
		}
		if bot.Named {
			r.AINamed++
		}
		r.AIBots = append(r.AIBots, bot)
	}
	return r
}

// SecurityTxt reviews the answer for /.well-known/security.txt. Many sites answer every path
// with their home page, so a response counts only if it is plain text with a Contact field.
func SecurityTxt(status int, contentType string, body []byte, url string, now time.Time) *scan.SecurityTxt {
	s := &scan.SecurityTxt{Status: scan.CheckInfo, Note: "no security.txt published"}
	if status < 200 || status >= 300 || !strings.Contains(strings.ToLower(contentType), "text/plain") {
		return s
	}
	text := string(body)
	fields := map[string][]string{}
	for _, line := range strings.Split(strings.ReplaceAll(text, "\r", ""), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		k = strings.ToLower(strings.TrimSpace(k))
		fields[k] = append(fields[k], strings.TrimSpace(v))
	}
	if len(fields["contact"]) == 0 {
		return s
	}
	s.Present, s.URL, s.Contacts = true, url, len(fields["contact"])
	s.HasPolicy, s.HasEncryption = len(fields["policy"]) > 0, len(fields["encryption"]) > 0
	s.Signed = strings.Contains(text, "-----BEGIN PGP SIGNED MESSAGE-----")
	s.Status, s.Note = scan.CheckOK, ""
	switch exp := fields["expires"]; {
	case len(exp) == 0:
		s.Status, s.Note = scan.CheckWeak, "no Expires field (RFC 9116 requires one)"
	default:
		t, err := time.Parse(time.RFC3339, exp[0])
		if err != nil {
			s.Status, s.Note = scan.CheckWeak, "the Expires field is not a valid date"
			break
		}
		s.Expires = t.UTC()
		if t.Before(now) {
			s.Expired = true
			s.Status, s.Note = scan.CheckWeak, "the file has expired"
		}
	}
	return s
}

// Transport reviews the connection of a response. cert is the certificate of the host, if read.
func Transport(page scan.Page, tls *scan.TLS, now time.Time) *scan.TransportCheck {
	t := &scan.TransportCheck{Proto: page.Proto}
	t.HTTPS = strings.HasPrefix(strings.ToLower(page.FinalURL), "https://")
	if tls != nil {
		t.TLSVersion, t.ALPN = tls.Version, tls.ALPN
		if !tls.NotAfter.IsZero() {
			d := int(tls.NotAfter.Sub(now).Hours() / 24)
			t.CertDaysLeft = &d
		}
	}
	t.HTTP2 = t.ALPN == "h2" || strings.HasPrefix(t.Proto, "HTTP/2")
	for k, v := range page.Headers {
		if strings.EqualFold(k, "alt-svc") {
			t.AltSvc = cut(v)
			for _, e := range strings.Split(strings.ToLower(v), ",") {
				if n, _, ok := strings.Cut(strings.TrimSpace(e), "="); ok && (n == "h3" || strings.HasPrefix(n, "h3-")) {
					t.HTTP3Advertised = true
				}
			}
		}
	}
	if !t.HTTPS {
		t.TLSStatus, t.Note = scan.CheckWeak, "the page was served over http"
		return t
	}
	switch {
	case t.CertDaysLeft != nil && *t.CertDaysLeft < 0:
		t.TLSStatus, t.Note = scan.CheckWeak, "the certificate has expired"
	case t.TLSVersion == "TLS 1.0" || t.TLSVersion == "TLS 1.1" || strings.HasPrefix(t.TLSVersion, "SSL"):
		t.TLSStatus, t.Note = scan.CheckWeak, t.TLSVersion+" is deprecated"
	case t.TLSVersion != "":
		t.TLSStatus = scan.CheckOK
	}
	return t
}
