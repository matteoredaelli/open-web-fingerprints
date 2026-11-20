// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

// Package web extracts what a page says about the site: its links, the domains
// they point to, social profiles and contact details. It works on HTML that is
// already in memory; it never touches the network.
package web

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"sync"
)

//go:embed platforms.json
var platformsJSON []byte

type rule struct {
	Kind     string   `json:"kind"`
	Path     string   `json:"path"`
	URL      string   `json:"url"`
	Query    string   `json:"query"`   // take the handle from this query parameter
	QueryRE  string   `json:"queryre"` // and require it to match
	Reserved []string `json:"reserved"`
	KeepCase bool     `json:"keep_case"`
	Prefix   string   `json:"prefix"` // put before the handle ("@")
	Hosts    []string `json:"hosts"`  // restrict the rule to these hosts
	pathRE   *regexp.Regexp
	queryRE  *regexp.Regexp
	reserved map[string]bool
}

type platform struct {
	Platform          string   `json:"platform"`
	Hosts             []string `json:"hosts"`
	Rules             []*rule  `json:"rules"`
	Subdomain         bool     `json:"subdomain"`
	SubdomainKind     string   `json:"subdomain_kind"`
	SubdomainURL      string   `json:"subdomain_url"`
	SubdomainReserved []string `json:"subdomain_reserved"`
}

var (
	platformsOnce sync.Once
	platforms     []*platform
	platformsErr  error
)

func loadPlatforms() ([]*platform, error) {
	platformsOnce.Do(func() {
		if err := json.Unmarshal(platformsJSON, &platforms); err != nil {
			platformsErr = fmt.Errorf("platforms.json: %w", err)
			return
		}
		for _, p := range platforms {
			for _, r := range p.Rules {
				var err error
				if r.pathRE, err = regexp.Compile(r.Path); err != nil {
					platformsErr = fmt.Errorf("platform %s: %w", p.Platform, err)
					return
				}
				if r.QueryRE != "" {
					if r.queryRE, err = regexp.Compile(r.QueryRE); err != nil {
						platformsErr = fmt.Errorf("platform %s: %w", p.Platform, err)
						return
					}
				}
				r.reserved = map[string]bool{}
				for _, s := range r.Reserved {
					r.reserved[strings.ToLower(s)] = true
				}
			}
		}
	})
	return platforms, platformsErr
}

// Profile is a social profile or similar identity found in a URL.
type Profile struct {
	Platform string
	Kind     string
	Handle   string
	URL      string
}

// hostIn reports whether host is one of the domains or a subdomain of one.
func hostIn(host string, domains []string) bool {
	for _, d := range domains {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

// ParseProfile recognises a profile in a URL. Only profile URLs match: share
// links, intents, posts and product pages do not. ok is false for any URL that
// is not a profile of a known platform.
func ParseProfile(raw string) (Profile, bool) {
	ps, err := loadPlatforms()
	if err != nil {
		return Profile{}, false
	}
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return Profile{}, false
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	path, err := url.PathUnescape(u.EscapedPath())
	if err != nil {
		return Profile{}, false
	}
	for _, p := range ps {
		if !hostIn(host, p.Hosts) {
			continue
		}
		if prof, ok := p.match(host, path, u.Query()); ok {
			return prof, true
		}
	}
	return Profile{}, false
}

func (p *platform) match(host, path string, q url.Values) (Profile, bool) {
	// Blogs on a subdomain of the platform: name.tumblr.com.
	if p.Subdomain {
		for _, d := range p.Hosts {
			if strings.HasSuffix(host, "."+d) {
				sub := strings.TrimSuffix(host, "."+d)
				if !strings.Contains(sub, ".") && !contains(p.SubdomainReserved, sub) {
					return Profile{Platform: p.Platform, Kind: p.SubdomainKind, Handle: sub, URL: strings.ReplaceAll(p.SubdomainURL, "{h}", sub)}, true
				}
			}
		}
	}
	for _, r := range p.Rules {
		if len(r.Hosts) > 0 && !hostIn(host, r.Hosts) {
			continue
		}
		m := r.pathRE.FindStringSubmatch(path)
		if m == nil {
			continue
		}
		var h string
		if r.Query != "" {
			h = q.Get(r.Query)
			if h == "" || (r.queryRE != nil && !r.queryRE.MatchString(h)) {
				continue
			}
		} else {
			if len(m) < 2 || m[1] == "" {
				continue
			}
			h = m[1]
		}
		if !r.KeepCase {
			h = strings.ToLower(h)
		}
		if r.reserved[strings.ToLower(h)] {
			continue
		}
		return Profile{Platform: p.Platform, Kind: r.Kind, Handle: r.Prefix + h, URL: strings.ReplaceAll(r.URL, "{h}", h)}, true
	}
	return Profile{}, false
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// mastodonProfile recognises @user on an unknown host. It is only used for links
// that the page itself marks rel="me": on any other link, "/@name" is
// as likely a Medium or TikTok profile as a Mastodon one.
var mastodonRE = regexp.MustCompile(`^/@([A-Za-z0-9_]{1,30})/?$`)

func mastodonProfile(raw string) (Profile, bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return Profile{}, false
	}
	m := mastodonRE.FindStringSubmatch(u.EscapedPath())
	if m == nil {
		return Profile{}, false
	}
	host := strings.ToLower(u.Hostname())
	return Profile{Platform: "mastodon", Kind: "user", Handle: "@" + strings.ToLower(m[1]) + "@" + host, URL: "https://" + host + "/@" + m[1]}, true
}

// IsPlatformHost reports whether a host belongs to a social platform the table knows
// (a profile site, not a company's own site).
func IsPlatformHost(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	ps, err := loadPlatforms()
	if err != nil {
		return false
	}
	for _, p := range ps {
		if hostIn(host, p.Hosts) {
			return true
		}
	}
	return false
}

// Platforms lists the platform names the table knows.
func Platforms() []string {
	ps, err := loadPlatforms()
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(ps)+1)
	for _, p := range ps {
		out = append(out, p.Platform)
	}
	return append(out, "mastodon")
}
