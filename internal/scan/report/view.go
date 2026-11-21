// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package report

import (
	"fmt"
	"hash/fnv"
	"html/template"
	"net/url"
	"sort"
	"strings"

	"github.com/matteoredaelli/open-web-fingerprints/scan"
)

type stat struct {
	Value int
	Label string
}

type evView struct {
	Observation, Target, Matched, Health, Source string
	Group                                        bool
	Version                                      string
}

type techView struct {
	Name, Vendor, Version, Initial string
	Confidence                     int
	Health                         string
	Sources                        []string
	Evidence                       []evView
	Extra                          int // evidence beyond the ones listed
	SameName                       int
	Hue                            template.CSS
	Width                          template.CSS
	Categories                     string
}

type group struct {
	Name  string
	Count int
	Hue   template.CSS
	Techs []techView
}

type glance struct{ Label, Value string }

type impliedView struct {
	Name, By string
	Conf     int
}

type suppressedView struct {
	Name, Why string
	Conf      int
}

type dnsRow struct {
	Type   string
	Values []string
}

type tlsView struct {
	Issuer, Subject, NotAfter, Version string
	DaysLeft                           int
	Class                              string // ok, soon, expired
	Names                              []string
}

type secRow struct {
	Name, Value, Note string
	Present           bool
}

type socialView struct {
	Platform, Kind, Handle, URL, Initial string
	Hue                                  template.CSS
}

type contactView struct {
	Kind, Value string
	Href        template.URL // mailto: or tel:, built here from characters that cannot break out
}

type domainBar struct {
	Domain string
	Links  int
	Width  template.CSS
}

type netItem struct {
	Domain, Level, Detail, URL string
	Evidence                   []netEv
}

type netEv struct{ Kind, Strength, Detail string }

type skipRow struct {
	Reason string
	N      int
	Width  template.CSS
}

type pageRow struct {
	Status int
	URL    string
	Bytes  int
	Class  string
}

type view struct {
	Title, Domain, URL, ScannedAt, Scanner string
	Status                                 int
	StatusClass                            string
	Notice                                 string
	Stats                                  []stat
	Glance                                 []glance
	Groups                                 []group
	Donut                                  template.HTML
	Implied                                []impliedView
	Suppressed                             []suppressedView
	IPs                                    []string
	DNS                                    []dnsRow
	TLS                                    *tlsView
	Security                               []secRow
	SecPresent, SecTotal                   int
	HeadersFiltered                        bool
	Socials                                []socialView
	Contacts                               []contactView
	Domains                                []domainBar
	MoreDomains                            int
	HasNetwork                             bool
	Graph                                  template.HTML
	Friends                                []netItem
	FriendsChecked, FriendsCandidates      int
	Related                                []netItem
	RelatedProbable, RelatedChecked        int
	RelatedCandidates                      int
	HasFriends, HasRelated                 bool
	Total, Evaluated, Pct                  int
	Skipped                                []skipRow
	Pages                                  []pageRow
	Warnings                               []scan.Warning
	Browser, Active                        string
	RegistryShort                          string
	RegistrySources                        string
	TechCount, HealthOK                    int
}

// categoryOrder puts the categories people look for first. Others follow alphabetically.
var categoryOrder = []string{
	"CMS", "Ecommerce", "Blogs", "Static site generator", "Web frameworks", "JavaScript frameworks",
	"Programming languages", "Web servers", "Reverse proxies", "CDN", "PaaS", "IaaS", "Hosting",
	"Databases", "Analytics", "Tag managers", "Advertising", "Marketing automation", "Security",
	"Cookie compliance", "Payment processors", "Live chat", "CRM", "Search engines", "Font scripts",
	"JavaScript libraries", "UI frameworks", "Web server extensions", "Miscellaneous",
}

func rank(c string) int {
	for i, o := range categoryOrder {
		if strings.EqualFold(o, c) {
			return i
		}
	}
	return len(categoryOrder)
}

// primary picks the category a technology is listed under: the best ranked of its own.
func primary(cats []string) string {
	if len(cats) == 0 {
		return "Other"
	}
	best := cats[0]
	for _, c := range cats[1:] {
		if rank(c) < rank(best) || (rank(c) == rank(best) && c < best) {
			best = c
		}
	}
	return best
}

func hue(s string) int {
	h := fnv.New32a()
	_, _ = h.Write([]byte(strings.ToLower(s)))
	return int(h.Sum32() % 360)
}

func hueCSS(s string) template.CSS {
	return template.CSS(fmt.Sprintf("--h:%d", hue(s))) //nolint:gosec // an integer
}

func widthCSS(pct int) template.CSS {
	if pct < 0 {
		pct = 0
	}
	if pct > 100 {
		pct = 100
	}
	return template.CSS(fmt.Sprintf("width:%d%%", pct)) //nolint:gosec // an integer
}

func initial(s string) string {
	for _, r := range s {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
			return strings.ToUpper(string(r))
		}
	}
	return "?"
}

var healthRank = map[string]int{"broken": 0, "degraded": 1, "unknown": 2, "ok": 3}

const maxEvidenceShown = 6

// safeURL returns the URL when it is http or https, else "". Everything in a result
// comes from a site and from a file that may not be ours: no javascript: or data: links.
func safeURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return ""
	}
	return u.String()
}

func short(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

var securityHeaders = []struct{ Name, Header, Note string }{
	{"HSTS", "strict-transport-security", "Browsers keep to HTTPS."},
	{"Content-Security-Policy", "content-security-policy", "Limits where scripts and content may load from."},
	{"X-Frame-Options", "x-frame-options", "Limits framing of the page."},
	{"X-Content-Type-Options", "x-content-type-options", "Stops content-type guessing."},
	{"Referrer-Policy", "referrer-policy", "Says how much of the address is passed on."},
	{"Permissions-Policy", "permissions-policy", "Limits browser features the page may use."},
}

func build(r *scan.Result, opt Options) view {
	v := view{
		Domain: r.Target.RegistrableDomain, URL: r.Target.URL, Scanner: r.Scanner,
		ScannedAt: r.ScannedAt.UTC().Format("2 Jan 2006, 15:04 UTC"),
		Notice:    r.Registry.Notice, TechCount: len(r.Technologies),
	}
	if v.Domain == "" {
		v.Domain = r.Target.Host
	}
	v.Title = opt.Title
	if v.Title == "" {
		v.Title = v.Domain
	}
	if len(r.Pages) > 0 {
		v.Status = r.Pages[0].Status
		switch {
		case v.Status >= 200 && v.Status < 300:
			v.StatusClass = "ok"
		case v.Status >= 300 && v.Status < 400:
			v.StatusClass = "soon"
		default:
			v.StatusClass = "bad"
		}
		v.HeadersFiltered = r.Pages[0].HeadersFiltered
		for _, p := range r.Pages {
			c := "ok"
			if p.Status >= 400 || p.Status == 0 {
				c = "bad"
			}
			v.Pages = append(v.Pages, pageRow{Status: p.Status, URL: p.FinalURL, Bytes: p.Bytes, Class: c})
		}
	}

	// Technologies, grouped.
	groups := map[string]*group{}
	for _, t := range r.Technologies {
		cat := primary(t.Categories)
		g := groups[cat]
		if g == nil {
			g = &group{Name: cat, Hue: hueCSS(cat)}
			groups[cat] = g
		}
		tv := techView{
			Name: t.Name, Vendor: t.Vendor, Version: t.Version, Initial: initial(t.Name),
			Confidence: int(t.Confidence*100 + 0.5), Sources: t.Sources, SameName: len(t.SameName),
			Hue: hueCSS(cat), Categories: strings.Join(t.Categories, ", "), Health: "broken",
		}
		tv.Width = widthCSS(tv.Confidence)
		for _, e := range t.Evidence {
			if healthRank[e.Health] >= healthRank[tv.Health] {
				tv.Health = e.Health
			}
		}
		if len(t.Evidence) == 0 {
			tv.Health = "unknown"
		}
		if tv.Health == "ok" {
			v.HealthOK++
		}
		for i, e := range t.Evidence {
			if i >= maxEvidenceShown {
				tv.Extra = len(t.Evidence) - maxEvidenceShown
				break
			}
			tv.Evidence = append(tv.Evidence, evView{
				Observation: e.Observation, Target: e.Target, Matched: short(e.Matched, 120),
				Health: e.Health, Source: e.Source, Group: e.Group != "", Version: e.Version,
			})
		}
		g.Techs = append(g.Techs, tv)
		g.Count++
	}
	for _, g := range groups {
		sort.Slice(g.Techs, func(i, j int) bool {
			if g.Techs[i].Confidence != g.Techs[j].Confidence {
				return g.Techs[i].Confidence > g.Techs[j].Confidence
			}
			return g.Techs[i].Name < g.Techs[j].Name
		})
		v.Groups = append(v.Groups, *g)
	}
	sort.Slice(v.Groups, func(i, j int) bool {
		ri, rj := rank(v.Groups[i].Name), rank(v.Groups[j].Name)
		if ri != rj {
			return ri < rj
		}
		return v.Groups[i].Name < v.Groups[j].Name
	})
	v.Donut = donut(v.Groups)

	// At a glance: the first technology of the categories people ask about.
	for _, label := range []string{"CMS", "Ecommerce", "Web frameworks", "JavaScript frameworks", "Web servers", "CDN", "PaaS", "Hosting", "Analytics", "Tag managers"} {
		for _, g := range v.Groups {
			if strings.EqualFold(g.Name, label) && len(g.Techs) > 0 {
				names := make([]string, 0, 2)
				for i, t := range g.Techs {
					if i == 2 {
						break
					}
					n := t.Name
					if t.Version != "" {
						n += " " + t.Version
					}
					names = append(names, n)
				}
				v.Glance = append(v.Glance, glance{Label: label, Value: strings.Join(names, ", ")})
			}
		}
	}

	for _, im := range r.Implied {
		v.Implied = append(v.Implied, impliedView{Name: im.Name, By: strings.Join(im.ImpliedBy, ", "), Conf: int(im.Confidence*100 + 0.5)})
	}
	for _, s := range r.Suppressed {
		why := "excluded by " + strings.Join(s.By, ", ")
		if s.Reason == scan.SuppressedRequirement {
			why = "needs one of " + strings.Join(s.By, ", ")
		}
		v.Suppressed = append(v.Suppressed, suppressedView{Name: s.Name, Why: why, Conf: int(s.Confidence*100 + 0.5)})
	}

	// Host.
	if h := r.Host; h != nil {
		v.IPs = h.IPs
		types := make([]string, 0, len(h.DNS))
		for k := range h.DNS {
			types = append(types, k)
		}
		sort.Strings(types)
		for _, k := range types {
			v.DNS = append(v.DNS, dnsRow{Type: k, Values: h.DNS[k]})
		}
		if t := h.TLS; t != nil {
			tv := &tlsView{Issuer: t.Issuer, Subject: t.Subject, Version: t.Version, Names: t.DNSNames}
			if !t.NotAfter.IsZero() {
				tv.NotAfter = t.NotAfter.UTC().Format("2 Jan 2006")
				tv.DaysLeft = int(t.NotAfter.Sub(r.ScannedAt).Hours() / 24)
				switch {
				case tv.DaysLeft < 0:
					tv.Class = "bad"
				case tv.DaysLeft < 30:
					tv.Class = "soon"
				default:
					tv.Class = "ok"
				}
			}
			if len(tv.Names) > 8 {
				tv.Names = tv.Names[:8]
			}
			v.TLS = tv
		}
	}

	// Security headers of the first page.
	if len(r.Pages) > 0 {
		h := r.Pages[0].Headers
		for _, s := range securityHeaders {
			val, ok := h[s.Header]
			row := secRow{Name: s.Name, Present: ok, Note: s.Note, Value: short(val, 90)}
			if ok {
				v.SecPresent++
			}
			v.Security = append(v.Security, row)
		}
		v.SecTotal = len(securityHeaders)
	}

	// People and places.
	for _, s := range r.Socials {
		v.Socials = append(v.Socials, socialView{Platform: s.Platform, Kind: s.Kind, Handle: s.Handle, URL: safeURL(s.URL), Initial: initial(s.Platform), Hue: hueCSS(s.Platform)})
	}
	for _, c := range r.Contacts {
		var href template.URL
		switch c.Kind {
		case "email":
			href = template.URL("mailto:" + strings.Replace(url.PathEscape(c.Value), "%40", "@", 1)) //nolint:gosec // path-escaped
		case "phone":
			//nolint:gosec // only digits and + survive
			href = template.URL("tel:" + strings.Map(func(r rune) rune {
				if r == '+' || (r >= '0' && r <= '9') {
					return r
				}
				return -1
			}, c.Value))
		}
		v.Contacts = append(v.Contacts, contactView{Kind: c.Kind, Value: c.Value, Href: href})
	}
	var ext []scan.Domain
	for _, d := range r.Domains {
		if !d.Internal {
			ext = append(ext, d)
		}
	}
	sort.SliceStable(ext, func(i, j int) bool { return ext[i].Links > ext[j].Links })
	maxLinks := 1
	if len(ext) > 0 {
		maxLinks = ext[0].Links
	}
	for i, d := range ext {
		if i == 12 {
			v.MoreDomains = len(ext) - 12
			break
		}
		v.Domains = append(v.Domains, domainBar{Domain: d.Domain, Links: d.Links, Width: widthCSS(d.Links * 100 / maxLinks)})
	}

	// Network.
	if f := r.Friends; f != nil {
		v.HasFriends, v.FriendsChecked, v.FriendsCandidates = true, f.Checked, f.Candidates
		for _, d := range f.Domains {
			if d.Status == scan.FriendYes {
				v.Friends = append(v.Friends, netItem{Domain: d.Domain, Level: "friend", Detail: d.Detail, URL: safeURL(d.URL)})
			}
		}
	}
	if rl := r.Related; rl != nil {
		v.HasRelated, v.RelatedChecked, v.RelatedCandidates, v.RelatedProbable = true, rl.Checked, rl.Candidates, len(rl.Probable)
		for _, d := range rl.Domains {
			it := netItem{Domain: d.Domain, Level: d.Level, Detail: d.Detail, URL: safeURL(d.URL)}
			for _, e := range d.Evidence {
				it.Evidence = append(it.Evidence, netEv{Kind: strings.ReplaceAll(e.Kind, "_", " "), Strength: e.Strength, Detail: short(e.Detail, 100)})
			}
			v.Related = append(v.Related, it)
		}
	}
	v.HasNetwork = v.HasFriends || v.HasRelated
	if v.HasNetwork {
		v.Graph = graph(v.Domain, v.Friends, v.Related)
	}

	// Coverage.
	c := r.Coverage
	v.Total, v.Evaluated = c.RulesTotal, c.RulesEvaluated
	if c.RulesTotal > 0 {
		v.Pct = c.RulesEvaluated * 100 / c.RulesTotal
	}
	keys := make([]string, 0, len(c.Skipped))
	for k := range c.Skipped {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if c.Skipped[keys[i]] != c.Skipped[keys[j]] {
			return c.Skipped[keys[i]] > c.Skipped[keys[j]]
		}
		return keys[i] < keys[j]
	})
	maxSkip := 1
	if len(keys) > 0 {
		maxSkip = c.Skipped[keys[0]]
	}
	for _, k := range keys {
		v.Skipped = append(v.Skipped, skipRow{Reason: k, N: c.Skipped[k], Width: widthCSS(c.Skipped[k] * 100 / maxSkip)})
	}

	v.Warnings = r.Warnings
	if b := r.Browser; b != nil {
		v.Browser = fmt.Sprintf("%s: %d requests (%d refused), %d global variables found", b.Version, b.Requests, b.Blocked, b.Globals)
		if b.TimedOut {
			v.Browser += ", timed out"
		}
	}
	if a := r.Active; a != nil {
		v.Active = fmt.Sprintf("%d probe paths approved, %d sent, %d failed, %d not sent", a.Approved, a.Sent, a.Failed, a.NotSent)
	}
	v.RegistryShort = r.Registry.ContentSHA256
	if len(v.RegistryShort) > 19 {
		v.RegistryShort = v.RegistryShort[:19]
	}
	v.RegistrySources = strings.Join(r.Registry.Sources, ", ")
	v.Stats = []stat{
		{v.TechCount, "technologies"}, {len(v.Groups), "categories"},
		{len(ext), "linked domains"}, {len(r.Socials), "social profiles"}, {len(r.Contacts), "contacts"},
	}
	if len(r.Pages) > 1 {
		v.Stats = append(v.Stats, stat{len(r.Pages), "pages read"})
	}
	return v
}
