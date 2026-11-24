// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

// Package statspage writes the static HTML summary page of a batch's statistics. It
// follows the rules of internal/scan/report: one self-contained file, no script, no
// network, system fonts, every value escaped by html/template, and the page is a
// function of the statistics (it never reads the clock), so the same input gives the
// same bytes. Only aggregates are shown: the input carries no site-level data.
package statspage

import (
	_ "embed"
	"fmt"
	"html/template"
	"io"
	"strings"

	"github.com/matteoredaelli/open-web-fingerprints/scan"
)

// Options tune the page.
type Options struct {
	// Title replaces the default title.
	Title string
	// TopTechnologies, TopCategories and TopPairs bound the lists (defaults 30, 20, 15).
	TopTechnologies, TopCategories, TopPairs int
}

//go:embed statspage.html.tmpl
var source string

var page = template.Must(template.New("stats").Parse(source))

type bar struct {
	Name, Detail string
	Sites        int
	Pct          string
	Width        template.CSS
}

type family struct {
	Name, Pct string
	Sites     int
	Techs     []bar
}

type view struct {
	Families                        []family
	Title, Generated, Scanner, List string
	Notice, RegistryShort, Sources  string
	Sites                           scan.StatsSites
	ReachedPct                      string
	Technologies, Signals           []bar
	Categories, Headers, Social     []bar
	DaysLeft, Issuers               []bar
	Status, Failures                []bar
	Pairs                           []bar
	Cov                             scan.StatsCoverage
	CovPct                          int
	WithCert                        int
	Hidden, MinSites                int
	MinConf                         string
	Excluded                        string
	Notes                           []string
	Checks                          *checksView
}

// checksView is the "Checks" part of the page.
type checksView struct {
	Sites, MailSites, MailReviewed                int
	Headers                                       []hdrRow
	Connection, Policies, AIBots                  []bar
	Cookies                                       []bar
	SPF, DMARC, Mail                              []bar
	MailProviders, SendingProviders, DNSProviders []bar
}

type hdrRow struct {
	Name                    string
	OK, Weak, Missing, Info string
	OKW, WeakW, MissingW    template.CSS
}

func pct(f float64) string { return fmt.Sprintf("%.1f%%", f*100) }

func width(f float64) template.CSS {
	p := int(f*100 + 0.5)
	if p < 0 {
		p = 0
	}
	if p > 100 {
		p = 100
	}
	return template.CSS(fmt.Sprintf("width:%d%%", p)) //nolint:gosec // an integer
}

// counts turns counts into bars scaled to the largest share in the list, so a list of
// small shares is still readable. The printed percentage is the real share.
func counts(l []scan.StatCount, n int) []bar {
	var out []bar
	max := 0.0
	for _, c := range l {
		if c.Share > max {
			max = c.Share
		}
	}
	for i, c := range l {
		if n > 0 && i == n {
			break
		}
		w := 0.0
		if max > 0 {
			w = c.Share / max
		}
		out = append(out, bar{Name: c.Name, Sites: c.Sites, Pct: pct(c.Share), Width: width(w)})
	}
	return out
}

func techs(l []scan.StatTech, n int) []bar {
	var out []bar
	max := 0.0
	for _, t := range l {
		if t.Share > max {
			max = t.Share
		}
	}
	for i, t := range l {
		if n > 0 && i == n {
			break
		}
		w := 0.0
		if max > 0 {
			w = t.Share / max
		}
		out = append(out, bar{Name: t.Name, Detail: strings.Join(t.Categories, ", "), Sites: t.Sites, Pct: pct(t.Share), Width: width(w)})
	}
	return out
}

func build(s *scan.Stats, opt Options) view {
	if opt.TopTechnologies <= 0 {
		opt.TopTechnologies = 30
	}
	if opt.TopCategories <= 0 {
		opt.TopCategories = 20
	}
	if opt.TopPairs <= 0 {
		opt.TopPairs = 15
	}
	v := view{
		Title: opt.Title, Generated: s.GeneratedAt.UTC().Format("2 Jan 2006, 15:04 UTC"),
		Scanner: s.Scanner, List: s.List, Notice: s.Registry.Notice, Sources: strings.Join(s.Registry.Sources, ", "),
		RegistryShort: s.Registry.ContentSHA256, Sites: s.Sites, Cov: s.Coverage, CovPct: int(s.Coverage.MeanPercent + 0.5),
		WithCert: s.TLS.WithCertificate, Hidden: s.Other.TechnologiesHidden, MinSites: s.Filters.MinSites,
		MinConf: fmt.Sprintf("%.2f", s.Filters.MinConfidence), Excluded: strings.Join(s.Filters.ExcludedTech, ", "),
		Notes: s.Notes,
	}
	if v.Title == "" {
		v.Title = "Web technology statistics"
	}
	if len(v.RegistryShort) > 19 {
		v.RegistryShort = v.RegistryShort[:19]
	}
	if s.Sites.Scanned > 0 {
		v.ReachedPct = pct(float64(s.Sites.Reached) / float64(s.Sites.Scanned))
	}
	v.Technologies = techs(s.Technologies, opt.TopTechnologies)
	v.Signals = techs(s.DomainSignals, opt.TopTechnologies)
	for _, f := range s.Families {
		v.Families = append(v.Families, family{Name: f.Name, Sites: f.Sites, Pct: pct(f.Share), Techs: techs(f.Technologies, 8)})
	}
	v.Categories = counts(s.Categories, opt.TopCategories)
	v.Headers = counts(s.Headers, 0)
	v.Social = counts(s.Social, 0)
	v.DaysLeft = counts(s.TLS.DaysLeft, 0)
	v.Issuers = counts(s.TLS.Issuers, 10)
	v.Status = counts(s.Sites.Status, 0)
	v.Failures = counts(s.Sites.Errors, 0)
	for i, p := range s.Pairs {
		if i == opt.TopPairs {
			break
		}
		v.Pairs = append(v.Pairs, bar{Name: p.A + " + " + p.B, Sites: p.Sites, Pct: pct(p.Share), Width: width(p.Share)})
	}
	if c := s.Checks; c != nil {
		cv := &checksView{Sites: c.Sites, MailSites: c.MailSites, MailReviewed: c.MailReviewed,
			Connection: counts(c.Connection, 0), Policies: counts(c.Policies, 0), AIBots: counts(c.AIBots, 0),
			SPF: counts(c.SPF, 0), DMARC: counts(c.DMARC, 0), Mail: counts(c.Mail, 0),
			MailProviders: counts(c.MailProviders, 10), SendingProviders: counts(c.SendingProviders, 10), DNSProviders: counts(c.DNSProviders, 10)}
		if c.Cookies.Sites > 0 {
			f := func(name string, n int) bar {
				sh := float64(n) / float64(c.Cookies.Sites)
				return bar{Name: name, Sites: n, Pct: pct(sh), Width: width(sh)}
			}
			cv.Cookies = []bar{f("without Secure (https)", c.Cookies.NoSecure), f("without HttpOnly", c.Cookies.NoHTTPOnly), f("without SameSite", c.Cookies.NoSameSite)}
		}
		for _, h := range c.Headers {
			n := float64(h.OK + h.Weak + h.Missing + h.Info)
			if n == 0 {
				continue
			}
			cv.Headers = append(cv.Headers, hdrRow{Name: h.Name,
				OK: pct(float64(h.OK) / n), Weak: pct(float64(h.Weak) / n), Missing: pct(float64(h.Missing) / n), Info: pct(float64(h.Info) / n),
				OKW: width(float64(h.OK) / n), WeakW: width(float64(h.Weak) / n), MissingW: width(float64(h.Missing) / n)})
		}
		v.Checks = cv
	}
	return v
}

// Render writes the summary page for the statistics.
func Render(w io.Writer, s *scan.Stats, opt Options) error {
	if s == nil {
		return fmt.Errorf("statspage: no statistics")
	}
	return page.Execute(w, build(s, opt))
}
