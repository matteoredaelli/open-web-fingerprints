// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package stats

import (
	"math"
	"sort"

	"github.com/matteoredaelli/open-web-fingerprints/scan"
)

// checksAcc adds up the checks of the reached sites. Counts only: nothing of a site is kept.
type checksAcc struct {
	sites, mailReviewed, mailSites int
	hdr                            map[string]*scan.StatHeaderStatus
	hdrOrder                       []string
	conn, pol, bots                map[string]int
	cookies                        scan.StatsCookies
	spf, dmarc, mail               map[string]int
	mailProv, sendProv, dnsProv    map[string]int
}

func (a *checksAcc) init() {
	if a.hdr == nil {
		a.hdr = map[string]*scan.StatHeaderStatus{}
		for _, m := range []*map[string]int{&a.conn, &a.pol, &a.bots, &a.spf, &a.dmarc, &a.mail, &a.mailProv, &a.sendProv, &a.dnsProv} {
			*m = map[string]int{}
		}
	}
}

func (a *checksAcc) add(c *scan.Checks) {
	a.init()
	if h := c.Headers; h != nil {
		a.sites++
		for _, x := range h.Headers {
			s := a.hdr[x.Name]
			if s == nil {
				s = &scan.StatHeaderStatus{Name: x.Name}
				a.hdr[x.Name] = s
				a.hdrOrder = append(a.hdrOrder, x.Name)
			}
			switch x.Status {
			case scan.CheckOK:
				s.OK++
			case scan.CheckWeak:
				s.Weak++
			case scan.CheckMissing:
				s.Missing++
			default:
				s.Info++
			}
		}
		var sec, httpOnly, sameSite bool
		for _, k := range h.Cookies {
			for _, i := range k.Issues {
				switch i {
				case "no_secure":
					sec = true
				case "no_httponly":
					httpOnly = true
				case "no_samesite":
					sameSite = true
				}
			}
		}
		if len(h.Cookies) > 0 {
			a.cookies.Sites++
		}
		for _, p := range []struct {
			on  bool
			dst *int
		}{{sec, &a.cookies.NoSecure}, {httpOnly, &a.cookies.NoHTTPOnly}, {sameSite, &a.cookies.NoSameSite}} {
			if p.on {
				*p.dst++
			}
		}
	}
	if t := c.Transport; t != nil {
		if t.HTTP2 {
			a.conn["HTTP/2"]++
		}
		if t.HTTP3Advertised {
			a.conn["HTTP/3 advertised"]++
		}
		switch t.TLSVersion {
		case "TLS 1.3", "TLS 1.2":
			a.conn[t.TLSVersion]++
		case "":
		default:
			a.conn["TLS older than 1.2"]++
		}
	}
	if p := c.Policies; p != nil {
		if r := p.Robots; r != nil {
			if r.Present {
				a.pol["robots.txt present"]++
			}
			if r.SitemapCount > 0 {
				a.pol["sitemap declared in robots.txt"]++
			}
			explicit := 0
			for _, b := range r.AIBots {
				if b.Named && b.Blocked {
					a.bots[b.Name]++
					explicit++
				}
			}
			if explicit > 0 {
				a.pol["bans at least one AI crawler by name"]++
			}
		}
		if s := p.SecurityTxt; s != nil && s.Present {
			a.pol["security.txt present"]++
			if s.Status == scan.CheckOK {
				a.pol["security.txt valid and not expired"]++
			}
		}
	}
	if m := c.Mail; m != nil {
		a.mailReviewed++
		for _, p := range m.Providers {
			if p.Role == scan.RoleDNS {
				a.dnsProv[p.Name]++
			}
		}
		if m.CAA != nil {
			a.pol["CAA record present"]++
		}
		if d := m.DNSSEC; d != nil && d.DS && d.Signed && d.Status == scan.CheckOK {
			a.pol["DNSSEC signed and delegated"]++
		}
		if len(m.MX) == 0 {
			return
		}
		a.mailSites++
		for _, p := range m.Providers {
			switch p.Role {
			case scan.RoleMailbox:
				a.mailProv[p.Name]++
			case scan.RoleSending:
				a.sendProv[p.Name]++
			}
		}
		switch s := m.SPF; {
		case s == nil:
		case s.Record == "":
			a.spf["no record"]++
		case s.All == "":
			a.spf["no all"]++
		default:
			a.spf[s.All]++
		}
		if m.SPF != nil && m.SPF.TotalLookups > 10 {
			a.mail["SPF tree over 10 lookups"]++
		}
		if d := m.DMARC; d != nil {
			if d.Policy == "" {
				a.dmarc["no record"]++
			} else {
				a.dmarc["p="+d.Policy]++
			}
		}
		if len(m.DKIM) > 0 {
			a.mail["DKIM: a common selector found"]++
		}
		for _, t := range []struct {
			n string
			v *scan.Tag
		}{{"MTA-STS", m.MTASTS}, {"TLS-RPT", m.TLSRPT}, {"BIMI", m.BIMI}} {
			if t.v != nil && t.v.Present {
				a.mail[t.n]++
			}
		}
	}
}

// result turns the counts into the statistics; nil when no scan had checks. Names seen on
// fewer than MinSites sites are left out, as for technologies.
func (a *checksAcc) result(opt Options) *scan.StatsChecks {
	if a.sites == 0 && a.mailReviewed == 0 {
		return nil
	}
	out := &scan.StatsChecks{Sites: a.sites, MailReviewed: a.mailReviewed, MailSites: a.mailSites, Cookies: a.cookies}
	ratio := func(n, d int) float64 {
		if d == 0 {
			return 0
		}
		return math.Round(float64(n)/float64(d)*10000) / 10000
	}
	list := func(m map[string]int, d, min int) []scan.StatCount {
		l := []scan.StatCount{}
		for k, n := range m {
			if n >= min {
				l = append(l, scan.StatCount{Name: k, Sites: n, Share: ratio(n, d)})
			}
		}
		sort.Slice(l, func(i, j int) bool {
			if l[i].Sites != l[j].Sites {
				return l[i].Sites > l[j].Sites
			}
			return l[i].Name < l[j].Name
		})
		if len(l) > opt.Top {
			l = l[:opt.Top]
		}
		return l
	}
	out.Headers = []scan.StatHeaderStatus{}
	for _, n := range a.hdrOrder {
		out.Headers = append(out.Headers, *a.hdr[n])
	}
	// The mail lists are of fixed names, shown whatever the count; provider names are not.
	out.Connection = list(a.conn, a.sites, 1)
	out.Policies = list(a.pol, a.sites, 1)
	out.AIBots = list(a.bots, a.sites, opt.MinSites)
	out.SPF = list(a.spf, a.mailSites, 1)
	out.DMARC = list(a.dmarc, a.mailSites, 1)
	out.Mail = list(a.mail, a.mailSites, 1)
	out.MailProviders = list(a.mailProv, a.mailSites, opt.MinSites)
	out.SendingProviders = list(a.sendProv, a.mailSites, opt.MinSites)
	out.DNSProviders = list(a.dnsProv, a.mailReviewed, opt.MinSites)
	return out
}
