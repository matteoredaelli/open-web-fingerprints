// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package checks

import (
	"context"
	"errors"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/matteoredaelli/open-web-fingerprints/scan"
)

// Resolver is the part of a DNS resolver that Mail needs.
type Resolver interface {
	LookupMX(ctx context.Context, domain string) ([]string, error) // "pref host"
	LookupNS(ctx context.Context, domain string) ([]string, error)
	LookupTXT(ctx context.Context, domain string) ([]string, error)
}

// DKIMSelectors are the selector names tried. Selectors cannot be listed in DNS, so this is a
// guess at the usual ones (Google, Microsoft 365, Mailchimp, SendGrid, common defaults).
var DKIMSelectors = []string{"default", "google", "selector1", "selector2", "k1", "k2", "k3", "s1", "s2", "mail", "dkim", "smtp", "mandrill", "mxvault", "everlytickey1", "scph0"}

const (
	lookupTimeout = 25 * time.Second
	retryDelay    = 300 * time.Millisecond
)

// retryName says whether an empty answer for name is asked again: the SPF and DMARC records,
// whose absence is reported as a finding.
func retryName(name, domain string) bool { return name == domain || name == "_dmarc."+domain }

// Mail reviews the mail and name server records of a registrable domain. A lookup that fails
// for a reason other than "no such record" is returned as a warning and its item is left out
// rather than reported as missing.
func Mail(ctx context.Context, r Resolver, domain string) (*scan.MailChecks, []scan.Warning) {
	ctx, cancel := context.WithTimeout(ctx, lookupTimeout)
	defer cancel()
	var warns []scan.Warning
	var wmu sync.Mutex
	warn := func(code string, err error, name string) {
		wmu.Lock()
		warns = append(warns, scan.Warning{Code: code, Message: err.Error(), Ref: name})
		wmu.Unlock()
	}
	// txt returns the records at name; ok is false when the lookup failed for a reason that
	// does not mean "nothing there".
	txt := func(name string) (recs []string, ok bool) {
		v, err := r.LookupTXT(ctx, name)
		if err != nil && notFound(err) && retryName(name, domain) {
			// A resolver can answer "nothing" to a big or rushed query: ask the records that
			// decide a verdict once more before saying they are not there.
			select {
			case <-ctx.Done():
			case <-time.After(retryDelay):
				v, err = r.LookupTXT(ctx, name)
			}
		}
		if err != nil && !notFound(err) {
			warn("check_dns_txt", err, name)
			return nil, false
		}
		return v, true
	}
	m := &scan.MailChecks{Domain: domain}

	mx, err := r.LookupMX(ctx, domain)
	if len(mx) == 0 && (err == nil || notFound(err)) {
		select {
		case <-ctx.Done():
		case <-time.After(retryDelay):
			mx, err = r.LookupMX(ctx, domain)
		}
	}
	mxOK := err == nil || notFound(err)
	if !mxOK {
		warn("check_dns_mx", err, domain)
	}
	sort.Strings(mx)
	for _, e := range mx {
		if strings.HasSuffix(strings.TrimSpace(e), " .") || strings.HasSuffix(strings.TrimSpace(e), " ") {
			m.NullMX = true
			continue
		}
		m.MX = append(m.MX, e)
		_, host, _ := strings.Cut(e, " ")
		if name, ok := recognise(mxProviders, host); ok {
			m.Providers = addProvider(m.Providers, scan.Provider{Name: name, Role: scan.RoleMailbox, Via: host})
		}
	}
	ns, err := r.LookupNS(ctx, domain)
	if err != nil && !notFound(err) {
		warn("check_dns_ns", err, domain)
	}
	sort.Strings(ns)
	m.NS = ns
	for _, h := range ns {
		if name, ok := recognise(nsProviders, h); ok {
			m.Providers = addProvider(m.Providers, scan.Provider{Name: name, Role: scan.RoleDNS, Via: h})
		}
	}

	domainTXT, txtOK := txt(domain)
	if txtOK {
		m.SPF = spf(domainTXT)
		expandSPF(m.SPF, txt)
		for _, inc := range append(append([]string(nil), m.SPF.Includes...), m.SPF.Nested...) {
			if name, ok := recognise(spfProviders, inc); ok {
				m.Providers = addProvider(m.Providers, scan.Provider{Name: name, Role: scan.RoleSending, Via: inc})
			}
		}
	}
	mail := len(m.MX) > 0 || (m.SPF != nil && m.SPF.Record != "" && !strings.EqualFold(m.SPF.Record, "v=spf1 -all"))
	noMail := mxOK && !mail
	if m.SPF != nil && m.SPF.Record == "" && noMail {
		m.SPF.Status, m.SPF.Note = scan.CheckInfo, "no SPF record, and the domain has no mail exchanger"
	}
	if rec, ok := txt("_dmarc." + domain); ok {
		m.DMARC = dmarc(rec, noMail)
	}
	if mail {
		type res struct {
			k   scan.DKIM
			hit bool
		}
		results := make([]res, len(DKIMSelectors))
		var wg sync.WaitGroup
		sem := make(chan struct{}, 8)
		for i, sel := range DKIMSelectors {
			wg.Add(1)
			go func() {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				v, ok := txt(sel + "._domainkey." + domain)
				if !ok {
					return
				}
				if k, hit := dkim(sel, v); hit {
					results[i] = res{k, true}
				}
			}()
		}
		wg.Wait()
		m.DKIMSelTried = len(DKIMSelectors)
		for _, x := range results {
			if x.hit {
				m.DKIM = append(m.DKIM, x.k)
			}
		}
		for _, t := range []struct {
			name, prefix string
			dst          **scan.Tag
		}{
			{"_mta-sts." + domain, "v=stsv1", &m.MTASTS},
			{"_smtp._tls." + domain, "v=tlsrptv1", &m.TLSRPT},
			{"default._bimi." + domain, "v=bimi1", &m.BIMI},
		} {
			if v, ok := txt(t.name); ok {
				*t.dst = tag(v, t.prefix)
			}
		}
	}
	return m, warns
}

func notFound(err error) bool {
	var nf *net.DNSError
	return errors.As(err, &nf) && nf.IsNotFound
}

func addProvider(list []scan.Provider, p scan.Provider) []scan.Provider {
	for _, q := range list {
		if q.Name == p.Name && q.Role == p.Role {
			return list
		}
	}
	return append(list, p)
}

// find returns the records that start with the version tag (case-insensitive, spaces ignored).
func find(recs []string, prefix string) []string {
	var out []string
	for _, r := range recs {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(r)), prefix) {
			out = append(out, strings.TrimSpace(r))
		}
	}
	return out
}

func tag(recs []string, prefix string) *scan.Tag {
	f := find(recs, prefix)
	if len(f) == 0 {
		return &scan.Tag{}
	}
	return &scan.Tag{Present: true, Record: cut(f[0])}
}

func spf(recs []string) *scan.SPF {
	f := find(recs, "v=spf1")
	s := &scan.SPF{}
	switch len(f) {
	case 0:
		s.Status, s.Note = scan.CheckMissing, "no SPF record: receivers cannot tell which servers may send for the domain"
		return s
	case 1:
	default:
		s.Record = cut(f[0])
		s.Status, s.Note = scan.CheckWeak, "more than one SPF record: the standard makes that a permanent error"
		return s
	}
	s.Record = cut(f[0])
	t := spfTerms(f[0])
	s.All, s.Includes, s.Lookups = t.all, t.includes, t.lookups
	ptr, redirect := t.ptr, t.redirect
	switch {
	case s.All == "+all" || s.All == "?all":
		s.Status, s.Note = scan.CheckWeak, s.All+" lets any server pass or stay neutral"
	case s.All == "" && !redirect:
		s.Status, s.Note = scan.CheckWeak, "the record does not end with an all mechanism"
	case ptr:
		s.Status, s.Note = scan.CheckWeak, "uses ptr, which the standard advises against"
	case s.Lookups > 10:
		s.Status, s.Note = scan.CheckWeak, "more than 10 DNS lookups in this record alone: receivers stop at 10"
	case s.All == "~all":
		s.Status, s.Note = scan.CheckOK, "soft fail (~all): unlisted servers are marked, not rejected"
	default:
		s.Status = scan.CheckOK
	}
	return s
}

func dmarc(recs []string, noMail bool) *scan.DMARC {
	f := find(recs, "v=dmarc1")
	d := &scan.DMARC{}
	switch len(f) {
	case 0:
		d.Status, d.Note = scan.CheckMissing, "no DMARC policy: receivers have no instruction for mail that fails SPF and DKIM"
		if noMail {
			d.Status, d.Note = scan.CheckInfo, "no DMARC record, and the domain has no mail exchanger"
		}
		return d
	case 1:
	default:
		d.Record = cut(f[0])
		d.Status, d.Note = scan.CheckWeak, "more than one DMARC record: receivers ignore them"
		return d
	}
	d.Record = cut(f[0])
	for _, kv := range strings.Split(f[0], ";") {
		k, v, ok := strings.Cut(strings.TrimSpace(kv), "=")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "p":
			d.Policy = strings.ToLower(v)
		case "sp":
			d.SubdomainPolicy = strings.ToLower(v)
		case "pct":
			d.Pct, _ = strconv.Atoi(v)
		case "rua":
			d.Rua = splitList(v)
		case "ruf":
			d.Ruf = splitList(v)
		}
	}
	if d.SubdomainPolicy == d.Policy {
		d.SubdomainPolicy = ""
	}
	switch d.Policy {
	case "reject", "quarantine":
		d.Status = scan.CheckOK
		if d.Pct > 0 && d.Pct < 100 {
			d.Note = "applied to " + strconv.Itoa(d.Pct) + "% of the mail"
		}
	case "none":
		d.Status, d.Note = scan.CheckWeak, "p=none: failures are only reported, nothing is enforced"
	default:
		d.Status, d.Note = scan.CheckWeak, "no valid p= tag"
	}
	return d
}

func splitList(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, cut(p))
		}
	}
	return out
}

func dkim(sel string, recs []string) (scan.DKIM, bool) {
	for _, r := range recs {
		l := strings.ToLower(r)
		if !strings.Contains(l, "p=") && !strings.Contains(l, "v=dkim1") {
			continue
		}
		k := scan.DKIM{Selector: sel, KeyType: "rsa"}
		for _, kv := range strings.Split(r, ";") {
			key, v, ok := strings.Cut(strings.TrimSpace(kv), "=")
			if !ok {
				continue
			}
			switch strings.ToLower(strings.TrimSpace(key)) {
			case "k":
				k.KeyType = strings.ToLower(strings.TrimSpace(v))
			case "p":
				k.Revoked = strings.TrimSpace(v) == ""
			}
		}
		return k, true
	}
	return scan.DKIM{}, false
}

type spfParsed struct {
	all           string
	includes      []string // include: and redirect= targets
	lookups       int
	ptr, redirect bool
}

// spfTerms reads the terms of one SPF record.
func spfTerms(rec string) spfParsed {
	var p spfParsed
	fields := strings.Fields(rec)
	if len(fields) == 0 {
		return p
	}
	for _, term := range fields[1:] {
		t := strings.ToLower(term)
		q := byte('+')
		if strings.IndexByte("+-~?", t[0]) >= 0 {
			q, t = t[0], t[1:]
		}
		if t == "all" {
			p.all = string(q) + "all"
			continue
		}
		name, val := t, ""
		if i := strings.IndexAny(t, ":=/"); i >= 0 {
			name = t[:i]
			if t[i] != '/' {
				val = t[i+1:]
			}
		}
		switch name {
		case "include":
			p.includes = append(p.includes, val)
			p.lookups++
		case "redirect":
			p.includes = append(p.includes, val)
			p.lookups++
			p.redirect = true
		case "a", "mx", "exists":
			p.lookups++
		case "ptr":
			p.lookups++
			p.ptr = true
		}
	}
	return p
}

// maxSPFQueries bounds the DNS queries made to follow the includes of one record.
const maxSPFQueries = 20

// expandSPF follows the include: and redirect= of a record (breadth first, each host once)
// and totals the lookups of the whole tree, which the standard limits to ten. The hosts
// reached are listed in Nested. If a lookup fails, or the bound is hit, the total is a lower
// bound and TreeComplete stays false.
func expandSPF(s *scan.SPF, txt func(string) ([]string, bool)) {
	if s == nil || s.Record == "" || len(s.Includes) == 0 {
		if s != nil && s.Record != "" {
			s.TotalLookups, s.TreeComplete = s.Lookups, true
		}
		return
	}
	total, complete, queries := s.Lookups, true, 0
	seen := map[string]bool{}
	queue := append([]string(nil), s.Includes...)
	for len(queue) > 0 {
		h := strings.TrimSuffix(queue[0], ".")
		queue = queue[1:]
		if h == "" || seen[h] {
			continue
		}
		if strings.Contains(h, "%") { // macros need the sender's address: not resolvable here
			complete = false
			continue
		}
		seen[h] = true
		if queries >= maxSPFQueries {
			complete = false
			break
		}
		queries++
		recs, ok := txt(h)
		if !ok {
			complete = false
			continue
		}
		f := find(recs, "v=spf1")
		if len(f) == 0 {
			continue
		}
		s.Nested = append(s.Nested, h)
		t := spfTerms(f[0])
		total += t.lookups
		queue = append(queue, t.includes...)
	}
	s.TotalLookups, s.TreeComplete = total, complete
	if total > 10 && s.Status == scan.CheckOK {
		s.Status, s.Note = scan.CheckWeak, "more than 10 DNS lookups in the whole tree: receivers stop at 10 and the record fails"
		if !complete {
			s.Note = "at least " + strconv.Itoa(total) + " DNS lookups in the tree (10 is the limit): receivers stop at 10 and the record fails"
		}
	}
}
