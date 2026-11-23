// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

// Package stats aggregates many scan results (a batch) into figures that say nothing
// about any single site: how many sites show a technology, which categories, which
// browser-facing headers, how long certificates last. Every share is of the sites
// reached (home page answered 2xx) and each figure is "detected on the home page".
//
// Technologies whose only evidence is in DNS records (a domain verification for a
// vendor, a mail provider) are kept apart as domain signals: they describe the domain,
// not the web stack. Anything seen on fewer than MinSites sites is counted, not named,
// so a figure cannot point at one site. No contact, address or handle is carried over.
package stats

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/batch"
	"github.com/matteoredaelli/open-web-fingerprints/scan"
)

// Options of an aggregation.
type Options struct {
	// MinConfidence drops technologies whose confidence is lower (0 keeps all).
	MinConfidence float64
	// MinSites is the fewest sites for a technology or pair to be named (default 3).
	MinSites int
	// Exclude lists technology names (case-insensitive) left out, for example rules known
	// to be unreliable.
	Exclude []string
	// IncludeGeneric keeps the technologies the registry marks as generic signals; by default
	// they are left out.
	IncludeGeneric bool
	// Top bounds the lists (default 30).
	Top int
	Now func() time.Time
}

var securityHeaders = []string{
	"strict-transport-security", "content-security-policy", "x-frame-options",
	"x-content-type-options", "referrer-policy", "permissions-policy",
}

type acc struct {
	cats     map[string]bool
	sites    int
	versions map[string]int
	domain   bool
	family   string
}

// Compute reads the batch and returns the statistics.
func Compute(ctx context.Context, st *batch.Store, opt Options) (*scan.Stats, error) {
	if opt.MinSites <= 0 {
		opt.MinSites = 3
	}
	if opt.Top <= 0 {
		opt.Top = 30
	}
	now := opt.Now
	if now == nil {
		now = time.Now
	}
	excl := map[string]bool{}
	for _, e := range opt.Exclude {
		excl[strings.ToLower(strings.TrimSpace(e))] = true
	}
	counts, err := st.Counts(ctx)
	if err != nil {
		return nil, err
	}
	meta, _ := st.Meta(ctx)

	out := &scan.Stats{SchemaVersion: scan.StatsSchemaVersion, GeneratedAt: now().UTC(), List: meta["list"], Scanner: meta["scanner"]}
	out.Filters = scan.StatsFilter{MinConfidence: opt.MinConfidence, MinSites: opt.MinSites, ExcludedGeneric: !opt.IncludeGeneric}
	for e := range excl {
		out.Filters.ExcludedTech = append(out.Filters.ExcludedTech, e)
	}
	sort.Strings(out.Filters.ExcludedTech)
	out.Sites = scan.StatsSites{Listed: counts.Total, Scanned: counts.Done, Failed: counts.Failed, Pending: counts.Pending}

	techs := map[string]*acc{}
	cats := map[string]int{}
	fams := map[string]int{}
	hdrs := map[string]int{}
	soc := map[string]int{}
	issuers := map[string]int{}
	days := map[string]int{}
	pairs := map[[2]string]int{}
	var perSite []int
	var covSum float64
	reached, withCert := 0, 0
	statusN := map[int]int{}
	var regSHA, notice string
	var regSources []string

	err = st.EachDone(ctx, func(domain string, status int, b []byte) error {
		statusN[status]++
		if status < 200 || status >= 300 {
			return nil
		}
		var r scan.Result
		if err := json.Unmarshal(b, &r); err != nil {
			return fmt.Errorf("stats: %s: %w", domain, err)
		}
		reached++
		if regSHA == "" {
			regSHA, regSources, notice = r.Registry.ContentSHA256, r.Registry.Sources, r.Registry.Notice
		}
		if r.Coverage.RulesTotal > 0 {
			covSum += float64(r.Coverage.RulesEvaluated) / float64(r.Coverage.RulesTotal)
		}
		web := map[string]bool{}
		// Results made before domain_signals existed have them among the technologies; the
		// evidence test below treats both the same.
		for _, t := range append(append([]scan.Technology(nil), r.Technologies...), r.DomainSignals...) {
			if t.Confidence < opt.MinConfidence || excl[strings.ToLower(t.Name)] || (t.Generic && !opt.IncludeGeneric) {
				continue
			}
			domainOnly := len(t.Evidence) > 0
			for _, e := range t.Evidence {
				if e.Observation != "dns_record" {
					domainOnly = false
				}
			}
			a := techs[t.Name]
			if a == nil {
				a = &acc{cats: map[string]bool{}, versions: map[string]int{}, domain: domainOnly, family: FamilyOf(t.Name, t.Categories)}
				techs[t.Name] = a
			}
			a.domain = a.domain && domainOnly
			a.sites++
			if t.Version != "" {
				a.versions[t.Version]++
			}
			for _, c := range t.Categories {
				a.cats[c] = true
			}
			if !domainOnly {
				web[t.Name] = true
			}
		}
		siteCats := map[string]bool{}
		for _, t := range r.Technologies {
			if web[t.Name] {
				for _, c := range t.Categories {
					siteCats[c] = true
				}
			}
		}
		for c := range siteCats {
			cats[c]++
		}
		siteFams := map[string]bool{}
		for n := range web {
			siteFams[techs[n].family] = true
		}
		for f := range siteFams {
			fams[f]++
		}
		perSite = append(perSite, len(web))
		names := make([]string, 0, len(web))
		for n := range web {
			names = append(names, n)
		}
		sort.Strings(names)
		for i := range names {
			for j := i + 1; j < len(names); j++ {
				pairs[[2]string{names[i], names[j]}]++
			}
		}
		if len(r.Pages) > 0 {
			for _, h := range securityHeaders {
				if _, ok := r.Pages[0].Headers[h]; ok {
					hdrs[h]++
				}
			}
		}
		if r.Host != nil && r.Host.TLS != nil {
			t := r.Host.TLS
			withCert++
			if t.Issuer != "" {
				issuers[issuerName(t.Issuer)]++
			}
			if !t.NotAfter.IsZero() {
				days[bucket(int(t.NotAfter.Sub(r.ScannedAt).Hours()/24))]++
			}
		}
		seen := map[string]bool{}
		for _, s := range r.Socials {
			if !seen[s.Platform] {
				seen[s.Platform] = true
				soc[s.Platform]++
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	out.Sites.Reached = reached
	out.Registry = scan.StatsSource{ContentSHA256: regSHA, Sources: regSources, Notice: notice}
	share := func(n int) float64 {
		if reached == 0 {
			return 0
		}
		return math.Round(float64(n)/float64(reached)*10000) / 10000
	}
	list := func(m map[string]int, min int) []scan.StatCount {
		var l []scan.StatCount
		for k, n := range m {
			if n >= min {
				l = append(l, scan.StatCount{Name: k, Sites: n, Share: share(n)})
			}
		}
		sort.Slice(l, func(i, j int) bool {
			if l[i].Sites != l[j].Sites {
				return l[i].Sites > l[j].Sites
			}
			return l[i].Name < l[j].Name
		})
		return l
	}
	top := func(l []scan.StatCount) []scan.StatCount {
		if len(l) > opt.Top {
			return l[:opt.Top]
		}
		if l == nil {
			return []scan.StatCount{}
		}
		return l
	}
	httpS := map[string]int{}
	for k, n := range statusN {
		httpS[fmt.Sprint(k)] = n
	}
	// Status and failures are shares of the sites scanned and listed, not of those reached.
	for _, c := range list(httpS, 1) {
		out.Sites.Status = append(out.Sites.Status, scan.StatCount{Name: c.Name, Sites: c.Sites, Share: ratio(c.Sites, counts.Done)})
	}
	for k, n := range counts.ByError {
		out.Sites.Errors = append(out.Sites.Errors, scan.StatCount{Name: k, Sites: n, Share: ratio(n, counts.Failed)})
	}
	sort.Slice(out.Sites.Errors, func(i, j int) bool {
		if out.Sites.Errors[i].Sites != out.Sites.Errors[j].Sites {
			return out.Sites.Errors[i].Sites > out.Sites.Errors[j].Sites
		}
		return out.Sites.Errors[i].Name < out.Sites.Errors[j].Name
	})
	if out.Sites.Status == nil {
		out.Sites.Status = []scan.StatCount{}
	}
	if out.Sites.Errors == nil {
		out.Sites.Errors = []scan.StatCount{}
	}

	out.Technologies, out.DomainSignals = []scan.StatTech{}, []scan.StatTech{}
	hidden := 0
	var names []string
	for n := range techs {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		a := techs[n]
		if a.sites < opt.MinSites {
			hidden++
			continue
		}
		t := scan.StatTech{Name: n, Sites: a.sites, Share: share(a.sites)}
		for c := range a.cats {
			t.Categories = append(t.Categories, c)
		}
		sort.Strings(t.Categories)
		if !a.domain {
			t.Versions = top8(list2(a.versions, opt.MinSites, share))
		}
		if a.domain {
			out.DomainSignals = append(out.DomainSignals, t)
		} else {
			out.Technologies = append(out.Technologies, t)
		}
	}
	byCount := func(l []scan.StatTech) {
		sort.SliceStable(l, func(i, j int) bool {
			if l[i].Sites != l[j].Sites {
				return l[i].Sites > l[j].Sites
			}
			return l[i].Name < l[j].Name
		})
	}
	byCount(out.Technologies)
	byCount(out.DomainSignals)
	out.Other.TechnologiesHidden = hidden

	out.Categories = top(list(cats, opt.MinSites))
	out.Families = []scan.StatFamily{}
	for _, name := range familyOrder {
		if fams[name] == 0 {
			continue
		}
		f := scan.StatFamily{Name: name, Sites: fams[name], Share: share(fams[name]), Technologies: []scan.StatTech{}}
		for _, t := range out.Technologies {
			if techs[t.Name].family == name {
				f.Technologies = append(f.Technologies, t)
			}
		}
		if len(f.Technologies) > opt.Top {
			f.Technologies = f.Technologies[:opt.Top]
		}
		out.Families = append(out.Families, f)
	}
	hl := map[string]int{}
	for _, h := range securityHeaders {
		hl[h] = hdrs[h]
	}
	out.Headers = list(hl, 0)
	out.TLS = scan.StatsTLS{WithCertificate: withCert, DaysLeft: list(days, 1), Issuers: top(list(issuers, opt.MinSites))}
	out.Social = top(list(soc, opt.MinSites))
	var pl []scan.StatPair
	for k, n := range pairs {
		if n >= opt.MinSites {
			pl = append(pl, scan.StatPair{A: k[0], B: k[1], Sites: n, Share: share(n)})
		}
	}
	sort.Slice(pl, func(i, j int) bool {
		if pl[i].Sites != pl[j].Sites {
			return pl[i].Sites > pl[j].Sites
		}
		if pl[i].A != pl[j].A {
			return pl[i].A < pl[j].A
		}
		return pl[i].B < pl[j].B
	})
	if len(pl) > opt.Top {
		pl = pl[:opt.Top]
	}
	if pl == nil {
		pl = []scan.StatPair{}
	}
	out.Pairs = pl

	sort.Ints(perSite)
	if reached > 0 {
		sum, none := 0, 0
		for _, n := range perSite {
			sum += n
			if n == 0 {
				none++
			}
		}
		out.Coverage = scan.StatsCoverage{
			MeanPercent: math.Round(covSum/float64(reached)*1000) / 10, MedianTechs: perSite[len(perSite)/2],
			MeanTechs: math.Round(float64(sum)/float64(reached)*10) / 10, SitesWithNone: none,
		}
	}
	out.Notes = []string{
		"Every figure is 'detected on the home page' of a site that answered 2xx, not 'used by the site'.",
		fmt.Sprintf("Shares of technologies, categories, headers, certificates and profiles are of the %d sites reached (of %d listed).", reached, counts.Total),
		"Most rules of the registry have no tests (health unknown); a false positive counts as a detection.",
		"Domain signals (DNS records only) describe the domain, not the web stack, and are listed apart.",
		fmt.Sprintf("Anything seen on fewer than %d sites is counted in other.technologies_hidden, not named.", opt.MinSites),
		"The list is a ranking of domains, not a sample of the web: it favours large organisations.",
	}
	return out, nil
}

func ratio(n, d int) float64 {
	if d == 0 {
		return 0
	}
	return math.Round(float64(n)/float64(d)*10000) / 10000
}

func list2(m map[string]int, min int, share func(int) float64) []scan.StatCount {
	var l []scan.StatCount
	for k, n := range m {
		if n >= min {
			l = append(l, scan.StatCount{Name: k, Sites: n, Share: share(n)})
		}
	}
	sort.Slice(l, func(i, j int) bool {
		if l[i].Sites != l[j].Sites {
			return l[i].Sites > l[j].Sites
		}
		return l[i].Name < l[j].Name
	})
	return l
}

func top8(l []scan.StatCount) []scan.StatCount {
	if len(l) > 8 {
		return l[:8]
	}
	return l
}

// bucket names how long a certificate still has to run.
func bucket(days int) string {
	switch {
	case days < 0:
		return "expired"
	case days < 30:
		return "under 30 days"
	case days < 60:
		return "30 to 59 days"
	case days < 90:
		return "60 to 89 days"
	}
	return "90 days or more"
}

// issuerName keeps the organisation of a certificate issuer ("O=Let's Encrypt") or its
// common name, which is what people recognise.
func issuerName(s string) string {
	for _, part := range strings.Split(s, ",") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(part), "O="); ok && v != "" {
			return v
		}
	}
	return s
}
