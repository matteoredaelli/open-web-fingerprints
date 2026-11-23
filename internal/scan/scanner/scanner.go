// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

// Package scanner runs a complete scan: it fetches and observes a target, applies
// the rules of a registry export, extracts links, domains, social profiles and
// contacts, and assembles the result.
package scanner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/matteoredaelli/open-web-fingerprints/internal/domain"
	"github.com/matteoredaelli/open-web-fingerprints/internal/export"
	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/browser"
	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/engine"
	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/fetch"
	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/observe"
	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/web"
	"github.com/matteoredaelli/open-web-fingerprints/scan"
	"github.com/matteoredaelli/open-web-fingerprints/schemas"
)

// Registry is a verified registry export, indexed for scanning.
type Registry struct {
	Engine *engine.Engine
	Ref    scan.RegistryRef
}

// LoadRegistry reads an export written by `owf export`. The file must satisfy the
// schema and its manifest (content hash and counts), so a damaged or edited file
// is refused. Sources whose redistribution is unreviewed are accepted: the
// scanner only reads the data, and the result repeats the export's notice.
func LoadRegistry(path string) (*Registry, error) {
	b, err := os.ReadFile(path) //nolint:gosec // user-supplied path
	if err != nil {
		return nil, err
	}
	return ParseRegistry(b)
}

// verifyRev changes whenever what verification checks changes, so stamps written by
// an older scanner are not trusted.
const verifyRev = "1"

// LoadRegistryCached is LoadRegistry, but remembers in stampDir that a file with
// exactly these bytes (by SHA-256) has been verified, and then skips the schema
// validation and the manifest checks, which take about half a second for a registry
// of 22000 rules. The stamp proves nothing about any other content: change one byte
// and the file is verified again. An empty stampDir verifies every time. A stamp that
// cannot be read or written is ignored.
func LoadRegistryCached(path, stampDir string) (*Registry, error) {
	b, err := os.ReadFile(path) //nolint:gosec // user-supplied path
	if err != nil {
		return nil, err
	}
	if stampDir == "" {
		return ParseRegistry(b)
	}
	sum := sha256.Sum256(b)
	stamp := filepath.Join(stampDir, hex.EncodeToString(sum[:])+"."+verifyRev)
	if _, err := os.Stat(stamp); err == nil { //nolint:gosec // the name is a hash inside the user's own directory
		if reg, err := decodeRegistry(b); err == nil {
			return reg, nil
		}
		// A stamp for a file that no longer decodes: verify again to get the error.
	}
	reg, err := ParseRegistry(b)
	if err != nil {
		return nil, err
	}
	if os.MkdirAll(stampDir, 0o750) == nil {
		_ = os.WriteFile(stamp, []byte(reg.Ref.ContentSHA256+"\n"), 0o600) //nolint:gosec // the name is a hash inside the user's own directory
	}
	return reg, nil
}

// ParseRegistry is LoadRegistry on bytes.
func ParseRegistry(b []byte) (*Registry, error) {
	reg, err := export.Verify(b)
	if err != nil {
		return nil, fmt.Errorf("registry: %w", err)
	}
	return newRegistry(&reg), nil
}

// decodeRegistry reads an export that is already known to be verified.
func decodeRegistry(b []byte) (*Registry, error) {
	var reg domain.Registry
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&reg); err != nil {
		return nil, fmt.Errorf("registry: %w", err)
	}
	if reg.Manifest == nil {
		return nil, fmt.Errorf("registry: no manifest")
	}
	return newRegistry(&reg), nil
}

func newRegistry(reg *domain.Registry) *Registry {
	ref := scan.RegistryRef{ContentSHA256: reg.Manifest.ContentSHA256, SchemaVersion: reg.SchemaVersion, Sources: []string{}}
	for _, s := range reg.Manifest.Sources {
		ref.Sources = append(ref.Sources, s.Slug)
	}
	if reg.Export != nil {
		ref.Notice = reg.Export.Notice
	}
	return &Registry{Engine: engine.New(reg), Ref: ref}
}

// Options configure a scan.
type Options struct {
	Registry  *Registry
	Fetch     fetch.Options
	Resolver  observe.Resolver // nil: no DNS
	NoFavicon bool
	// Depth, MaxPages, Delay and IgnoreRobots control how many pages beyond the one
	// asked for are read; see CrawlOptions. Depth 0 reads only that page.
	Depth, MaxPages int
	Delay           time.Duration
	IgnoreRobots    bool
	// Friends looks for friend domains (see FindFriends); FriendsMax bounds how many
	// other sites are contacted (0: DefaultMaxFriends).
	Friends bool
	// Related looks for domains that may belong to the same owner (see FindRelated);
	// RelatedMax bounds how many other sites are contacted (0: DefaultMaxRelated).
	Related    bool
	RelatedMax int
	// RelatedTLDs also tries the target's name under these TLDs (needs Resolver).
	RelatedTLDs []string
	// Active sends the approved probes (see RunProbes); ActiveMax bounds the requests.
	Active    bool
	ActiveMax int
	// Browser also opens the first page in headless Chrome (see package browser).
	// BrowserPath names the executable (empty: the usual places); BrowserTimeout bounds the run.
	Browser        bool
	BrowserPath    string
	BrowserTimeout time.Duration
	// BrowserSettle is the wait after the load for late scripts, and BrowserMaxRequests
	// bounds the requests the page may make (0: the browser package's defaults).
	BrowserSettle      time.Duration
	BrowserMaxRequests int
	// MaxDelay caps a robots.txt Crawl-delay; ActiveMaxBody is how much of a probe answer
	// is kept; MaxEvidence is how many matching rules are listed for a technology
	// (0: the defaults of each).
	MaxDelay      time.Duration
	ActiveMaxBody int
	MaxEvidence   int
	// DropHeaders lists response headers left out of the result's pages (names, or
	// prefixes ending in "*"). The rules still see them.
	DropHeaders []string
	FriendsMax  int
	MinHealth   string
	// Version names the scanner in the result.
	Version string
	Now     func() time.Time
}

// Scan scans a target.
func Scan(ctx context.Context, opt Options, target string) (*scan.Result, error) {
	if opt.Registry == nil {
		return nil, fmt.Errorf("scanner: no registry")
	}
	if opt.MinHealth != "" && !engine.ValidHealth(opt.MinHealth) {
		return nil, fmt.Errorf("scanner: unknown health %q (broken, degraded, unknown or ok)", opt.MinHealth)
	}
	now := time.Now
	if opt.Now != nil {
		now = opt.Now
	}
	started := now().UTC()
	crawl, err := Crawl(ctx, CrawlOptions{
		Fetch: opt.Fetch, Resolver: opt.Resolver, NoFavicon: opt.NoFavicon,
		Depth: opt.Depth, MaxPages: opt.MaxPages, Delay: opt.Delay, IgnoreRobots: opt.IgnoreRobots, MaxDelay: opt.MaxDelay,
	}, target)
	if err != nil {
		return nil, err
	}
	ob := crawl.Main
	final, err := url.Parse(ob.Page.FinalURL)
	if err != nil {
		return nil, fmt.Errorf("scanner: %w", err)
	}
	ob.Observation.Robots = crawl.Robots
	var probed *Probed
	if opt.Active {
		if plan := opt.Registry.Engine.ApprovedProbes(); len(plan) == 0 {
			probed = &Probed{Warnings: []scan.Warning{{Code: "no_approved_probes",
				Message: "--active was given but no probe is approved in this registry (see `owf probe list`)"}}}
		} else {
			probed = RunProbes(ctx, ActiveOptions{Fetch: opt.Fetch, Max: opt.ActiveMax, Delay: opt.Delay, MaxBody: opt.ActiveMaxBody}, final, web.RegistrableDomain(final.Hostname()), plan)
			ob.Observation.Probes = probed.Responses
		}
	}
	var browserInfo *scan.Browser
	var browserWarn []scan.Warning
	if opt.Browser {
		ua := opt.Fetch.UserAgent
		if ua == "" {
			ua = fetch.DefaultUserAgent
		}
		br, err := browser.Run(ctx, browser.Options{
			ChromePath: opt.BrowserPath, Timeout: opt.BrowserTimeout, Settle: opt.BrowserSettle, MaxRequests: opt.BrowserMaxRequests, AllowPrivate: opt.Fetch.AllowPrivate,
			Paths: opt.Registry.Engine.JSGlobals(), UserAgent: ua,
		}, ob.Page.FinalURL)
		switch {
		case errors.Is(err, browser.ErrNoChrome):
			return nil, err
		case err != nil:
			browserWarn = append(browserWarn, scan.Warning{Code: "browser_failed", Message: err.Error(), Ref: ob.Page.FinalURL})
		default:
			ob.Observation.JS, ob.Observation.XHR, ob.Observation.RequestHosts = br.Globals, br.XHR, br.Hosts
			// The document after scripts ran replaces the source for the rules and the extraction.
			ob.HTML, ob.Observation.HTML = []byte(br.DOM), br.DOM
			browserInfo = &scan.Browser{Version: br.Version, Requests: br.Requests, Blocked: br.Blocked, TimedOut: br.TimedOut, Globals: len(br.Globals)}
			if br.TimedOut {
				browserWarn = append(browserWarn, scan.Warning{Code: "browser_timeout", Message: "the page had not settled in time; what had loaded was used", Ref: ob.Page.FinalURL})
			}
		}
	}

	var pages []web.Page
	var outs []engine.Output
	for i, p := range crawl.Pages {
		if len(p.HTML) > 0 {
			pages = append(pages, web.Page{URL: p.Page.FinalURL, Body: p.HTML})
		}
		in := engine.Input{Observation: &p.Observation, Page: p.Page.FinalURL}
		if i == 0 {
			// Host-level observations belong to the first page.
			in.DNSLooked, in.HasTLS, in.FaviconTried, in.RobotsFetched = ob.DNSLooked, ob.Host.TLS != nil, ob.FaviconTried, crawl.RobotsFetched
			in.HasBrowser = browserInfo != nil
			if probed != nil {
				in.ActiveOn, in.ProbesSent = true, probed.Sent
			}
		}
		outs = append(outs, opt.Registry.Engine.Run(in, engine.Options{MinHealth: opt.MinHealth}))
	}
	ex := web.Extract(pages, final.Hostname())
	out := opt.Registry.Engine.Resolve(engine.Merge(outs, opt.MaxEvidence))
	ex.Warnings = append(append(append(append([]scan.Warning{}, crawl.Warnings...), browserWarn...), probedWarnings(probed)...), ex.Warnings...)

	res := &scan.Result{
		Schema: "https://github.com/matteoredaelli/open-web-fingerprints/schemas/scan-result.schema.json", SchemaVersion: scan.SchemaVersion,
		ScannedAt: started, Scanner: "owfscan " + opt.Version,
		Target:       scan.Target{Input: target, URL: ob.Page.FinalURL, Host: final.Hostname(), RegistrableDomain: web.RegistrableDomain(final.Hostname())},
		Technologies: out.Technologies, Suppressed: out.Suppressed, Implied: out.Implied,
		Links: ex.Links, Domains: ex.Domains, Socials: ex.Socials, Contacts: ex.Contacts,
		Coverage: out.Coverage, Registry: opt.Registry.Ref,
		Warnings: append(append([]scan.Warning{}, ex.Warnings...), out.Warnings...),
	}
	res.Technologies, res.DomainSignals = splitDomainSignals(res.Technologies)
	redactVolatile(res.Technologies, opt.DropHeaders)
	res.Browser = browserInfo
	if probed != nil {
		r := probed.Report
		res.Active = &r
	}
	for _, p := range crawl.Pages {
		pg := p.Page
		if len(opt.DropHeaders) > 0 {
			pg.Headers, pg.HeadersFiltered = observe.FilterHeaders(pg.Headers, opt.DropHeaders), true
		}
		res.Pages = append(res.Pages, pg)
	}
	if opt.Friends {
		// Only the home page counts: the page that was asked for, not the pages a crawl added.
		homeLinks := web.Extract([]web.Page{{URL: ob.Page.FinalURL, Body: ob.HTML}}, final.Hostname()).Links
		res.Friends = FindFriends(ctx, FriendsOptions{Fetch: opt.Fetch, Max: opt.FriendsMax, Delay: opt.Delay},
			Home{Domain: res.Target.RegistrableDomain, Links: homeLinks})
	}
	if opt.Related {
		res.Related = FindRelated(ctx, RelatedOptions{Fetch: opt.Fetch, Max: opt.RelatedMax, Delay: opt.Delay, TLDs: opt.RelatedTLDs, Resolver: opt.Resolver}, HomeInfo{
			Domain: res.Target.RegistrableDomain, URL: ob.Page.FinalURL, HTML: crawl.Main.HTML, Links: homeLinks(crawl, final), TLS: ob.Host.TLS,
		})
	}
	if len(ob.Host.IPs) > 0 || ob.Host.DNS != nil || ob.Host.TLS != nil {
		h := ob.Host
		res.Host = &h
	}
	if opt.Version == "" {
		res.Scanner = "owfscan"
	}
	if res.Registry.Sources == nil {
		res.Registry.Sources = []string{}
	}
	return res, nil
}

// Validate checks a result against the published schema.
func Validate(r *scan.Result) error {
	b, err := marshal(r)
	if err != nil {
		return err
	}
	return schemas.ValidateScanResult(b)
}

func marshal(r *scan.Result) ([]byte, error) {
	return json.Marshal(r)
}

func probedWarnings(p *Probed) []scan.Warning {
	if p == nil {
		return nil
	}
	return p.Warnings
}

// homeLinks are the links of the first page alone: what the site says on the page that was
// asked for, not on the pages a crawl added.
func homeLinks(c *Crawled, final *url.URL) []scan.Link {
	return web.Extract([]web.Page{{URL: c.Main.Page.FinalURL, Body: c.Main.HTML}}, final.Hostname()).Links
}

// redactVolatile empties the matched value of evidence that comes from a header or cookie
// on the drop list. The rule did match it (that is the trace), but a request id or a
// cookie value would make two scans of the same site differ.
func redactVolatile(techs []scan.Technology, drop []string) {
	if len(drop) == 0 {
		return
	}
	for i := range techs {
		ev := techs[i].Evidence
		for j := range ev {
			e := &ev[j]
			switch e.Observation {
			case "http_header":
				if observe.Dropped(e.Target, drop) {
					e.Matched = ""
				}
			case "set_cookie", "cookie":
				if observe.Dropped("set-cookie", drop) {
					e.Matched = ""
				}
			}
		}
	}
}

// splitDomainSignals moves the technologies whose every piece of evidence is a DNS record out
// of the list: they describe the services of the domain's owner, not the site.
func splitDomainSignals(all []scan.Technology) (web, domain []scan.Technology) {
	web = make([]scan.Technology, 0, len(all))
	for _, t := range all {
		only := len(t.Evidence) > 0
		for _, e := range t.Evidence {
			if e.Observation != "dns_record" {
				only = false
				break
			}
		}
		if only {
			domain = append(domain, t)
		} else {
			web = append(web, t)
		}
	}
	return web, domain
}
