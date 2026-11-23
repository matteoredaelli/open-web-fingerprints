// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

// Package client scans a site with the rules of a registry export: the same code
// as the `owfscan scan` command, for programs written in Go.
//
//	reg, err := client.LoadRegistry("registry.json")
//	res, err := client.Scan(ctx, reg, client.Options{DNS: true}, "https://example.org")
//
// The result is a [scan.Result]. The guards of the command hold here too: only GET
// requests, no private addresses (also after redirects, unless AllowPrivate is set),
// robots.txt honoured when links are followed, probes only if approved and asked for.
// Scan only sites you are allowed to scan.
package client

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/fetch"
	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/observe"
	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/scanner"
	"github.com/matteoredaelli/open-web-fingerprints/scan"
)

var errBadURL = errors.New("client: the page address must be an http(s) URL")

// Registry is a verified registry export, indexed for scanning. It is safe to share
// between concurrent scans.
type Registry struct{ r *scanner.Registry }

// LoadRegistry reads an export written by `owf export`. The file must satisfy the
// schema and its manifest, so a damaged or edited file is refused.
func LoadRegistry(path string) (*Registry, error) {
	r, err := scanner.LoadRegistry(path)
	if err != nil {
		return nil, err
	}
	return &Registry{r}, nil
}

// LoadRegistryCached is LoadRegistry, but remembers in stampDir that a file with these
// exact bytes was verified, which makes loading faster. An empty stampDir verifies
// every time.
func LoadRegistryCached(path, stampDir string) (*Registry, error) {
	r, err := scanner.LoadRegistryCached(path, stampDir)
	if err != nil {
		return nil, err
	}
	return &Registry{r}, nil
}

// ParseRegistry is LoadRegistry on bytes.
func ParseRegistry(b []byte) (*Registry, error) {
	r, err := scanner.ParseRegistry(b)
	if err != nil {
		return nil, err
	}
	return &Registry{r}, nil
}

// Ref identifies the registry: content hash, schema version, sources and the export's notice.
func (r *Registry) Ref() scan.RegistryRef { return r.r.Ref }

// Options configure a scan. The zero value reads one page, with the defaults of each
// limit, and does no DNS lookup, crawling, probing or browsing.
type Options struct {
	// Network. Zero limits mean the defaults.
	Timeout      time.Duration
	MaxBody      int64
	MaxRedirects int
	UserAgent    string
	// AllowPrivate lets requests reach private and local addresses (your own network).
	AllowPrivate bool
	// Insecure accepts invalid TLS certificates.
	Insecure bool
	// CacheDir caches responses on disk, for MaxAge.
	CacheDir string
	MaxAge   time.Duration
	// Transport replaces the network transport. Whoever sets it owns the guards: the
	// refusal of private addresses, and TLS settings, are part of the default transport and
	// are not applied to this one. It is meant for a program that makes many scans and wants
	// one connection pool, a shared rate limit and a robots.txt cache (owfscan's crawler).
	Transport http.RoundTripper

	// DNS looks up DNS records of the site.
	DNS bool
	// NoFavicon skips the favicon.
	NoFavicon bool
	// KeepHTML keeps the page body in what Observe returns.
	KeepHTML bool

	// Depth follows links this many levels to pages likely to list contacts and
	// profiles; 0 reads only the page given. MaxPages bounds the pages in total, Delay
	// is the pause before each further page, MaxDelay caps a robots.txt Crawl-delay.
	Depth, MaxPages int
	Delay, MaxDelay time.Duration
	// IgnoreRobots fetches pages that robots.txt asks crawlers to avoid.
	IgnoreRobots bool

	// Friends looks for friend domains; Related for domains that may share the owner,
	// also trying the name under RelatedTLDs (needs DNS). Both contact other sites,
	// at most FriendsMax and RelatedMax of them.
	Friends, Related       bool
	FriendsMax, RelatedMax int
	RelatedTLDs            []string

	// Active sends the probes a reviewer approved, at most ActiveMax requests, keeping
	// ActiveMaxBody bytes of each answer.
	Active        bool
	ActiveMax     int
	ActiveMaxBody int

	// Browser also opens the first page in headless Chrome (runs the page's JavaScript).
	Browser            bool
	BrowserPath        string
	BrowserTimeout     time.Duration
	BrowserSettle      time.Duration
	BrowserMaxRequests int

	// MinHealth keeps only rules at least this healthy: broken (all), degraded, unknown, ok.
	MinHealth string
	// MaxEvidence is how many matching rules are listed for a technology.
	MaxEvidence int
	// DropHeaders lists response headers left out of the result (names, or prefixes
	// ending in "*"). The rules still see them.
	DropHeaders []string
	// Version names the scanner in the result.
	Version string
	// Now is the clock (tests).
	Now func() time.Time
}

func (o Options) internal(reg *Registry) scanner.Options {
	io := scanner.Options{
		Registry:  reg.r,
		Fetch:     o.fetchOptions(),
		NoFavicon: o.NoFavicon,
		Depth:     o.Depth, MaxPages: o.MaxPages, Delay: o.Delay, MaxDelay: o.MaxDelay, IgnoreRobots: o.IgnoreRobots,
		Friends: o.Friends, FriendsMax: o.FriendsMax,
		Related: o.Related, RelatedMax: o.RelatedMax, RelatedTLDs: o.RelatedTLDs,
		Active: o.Active, ActiveMax: o.ActiveMax, ActiveMaxBody: o.ActiveMaxBody,
		Browser: o.Browser, BrowserPath: o.BrowserPath, BrowserTimeout: o.BrowserTimeout,
		BrowserSettle: o.BrowserSettle, BrowserMaxRequests: o.BrowserMaxRequests,
		MinHealth: o.MinHealth, MaxEvidence: o.MaxEvidence, DropHeaders: o.DropHeaders,
		Version: o.Version, Now: o.Now,
	}
	if o.DNS {
		io.Resolver = observe.SystemResolver{}
	}
	return io
}

// Scan scans target (a URL or a host name) with the rules of reg.
func Scan(ctx context.Context, reg *Registry, opt Options, target string) (*scan.Result, error) {
	if reg == nil {
		return scanner.Scan(ctx, scanner.Options{}, target) // reports "no registry"
	}
	return scanner.Scan(ctx, opt.internal(reg), target)
}

// Validate checks a result against the public JSON Schema of scan results.
func Validate(r *scan.Result) error { return scanner.Validate(r) }

func (o Options) fetchOptions() fetch.Options {
	return fetch.Options{
		Timeout: o.Timeout, MaxBody: o.MaxBody, MaxRedirects: o.MaxRedirects, UserAgent: o.UserAgent,
		AllowPrivate: o.AllowPrivate, Insecure: o.Insecure, CacheDir: o.CacheDir, MaxAge: o.MaxAge,
		Transport: o.Transport,
	}
}
