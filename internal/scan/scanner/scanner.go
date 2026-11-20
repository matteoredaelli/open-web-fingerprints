// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

// Package scanner runs a complete scan: it fetches and observes a target, applies
// the rules of a registry export, extracts links, domains, social profiles and
// contacts, and assembles the result.
package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"time"

	"github.com/matteoredaelli/open-web-fingerprints/internal/export"
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

// ParseRegistry is LoadRegistry on bytes.
func ParseRegistry(b []byte) (*Registry, error) {
	reg, err := export.Verify(b)
	if err != nil {
		return nil, fmt.Errorf("registry: %w", err)
	}
	ref := scan.RegistryRef{ContentSHA256: reg.Manifest.ContentSHA256, SchemaVersion: reg.SchemaVersion, Sources: []string{}}
	for _, s := range reg.Manifest.Sources {
		ref.Sources = append(ref.Sources, s.Slug)
	}
	if reg.Export != nil {
		ref.Notice = reg.Export.Notice
	}
	return &Registry{Engine: engine.New(&reg), Ref: ref}, nil
}

// Options configure a scan.
type Options struct {
	Registry  *Registry
	Fetch     fetch.Options
	Resolver  observe.Resolver // nil: no DNS
	NoFavicon bool
	MinHealth string
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
	ob, err := observe.Observe(ctx, observe.Options{Fetcher: fetch.New(opt.Fetch), Resolver: opt.Resolver, NoFavicon: opt.NoFavicon}, target)
	if err != nil {
		return nil, err
	}
	final, err := url.Parse(ob.Page.FinalURL)
	if err != nil {
		return nil, fmt.Errorf("scanner: %w", err)
	}
	ex := web.Extract([]web.Page{{URL: ob.Page.FinalURL, Body: ob.HTML}}, final.Hostname())
	out := opt.Registry.Engine.Run(engine.Input{
		Observation: &ob.Observation, Page: ob.Page.FinalURL,
		DNSLooked: ob.DNSLooked, HasTLS: ob.Host.TLS != nil, FaviconTried: ob.FaviconTried,
	}, engine.Options{MinHealth: opt.MinHealth})

	res := &scan.Result{
		Schema: "https://github.com/matteoredaelli/open-web-fingerprints/schemas/scan-result.schema.json", SchemaVersion: scan.SchemaVersion,
		ScannedAt: started, Scanner: "owfscan " + opt.Version,
		Target: scan.Target{Input: target, URL: ob.Page.FinalURL, Host: final.Hostname(), RegistrableDomain: web.RegistrableDomain(final.Hostname())},
		Pages:  []scan.Page{ob.Page}, Technologies: out.Technologies,
		Links: ex.Links, Domains: ex.Domains, Socials: ex.Socials, Contacts: ex.Contacts,
		Coverage: out.Coverage, Registry: opt.Registry.Ref,
		Warnings: append(append(append([]scan.Warning{}, ob.Warnings...), ex.Warnings...), out.Warnings...),
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
