// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

// Package enthec extracts technologies and fingerprints from a snapshot of
// https://github.com/enthec/webappanalyzer (Wappalyzer JSON format).
//
// Mapping notes:
//   - Every pattern entry becomes one fingerprint. Wappalyzer combines the
//     entries of a technology with OR, so no fingerprint groups are produced.
//   - An empty pattern means "exists".
//   - Icons are not extracted (third-party marks); the file name stays in Raw.
//   - Observation types beyond the domain's known set: script_content
//     (inline scripts), page_url, page_text and css_rule.
package enthec

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"

	"github.com/matteoredaelli/open-web-fingerprints/internal/domain"
	"github.com/matteoredaelli/open-web-fingerprints/internal/extractor"
)

// ID is the stable extractor identifier.
const ID = "enthec"

// Extractor implements extractor.Extractor for Enthec WebAppAnalyzer.
type Extractor struct{}

// New returns an Enthec extractor.
func New() *Extractor { return &Extractor{} }

// ID implements extractor.Extractor.
func (*Extractor) ID() string { return ID }

// Name implements extractor.Extractor.
func (*Extractor) Name() string { return "Enthec WebAppAnalyzer" }

// Capabilities implements extractor.CapabilityReporter.
func (*Extractor) Capabilities() []extractor.Capability {
	return []extractor.Capability{
		extractor.CapTechnologies, extractor.CapFingerprints, extractor.CapVersions,
		extractor.CapCategories, extractor.CapRelationships,
	}
}

const (
	categoriesFile = "src/categories.json"
	groupsFile     = "src/groups.json"
	techGlob       = "src/technologies/*.json"
)

// Extract implements extractor.Extractor.
func (x *Extractor) Extract(ctx context.Context, src extractor.Source) (*extractor.ExtractionResult, error) {
	if src.FS == nil {
		return nil, fmt.Errorf("enthec: source %q has no snapshot filesystem", src.ID)
	}
	res := &extractor.ExtractionResult{Metadata: map[string]any{"revision": src.Revision}}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := extractCategories(src.FS, res); err != nil {
		return nil, err
	}
	files, err := fs.Glob(src.FS, techGlob)
	if err != nil {
		return nil, fmt.Errorf("enthec: list technology files: %w", err)
	}
	sort.Strings(files)
	seen := map[string]string{}
	for _, f := range files {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		b, err := fs.ReadFile(src.FS, f)
		if err != nil {
			return nil, fmt.Errorf("enthec: read %s: %w", f, err)
		}
		var techs map[string]json.RawMessage
		if err := json.Unmarshal(b, &techs); err != nil {
			return nil, fmt.Errorf("enthec: parse %s: %w", f, err)
		}
		names := sortedKeys(techs)
		for _, name := range names {
			if prev, dup := seen[name]; dup {
				res.Warnings = append(res.Warnings, extractor.Warning{
					Code: "duplicate_technology", Ref: name,
					Message: fmt.Sprintf("%s already defined in %s; later definition skipped", f, prev),
				})
				continue
			}
			seen[name] = f
			extractTechnology(f, name, techs[name], res)
		}
	}
	res.Metadata["technology_files"] = len(files)
	return res, nil
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func extractCategories(fsys fs.FS, res *extractor.ExtractionResult) error {
	type cat struct {
		Name   string `json:"name"`
		Groups []int  `json:"groups"`
	}
	type group struct {
		Name string `json:"name"`
	}
	cb, err := fs.ReadFile(fsys, categoriesFile)
	if err != nil {
		return fmt.Errorf("enthec: read categories: %w", err)
	}
	var cats map[string]json.RawMessage
	if err := json.Unmarshal(cb, &cats); err != nil {
		return fmt.Errorf("enthec: parse categories: %w", err)
	}
	groups := map[string]group{}
	if gb, err := fs.ReadFile(fsys, groupsFile); err == nil {
		if err := json.Unmarshal(gb, &groups); err != nil {
			return fmt.Errorf("enthec: parse groups: %w", err)
		}
	}
	keys := sortedKeys(cats)
	sort.SliceStable(keys, func(i, j int) bool { return numLess(keys[i], keys[j]) })
	for _, k := range keys {
		var c cat
		if err := json.Unmarshal(cats[k], &c); err != nil {
			return fmt.Errorf("enthec: parse category %s: %w", k, err)
		}
		g := ""
		if len(c.Groups) > 0 {
			g = groups[strconv.Itoa(c.Groups[0])].Name
			if len(c.Groups) > 1 {
				res.Warnings = append(res.Warnings, extractor.Warning{
					Code: "multiple_category_groups", Ref: k,
					Message: "only the first group is mapped to Group; all are kept in Raw",
				})
			}
		}
		res.Categories = append(res.Categories, extractor.ExtractedCategory{
			Key: k, Name: c.Name, Group: g, File: categoriesFile, Raw: cats[k],
		})
	}
	return nil
}

func numLess(a, b string) bool {
	x, e1 := strconv.Atoi(a)
	y, e2 := strconv.Atoi(b)
	if e1 != nil || e2 != nil {
		return a < b
	}
	return x < y
}

func warn(res *extractor.ExtractionResult, code, ref, msg string) {
	res.Warnings = append(res.Warnings, extractor.Warning{Code: code, Ref: ref, Message: msg})
}

func extractTechnology(file, name string, raw json.RawMessage, res *extractor.ExtractionResult) {
	var d map[string]json.RawMessage
	if err := json.Unmarshal(raw, &d); err != nil {
		warn(res, "invalid_technology", name, err.Error())
		return
	}
	t := extractor.ExtractedTechnology{Key: name, File: file, Name: name, Raw: raw}
	b := &builder{res: res, tech: name, file: file}

	for _, k := range sortedKeys(d) {
		v := d[k]
		switch k {
		case "description":
			b.decode(k, v, &t.Description)
		case "website":
			b.decode(k, v, &t.Website)
		case "cpe":
			var s string
			if b.decode(k, v, &s) && s != "" {
				t.CPE = []string{s}
			}
		case "oss":
			var o bool
			if b.decode(k, v, &o) {
				t.OpenSource = &o
			}
		case "saas":
			var o bool
			if b.decode(k, v, &o) {
				t.SaaS = &o
			}
		case "cats":
			var cats []int
			if b.decode(k, v, &cats) {
				for _, c := range cats {
					t.CategoryKeys = append(t.CategoryKeys, strconv.Itoa(c))
				}
			}
		case "icon", "pricing":
			// Kept only in Raw: icons are third-party marks, pricing is out of scope.
		case "html":
			b.patternList(k, v, domain.ObsHTML)
		case "scriptSrc":
			b.patternList(k, v, domain.ObsScriptURL)
		case "scripts":
			b.patternList(k, v, "script_content")
		case "url":
			b.patternList(k, v, "page_url")
		case "text":
			b.patternList(k, v, "page_text")
		case "css":
			b.patternList(k, v, "css_rule")
		case "xhr":
			b.patternList(k, v, domain.ObsXHR)
		case "robots":
			b.patternList(k, v, domain.ObsRobots)
		case "headers":
			b.patternMap(k, v, domain.ObsHTTPHeader)
		case "cookies":
			b.patternMap(k, v, domain.ObsCookie)
		case "meta":
			b.patternMap(k, v, domain.ObsMetaTag)
		case "js":
			b.patternMap(k, v, domain.ObsJSGlobal)
		case "dns":
			b.dns(k, v)
		case "certIssuer":
			var s string
			if b.decode(k, v, &s) {
				b.add(k, "", domain.ObsTLSCert, "issuer", s)
			}
		case "dom":
			b.dom(k, v)
		case "probe":
			b.probe(k, v)
		case "implies":
			b.relations(k, v, "implies")
		case "requires":
			b.relations(k, v, "requires")
		case "excludes":
			b.relations(k, v, "excludes")
		case "requiresCategory":
			var cats []int
			if b.decode(k, v, &cats) {
				for _, c := range cats {
					res.Relationships = append(res.Relationships, extractor.ExtractedRelationship{
						FromKey: name, ToCategoryKey: strconv.Itoa(c), Type: "requires", File: file,
						Raw: mustJSON(map[string]any{"field": k, "value": c}),
					})
				}
			}
		default:
			warn(res, "unknown_field", name, fmt.Sprintf("field %q is not mapped (kept in Raw)", k))
		}
	}
	res.Technologies = append(res.Technologies, t)
}

// builder accumulates fingerprints and relationships of one technology.
type builder struct {
	res        *extractor.ExtractionResult
	tech, file string
}

func (b *builder) decode(field string, raw json.RawMessage, into any) bool {
	if err := json.Unmarshal(raw, into); err != nil {
		warn(b.res, "unexpected_shape", b.tech, fmt.Sprintf("field %q: %v", field, err))
		return false
	}
	return true
}

// add appends one fingerprint from a Wappalyzer pattern string.
func (b *builder) add(field, key string, obs domain.Observation, target, pattern string) {
	f := extractor.ExtractedFingerprint{
		TechnologyKey: b.tech, Observation: obs, Target: target, File: b.file,
		Raw: mustJSON(map[string]any{"field": field, "key": key, "value": pattern}),
	}
	p := parsePattern(pattern)
	for _, u := range p.Unknown {
		warn(b.res, "unknown_modifier", b.tech, fmt.Sprintf("%s: modifier %q ignored (kept in Raw)", field, u))
	}
	f.Confidence = p.Confidence
	f.VersionExtract = p.Version
	if p.Regex == "" {
		f.Operator = domain.OpExists
	} else {
		f.Operator = domain.OpRegex
		f.Pattern = p.Regex
		f.RegexFlavor = flavorFor(p.Regex)
		if f.RegexFlavor == domain.FlavorECMAScript {
			warn(b.res, "unsupported_regex", b.tech,
				fmt.Sprintf("%s: pattern %q is not RE2-compatible; flavor set to ecmascript", field, p.Regex))
		}
	}
	b.res.Fingerprints = append(b.res.Fingerprints, f)
}

func (b *builder) patternList(field string, raw json.RawMessage, obs domain.Observation) {
	var l []string
	if !b.decode(field, raw, &l) {
		return
	}
	for _, s := range l {
		b.add(field, "", obs, "", s)
	}
}

func (b *builder) patternMap(field string, raw json.RawMessage, obs domain.Observation) {
	var m map[string]string
	if !b.decode(field, raw, &m) {
		return
	}
	for _, k := range sortedKeys(m) {
		b.add(field, k, obs, k, m[k])
	}
}

func (b *builder) dns(field string, raw json.RawMessage) {
	var m map[string][]string
	if !b.decode(field, raw, &m) {
		return
	}
	for _, k := range sortedKeys(m) {
		for _, s := range m[k] {
			b.add(field, k, domain.ObsDNSRecord, k, s)
		}
	}
}

// dom handles both forms: a list of selectors (existence) and a map from
// selector to {exists, text, attributes, properties}. Targets use
// "<selector>", "<selector>::text", "<selector>::attr(<name>)" and
// "<selector>::prop(<name>)".
func (b *builder) dom(field string, raw json.RawMessage) {
	var list []string
	if err := json.Unmarshal(raw, &list); err == nil {
		for _, entry := range list {
			// A selector can carry modifiers too, for example \;confidence:40.
			p := parsePattern(entry)
			for _, u := range p.Unknown {
				warn(b.res, "unknown_modifier", b.tech, fmt.Sprintf("%s: modifier %q ignored (kept in Raw)", field, u))
			}
			b.res.Fingerprints = append(b.res.Fingerprints, extractor.ExtractedFingerprint{
				TechnologyKey: b.tech, Observation: domain.ObsDOM, Target: p.Regex,
				Operator: domain.OpExists, Confidence: p.Confidence, File: b.file,
				Raw: mustJSON(map[string]any{"field": field, "selector": entry}),
			})
		}
		return
	}
	var m map[string]map[string]json.RawMessage
	if !b.decode(field, raw, &m) {
		return
	}
	for _, sel := range sortedKeys(m) {
		spec := m[sel]
		keys := sortedKeys(spec)
		if len(keys) == 0 {
			keys = []string{"exists"}
			spec = map[string]json.RawMessage{"exists": []byte(`""`)}
		}
		for _, k := range keys {
			switch k {
			case "exists":
				b.add(field, sel, domain.ObsDOM, sel, "")
			case "text":
				var s string
				if b.decode(field+"."+k, spec[k], &s) {
					b.add(field, sel+"::text", domain.ObsDOM, sel+"::text", s)
				}
			case "attributes", "properties":
				var am map[string]string
				if !b.decode(field+"."+k, spec[k], &am) {
					continue
				}
				kind := "attr"
				if k == "properties" {
					kind = "prop"
				}
				for _, n := range sortedKeys(am) {
					t := fmt.Sprintf("%s::%s(%s)", sel, kind, n)
					b.add(field, t, domain.ObsDOM, t, am[n])
				}
			default:
				warn(b.res, "unknown_dom_key", b.tech, fmt.Sprintf("dom selector %q key %q not mapped", sel, k))
			}
		}
	}
}

// probe maps Wappalyzer's {"/path": ""} to a pending, passive-looking GET
// probe. Extractors never approve probes.
func (b *builder) probe(field string, raw json.RawMessage) {
	var m map[string]string
	if !b.decode(field, raw, &m) {
		return
	}
	for _, path := range sortedKeys(m) {
		f := extractor.ExtractedFingerprint{
			TechnologyKey: b.tech, Observation: domain.ObsProbeResponse, Target: "status",
			Operator: domain.OpExists, File: b.file,
			Probe: &domain.Probe{
				Method: "GET", Path: path, RateLimitClass: "low", SafetyReview: "pending",
			},
			Raw: mustJSON(map[string]any{"field": field, "key": path, "value": m[path]}),
		}
		if !strings.HasPrefix(path, "/") {
			warn(b.res, "invalid_probe_path", b.tech, fmt.Sprintf("probe path %q does not start with /; skipped", path))
			continue
		}
		if m[path] != "" {
			p := parsePattern(m[path])
			f.Operator = domain.OpRegex
			f.Target = "body"
			f.Pattern = p.Regex
			f.RegexFlavor = flavorFor(p.Regex)
			f.Confidence = p.Confidence
		}
		b.res.Fingerprints = append(b.res.Fingerprints, f)
	}
}

func (b *builder) relations(field string, raw json.RawMessage, typ string) {
	var l []string
	if !b.decode(field, raw, &l) {
		return
	}
	for _, s := range l {
		p := parsePattern(s)
		for _, u := range p.Unknown {
			warn(b.res, "unknown_modifier", b.tech, fmt.Sprintf("%s: modifier %q ignored", field, u))
		}
		b.res.Relationships = append(b.res.Relationships, extractor.ExtractedRelationship{
			FromKey: b.tech, ToTechnologyKey: p.Regex, Type: typ, File: b.file,
			Confidence: p.Confidence,
			Raw:        mustJSON(map[string]any{"field": field, "value": s}),
		})
	}
}

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err) // inputs are plain maps of strings and numbers
	}
	return b
}
