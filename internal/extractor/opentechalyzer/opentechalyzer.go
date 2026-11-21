// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

// Package opentechalyzer extracts fingerprints from the database of
// OpenTechalyzer (https://github.com/Houseofmvps/opentechalyzer), whose
// fingerprints are TypeScript object literals under src/fingerprints/.
//
// The files are read as data (see ts.go); no code is run. Signals the model
// cannot carry yet are kept in Raw and counted in warnings: npmDep (package
// names inside bundles), the account identifier of a pattern (id) and the
// note. Probes marked intrusive, which look for exposed files, are out of
// scope and the technology is skipped.
package opentechalyzer

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/matteoredaelli/open-web-fingerprints/internal/domain"
	"github.com/matteoredaelli/open-web-fingerprints/internal/extractor"
)

// ID is the stable extractor identifier.
const ID = "opentechalyzer"

// Root is the directory of the fingerprint files in the repository.
const Root = "src/fingerprints"

// notData lists files of Root that are code, not fingerprints.
var notData = map[string]bool{"index.ts": true, "external.ts": true}

// IsFingerprintFile reports whether a repository path is a fingerprint file.
func IsFingerprintFile(p string) bool {
	dir, name := splitPath(p)
	return dir == Root && strings.HasSuffix(name, ".ts") && !notData[name]
}

func splitPath(p string) (dir, name string) {
	i := strings.LastIndexByte(p, '/')
	if i < 0 {
		return "", p
	}
	return p[:i], p[i+1:]
}

// Extractor implements extractor.Extractor.
type Extractor struct{}

// New returns an OpenTechalyzer extractor.
func New() *Extractor { return &Extractor{} }

// ID implements extractor.Extractor.
func (*Extractor) ID() string { return ID }

// Name implements extractor.Extractor.
func (*Extractor) Name() string { return "OpenTechalyzer fingerprints" }

// Capabilities implements extractor.CapabilityReporter.
func (*Extractor) Capabilities() []extractor.Capability {
	return []extractor.Capability{
		extractor.CapTechnologies, extractor.CapFingerprints, extractor.CapVersions,
		extractor.CapCategories, extractor.CapRelationships,
	}
}

// Extract implements extractor.Extractor.
func (x *Extractor) Extract(ctx context.Context, src extractor.Source) (*extractor.ExtractionResult, error) {
	if src.FS == nil {
		return nil, fmt.Errorf("opentechalyzer: source %q has no snapshot filesystem", src.ID)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	files, err := fs.Glob(src.FS, Root+"/*.ts")
	if err != nil {
		return nil, fmt.Errorf("opentechalyzer: list fingerprint files: %w", err)
	}
	sort.Strings(files)
	res := &extractor.ExtractionResult{Metadata: map[string]any{"revision": src.Revision}}
	st := &state{res: res, seen: map[string]string{}, cats: map[string]bool{}, skipped: map[string]int{}}
	n := 0
	for _, f := range files {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !IsFingerprintFile(f) {
			continue
		}
		b, err := fs.ReadFile(src.FS, f)
		if err != nil {
			return nil, fmt.Errorf("opentechalyzer: read %s: %w", f, err)
		}
		decls, err := parseModule(string(b))
		if err != nil {
			warn(res, "unparsable_file", f, "file skipped: "+err.Error())
			continue
		}
		n++
		for _, d := range decls {
			list, ok := d.Value.([]any)
			if !ok {
				continue
			}
			for _, item := range list {
				if m, ok := item.(map[string]any); ok {
					st.technology(f, m)
				}
			}
		}
	}
	res.Metadata["fingerprint_files"] = n
	for _, k := range sortedKeys(st.skipped) {
		warn(res, "unsupported_signal", k, fmt.Sprintf("%d %s not mapped (kept in Raw)", st.skipped[k], k))
	}
	return res, nil
}

func warn(res *extractor.ExtractionResult, code, ref, msg string) {
	res.Warnings = append(res.Warnings, extractor.Warning{Code: code, Ref: ref, Message: msg})
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err) // inputs are plain trees of maps, lists, strings and numbers
	}
	return b
}

type state struct {
	res     *extractor.ExtractionResult
	seen    map[string]string
	cats    map[string]bool
	skipped map[string]int
}

// pattern is one PatternInput after normalisation.
type pattern struct {
	re        string
	version   string
	conf      *float64
	caseSens  bool
	hasID     bool
	hasNote   bool
	raw       any
	malformed bool
}

func toPattern(v any) pattern {
	switch x := v.(type) {
	case string:
		return pattern{re: x, raw: v}
	case map[string]any:
		p := pattern{raw: v}
		re, ok := x["re"].(string)
		if !ok {
			p.malformed = true
			return p
		}
		p.re = re
		p.version, _ = x["version"].(string)
		if c, ok := x["confidence"].(float64); ok && c >= 0 && c <= 1 {
			p.conf = &c
		}
		p.caseSens, _ = x["caseSensitive"].(bool)
		_, p.hasID = x["id"]
		_, p.hasNote = x["note"]
		return p
	}
	return pattern{raw: v, malformed: true}
}

func toList(v any) []any {
	switch x := v.(type) {
	case nil:
		return nil
	case []any:
		return x
	}
	return []any{v}
}

var versionRef = regexp.MustCompile(`\$(\d)`)

// technology maps one fingerprint object.
func (st *state) technology(file string, m map[string]any) {
	name, _ := m["name"].(string)
	if name == "" {
		warn(st.res, "invalid_technology", file, "a fingerprint without a name was skipped")
		return
	}
	if prev, dup := st.seen[name]; dup {
		warn(st.res, "duplicate_technology", name, fmt.Sprintf("%s already defined in %s; later definition skipped", file, prev))
		return
	}
	if intrusive(m) {
		warn(st.res, "out_of_scope", name, "has a probe marked intrusive (looks for an exposed file); technology skipped")
		return
	}
	st.seen[name] = file

	t := extractor.ExtractedTechnology{Key: name, File: file, Name: name, Raw: mustJSON(m)}
	t.Description, _ = m["description"].(string)
	if w, _ := m["website"].(string); w != "" {
		if u, err := url.Parse(w); err != nil || u.Host == "" || strings.ContainsAny(w, `\ `) {
			warn(st.res, "invalid_website", name, fmt.Sprintf("website %q is not a URL; left out (kept in Raw)", w))
		} else {
			t.Website = w
		}
	}
	for _, c := range toList(m["categories"]) {
		if s, ok := c.(string); ok {
			t.CategoryKeys = append(t.CategoryKeys, s)
			if !st.cats[s] {
				st.cats[s] = true
				st.res.Categories = append(st.res.Categories, extractor.ExtractedCategory{
					Key: s, Name: strings.ReplaceAll(s, "-", " "), File: file, Raw: mustJSON(s),
				})
			}
		}
	}
	b := &builder{st: st, tech: name, file: file}
	for _, k := range sortedKeys(m) {
		v := m[k]
		switch k {
		case "name", "categories", "website", "description":
		case "html":
			b.list(k, v, domain.ObsHTML, "")
		case "scriptSrc":
			b.list(k, v, domain.ObsScriptURL, "")
		case "scriptContent":
			b.list(k, v, "script_content", "")
		case "stylesheetSrc":
			b.list(k, v, domain.ObsStylesheetURL, "")
		case "cssContent":
			b.list(k, v, "css_content", "")
		case "url":
			b.list(k, v, "page_url", "")
		case "robots":
			b.list(k, v, domain.ObsRobots, "")
		case "requestHost":
			b.list(k, v, "request_host", "")
		case "dnsTxt":
			b.list(k, v, domain.ObsDNSRecord, "TXT")
		case "dnsMx":
			b.list(k, v, domain.ObsDNSRecord, "MX")
		case "dnsCname":
			b.list(k, v, domain.ObsDNSRecord, "CNAME")
		case "dnsNs":
			b.list(k, v, domain.ObsDNSRecord, "NS")
		case "headers":
			b.record(k, v, domain.ObsHTTPHeader)
		case "meta":
			b.record(k, v, domain.ObsMetaTag)
		case "js":
			b.record(k, v, domain.ObsJSGlobal)
		case "cookies":
			b.cookies(k, v)
		case "dom":
			b.dom(k, v)
		case "probe":
			b.probes(k, v)
		case "implies", "requires", "excludes":
			for _, r := range toList(v) {
				if s, ok := r.(string); ok {
					st.res.Relationships = append(st.res.Relationships, extractor.ExtractedRelationship{
						FromKey: name, ToTechnologyKey: s, Type: k, File: file,
						Raw: mustJSON(map[string]any{"field": k, "value": s}),
					})
				}
			}
		case "npmDep", "certSubdomain", "faviconMd5", "weight":
			st.skipped[k] += len(toList(v))
		default:
			warn(st.res, "unknown_field", name, fmt.Sprintf("field %q is not mapped (kept in Raw)", k))
		}
	}
	st.res.Technologies = append(st.res.Technologies, t)
}

func intrusive(m map[string]any) bool {
	for _, p := range toList(m["probe"]) {
		if pm, ok := p.(map[string]any); ok {
			if b, _ := pm["intrusive"].(bool); b {
				return true
			}
		}
	}
	return false
}

type builder struct {
	st         *state
	tech, file string
}

// add appends one regex fingerprint from a pattern. An empty expression means
// "present".
func (b *builder) add(field, key string, obs domain.Observation, target string, p pattern, reg string) {
	if p.hasID {
		b.st.skipped["pattern identifiers (id)"]++
	}
	f := extractor.ExtractedFingerprint{
		TechnologyKey: b.tech, Observation: obs, Target: target, File: b.file, Confidence: p.conf,
		Raw: mustJSON(map[string]any{"field": field, "key": key, "value": p.raw}),
	}
	if reg == "" {
		f.Operator = domain.OpExists
	} else {
		if p.caseSens {
			// The engine matches case-insensitively; (?-i:) restores the
			// original meaning of an identifier format such as GTM-XXXXXXX.
			reg = "(?-i:" + reg + ")"
		}
		f.Operator, f.Pattern = domain.OpRegex, reg
		f.RegexFlavor = extractor.RegexFlavorFor(reg, domain.FlavorECMAScript)
		if f.RegexFlavor != domain.FlavorRE2 {
			warn(b.st.res, "unsupported_regex", b.tech, fmt.Sprintf("%s: pattern %q is not RE2-compatible; flavor set to ecmascript", field, reg))
		}
		f.VersionExtract = versionRef.ReplaceAllString(p.version, `\${1}`)
	}
	b.st.res.Fingerprints = append(b.st.res.Fingerprints, f)
}

func (b *builder) list(field string, v any, obs domain.Observation, target string) {
	for _, item := range toList(v) {
		p := toPattern(item)
		if p.malformed || p.re == "" {
			warn(b.st.res, "unexpected_shape", b.tech, fmt.Sprintf("field %q: an entry is not a pattern; skipped", field))
			continue
		}
		b.add(field, "", obs, target, p, p.re)
	}
}

func (b *builder) record(field string, v any, obs domain.Observation) {
	m, ok := v.(map[string]any)
	if !ok {
		warn(b.st.res, "unexpected_shape", b.tech, fmt.Sprintf("field %q is not a map", field))
		return
	}
	for _, k := range sortedKeys(m) {
		p := toPattern(m[k])
		if p.malformed {
			warn(b.st.res, "unexpected_shape", b.tech, fmt.Sprintf("field %q key %q is not a pattern; skipped", field, k))
			continue
		}
		b.add(field, k, obs, k, p, p.re)
	}
}

// cookies: OpenTechalyzer's keys are regular expressions over the cookie
// name (`^PHPSESSID$`), so they become rules over the Set-Cookie line, which
// starts with the name, as Recog's do.
func (b *builder) cookies(field string, v any) {
	m, ok := v.(map[string]any)
	if !ok {
		warn(b.st.res, "unexpected_shape", b.tech, fmt.Sprintf("field %q is not a map", field))
		return
	}
	for _, k := range sortedKeys(m) {
		p := toPattern(m[k])
		if p.malformed || p.re != "" {
			b.st.skipped["cookie value patterns"]++
			continue
		}
		b.add(field, k, "set_cookie", "", p, cookieLine(k))
	}
}

// cookieLine turns a cookie-name expression into one over "name=value; ...".
func cookieLine(name string) string {
	start := strings.HasPrefix(name, "^")
	inner := strings.TrimPrefix(name, "^")
	end := strings.HasSuffix(inner, "$") && !strings.HasSuffix(inner, `\$`)
	inner = strings.TrimSuffix(inner, "$")
	out := "^"
	if !start {
		out += "[^=]*"
	}
	out += "(?:" + inner + ")"
	if !end {
		out += "[^=]*"
	}
	return out + "="
}

func (b *builder) dom(field string, v any) {
	for _, item := range toList(v) {
		if s, ok := item.(string); ok && s != "" {
			b.st.res.Fingerprints = append(b.st.res.Fingerprints, extractor.ExtractedFingerprint{
				TechnologyKey: b.tech, Observation: domain.ObsDOM, Target: s, Operator: domain.OpExists, File: b.file,
				Raw: mustJSON(map[string]any{"field": field, "selector": s}),
			})
		}
	}
}

// probes maps a probe to a pending GET probe. Extractors never approve probes.
// The accepted status codes stay in Raw: the matcher reads the body.
func (b *builder) probes(field string, v any) {
	for _, item := range toList(v) {
		pm, ok := item.(map[string]any)
		path, _ := pm["path"].(string)
		if !ok || !strings.HasPrefix(path, "/") {
			warn(b.st.res, "invalid_probe_path", b.tech, fmt.Sprintf("probe path %q does not start with /; skipped", path))
			continue
		}
		if _, has := pm["header"]; has {
			b.st.skipped["probe header conditions"]++
			continue
		}
		f := extractor.ExtractedFingerprint{
			TechnologyKey: b.tech, Observation: domain.ObsProbeResponse, Target: "status",
			Operator: domain.OpExists, File: b.file,
			Probe: &domain.Probe{Method: "GET", Path: path, RateLimitClass: "low", SafetyReview: "pending"},
			Raw:   mustJSON(map[string]any{"field": field, "value": pm}),
		}
		if body, has := pm["body"]; has {
			p := toPattern(body)
			if p.malformed || p.re == "" {
				warn(b.st.res, "unexpected_shape", b.tech, fmt.Sprintf("probe %s: body is not a pattern; skipped", path))
				continue
			}
			reg := p.re
			if p.caseSens {
				reg = "(?-i:" + reg + ")"
			}
			f.Target, f.Operator, f.Pattern, f.Confidence = "body", domain.OpRegex, reg, p.conf
			f.RegexFlavor = extractor.RegexFlavorFor(reg, domain.FlavorECMAScript)
		}
		b.st.res.Fingerprints = append(b.st.res.Fingerprints, f)
	}
}
