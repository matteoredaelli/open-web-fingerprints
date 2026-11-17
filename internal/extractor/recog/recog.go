// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

// Package recog extracts fingerprints from https://github.com/rapid7/recog
// (XML), restricted to the databases that match what a web server sends.
//
// A Recog fingerprint is a regular expression for one field (the Server
// header, a cookie, the page title, the favicon MD5, ...) and a list of params
// saying what a match means. This extractor keeps the service params:
//
//   - service.product is the technology (a literal; a product taken from a
//     capture group is skipped). A product name is not an identity in Recog:
//     "Dashboard", "HTTP" and "Media Server" are products of several vendors.
//     A technology is therefore a (vendor, product) pair, and a product name
//     shared by several vendors is shown as "<vendor> <product>";
//   - service.vendor and service.cpe23 give the vendor and CPE;
//   - service.version gives the version, from a capture group or a literal;
//   - service.certainty, when present, and else the database's preference,
//     is the source's confidence.
//
// Entries that only identify an operating system or hardware (os.*, hw.*) or
// that assert nothing (certainty 0) are skipped and counted in a warning.
// Everything is kept in Raw, including the upstream examples.
//
// Matching differences that matter: Recog patterns are Ruby regular
// expressions and case-sensitive unless flagged REG_ICASE, while the registry
// matches case-insensitively by default. Case-sensitive patterns therefore get
// an explicit (?-i) prefix, and patterns RE2 cannot run are marked pcre.
package recog

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"

	"github.com/matteoredaelli/open-web-fingerprints/internal/domain"
	"github.com/matteoredaelli/open-web-fingerprints/internal/extractor"
)

// ID is the stable extractor identifier.
const ID = "recog"

// Files lists the databases that are read, and what each one matches.
var files = []struct {
	Name        string
	Observation domain.Observation
	Target      string
}{
	{"favicons", domain.ObsFaviconHash, "md5"},
	{"html_title", "page_title", ""},
	{"http_cookies", "set_cookie", ""},
	{"http_header.x-fortisandbox-version", domain.ObsHTTPHeader, "X-FortiSandbox-Version"},
	{"http_servers", domain.ObsHTTPHeader, "Server"},
	{"http_wwwauth", domain.ObsHTTPHeader, "WWW-Authenticate"},
	{"http_xpoweredby", domain.ObsHTTPHeader, "X-Powered-By"},
}

// IsDatabase reports whether a snapshot path is one of the databases that are
// read. The snapshot checksum covers exactly these files.
func IsDatabase(path string) bool {
	for _, f := range files {
		if path == "xml/"+f.Name+".xml" {
			return true
		}
	}
	return false
}

// wantMatches is the matches attribute each file must declare. It is checked
// so that a renamed or repurposed upstream database is noticed.
var wantMatches = map[string]string{
	"favicons": "favicon.md5", "html_title": "html_title", "http_cookies": "http_header.cookie",
	"http_header.x-fortisandbox-version": "http_header.x-fortisandbox-version",
	"http_servers":                       "http_header.server", "http_wwwauth": "http_header.wwwauth",
	"http_xpoweredby": "http_header.x-powered-by",
}

// Extractor implements extractor.Extractor for Recog.
type Extractor struct{}

// New returns a Recog extractor.
func New() *Extractor { return &Extractor{} }

// ID implements extractor.Extractor.
func (*Extractor) ID() string { return ID }

// Name implements extractor.Extractor.
func (*Extractor) Name() string { return "Rapid7 Recog" }

// Capabilities implements extractor.CapabilityReporter.
func (*Extractor) Capabilities() []extractor.Capability {
	return []extractor.Capability{
		extractor.CapTechnologies, extractor.CapFingerprints, extractor.CapVersions, extractor.CapVendors,
	}
}

type dbXML struct {
	Matches      string          `xml:"matches,attr"`
	Preference   string          `xml:"preference,attr"`
	Fingerprints []fingerprintXM `xml:"fingerprint"`
}

type fingerprintXM struct {
	Pattern     string       `xml:"pattern,attr"`
	Flags       string       `xml:"flags,attr"`
	Description string       `xml:"description"`
	Examples    []exampleXML `xml:"example"`
	Params      []paramXML   `xml:"param"`
}

type exampleXML struct {
	Text  string     `xml:",chardata"`
	Attrs []xml.Attr `xml:",any,attr"`
}

type paramXML struct {
	Pos   int     `xml:"pos,attr"`
	Name  string  `xml:"name,attr"`
	Value *string `xml:"value,attr"`
}

// Extract implements extractor.Extractor.
func (x *Extractor) Extract(ctx context.Context, src extractor.Source) (*extractor.ExtractionResult, error) {
	if src.FS == nil {
		return nil, fmt.Errorf("recog: source %q has no snapshot filesystem", src.ID)
	}
	res := &extractor.ExtractionResult{Metadata: map[string]any{"revision": src.Revision}}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	techs := map[string]int{}      // product (lower case) -> index in res.Technologies
	vendors := map[string]string{} // technology key -> vendor
	read := 0
	for _, f := range files {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		path := "xml/" + f.Name + ".xml"
		b, err := fs.ReadFile(src.FS, path)
		if err != nil {
			res.Warnings = append(res.Warnings, extractor.Warning{Code: "missing_file", Ref: path,
				Message: "database not found in the snapshot: " + err.Error()})
			continue
		}
		var db dbXML
		if err := xml.Unmarshal(b, &db); err != nil {
			return nil, fmt.Errorf("recog: parse %s: %w", path, err)
		}
		if db.Matches != wantMatches[f.Name] {
			return nil, fmt.Errorf("recog: %s matches %q, expected %q: upstream changed the database", path, db.Matches, wantMatches[f.Name])
		}
		read++
		x.database(res, techs, vendors, path, f.Observation, f.Target, db)
	}
	if read == 0 {
		return nil, fmt.Errorf("recog: no Recog database found under xml/")
	}
	qualified := extractor.QualifyNames(res, vendors)
	res.Metadata["databases"] = read
	res.Metadata["qualified_names"] = qualified
	return res, nil
}

func (x *Extractor) database(res *extractor.ExtractionResult, techs map[string]int,
	vendors map[string]string, path string, obs domain.Observation, target string, db dbXML) {
	pref := parseUnit(db.Preference)
	skipped := map[string]int{}
	for _, fp := range db.Fingerprints {
		params := map[string][]paramXML{}
		for _, p := range fp.Params {
			params[p.Name] = append(params[p.Name], p)
		}
		prod, ok := literal(params["service.product"])
		switch {
		case !ok && len(params["service.product"]) > 0:
			skipped["the product is taken from a capture group"]++
			continue
		case !ok:
			skipped["it identifies no service (operating system or hardware only)"]++
			continue
		}
		conf := pref
		if c, ok := literal(params["service.certainty"]); ok {
			v := parseUnit(c)
			if v != nil && *v == 0 {
				skipped["it asserts nothing (certainty 0)"]++
				continue
			}
			if v != nil {
				conf = v
			}
		}
		prefix, err := flagPrefix(fp.Flags)
		if err != nil {
			res.Warnings = append(res.Warnings, extractor.Warning{Code: "unknown_flag", Ref: path, Message: err.Error() + "; fingerprint skipped"})
			continue
		}
		pattern := prefix + fp.Pattern

		vendor, _ := literal(params["service.vendor"])
		key := strings.ToLower(vendor) + "|" + strings.ToLower(prod)
		idx, known := techs[key]
		if !known {
			idx = len(res.Technologies)
			techs[key] = idx
			vendors[key] = vendor
			res.Technologies = append(res.Technologies, extractor.ExtractedTechnology{
				Key: key, File: path, Name: prod, Raw: mustJSON(map[string]string{"product": prod, "vendor": vendor}),
			})
		}
		if cpe, ok := cpeOf(params["service.cpe23"]); ok && !contains(res.Technologies[idx].CPE, cpe) {
			res.Technologies[idx].CPE = append(res.Technologies[idx].CPE, cpe)
		}

		f := extractor.ExtractedFingerprint{
			TechnologyKey: key, Observation: obs, Target: target,
			Operator: domain.OpRegex, Pattern: pattern,
			RegexFlavor:    extractor.RegexFlavorFor(pattern, domain.FlavorPCRE),
			VersionExtract: versionOf(params["service.version"]), Confidence: conf, File: path,
			Raw: rawFingerprint(path, db.Matches, fp),
		}
		if f.RegexFlavor == domain.FlavorPCRE {
			res.Warnings = append(res.Warnings, extractor.Warning{Code: "unsupported_regex", Ref: prod,
				Message: fmt.Sprintf("%s: pattern %q is not RE2-compatible; flavor set to pcre", path, fp.Pattern)})
		}
		res.Fingerprints = append(res.Fingerprints, f)
	}
	reasons := make([]string, 0, len(skipped))
	for r := range skipped {
		reasons = append(reasons, r)
	}
	sort.Strings(reasons)
	for _, r := range reasons {
		res.Warnings = append(res.Warnings, extractor.Warning{Code: "skipped_fingerprints", Ref: path,
			Message: fmt.Sprintf("%d fingerprints skipped: %s", skipped[r], r)})
	}
}

// literal returns the value of the first param that has one.
func literal(ps []paramXML) (string, bool) {
	for _, p := range ps {
		if p.Pos == 0 && p.Value != nil {
			return *p.Value, true
		}
	}
	return "", false
}

// versionOf returns the version_extract for a service.version param.
func versionOf(ps []paramXML) string {
	for _, p := range ps {
		switch {
		case p.Pos > 0 && p.Value == nil:
			return `\` + strconv.Itoa(p.Pos)
		case p.Pos == 0 && p.Value != nil:
			return *p.Value
		}
	}
	return ""
}

// flagPrefix turns Recog flags into inline regex flags. Recog patterns are
// case-sensitive unless REG_ICASE is set; the registry is case-insensitive by
// default, so the absence of the flag becomes an explicit (?-i).
func flagPrefix(flags string) (string, error) {
	icase, dotall, multiline := false, false, false
	for _, f := range strings.FieldsFunc(flags, func(r rune) bool { return r == ',' || r == ' ' || r == '|' }) {
		switch f {
		case "REG_ICASE":
			icase = true
		case "REG_DOT_NEWLINE":
			dotall = true
		case "REG_LINE_ANCHORS":
			multiline = true
		default:
			return "", fmt.Errorf("unknown flag %q", f)
		}
	}
	p := ""
	if !icase {
		p += "(?-i)"
	}
	if dotall {
		p += "(?s)"
	}
	if multiline {
		p += "(?m)"
	}
	return p, nil
}

func parseUnit(s string) *float64 {
	if s == "" {
		return nil
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil || v < 0 || v > 1 {
		return nil
	}
	return &v
}

// cpeOf converts a literal service.cpe23 value into a CPE 2.3 string with
// only the part, vendor and product.
func cpeOf(ps []paramXML) (string, bool) {
	v, ok := literal(ps)
	if !ok {
		return "", false
	}
	return extractor.NormalizeCPE(v)
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// rawFingerprint keeps the whole upstream element, including the examples.
func rawFingerprint(path, matches string, fp fingerprintXM) json.RawMessage {
	type ex struct {
		Text  string            `json:"text"`
		Attrs map[string]string `json:"attrs,omitempty"`
	}
	type param struct {
		Pos   int     `json:"pos"`
		Name  string  `json:"name"`
		Value *string `json:"value,omitempty"`
	}
	out := struct {
		File        string  `json:"file"`
		Matches     string  `json:"matches"`
		Pattern     string  `json:"pattern"`
		Flags       string  `json:"flags,omitempty"`
		Description string  `json:"description,omitempty"`
		Examples    []ex    `json:"examples,omitempty"`
		Params      []param `json:"params,omitempty"`
	}{File: path, Matches: matches, Pattern: fp.Pattern, Flags: fp.Flags, Description: strings.TrimSpace(fp.Description)}
	for _, e := range fp.Examples {
		x := ex{Text: e.Text}
		for _, a := range e.Attrs {
			if x.Attrs == nil {
				x.Attrs = map[string]string{}
			}
			x.Attrs[a.Name.Local] = a.Value
		}
		out.Examples = append(out.Examples, x)
	}
	for _, p := range fp.Params {
		out.Params = append(out.Params, param(p))
	}
	return mustJSON(out)
}

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err) // inputs are plain structs of strings and numbers
	}
	return b
}
