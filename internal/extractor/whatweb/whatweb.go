// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

// Package whatweb extracts fingerprints from the plugins of WhatWeb
// (https://github.com/urbanadventurer/WhatWeb), which are Ruby files under
// plugins/. Most of a plugin is data: a `matches [ {...}, ... ]` list. The
// files are read as data (see ruby.go); no Ruby is run.
//
// What is read: each hash of `matches` that has `:text` (a literal in the body),
// `:regexp` (a regular expression over the body) or `:version` (a regular
// expression whose first group is the version), optionally with `:search`
// ("body" or "headers[name]") and `:certainty`. A hash with `:url` (another
// path of the site) becomes a probe, imported as a draft with a pending safety
// review; the extractor never approves it.
//
// What is skipped, and counted in warnings: the code of a plugin (`passive` and
// `aggressive` blocks), hashes with other keys (md5 of a file, tagpattern, a
// search over the URL extension...), regular expressions outside RE2 are kept
// but marked (flavor pcre), and a hash that is not data (interpolation,
// concatenation, method calls) is skipped whole: a partial clause would match
// more than the original.
//
// Matching in WhatWeb is case-sensitive unless a regular expression has the i
// flag, while the registry matches case-insensitively; a rule is wrapped in
// (?-i:...) to keep the original meaning.
package whatweb

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
const ID = "whatweb"

// Root is the directory of the plugins in the repository.
const Root = "plugins"

// IsPluginFile reports whether a repository path is a plugin.
func IsPluginFile(p string) bool {
	return strings.HasPrefix(p, Root+"/") && strings.Count(p, "/") == 1 && strings.HasSuffix(p, ".rb")
}

// Extractor implements extractor.Extractor.
type Extractor struct{}

// New returns a WhatWeb extractor.
func New() *Extractor { return &Extractor{} }

// ID implements extractor.Extractor.
func (*Extractor) ID() string { return ID }

// Name implements extractor.Extractor.
func (*Extractor) Name() string { return "WhatWeb plugins" }

// Capabilities implements extractor.CapabilityReporter.
func (*Extractor) Capabilities() []extractor.Capability {
	return []extractor.Capability{extractor.CapTechnologies, extractor.CapFingerprints, extractor.CapVersions}
}

// Extract implements extractor.Extractor.
func (x *Extractor) Extract(ctx context.Context, src extractor.Source) (*extractor.ExtractionResult, error) {
	if src.FS == nil {
		return nil, fmt.Errorf("whatweb: source %q has no snapshot filesystem", src.ID)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	files, err := fs.Glob(src.FS, Root+"/*.rb")
	if err != nil {
		return nil, fmt.Errorf("whatweb: list plugins: %w", err)
	}
	sort.Strings(files)
	res := &extractor.ExtractionResult{Metadata: map[string]any{"revision": src.Revision}}
	st := &state{res: res, seen: map[string]string{}, skipped: map[string]int{}}
	n := 0
	for _, f := range files {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		b, err := fs.ReadFile(src.FS, f)
		if err != nil {
			return nil, fmt.Errorf("whatweb: read %s: %w", f, err)
		}
		n++
		st.plugin(f, string(b))
	}
	res.Metadata["plugin_files"] = n
	if st.codeOnly > 0 {
		warn(res, "code_only_plugin", "plugins", fmt.Sprintf("%d plugins detect only with Ruby code and were not read", st.codeOnly))
	}
	for _, k := range sortedKeys(st.skipped) {
		warn(res, "unsupported_clause", k, fmt.Sprintf("%d clauses with %s not mapped", st.skipped[k], k))
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

type state struct {
	res     *extractor.ExtractionResult
	seen    map[string]string
	skipped map[string]int
	// codeOnly counts plugins that detect only with Ruby code.
	codeOnly int
}

var (
	hostLike  = regexp.MustCompile(`^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+(/\S*)?$`)
	codeBlock = regexp.MustCompile(`(?m)^[ \t]*(passive|aggressive|startup)[ \t]+do\b`)
)

// plugin maps one plugin file.
func (st *state) plugin(file, src string) {
	name, _ := declaration(src, "name")
	if name == "" {
		warn(st.res, "invalid_plugin", file, "a plugin without a name was skipped")
		return
	}
	hashes, bad, found, err := readMatches(src)
	if err != nil {
		warn(st.res, "unparsable_plugin", file, "matches list skipped: "+err.Error())
		return
	}
	hasCode := codeBlock.MatchString(src)
	if !found {
		if hasCode {
			st.codeOnly++
		} else {
			warn(st.res, "no_matches", name, "plugin without a matches list")
		}
		return
	}
	if prev, dup := st.seen[name]; dup {
		warn(st.res, "duplicate_technology", name, fmt.Sprintf("%s already defined in %s; later definition skipped", file, prev))
		return
	}
	for _, msg := range bad {
		warn(st.res, "unparsable_clause", name, "clause skipped: "+msg)
	}
	if hasCode {
		warn(st.res, "code_not_imported", name, "the plugin also detects with Ruby code, which is not read")
	}

	b := &builder{st: st, tech: name, file: file}
	for _, h := range hashes {
		b.clause(h)
	}
	if len(b.fps) == 0 {
		warn(st.res, "no_rules", name, "no clause could be mapped; technology skipped")
		return
	}
	if reportsAHeader(name, b.fps) {
		warn(st.res, "header_plugin", name, "the plugin only reports a header or cookie of the same name, which is not a technology; skipped")
		return
	}
	st.seen[name] = file

	t := extractor.ExtractedTechnology{Key: name, File: file, Name: name}
	t.Description, _ = declaration(src, "description")
	raw := map[string]any{"name": name}
	if v, ok := declaration(src, "version"); ok {
		raw["plugin_version"] = v
	}
	if t.Description != "" {
		raw["description"] = t.Description
	}
	if w, _ := declaration(src, "website"); w != "" {
		raw["website"] = w
		if hostLike.MatchString(w) {
			w = "http://" + w // the plugin writes "www.example.org" without a scheme
		}
		if u, err := url.Parse(w); err != nil || u.Host == "" || strings.ContainsAny(w, `\ `) || (u.Scheme != "http" && u.Scheme != "https") {
			warn(st.res, "invalid_website", name, fmt.Sprintf("website %q is not a URL; left out (kept in Raw)", w))
		} else {
			t.Website = w
		}
	}
	t.Raw = mustJSON(raw)
	st.res.Technologies = append(st.res.Technologies, t)
	st.res.Fingerprints = append(st.res.Fingerprints, b.fps...)
}

// reportsAHeader is true for a plugin such as "Content-Security-Policy" whose
// rules are all "this header is present", one of them for a header that carries
// its name (also with an x- prefix): it
// prints a value, it does not identify a technology.
func reportsAHeader(name string, fps []extractor.ExtractedFingerprint) bool {
	norm := func(s string) string {
		return strings.ToLower(strings.NewReplacer("-", "", "_", "", " ", "").Replace(s))
	}
	related := false
	for _, f := range fps {
		if f.Observation != domain.ObsHTTPHeader || f.Operator != domain.OpExists {
			return false
		}
		if n, tg := norm(name), norm(f.Target); strings.Contains(tg, n) || strings.Contains(n, tg) {
			related = true
		}
	}
	return related
}

func mustJSON(v any) json.RawMessage {
	bs, err := json.Marshal(v)
	if err != nil {
		panic(err) // inputs are plain trees of maps, lists and strings
	}
	return bs
}

type builder struct {
	st         *state
	tech, file string
	fps        []extractor.ExtractedFingerprint
}

// rawOf renders a clause for Raw: regular expressions as their literal.
func rawOf(h map[string]rubyValue) json.RawMessage {
	out := map[string]any{}
	for k, v := range h {
		if r, ok := v.(rubyRegexp); ok {
			out[k] = r.String()
		} else {
			out[k] = v
		}
	}
	return mustJSON(out)
}

var searchHeader = regexp.MustCompile(`^headers\[([A-Za-z0-9-]+)\]$`)

// clause maps one hash of the matches list.
func (b *builder) clause(h map[string]rubyValue) {
	skip := func(why string) { b.st.skipped[why]++ }
	for _, k := range sortedKeys(h) {
		switch k {
		case "text", "regexp", "version", "search", "url", "certainty", "name", "string", "offset", "model",
			"module", "ghdb", "account", "os", "firmware", "filepath", "status", "full":
		case "md5":
			skip("md5 of a file")
			return
		case "tagpattern":
			skip("tagpattern (shape of the page)")
			return
		default:
			skip("key :" + k)
			return
		}
	}
	if isTrue, _ := h["string"].(bool); isTrue && h["text"] == nil && h["regexp"] == nil && h["version"] == nil {
		// :string=>true on a header: the header is present.
		if m := searchHeader.FindStringSubmatch(searchOf(h)); m != nil && !strings.EqualFold(m[1], "set-cookie") {
			b.fps = append(b.fps, extractor.ExtractedFingerprint{
				TechnologyKey: b.tech, Observation: domain.ObsHTTPHeader, Target: m[1], Operator: domain.OpExists,
				Confidence: certainty(h), File: b.file, Raw: rawOf(h),
			})
			return
		}
	}
	text, hasText := h["text"].(string)
	re, hasRe := h["regexp"].(rubyRegexp)
	if sr, ok := h["string"].(rubyRegexp); ok && !hasText && !hasRe {
		// :string with a regular expression matches the body and reports the group;
		// with a plain string it is only the text the plugin prints.
		re, hasRe = sr, true
	}
	ver, hasVer := h["version"].(rubyRegexp)
	if _, isStr := h["version"].(string); isStr {
		// A fixed version string is an output of the plugin, not a condition.
		delete(h, "version")
	}
	if n := btoi(hasText) + btoi(hasRe) + btoi(hasVer); n == 0 {
		if _, onlyURL := h["url"]; onlyURL {
			// A path that must exist, with no condition on its content.
			b.probeRule(h, "", "", certainty(h), rawOf(h))
			return
		}
		skip("no condition (no :text, :regexp or :version)")
		return
	} else if n > 1 {
		// Several conditions in one clause: WhatWeb requires all of them. A single rule
		// cannot say that without a group; the clause is skipped, counted.
		skip("several conditions in one clause")
		return
	}

	var pattern, versionExtract string
	switch {
	case hasText:
		if text == "" {
			skip("an empty :text")
			return
		}
		pattern = "(?-i:" + regexp.QuoteMeta(text) + ")"
	case hasRe:
		p, ok := translate(re)
		if !ok {
			skip("a regular expression outside the supported syntax")
			return
		}
		pattern = p
	case hasVer:
		p, ok := translate(ver)
		if !ok {
			skip("a regular expression outside the supported syntax")
			return
		}
		pattern = p
		// :offset says which group holds the version (0, the first, by default).
		off, _ := h["offset"].(float64)
		if g := int(off) + 1; off >= 0 && g <= groupCount(ver.Source) {
			versionExtract = fmt.Sprintf(`\%d`, g)
		}
	}

	conf := certainty(h)
	raw := rawOf(h)

	if _, isProbe := h["url"]; isProbe {
		b.probeRule(h, pattern, versionExtract, conf, raw)
		return
	}
	f := extractor.ExtractedFingerprint{
		TechnologyKey: b.tech, Operator: domain.OpRegex, Pattern: pattern, VersionExtract: versionExtract,
		Confidence: conf, File: b.file, Raw: raw,
	}
	search, _ := h["search"].(string)
	switch m := searchHeader.FindStringSubmatch(search); {
	case search == "" || search == "body":
		f.Observation = domain.ObsHTML
	case m != nil && strings.EqualFold(m[1], "set-cookie"):
		f.Observation = "set_cookie"
	case m != nil:
		f.Observation, f.Target = domain.ObsHTTPHeader, m[1]
	default:
		skip("a search over " + search)
		return
	}
	if f.VersionExtract == "" && hasRe && matchesAnything(re.Source) && f.Observation != domain.ObsHTML {
		// "Any value": the rule says the header or cookie is present.
		f.Operator, f.Pattern = domain.OpExists, ""
	} else {
		f.RegexFlavor = extractor.RegexFlavorFor(pattern, domain.FlavorPCRE)
		if f.RegexFlavor != domain.FlavorRE2 {
			warn(b.st.res, "unsupported_regex", b.tech, fmt.Sprintf("pattern %q is not RE2-compatible; flavor set to pcre", pattern))
		}
	}
	b.fps = append(b.fps, f)
}

// anything is the set of expressions that match every value.
var anything = map[string]bool{
	".": true, ".+": true, ".*": true, "(.+)": true, "(.*)": true, "^.+$": true, "^.*$": true,
	"^(.+)$": true, "^(.*)$": true, "^.": true, "^(.+?)$": true, "(.+?)": true,
}

func matchesAnything(src string) bool { return anything[src] }

func searchOf(h map[string]rubyValue) string {
	s, _ := h["search"].(string)
	return s
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

// certainty reads :certainty (0 to 100) as a confidence between 0 and 1.
func certainty(h map[string]rubyValue) *float64 {
	if c, ok := h["certainty"].(float64); ok && c > 0 && c <= 100 {
		v := c / 100
		return &v
	}
	return nil
}

// probeRule maps a clause with :url to a GET probe. Extractors never approve
// probes: they are drafts with a pending safety review.
func (b *builder) probeRule(h map[string]rubyValue, pattern, versionExtract string, conf *float64, raw json.RawMessage) {
	path, _ := h["url"].(string)
	if path == "" || strings.ContainsAny(path, " \t\r\n{}\\#") || strings.Contains(path, "://") || strings.HasPrefix(path, "//") {
		b.st.skipped["a :url that is not a plain path"]++
		return
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if s, _ := h["search"].(string); s != "" && s != "body" {
		b.st.skipped["a :url with a search over "+s]++
		return
	}
	f := extractor.ExtractedFingerprint{
		TechnologyKey: b.tech, Observation: domain.ObsProbeResponse, Target: "status", Operator: domain.OpExists,
		Confidence: conf, File: b.file, Raw: raw,
		Probe: &domain.Probe{Method: "GET", Path: path, RateLimitClass: "low", SafetyReview: "pending"},
	}
	if pattern != "" {
		f.Target, f.Operator, f.Pattern, f.VersionExtract = "body", domain.OpRegex, pattern, versionExtract
		f.RegexFlavor = extractor.RegexFlavorFor(pattern, domain.FlavorPCRE)
		if f.RegexFlavor != domain.FlavorRE2 {
			warn(b.st.res, "unsupported_regex", b.tech, fmt.Sprintf("pattern %q is not RE2-compatible; flavor set to pcre", pattern))
		}
	}
	b.fps = append(b.fps, f)
}

var (
	rubyHexClass = regexp.MustCompile(`\\h`)
	rubyEndAnch  = regexp.MustCompile(`\\Z`)
)

// groupCount counts capturing groups roughly: a ( not escaped and not followed
// by ?, except named groups.
func groupCount(src string) int {
	n := 0
	inClass := false
	for i := 0; i < len(src); i++ {
		switch c := src[i]; {
		case c == '\\':
			i++
		case c == '[':
			inClass = true
		case c == ']':
			inClass = false
		case c == '(' && !inClass:
			if i+1 < len(src) && src[i+1] == '?' {
				if i+2 < len(src) && (src[i+2] == 'P' || src[i+2] == '<' && i+3 < len(src) && src[i+3] != '=' && src[i+3] != '!') {
					n++
				}
				continue
			}
			n++
		}
	}
	return n
}

// translate turns a Ruby regular expression into the registry's dialect. Ruby
// anchors ^ and $ are line anchors (m), the Ruby m flag is dotall (s), and
// matching is case-sensitive unless i: the rule is wrapped in a flag group
// that says so, which also keeps the numbering of capture groups.
func translate(r rubyRegexp) (string, bool) {
	s := r.Source
	if s == "" || strings.Contains(s, "(?#") || strings.Contains(s, `\G`) || strings.Contains(s, `\R`) || strings.Contains(s, `\X`) {
		return "", false
	}
	s = rubyHexClass.ReplaceAllString(s, `[0-9a-fA-F]`)
	s = rubyEndAnch.ReplaceAllString(s, `\z`)
	flags := "m"
	if strings.Contains(r.Flags, "m") {
		flags += "s"
	}
	if !strings.Contains(r.Flags, "i") {
		flags += "-i"
	}
	return "(?" + flags + ":" + s + ")", true
}
