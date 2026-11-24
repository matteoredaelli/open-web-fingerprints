// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

// Package nuclei extracts fingerprints from the technology templates of
// https://github.com/projectdiscovery/nuclei-templates (http/technologies).
//
// A template is a request plus matchers. A matcher is a word list, a regex
// list, a status list or a DSL expression, and the matchers are combined with
// "and" or "or". This extractor turns the boolean formula of a template into
// disjunctive normal form: an OR of clauses, each clause an AND of terms.
// A clause with one term is a plain rule; a clause with several terms is a
// group of rules that must all hold (they share a group key).
//
// What is read:
//
//   - GET and HEAD requests to the base URL (passive: the page already
//     observed) or to a literal path (an active probe, which is imported as a
//     draft with a pending safety review);
//   - word, regex and status matchers and a small subset of the DSL (dsl.go);
//   - the parts body, header, content_type, server and the whole response.
//
// What is skipped, and counted in warnings: raw requests, POST, request
// headers or bodies, payload lists (wordlists), flows, negative matchers,
// other matcher types and encodings, DSL outside the subset, and templates
// whose formula expands to more than maxClauses clauses.
//
// Extractors that read a version with a regular expression are mapped to rules
// with role "version" (see versionRules). Other extractors (kval, json, dsl,
// xpath) and regex extractors that do not read a version are skipped and counted.
//
// Five templates are not read as products: tech-detect and
// fingerprinthub-web-fingerprints are generated from Wappalyzer and
// FingerprintHub data (their lineage is that of those projects, and tech-detect
// duplicates what the Wappalyzer-format sources already give), and the
// wordpress plugin, theme and waf lists are generated lists of thousands of
// entries. favicon-detect is read as a table of favicon hashes.
package nuclei

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/matteoredaelli/open-web-fingerprints/internal/domain"
	"github.com/matteoredaelli/open-web-fingerprints/internal/extractor"
)

// ID is the stable extractor identifier.
const ID = "nuclei"

// Root is the directory of the snapshot that is read.
const Root = "http/technologies"

// maxClauses bounds the expansion of a formula into clauses.
const maxClauses = 32

// skipTemplates are not read as products, with the reason.
var skipTemplates = map[string]string{
	"tech-detect":                     "generated from Wappalyzer data",
	"fingerprinthub-web-fingerprints": "generated from FingerprintHub data",
	"wordpress-plugin-detect":         "a generated list of thousands of plugin paths",
	"wordpress-theme-detect":          "a generated list of thousands of theme paths",
	"waf-detect":                      "a generated list of WAF names",
}

// Extractor implements extractor.Extractor for nuclei technology templates.
type Extractor struct{ id, name, root string }

// New returns a nuclei extractor.
func New() *Extractor {
	return &Extractor{id: ID, name: "Nuclei technology templates", root: Root}
}

// NewFor returns an extractor for another collection written in the nuclei
// template format (FingerprintHub is one): same reading, other identity and root.
func NewFor(id, name, root string) *Extractor {
	return &Extractor{id: id, name: name, root: root}
}

// ID implements extractor.Extractor.
func (x *Extractor) ID() string { return x.id }

// Name implements extractor.Extractor.
func (x *Extractor) Name() string { return x.name }

// Capabilities implements extractor.CapabilityReporter.
func (*Extractor) Capabilities() []extractor.Capability {
	return []extractor.Capability{extractor.CapTechnologies, extractor.CapFingerprints, extractor.CapVendors}
}

type template struct {
	ID   string `yaml:"id"`
	Info struct {
		Name           string         `yaml:"name"`
		Description    string         `yaml:"description"`
		Tags           yaml.Node      `yaml:"tags"`
		Metadata       map[string]any `yaml:"metadata"`
		Classification struct {
			CPE string `yaml:"cpe"`
		} `yaml:"classification"`
	} `yaml:"info"`
	HTTP     []block   `yaml:"http"`
	Requests []block   `yaml:"requests"` // the old name of http
	Flow     string    `yaml:"flow"`
	Headless yaml.Node `yaml:"headless"`
}

type block struct {
	Method            string           `yaml:"method"`
	Path              []string         `yaml:"path"`
	Raw               []string         `yaml:"raw"`
	Headers           map[string]any   `yaml:"headers"`
	Body              string           `yaml:"body"`
	Payloads          yaml.Node        `yaml:"payloads"`
	Fuzzing           yaml.Node        `yaml:"fuzzing"`
	Flow              string           `yaml:"flow"`
	MatchersCondition string           `yaml:"matchers-condition"`
	Matchers          []tmatcher       `yaml:"matchers"`
	Extractors        []map[string]any `yaml:"extractors"`
}

type tmatcher struct {
	Type            string   `yaml:"type"`
	Name            string   `yaml:"name"`
	Part            string   `yaml:"part"`
	Condition       string   `yaml:"condition"`
	Words           []string `yaml:"words"`
	Regex           []string `yaml:"regex"`
	Status          []int    `yaml:"status"`
	DSL             []string `yaml:"dsl"`
	CaseInsensitive bool     `yaml:"case-insensitive"`
	Negative        bool     `yaml:"negative"`
	Hash            []string `yaml:"hash"` // favicon matchers: md5 (hex) or mmh3 (decimal)
	Encoding        string   `yaml:"encoding"`
}

// term is one condition on one part of one response.
type term struct {
	part    string // body, headers, response, content_type, server, status, favicon
	op      domain.Operator
	pattern string
	target  string // for favicon: the hash algorithm
}

// clause is an AND of terms.
type clause []term

// skip is returned when a template or block cannot be represented.
type skip struct{ reason string }

func (s *skip) Error() string { return s.reason }

func skipf(format string, a ...any) error { return &skip{fmt.Sprintf(format, a...)} }

type state struct {
	res        *extractor.ExtractionResult
	techs      map[string]int // technology key -> index
	vendors    map[string]string
	skipped    map[string]int
	derived    int
	blocks     int
	rules      int
	extracts   int
	versioned  int // version rules produced
	tplVersion map[string]bool
}

// Extract implements extractor.Extractor.
func (x *Extractor) Extract(ctx context.Context, src extractor.Source) (*extractor.ExtractionResult, error) {
	if src.FS == nil {
		return nil, fmt.Errorf("nuclei: source %q has no snapshot filesystem", src.ID)
	}
	res := &extractor.ExtractionResult{Metadata: map[string]any{"revision": src.Revision}}
	var files []string
	err := fs.WalkDir(src.FS, x.root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(p, ".yaml") {
			files = append(files, p)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("nuclei: list templates: %w", err)
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("nuclei: no templates under %s", x.root)
	}
	// A collection may keep a copy of a template whose vendor is unknown
	// (FingerprintHub's 00_unknown): the copy with a vendor is read first, so
	// it is the one that wins when both have the same id.
	unknown := func(p string) bool { return strings.Contains(p, "/00_unknown/") }
	sort.Slice(files, func(i, j int) bool {
		if ui, uj := unknown(files[i]), unknown(files[j]); ui != uj {
			return uj
		}
		return files[i] < files[j]
	})

	st := &state{res: res, techs: map[string]int{}, vendors: map[string]string{}, skipped: map[string]int{}, tplVersion: map[string]bool{}}
	seen := map[string]string{}
	for _, f := range files {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		b, err := fs.ReadFile(src.FS, f)
		if err != nil {
			return nil, fmt.Errorf("nuclei: read %s: %w", f, err)
		}
		var t template
		if err := yaml.Unmarshal(b, &t); err != nil {
			res.Warnings = append(res.Warnings, extractor.Warning{Code: "invalid_template", Ref: f, Message: err.Error()})
			continue
		}
		if t.ID == "" {
			res.Warnings = append(res.Warnings, extractor.Warning{Code: "invalid_template", Ref: f, Message: "no id"})
			continue
		}
		if prev, dup := seen[t.ID]; dup {
			res.Warnings = append(res.Warnings, extractor.Warning{Code: "duplicate_template", Ref: f, Message: "id " + t.ID + " already defined in " + prev})
			continue
		}
		seen[t.ID] = f
		if why, no := skipTemplates[t.ID]; no && t.ID != "favicon-detect" {
			st.skipped["template skipped: "+why]++
			continue
		}
		if t.ID == "favicon-detect" {
			st.favicons(f, &t)
			continue
		}
		st.template(f, &t)
	}
	reasons := make([]string, 0, len(st.skipped))
	for r := range st.skipped {
		reasons = append(reasons, r)
	}
	sort.Strings(reasons)
	for _, r := range reasons {
		res.Warnings = append(res.Warnings, extractor.Warning{Code: "skipped", Ref: x.root,
			Message: fmt.Sprintf("%d: %s", st.skipped[r], r)})
	}
	res.Metadata["templates"] = len(files)
	res.Metadata["blocks_mapped"] = st.blocks
	res.Metadata["derived_names"] = st.derived
	res.Metadata["qualified_names"] = extractor.QualifyNames(res, st.vendors)
	res.Metadata["templates_with_extractors"] = st.extracts
	res.Metadata["version_rules"] = st.versioned
	res.Metadata["templates_with_version"] = len(st.tplVersion)
	return res, nil
}

// template maps the http blocks of one template onto the technology it names.
func (st *state) template(file string, t *template) {
	blocks := t.HTTP
	if len(blocks) == 0 {
		blocks = t.Requests
	}
	if len(blocks) == 0 {
		st.skipped["no http request"]++
		return
	}
	if t.Flow != "" {
		st.skipped["the template uses a flow"]++
		return
	}
	type mapped struct {
		clauses []clause
		probe   *domain.Probe
		index   int
		path    string
		ex      []map[string]any
	}
	var all []mapped
	for bi, b := range blocks {
		reqs, err := st.requests(b)
		if err != nil {
			st.count(err)
			continue
		}
		cls, err := formula(b)
		if err != nil {
			st.count(err)
			continue
		}
		for _, r := range reqs {
			all = append(all, mapped{clauses: cls, probe: r.probe, index: bi, path: r.path, ex: b.Extractors})
		}
		if len(b.Extractors) > 0 {
			st.extracts++
		}
	}
	if len(all) == 0 {
		return
	}
	var emitted []extractor.ExtractedFingerprint
	var versions []extractor.ExtractedFingerprint
	for _, m := range all {
		st.blocks++
		before := len(emitted)
		for ci, cl := range m.clauses {
			group := ""
			if len(cl) > 1 {
				group = fmt.Sprintf("%s#b%d#%s#c%d", t.ID, m.index, m.path, ci)
			}
			// A clause is all or nothing: dropping one term would make the rule
			// match more than the template does.
			var rules []extractor.ExtractedFingerprint
			complete := true
			for _, tm := range cl {
				f, ok := st.fingerprint("", group, m.probe, tm, file)
				if !ok {
					complete = false
					break
				}
				f.Raw = mustJSON(map[string]any{
					"template": t.ID, "block": m.index, "path": m.path, "clause": ci, "term": tm.part + " " + string(tm.op) + " " + tm.pattern,
				})
				rules = append(rules, f)
			}
			if !complete {
				continue
			}
			emitted = append(emitted, rules...)
		}
		// Versions are read on the requests that detect something.
		if len(emitted) > before {
			versions = append(versions, st.versionRules(t.ID, file, m.index, m.path, m.probe, m.ex)...)
		}
	}
	// A technology exists only if at least one rule of it was understood.
	if len(emitted) == 0 {
		st.skipped["no rule could be represented"]++
		return
	}
	key := st.technology(file, t)
	for i := range emitted {
		emitted[i].TechnologyKey = key
	}
	for i := range versions {
		versions[i].TechnologyKey = key
	}
	st.res.Fingerprints = append(st.res.Fingerprints, emitted...)
	st.res.Fingerprints = append(st.res.Fingerprints, versions...)
	st.versioned += len(versions)
	st.rules += len(emitted)
}

func (st *state) count(err error) {
	var s *skip
	if errors.As(err, &s) {
		st.skipped[s.reason]++
		return
	}
	st.skipped[err.Error()]++
}

// request is one place a block is sent to.
type request struct {
	path  string
	probe *domain.Probe // nil for the page already observed
}

var (
	basePrefix = regexp.MustCompile(`^\{\{(?:BaseURL|RootURL)\}\}`)
	hostLike   = regexp.MustCompile(`\{\{`)
)

func (st *state) requests(b block) ([]request, error) {
	if len(b.Raw) > 0 {
		return nil, skipf("raw request")
	}
	method := strings.ToUpper(b.Method)
	if method == "" {
		method = "GET"
	}
	if method != "GET" && method != "HEAD" {
		return nil, skipf("method %s", method)
	}
	switch {
	case b.Payloads.Kind != 0 || b.Fuzzing.Kind != 0:
		return nil, skipf("payload list")
	case b.Body != "" || len(b.Headers) > 0:
		return nil, skipf("request headers or body")
	case b.Flow != "":
		return nil, skipf("the template uses a flow")
	}
	if len(b.Path) == 0 {
		return nil, skipf("no path")
	}
	var out []request
	seen := map[string]bool{}
	for _, p := range b.Path {
		if !basePrefix.MatchString(p) {
			return nil, skipf("path not relative to the base URL")
		}
		rest := basePrefix.ReplaceAllString(p, "")
		switch {
		case rest == "" || rest == "/":
			if !seen["/"] {
				seen["/"] = true
				out = append(out, request{path: "/"})
			}
		case strings.HasPrefix(rest, "/") && !hostLike.MatchString(rest):
			if !seen[rest] {
				seen[rest] = true
				out = append(out, request{path: rest, probe: &domain.Probe{
					Method: method, Path: rest, RateLimitClass: "low", SafetyReview: "pending",
				}})
			}
		default:
			return nil, skipf("path with a variable")
		}
	}
	return out, nil
}

// formula turns the matchers of a block into clauses (disjunctive normal form).
func formula(b block) ([]clause, error) {
	if len(b.Matchers) == 0 {
		return nil, skipf("no matchers")
	}
	var perMatcher [][]clause
	for _, m := range b.Matchers {
		alts, err := matcherClauses(m)
		if err != nil {
			return nil, err
		}
		perMatcher = append(perMatcher, alts)
	}
	var out []clause
	if strings.EqualFold(b.MatchersCondition, "and") {
		out = []clause{{}}
		for _, alts := range perMatcher {
			var next []clause
			for _, c := range out {
				for _, a := range alts {
					next = append(next, append(append(clause{}, c...), a...))
				}
			}
			out = next
			if len(out) > maxClauses {
				return nil, skipf("more than %d combinations", maxClauses)
			}
		}
	} else {
		for _, alts := range perMatcher {
			out = append(out, alts...)
		}
		if len(out) > maxClauses {
			return nil, skipf("more than %d combinations", maxClauses)
		}
	}
	return dedupe(out), nil
}

func dedupe(cls []clause) []clause {
	seen := map[string]bool{}
	var out []clause
	for _, c := range cls {
		var terms []term
		ts := map[term]bool{}
		for _, t := range c {
			if !ts[t] {
				ts[t] = true
				terms = append(terms, t)
			}
		}
		key := fmt.Sprint(terms)
		if !seen[key] {
			seen[key] = true
			out = append(out, terms)
		}
	}
	return out
}

var partNames = map[string]string{
	"": "body", "body": "body", "header": "headers", "all_headers": "headers", "response": "response",
	"all": "response", "content_type": "content_type", "server": "server",
}

var (
	md5Hex  = regexp.MustCompile(`^[0-9a-fA-F]{32}$`)
	mmh3Dec = regexp.MustCompile(`^-?[0-9]+$`)
)

// matcherClauses returns the alternatives a matcher stands for.
func matcherClauses(m tmatcher) ([]clause, error) {
	if m.Negative {
		return nil, skipf("negative matcher")
	}
	if m.Encoding != "" {
		return nil, skipf("matcher encoding")
	}
	and := strings.EqualFold(m.Condition, "and")
	switch m.Type {
	case "status":
		if len(m.Status) == 0 {
			return nil, skipf("empty status matcher")
		}
		var alts []clause
		for _, s := range m.Status {
			alts = append(alts, clause{{part: "status", op: domain.OpEquals, pattern: strconv.Itoa(s)}})
		}
		return alts, nil
	case "favicon":
		var alts []clause
		for _, h := range m.Hash {
			h = strings.TrimSpace(h)
			switch {
			case md5Hex.MatchString(h):
				alts = append(alts, clause{{part: "favicon", op: domain.OpHashEquals, pattern: strings.ToLower(h), target: "md5"}})
			case mmh3Dec.MatchString(h):
				alts = append(alts, clause{{part: "favicon", op: domain.OpHashEquals, pattern: h, target: "mmh3"}})
			default:
				return nil, skipf("favicon hash in an unknown form")
			}
		}
		if len(alts) == 0 {
			return nil, skipf("empty favicon matcher")
		}
		return alts, nil
	case "word", "regex":
		part, ok := partNames[m.Part]
		if !ok {
			return nil, skipf("part %s", m.Part)
		}
		items := m.Words
		if m.Type == "regex" {
			items = m.Regex
		}
		if len(items) == 0 {
			return nil, skipf("empty %s matcher", m.Type)
		}
		var terms []term
		for _, it := range items {
			if m.Type == "regex" {
				terms = append(terms, term{part: part, op: domain.OpRegex, pattern: "(?-i)" + it})
			} else if m.CaseInsensitive {
				terms = append(terms, term{part: part, op: domain.OpRegex, pattern: regexp.QuoteMeta(it)})
			} else {
				terms = append(terms, term{part: part, op: domain.OpContains, pattern: it})
			}
		}
		return combine(terms, and), nil
	case "dsl":
		if len(m.DSL) == 0 {
			return nil, skipf("empty dsl matcher")
		}
		// Each expression is an AND of terms, and a term such as contains_any
		// may offer alternatives: an expression stands for several clauses.
		var perExpr [][]clause
		for _, e := range m.DSL {
			terms, err := parseDSL(e)
			if err != nil {
				return nil, skipf("dsl outside the subset")
			}
			variants := []clause{{}}
			for _, t := range terms {
				opts, err := dslOptions(t)
				if err != nil {
					return nil, err
				}
				var next []clause
				for _, v := range variants {
					for _, o := range opts {
						next = append(next, append(append(clause{}, v...), o...))
					}
				}
				variants = next
				if len(variants) > maxClauses {
					return nil, skipf("more than %d combinations", maxClauses)
				}
			}
			perExpr = append(perExpr, variants)
		}
		if !and {
			var alts []clause
			for _, v := range perExpr {
				alts = append(alts, v...)
			}
			return alts, nil
		}
		out := []clause{{}}
		for _, v := range perExpr {
			var next []clause
			for _, c := range out {
				for _, a := range v {
					next = append(next, append(append(clause{}, c...), a...))
				}
			}
			out = next
			if len(out) > maxClauses {
				return nil, skipf("more than %d combinations", maxClauses)
			}
		}
		return out, nil
	}
	return nil, skipf("matcher type %s", m.Type)
}

// combine turns terms joined by and (one clause) or or (one clause each).
func combine(terms []term, and bool) []clause {
	if and {
		return []clause{clause(terms)}
	}
	out := make([]clause, len(terms))
	for i, t := range terms {
		out[i] = clause{t}
	}
	return out
}

// dslOptions returns the alternatives of one DSL term; each alternative is a
// clause (terms that all hold).
func dslOptions(t dslTerm) ([]clause, error) {
	switch t.kind {
	case "status":
		return []clause{{{part: "status", op: domain.OpEquals, pattern: strconv.Itoa(t.status)}}}, nil
	case "mmh3":
		return []clause{{{part: "favicon", op: domain.OpHashEquals, pattern: t.args[0], target: "mmh3"}}}, nil
	}
	part, ok := partNames[t.part]
	if !ok {
		return nil, skipf("part %s", t.part)
	}
	contains := func(s string) term {
		if t.lower {
			return term{part: part, op: domain.OpRegex, pattern: regexp.QuoteMeta(s)}
		}
		return term{part: part, op: domain.OpContains, pattern: s}
	}
	switch t.kind {
	case "regex":
		return []clause{{{part: part, op: domain.OpRegex, pattern: "(?-i)" + t.args[0]}}}, nil
	case "contains":
		return []clause{{contains(t.args[0])}}, nil
	case "any":
		var out []clause
		for _, a := range t.args {
			out = append(out, clause{contains(a)})
		}
		return out, nil
	case "all":
		var all clause
		for _, a := range t.args {
			all = append(all, contains(a))
		}
		return []clause{all}, nil
	}
	return nil, skipf("dsl term %s", t.kind)
}

// fingerprint builds the extracted rule for a term in the context of a request.
func (st *state) fingerprint(key, group string, probe *domain.Probe, tm term, file string) (extractor.ExtractedFingerprint, bool) {
	f := extractor.ExtractedFingerprint{
		TechnologyKey: key, GroupKey: group, Operator: tm.op, Pattern: tm.pattern, File: file,
	}
	if probe != nil {
		p := *probe
		f.Probe = &p
		f.Observation, f.Target = domain.ObsProbeResponse, tm.part
		if tm.part == "favicon" {
			st.skipped["a favicon hash on a probed path"]++
			return f, false
		}
	} else {
		switch tm.part {
		case "body":
			f.Observation = domain.ObsHTML
		case "headers":
			f.Observation = "response_headers"
		case "response":
			f.Observation = "http_response"
		case "content_type":
			f.Observation, f.Target = domain.ObsHTTPHeader, "Content-Type"
		case "server":
			f.Observation, f.Target = domain.ObsHTTPHeader, "Server"
		case "status":
			f.Observation = "http_status"
		case "favicon":
			f.Observation, f.Target = domain.ObsFaviconHash, tm.target
		}
	}
	if tm.op == domain.OpRegex {
		f.RegexFlavor = extractor.RegexFlavorFor(tm.pattern, domain.FlavorPCRE)
		if f.RegexFlavor != domain.FlavorRE2 {
			st.res.Warnings = append(st.res.Warnings, extractor.Warning{Code: "unsupported_regex", Ref: file,
				Message: fmt.Sprintf("pattern %q is not RE2-compatible; flavor set to pcre", tm.pattern)})
		}
	}
	return f, true
}

// technology returns the key of the technology a template detects,
// creating it on first sight.
func (st *state) technology(file string, t *template) string {
	product, _ := t.Info.Metadata["product"].(string)
	vendor, _ := t.Info.Metadata["vendor"].(string)
	name, derived := displayName(strings.TrimSpace(product), t.Info.Name, t.ID)
	id := strings.ToLower(strings.TrimSpace(product))
	if id == "" {
		id = strings.ToLower(name)
	}
	key := strings.ToLower(vendor) + "|" + id
	idx, ok := st.techs[key]
	if !ok {
		idx = len(st.res.Technologies)
		st.techs[key] = idx
		st.vendors[key] = vendor
		if derived {
			st.derived++
		}
		st.res.Technologies = append(st.res.Technologies, extractor.ExtractedTechnology{
			Key: key, File: file, Name: name, Description: strings.TrimSpace(t.Info.Description),
			Raw: mustJSON(map[string]any{"template": t.ID, "name": t.Info.Name, "derived_name": derived}),
		})
	}
	tech := &st.res.Technologies[idx]
	if tech.Description == "" {
		tech.Description = strings.TrimSpace(t.Info.Description)
	}
	if cpe, ok := extractor.NormalizeCPE(t.Info.Classification.CPE); ok && !contains(tech.CPE, cpe) {
		tech.CPE = append(tech.CPE, cpe)
	}
	return key
}

var nameNoise = []*regexp.Regexp{
	regexp.MustCompile(`(?i)^(detect|detection of|finder for)\s+`),
	regexp.MustCompile(`(?i)\s*[-–:]*\s*((version|login( page)?)\s+)*(detect(ed|ion|or|s)?|finder|fingerprint(ing)?)\s*$`),
}

// cleanName drops the words of a template title that are not part of the
// product name: "Apache Detection" becomes "Apache". It is a guess, used only
// when the template states no product.
func cleanName(n string) string {
	n = strings.TrimSpace(n)
	for i := 0; i < 3; i++ {
		prev := n
		for _, re := range nameNoise {
			n = strings.TrimSpace(re.ReplaceAllString(n, ""))
		}
		if n == prev {
			break
		}
	}
	return n
}

// versionNames are the extractor names that mean "the version" (a name that
// contains "version" also does, as in version_by_js). An unnamed
// extractor counts only if its pattern looks like it reads a number.
var versionNames = map[string]bool{
	"": true, "version": true, "detected_version": true, "internal_detected_version": true,
}

var numericHint = regexp.MustCompile(`(?i)0-9|\d|version|ver\.`)

// versionRules turns the regex extractors of a block into rules that read a
// version. An extractor is not a matcher: it never decides whether the product
// is there, so its rule has role "version" and applies only when a detection
// rule of the same request matched. Extractors for other things (a domain, a
// timestamp), extractors without a capture group, and non-regex extractors are
// skipped and counted.
func (st *state) versionRules(id, file string, block int, path string, probe *domain.Probe, exs []map[string]any) []extractor.ExtractedFingerprint {
	var out []extractor.ExtractedFingerprint
	for xi, e := range exs {
		typ, _ := e["type"].(string)
		if typ != "regex" {
			st.skipped["extractor of type "+typ+" (not a regex)"]++
			continue
		}
		name, _ := e["name"].(string)
		patterns := toStrings(e["regex"])
		group, _ := e["group"].(int)
		switch {
		case !versionNames[strings.ToLower(name)] && !strings.Contains(strings.ToLower(name), "version"):
			st.skipped["extractor that reads something else than a version"]++
			continue
		case group < 1 || len(patterns) == 0:
			st.skipped["extractor without a capture group"]++
			continue
		}
		part, ok := partNames[strFrom(e["part"])]
		if !ok || part == "status" {
			st.skipped["extractor on an unsupported part"]++
			continue
		}
		for pi, pat := range patterns {
			if name == "" && !numericHint.MatchString(pat) {
				st.skipped["extractor that reads something else than a version"]++
				continue
			}
			if re, err := regexp.Compile(pat); err == nil && re.NumSubexp() < group {
				st.skipped["extractor whose group does not exist"]++
				continue
			}
			f, ok := st.fingerprint("", "", probe, term{part: part, op: domain.OpRegex, pattern: "(?-i)" + pat}, file)
			if !ok {
				continue
			}
			f.Role = domain.RoleVersion
			f.VersionExtract = `\` + strconv.Itoa(group)
			f.Raw = mustJSON(map[string]any{"template": id, "block": block, "path": path, "extractor": xi, "pattern": pi, "name": name, "group": group})
			out = append(out, f)
		}
	}
	if len(out) > 0 {
		st.tplVersion[id] = true
	}
	return out
}

func toStrings(v any) []string {
	l, _ := v.([]any)
	var out []string
	for _, x := range l {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func strFrom(v any) string {
	s, _ := v.(string)
	return s
}

// displayName chooses how a technology is shown. The product of the metadata
// is an identifier (often a CPE token such as "experience_manager"); the title
// of the template is written for people, so its cleaned form is used when it
// names the same product. The second result tells that the name is a guess made
// from the title because the template states no product.
func displayName(product, title, id string) (string, bool) {
	cleaned := cleanName(title)
	if product == "" {
		if cleaned != "" {
			return cleaned, true
		}
		return id, true
	}
	if cleaned != "" && strings.Contains(squash(cleaned), squash(product)) {
		return cleaned, false
	}
	words := strings.Fields(strings.NewReplacer("_", " ", "-", " ").Replace(product))
	for i, w := range words {
		words[i] = strings.ToUpper(w[:1]) + w[1:]
	}
	return strings.Join(words, " "), false
}

// squash keeps lower-case letters and digits only, to compare names.
func squash(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// favicons reads favicon-detect as a table: each named matcher is the hash of
// one product's favicon. The status condition is dropped because a matching
// hash already implies that a favicon was served.
func (st *state) favicons(file string, t *template) {
	re := regexp.MustCompile(`^status_code\s*==\s*200\s*&&\s*\(\s*("(?:[^"\\]|\\.)*")\s*==\s*mmh3\(base64_py\(body\)\)\s*\)$`)
	blocks := t.HTTP
	for _, b := range blocks {
		for _, m := range b.Matchers {
			if m.Type != "dsl" || m.Name == "" || len(m.DSL) != 1 {
				st.skipped["favicon matcher in an unexpected shape"]++
				continue
			}
			mm := re.FindStringSubmatch(strings.TrimSpace(m.DSL[0]))
			if mm == nil {
				st.skipped["favicon matcher in an unexpected shape"]++
				continue
			}
			h, err := strconv.Unquote(mm[1])
			if err != nil {
				st.skipped["favicon matcher in an unexpected shape"]++
				continue
			}
			key := "|" + strings.ToLower(m.Name)
			if _, ok := st.techs[key]; !ok {
				st.techs[key] = len(st.res.Technologies)
				st.vendors[key] = ""
				st.res.Technologies = append(st.res.Technologies, extractor.ExtractedTechnology{
					Key: key, File: file, Name: m.Name, Raw: mustJSON(map[string]any{"template": t.ID, "name": m.Name}),
				})
			}
			st.res.Fingerprints = append(st.res.Fingerprints, extractor.ExtractedFingerprint{
				TechnologyKey: key, Observation: domain.ObsFaviconHash, Target: "mmh3",
				Operator: domain.OpHashEquals, Pattern: h, File: file,
				Raw: mustJSON(map[string]any{"template": t.ID, "matcher": m.Name, "hash": h}),
			})
			st.blocks++
			st.rules++
		}
	}
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err) // inputs are plain maps of strings and numbers
	}
	return b
}
