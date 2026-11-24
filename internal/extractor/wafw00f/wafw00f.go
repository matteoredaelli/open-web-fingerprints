// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

// Package wafw00f extracts fingerprints from the plugins of WAFW00F
// (https://github.com/EnableSecurity/wafw00f), which are Python files under
// wafw00f/plugins/ that identify web application firewalls and CDNs. The
// files are read as data (py.go reads the small subset of Python they use);
// no Python is run.
//
// A plugin is a function `is_waf` (and sometimes helpers) made of
// `if <condition>: return True|False`. WAFW00F makes two requests: a normal
// one and an *attack* request (a request carrying a malicious payload that a
// WAF is expected to block). Only matchHeader and matchCookie on the normal
// response are read here, as http_header and set_cookie rules. Everything that
// looks at the response to the attack (matchContent, matchStatus, matchReason,
// and any call with attack=True) is skipped and counted: this project never
// sends such a request.
//
// Also skipped, whole: a statement that is not an `if ...: return`, a negated
// condition that is not a plain guard, and a condition that is not a call.
// A skipped alternative only narrows what the plugin detects, never widens it,
// except after `if <condition>: return False`, where the rest of the function
// is dropped.
package wafw00f

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strings"

	"github.com/matteoredaelli/open-web-fingerprints/internal/domain"
	"github.com/matteoredaelli/open-web-fingerprints/internal/extractor"
)

// ID is the stable extractor identifier.
const ID = "wafw00f"

// Root is the directory of the plugins in the repository.
const Root = "wafw00f/plugins"

// maxClauses bounds the expansion of a condition into clauses.
const maxClauses = 32

// IsPluginFile reports whether a repository path is a plugin.
func IsPluginFile(p string) bool {
	return strings.HasPrefix(p, Root+"/") && strings.Count(p, "/") == strings.Count(Root, "/")+1 &&
		strings.HasSuffix(p, ".py") && !strings.HasSuffix(p, "/__init__.py")
}

// Extractor implements extractor.Extractor.
type Extractor struct{}

// New returns a WAFW00F extractor.
func New() *Extractor { return &Extractor{} }

// ID implements extractor.Extractor.
func (*Extractor) ID() string { return ID }

// Name implements extractor.Extractor.
func (*Extractor) Name() string { return "WAFW00F plugins" }

// Capabilities implements extractor.CapabilityReporter.
func (*Extractor) Capabilities() []extractor.Capability {
	return []extractor.Capability{extractor.CapTechnologies, extractor.CapFingerprints}
}

// Extract implements extractor.Extractor.
func (x *Extractor) Extract(ctx context.Context, src extractor.Source) (*extractor.ExtractionResult, error) {
	if src.FS == nil {
		return nil, fmt.Errorf("wafw00f: source %q has no snapshot filesystem", src.ID)
	}
	files, err := fs.Glob(src.FS, Root+"/*.py")
	if err != nil {
		return nil, fmt.Errorf("wafw00f: list plugins: %w", err)
	}
	sort.Strings(files)
	res := &extractor.ExtractionResult{Metadata: map[string]any{"revision": src.Revision}}
	st := &state{res: res, skipped: map[string]int{}}
	n := 0
	for _, f := range files {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if strings.HasSuffix(f, "/__init__.py") {
			continue
		}
		b, err := fs.ReadFile(src.FS, f)
		if err != nil {
			return nil, fmt.Errorf("wafw00f: read %s: %w", f, err)
		}
		n++
		st.plugin(f, string(b))
	}
	if n == 0 {
		return nil, fmt.Errorf("wafw00f: no plugins under %s", Root)
	}
	keys := make([]string, 0, len(st.skipped))
	for k := range st.skipped {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		res.Warnings = append(res.Warnings, extractor.Warning{Code: "skipped", Ref: Root, Message: fmt.Sprintf("%d: %s", st.skipped[k], k)})
	}
	res.Metadata["plugin_files"] = n
	res.Metadata["plugins_read"] = len(res.Technologies)
	return res, nil
}

type state struct {
	res     *extractor.ExtractionResult
	skipped map[string]int
}

// term is one passive condition.
type term struct {
	obs     domain.Observation
	target  string
	op      domain.Operator
	pattern string
}

// dnf is an OR of clauses, each an AND of terms. An empty dnf stands for a
// condition that cannot be expressed (it never matches, so it only narrows).
type dnf [][]term

func or(a, b dnf) dnf { return append(append(dnf{}, a...), b...) }

func and(a, b dnf) dnf {
	var out dnf
	for _, x := range a {
		for _, y := range b {
			out = append(out, append(append([]term{}, x...), y...))
		}
	}
	if len(out) > maxClauses {
		return nil
	}
	return out
}

var (
	nameRe     = regexp.MustCompile(`(?m)^NAME\s*=\s*('(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*")`)
	vendorRe   = regexp.MustCompile(`^(.*?)\s*\(([^()]*)\)\s*$`)
	anythingRe = regexp.MustCompile(`^\^?\.[+*]\??\$?$`)
	defRe      = regexp.MustCompile(`^def\s+(\w+)\s*\(\s*self\s*\)\s*(->\s*\w+\s*)?:\s*$`)
)

// function is the body of one def.
type function struct {
	name  string
	stmts []logical
}

// functions splits a file into its top-level defs.
func functions(src string) map[string]*function {
	out := map[string]*function{}
	var cur *function
	for _, l := range logicalLines(src) {
		if l.indent == 0 {
			cur = nil
			if m := defRe.FindStringSubmatch(l.text); m != nil {
				cur = &function{name: m[1]}
				out[m[1]] = cur
			}
			continue
		}
		if cur != nil {
			cur.stmts = append(cur.stmts, l)
		}
	}
	return out
}

type plugin struct {
	st    *state
	file  string
	funcs map[string]*function
	depth int
}

func (st *state) plugin(file, src string) {
	m := nameRe.FindStringSubmatch(src)
	if m == nil {
		st.res.Warnings = append(st.res.Warnings, extractor.Warning{Code: "invalid_plugin", Ref: file, Message: "no NAME"})
		return
	}
	toks, err := tokenize(m[1])
	if err != nil || len(toks) < 2 {
		st.res.Warnings = append(st.res.Warnings, extractor.Warning{Code: "invalid_plugin", Ref: file, Message: "unreadable NAME"})
		return
	}
	full := toks[0].text
	name, vendor := full, ""
	if v := vendorRe.FindStringSubmatch(full); v != nil && strings.TrimSpace(v[1]) != "" {
		name, vendor = strings.TrimSpace(v[1]), strings.TrimSpace(v[2])
	}
	p := &plugin{st: st, file: file, funcs: functions(src)}
	alts := p.eval("is_waf")
	if len(alts) == 0 {
		st.skipped["plugins with no rule that reads the normal response"]++
		return
	}
	key := strings.TrimSuffix(file[strings.LastIndex(file, "/")+1:], ".py")
	for i, cl := range alts {
		group := ""
		if len(cl) > 1 {
			group = fmt.Sprintf("%s#a%d", key, i)
		}
		for _, t := range cl {
			f := extractor.ExtractedFingerprint{
				TechnologyKey: key, GroupKey: group, Observation: t.obs, Target: t.target,
				Operator: t.op, Pattern: t.pattern, File: file,
				Raw: mustJSON(map[string]any{"plugin": key, "alternative": i, "observation": string(t.obs), "target": t.target, "pattern": t.pattern}),
			}
			if t.op == domain.OpRegex {
				f.RegexFlavor = extractor.RegexFlavorFor(t.pattern, domain.FlavorPCRE)
				if f.RegexFlavor != domain.FlavorRE2 {
					st.res.Warnings = append(st.res.Warnings, extractor.Warning{Code: "unsupported_regex", Ref: file,
						Message: fmt.Sprintf("pattern %q is not RE2-compatible; flavor set to pcre", t.pattern)})
				}
			}
			st.res.Fingerprints = append(st.res.Fingerprints, f)
		}
	}
	st.res.Technologies = append(st.res.Technologies, extractor.ExtractedTechnology{
		Key: key, File: file, Name: name,
		Raw: mustJSON(map[string]any{"plugin": key, "name": full, "vendor": vendor}),
	})
}

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err) // maps of strings and ints always marshal
	}
	return b
}

// eval returns the clauses under which a function returns True, as far as
// they can be expressed. Statements are read in order: `if not X: return
// False` makes X required from then on, `if X: return True` is an alternative
// (together with what is required), and anything else ends the reading.
func (p *plugin) eval(name string) dnf {
	fn := p.funcs[name]
	if fn == nil || p.depth > 4 {
		p.st.skipped["a call to a function that is not in the plugin"]++
		return nil
	}
	p.depth++
	defer func() { p.depth-- }()

	required := dnf{{}}
	var out dnf
	stmts := fn.stmts
	for i := 0; i < len(stmts); i++ {
		s := stmts[i]
		if ret, ok := returnOf(s.text); ok {
			if ret {
				out = or(out, required)
			}
			return out
		}
		cond, inline, ok := splitIf(s.text)
		if !ok {
			p.st.skipped["a statement that is not an if/return"]++
			return out
		}
		body := inline
		if body == "" {
			if i+1 >= len(stmts) || stmts[i+1].indent <= s.indent {
				p.st.skipped["an if without a return body"]++
				return out
			}
			body = stmts[i+1].text
			i++
			if i+1 < len(stmts) && stmts[i+1].indent > s.indent {
				p.st.skipped["an if with more than one statement"]++
				return out
			}
		}
		ret, ok := returnOf(body)
		if !ok {
			p.st.skipped["an if whose body is not a return"]++
			return out
		}
		tree, err := parseCondition(cond)
		if err != nil {
			p.st.skipped["a condition outside the subset"]++
			return out
		}
		switch {
		case ret && tree.op != "not":
			out = or(out, and(required, p.dnf(tree)))
		case !ret && tree.op == "not":
			required = and(required, p.dnf(tree.kids[0]))
		default:
			// `if X: return False` or `if not X: return True`: the rest holds
			// only when X does not, which a rule cannot say.
			p.st.skipped["a guard that returns the opposite of its condition"]++
			return out
		}
	}
	return out
}

var returnRe = regexp.MustCompile(`^return\s+(True|False)$`)

func returnOf(s string) (value, ok bool) {
	m := returnRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return false, false
	}
	return m[1] == "True", true
}

// splitIf splits `if <cond>: [body]`.
func splitIf(s string) (cond, body string, ok bool) {
	if !strings.HasPrefix(s, "if ") {
		return "", "", false
	}
	s = s[3:]
	var quote byte
	depth := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			switch c {
			case '\\':
				i++
			case quote:
				quote = 0
			}
		case c == '\'' || c == '"':
			quote = c
		case c == '(':
			depth++
		case c == ')':
			depth--
		case c == ':' && depth == 0:
			return strings.TrimSpace(s[:i]), strings.TrimSpace(s[i+1:]), true
		}
	}
	return "", "", false
}

// dnf turns a condition into clauses.
func (p *plugin) dnf(n *node) dnf {
	switch n.op {
	case "or":
		return or(p.dnf(n.kids[0]), p.dnf(n.kids[1]))
	case "and":
		return and(p.dnf(n.kids[0]), p.dnf(n.kids[1]))
	case "not":
		p.st.skipped["a negated condition inside a larger one"]++
		return nil
	}
	c := n.call
	if c.helper != "" {
		return p.eval(c.helper)
	}
	switch c.method {
	case "matchStatus", "matchReason", "matchContent":
		// These default to the attack response.
		if c.attack == nil || *c.attack {
			p.st.skipped["a term on the response to an attack payload ("+c.method+")"]++
			return nil
		}
		p.st.skipped["a "+c.method+" on the normal response (not mapped)"]++
		return nil
	case "matchHeader", "matchCookie":
		if c.attack != nil && *c.attack {
			p.st.skipped["a term on the response to an attack payload ("+c.method+" with attack=True)"]++
			return nil
		}
	default:
		p.st.skipped["a call to "+c.method]++
		return nil
	}
	return p.passive(c)
}

func (p *plugin) passive(c *call) dnf {
	var header, pattern string
	switch {
	case c.method == "matchCookie" && len(c.args) == 1 && len(c.args[0].strs) == 1:
		header, pattern = "Set-Cookie", c.args[0].strs[0]
	case c.method == "matchHeader" && len(c.args) == 1 && len(c.args[0].strs) == 2:
		header, pattern = c.args[0].strs[0], c.args[0].strs[1]
	default:
		p.st.skipped["a "+c.method+" call in an unexpected shape"]++
		return nil
	}
	t := term{op: domain.OpRegex, pattern: pattern}
	if strings.EqualFold(header, "Set-Cookie") {
		t.obs = "set_cookie"
	} else {
		t.obs, t.target = domain.ObsHTTPHeader, header
	}
	if anythingRe.MatchString(pattern) {
		// The header or cookie is present with any value.
		t.op, t.pattern = domain.OpExists, ""
	}
	return dnf{{t}}
}
