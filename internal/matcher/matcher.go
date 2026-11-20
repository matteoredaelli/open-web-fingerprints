// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package matcher

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/matteoredaelli/open-web-fingerprints/internal/domain"
)

// ErrUnsupported means the rule cannot be evaluated offline yet. It is not a
// failure of the rule.
var ErrUnsupported = errors.New("unsupported")

// Outcome is the result of evaluating one rule.
type Outcome struct {
	Matched bool
	// Version is the version read through the rule's version_extract.
	Version string
}

var regexCache sync.Map // pattern -> *regexp.Regexp

func compile(pattern string) (*regexp.Regexp, error) {
	if re, ok := regexCache.Load(pattern); ok {
		return re.(*regexp.Regexp), nil
	}
	re, err := regexp.Compile("(?i)" + pattern)
	if err != nil {
		return nil, err
	}
	regexCache.Store(pattern, re)
	return re, nil
}

// Evaluate applies one fingerprint to an observation.
func Evaluate(f domain.Fingerprint, o *Observation) (Outcome, error) {
	if f.Operator == domain.OpRegex && f.RegexFlavor != domain.FlavorRE2 {
		return Outcome{}, fmt.Errorf("%w: regex flavor %q", ErrUnsupported, f.RegexFlavor)
	}
	d := derive(o)
	vals, present, err := candidates(f, o, &d)
	if err != nil {
		return Outcome{}, err
	}
	if f.Operator == domain.OpExists {
		return Outcome{Matched: present}, nil
	}
	for _, v := range vals {
		ok, groups, err := compare(f, v)
		if err != nil {
			return Outcome{}, err
		}
		if ok {
			return Outcome{Matched: true, Version: renderVersion(f.VersionExtract, groups)}, nil
		}
	}
	return Outcome{}, nil
}

// candidates returns the observed values a rule looks at, and whether the
// observed thing exists at all (for the exists operator).
func candidates(f domain.Fingerprint, o *Observation, d *derived) (vals []string, present bool, err error) {
	one := func(v string, ok bool) ([]string, bool, error) {
		if !ok {
			return nil, false, nil
		}
		return []string{v}, true, nil
	}
	many := func(l []string) ([]string, bool, error) { return l, len(l) > 0, nil }
	text := func(s string) ([]string, bool, error) { return one(s, s != "") }

	switch f.Observation {
	case domain.ObsHTTPHeader:
		for k, v := range o.Headers {
			if strings.EqualFold(k, f.Target) {
				return one(v, true)
			}
		}
		return nil, false, nil
	case domain.ObsCookie:
		v, ok := o.Cookies[f.Target]
		return one(v, ok)
	case domain.ObsMetaTag:
		v, ok := d.meta[strings.ToLower(f.Target)]
		return one(v, ok)
	case domain.ObsDOM:
		return domValues(f.Target, o.HTML)
	case domain.ObsHTML:
		return text(o.HTML)
	case domain.ObsScriptURL:
		return many(d.scripts)
	case domain.ObsStylesheetURL:
		return many(d.stylesheets)
	case "script_content":
		return many(d.inlineScripts)
	case "css_rule":
		return text(d.css)
	case "page_text":
		return text(d.text)
	case "page_url":
		return text(o.URL)
	case domain.ObsJSGlobal:
		v, ok := o.JS[f.Target]
		return one(v, ok)
	case domain.ObsDNSRecord:
		return many(o.DNS[strings.ToUpper(f.Target)])
	case domain.ObsTLSCert:
		v, ok := o.TLS[f.Target]
		return one(v, ok)
	case domain.ObsXHR:
		return many(o.XHR)
	case domain.ObsRobots:
		return text(o.Robots)
	case domain.ObsFaviconHash:
		if f.Target != "" {
			v, ok := o.FaviconHashes[f.Target]
			return one(v, ok)
		}
		return text(o.FaviconHash)
	case "set_cookie":
		return many(o.SetCookies)
	case "page_title":
		return text(d.title)
	case "response_headers":
		return text(headerBlock(o.Headers))
	case "http_response":
		return text(headerBlock(o.Headers) + "\n\n" + o.HTML)
	case "http_status":
		if o.Status == 0 {
			return nil, false, nil
		}
		return one(fmt.Sprint(o.Status), true)
	case domain.ObsProbeResponse:
		return probeValues(f, o)
	}
	return nil, false, fmt.Errorf("%w: observation %q", ErrUnsupported, f.Observation)
}

func compare(f domain.Fingerprint, v string) (bool, []string, error) {
	switch f.Operator {
	case domain.OpEquals, domain.OpHashEquals:
		return v == f.Pattern, nil, nil
	case domain.OpContains:
		return strings.Contains(v, f.Pattern), nil, nil
	case domain.OpRegex:
		re, err := compile(f.Pattern)
		if err != nil {
			return false, nil, fmt.Errorf("pattern does not compile: %w", err)
		}
		m := re.FindStringSubmatch(v)
		return m != nil, m, nil
	}
	return false, nil, fmt.Errorf("%w: operator %q", ErrUnsupported, f.Operator)
}

var (
	groupRE   = regexp.MustCompile(`\\(\d)`)
	ternaryRE = regexp.MustCompile(`^\\(\d)\?([^:]*):(.*)$`)
)

// renderVersion expands a version_extract template: "\1" is capture group 1,
// and "\1?a:b" is a if group 1 is not empty, else b.
func renderVersion(tpl string, groups []string) string {
	if tpl == "" || groups == nil {
		return ""
	}
	group := func(n string) string {
		i := int(n[0] - '0')
		if i < len(groups) {
			return groups[i]
		}
		return ""
	}
	if m := ternaryRE.FindStringSubmatch(tpl); m != nil {
		if group(m[1]) != "" {
			return m[2]
		}
		return m[3]
	}
	return groupRE.ReplaceAllStringFunc(tpl, func(s string) string { return group(s[1:]) })
}

// probeValues reads the recorded answer to a rule's probe. The target says what
// the rule looks at: status, body, headers (the raw block), response (headers
// and body), content_type or server. A rule with target "status" and the
// exists operator means "the path answers": any 2xx status.
func probeValues(f domain.Fingerprint, o *Observation) (vals []string, present bool, err error) {
	if f.Probe == nil {
		return nil, false, fmt.Errorf("probe_response rule without probe")
	}
	r, ok := o.Probes[f.Probe.Path]
	if !ok {
		return nil, false, nil
	}
	switch f.Target {
	case "body":
		return []string{r.Body}, r.Body != "", nil
	case "headers":
		b := headerBlock(r.Headers)
		return []string{b}, b != "", nil
	case "response":
		return []string{headerBlock(r.Headers) + "\n\n" + r.Body}, true, nil
	case "content_type", "server":
		name := map[string]string{"content_type": "Content-Type", "server": "Server"}[f.Target]
		v, ok := headerValue(r.Headers, name)
		return []string{v}, ok, nil
	case "status", "":
		exists := r.Status >= 200 && r.Status <= 299
		if f.Operator != domain.OpExists {
			exists = r.Status != 0
		}
		return []string{fmt.Sprint(r.Status)}, exists, nil
	}
	return nil, false, fmt.Errorf("%w: probe target %q", ErrUnsupported, f.Target)
}

// EvaluateGroup applies rules that must all hold together (they share a
// group ID). It matches only if every rule matches; the version comes from the
// first rule that yields one. An unsupported rule makes the group unsupported.
func EvaluateGroup(rules []domain.Fingerprint, o *Observation) (Outcome, error) {
	if len(rules) == 0 {
		return Outcome{}, fmt.Errorf("empty group")
	}
	out := Outcome{Matched: true}
	for _, r := range rules {
		got, err := Evaluate(r, o)
		if err != nil {
			return Outcome{}, err
		}
		if !got.Matched {
			out.Matched, out.Version = false, ""
			continue
		}
		if out.Version == "" {
			out.Version = got.Version
		}
	}
	if !out.Matched {
		out.Version = ""
	}
	return out, nil
}

// Version reads the version of a detected technology. rules are the technology's
// rules with role "version" for the request that matched; the first one that
// matches and yields a version wins. Call it only after a detection matched:
// a version rule does not detect.
func Version(rules []domain.Fingerprint, o *Observation) (string, error) {
	for _, r := range rules {
		if r.Role != domain.RoleVersion {
			continue
		}
		got, err := Evaluate(r, o)
		if err != nil {
			return "", err
		}
		if got.Matched && got.Version != "" {
			return got.Version, nil
		}
	}
	return "", nil
}
