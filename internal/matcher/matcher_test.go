// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package matcher

import (
	"errors"
	"testing"

	"github.com/matteoredaelli/open-web-fingerprints/internal/domain"
)

func rule(obs domain.Observation, target string, op domain.Operator, pattern string) domain.Fingerprint {
	f := domain.Fingerprint{Observation: obs, Target: target, Operator: op, Pattern: pattern}
	if op == domain.OpRegex {
		f.RegexFlavor = domain.FlavorRE2
	}
	return f
}

const page = `<html><head>
<meta name="Generator" content="WordPress 6.4.2">
<link rel="stylesheet" href="/wp-content/themes/x/style.css?ver=1.2">
<style>.wp-block-group{margin:0}</style>
<script src="https://cdn.example.com/jquery-3.6.0.min.js"></script>
<script>window.wpApiSettings = {};</script>
</head><body><h1>Hello World</h1><p>Powered by <b>Acme</b></p></body></html>`

func TestEvaluate(t *testing.T) {
	o := &Observation{
		URL:         "https://example.com/blog/",
		Headers:     map[string]string{"Server": "nginx/1.25.3", "X-Powered-By": "PHP/8.2.1"},
		Cookies:     map[string]string{"PHPSESSID": "abc"},
		HTML:        page,
		JS:          map[string]string{"jQuery.fn.jquery": "3.6.0"},
		DNS:         map[string][]string{"NS": {"ada.ns.cloudflare.com", "bob.ns.cloudflare.com"}},
		TLS:         map[string]string{"issuer": "Cloudflare Inc ECC CA-3"},
		XHR:         []string{"https://api.taboola.com/x"},
		Robots:      "User-agent: *\n# Powered by Shoporama",
		Probes:      map[string]ProbeResponse{"/wp-login.php": {Status: 200, Body: "Powered by WordPress"}, "/gone": {Status: 404}},
		FaviconHash: "f420dc2c7d90d7873a90d82cd7fde315",
	}
	withVersion := func(f domain.Fingerprint, v string) domain.Fingerprint { f.VersionExtract = v; return f }
	probe := func(f domain.Fingerprint, path string) domain.Fingerprint {
		f.Probe = &domain.Probe{Method: "GET", Path: path, SafetyReview: "pending"}
		return f
	}
	cases := []struct {
		name    string
		f       domain.Fingerprint
		match   bool
		version string
	}{
		{"header regex with version", withVersion(rule(domain.ObsHTTPHeader, "server", domain.OpRegex, `^nginx(?:/([\d.]+))?`), `\1`), true, "1.25.3"},
		{"header name is case-insensitive", rule(domain.ObsHTTPHeader, "SERVER", domain.OpExists, ""), true, ""},
		{"header regex is case-insensitive", rule(domain.ObsHTTPHeader, "Server", domain.OpRegex, `^NGINX`), true, ""},
		{"header miss", rule(domain.ObsHTTPHeader, "Server", domain.OpRegex, `^apache`), false, ""},
		{"header absent", rule(domain.ObsHTTPHeader, "X-Nope", domain.OpExists, ""), false, ""},
		{"header equals is case-sensitive", rule(domain.ObsHTTPHeader, "Server", domain.OpEquals, "NGINX/1.25.3"), false, ""},
		{"header contains", rule(domain.ObsHTTPHeader, "Server", domain.OpContains, "nginx"), true, ""},
		{"cookie exists", rule(domain.ObsCookie, "PHPSESSID", domain.OpExists, ""), true, ""},
		{"cookie name is case-sensitive", rule(domain.ObsCookie, "phpsessid", domain.OpExists, ""), false, ""},
		{"meta regex with version", withVersion(rule(domain.ObsMetaTag, "generator", domain.OpRegex, `^WordPress ([\d.]+)`), `\1`), true, "6.4.2"},
		{"meta name case", rule(domain.ObsMetaTag, "GENERATOR", domain.OpExists, ""), true, ""},
		{"html regex", rule(domain.ObsHTML, "", domain.OpRegex, `wp-content/themes`), true, ""},
		{"script url with version", withVersion(rule(domain.ObsScriptURL, "", domain.OpRegex, `jquery-([\d.]+)\.min\.js`), `\1`), true, "3.6.0"},
		{"script url miss", rule(domain.ObsScriptURL, "", domain.OpRegex, `angular`), false, ""},
		{"stylesheet", rule(domain.ObsStylesheetURL, "", domain.OpContains, "/wp-content/themes/x/style.css"), true, ""},
		{"inline script", rule(domain.Observation("script_content"), "", domain.OpRegex, `wpApiSettings`), true, ""},
		{"css", rule(domain.Observation("css_rule"), "", domain.OpRegex, `wp-block-group`), true, ""},
		{"page text excludes scripts", rule(domain.Observation("page_text"), "", domain.OpRegex, `wpApiSettings`), false, ""},
		{"page text", rule(domain.Observation("page_text"), "", domain.OpRegex, `Powered by Acme`), true, ""},
		{"page url", rule(domain.Observation("page_url"), "", domain.OpRegex, `/blog/$`), true, ""},
		{"js value", withVersion(rule(domain.ObsJSGlobal, "jQuery.fn.jquery", domain.OpRegex, `^([\d.]+)$`), `\1`), true, "3.6.0"},
		{"js absent", rule(domain.ObsJSGlobal, "Vue", domain.OpExists, ""), false, ""},
		{"dns any record", rule(domain.ObsDNSRecord, "ns", domain.OpRegex, `\.ns\.cloudflare\.com$`), true, ""},
		{"dns other type", rule(domain.ObsDNSRecord, "MX", domain.OpExists, ""), false, ""},
		{"tls issuer", rule(domain.ObsTLSCert, "issuer", domain.OpContains, "Cloudflare"), true, ""},
		{"xhr", rule(domain.ObsXHR, "", domain.OpRegex, `\.taboola\.com`), true, ""},
		{"robots", rule(domain.ObsRobots, "", domain.OpRegex, `Powered by Shoporama`), true, ""},
		{"favicon hash", rule(domain.ObsFaviconHash, "", domain.OpHashEquals, "f420dc2c7d90d7873a90d82cd7fde315"), true, ""},
		{"favicon hash miss", rule(domain.ObsFaviconHash, "", domain.OpHashEquals, "00"), false, ""},
		{"probe body", probe(rule(domain.ObsProbeResponse, "body", domain.OpContains, "WordPress"), "/wp-login.php"), true, ""},
		{"probe exists", probe(rule(domain.ObsProbeResponse, "status", domain.OpExists, ""), "/wp-login.php"), true, ""},
		{"probe 404 is not a match", probe(rule(domain.ObsProbeResponse, "status", domain.OpExists, ""), "/gone"), false, ""},
		{"probe not recorded", probe(rule(domain.ObsProbeResponse, "status", domain.OpExists, ""), "/other"), false, ""},
		{"ternary version, group set", withVersion(rule(domain.ObsHTTPHeader, "Server", domain.OpRegex, `nginx(/)?`), `\1?with:without`), true, "with"},
		{"ternary version, group empty", withVersion(rule(domain.ObsHTTPHeader, "X-Powered-By", domain.OpRegex, `PHP(/x)?`), `\1?with:without`), true, "without"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Evaluate(tc.f, o)
			if err != nil {
				t.Fatal(err)
			}
			if got.Matched != tc.match || got.Version != tc.version {
				t.Errorf("got %+v, want match=%v version=%q", got, tc.match, tc.version)
			}
		})
	}
}

func TestUnsupportedAndErrors(t *testing.T) {
	o := &Observation{}
	for name, f := range map[string]domain.Fingerprint{
		"dom selectors":    rule(domain.ObsDOM, "div.x", domain.OpExists, ""),
		"unknown":          rule("future_thing", "", domain.OpExists, ""),
		"ecmascript regex": {Observation: domain.ObsHTML, Operator: domain.OpRegex, Pattern: "(?!x)", RegexFlavor: domain.FlavorECMAScript},
		"unknown operator": {Observation: domain.ObsHTML, Operator: "fuzzy", Pattern: "x"},
	} {
		if _, err := Evaluate(f, &Observation{HTML: "x"}); !errors.Is(err, ErrUnsupported) && name != "unknown operator" {
			t.Errorf("%s: want ErrUnsupported, got %v", name, err)
		}
		_ = o
	}
	if _, err := Evaluate(domain.Fingerprint{Observation: domain.ObsHTML, Operator: "fuzzy", Pattern: "x"}, &Observation{HTML: "x"}); !errors.Is(err, ErrUnsupported) {
		t.Errorf("unknown operator: %v", err)
	}
	bad := rule(domain.ObsHTML, "", domain.OpRegex, "(")
	if _, err := Evaluate(bad, &Observation{HTML: "x"}); err == nil || errors.Is(err, ErrUnsupported) {
		t.Errorf("a broken pattern is an error, not unsupported: %v", err)
	}
	noProbe := rule(domain.ObsProbeResponse, "status", domain.OpExists, "")
	if _, err := Evaluate(noProbe, &Observation{}); err == nil {
		t.Error("probe_response without probe must fail")
	}
}

func TestRenderVersion(t *testing.T) {
	g := []string{"whole", "1.2", "x"}
	for tpl, want := range map[string]string{
		"": "", `\1`: "1.2", `v\1`: "v1.2", `\1.\2`: "1.2.x", `\9`: "", `\1?yes:no`: "yes",
	} {
		if got := renderVersion(tpl, g); got != want {
			t.Errorf("renderVersion(%q) = %q, want %q", tpl, got, want)
		}
	}
	if renderVersion(`\1`, nil) != "" {
		t.Error("no groups, no version")
	}
}

func TestDerivedFromGivenFieldsOverridesHTML(t *testing.T) {
	o := &Observation{HTML: page, Scripts: []string{"/only-this.js"}}
	f := rule(domain.ObsScriptURL, "", domain.OpRegex, `jquery`)
	if got, _ := Evaluate(f, o); got.Matched {
		t.Error("explicit scripts must replace the ones found in the HTML")
	}
}
