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
		"dom property":     rule(domain.ObsDOM, "div.x::prop(foo)", domain.OpExists, ""),
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

const domPage = `<html><body>
<div class="wp-block-group"><div class="wp-block-columns">hello</div></div>
<a href="https://shop.example.com/cart" title="Powered by Pixelfed 0.11.4" id="x">Cart <b>now</b></a>
<form name="login" action="/Login.ASPX"><input type="text" disabled></form>
<p class="empty"></p>
</body></html>`

func TestDOM(t *testing.T) {
	o := &Observation{HTML: domPage}
	ver := func(f domain.Fingerprint, v string) domain.Fingerprint { f.VersionExtract = v; return f }
	cases := []struct {
		name    string
		f       domain.Fingerprint
		match   bool
		version string
	}{
		{"element exists", rule(domain.ObsDOM, "div.wp-block-group", domain.OpExists, ""), true, ""},
		{"child combinator", rule(domain.ObsDOM, "div[class*='wp-block-group'] > div[class*='wp-block-']", domain.OpExists, ""), true, ""},
		{"comma group, second matches", rule(domain.ObsDOM, "img.logo, form[name=login]", domain.OpExists, ""), true, ""},
		{"element absent", rule(domain.ObsDOM, "div.nope", domain.OpExists, ""), false, ""},
		{"attribute exists", rule(domain.ObsDOM, "input::attr(disabled)", domain.OpExists, ""), true, ""},
		{"attribute missing", rule(domain.ObsDOM, "input::attr(readonly)", domain.OpExists, ""), false, ""},
		{"attribute name is case-insensitive", rule(domain.ObsDOM, "a::attr(HREF)", domain.OpExists, ""), true, ""},
		{"attribute regex with version", ver(rule(domain.ObsDOM, "a[href*='shop.example.com']::attr(title)", domain.OpRegex, `^Powered by Pixelfed ([\d.]+)$`), `\1`), true, "0.11.4"},
		{"attribute regex miss", rule(domain.ObsDOM, "a::attr(title)", domain.OpRegex, `^Wordpress`), false, ""},
		{"text regex", rule(domain.ObsDOM, "a::text", domain.OpRegex, `^Cart now$`), true, ""},
		{"text exists", rule(domain.ObsDOM, "a::text", domain.OpExists, ""), true, ""},
		{"empty element has no text", rule(domain.ObsDOM, "p.empty::text", domain.OpExists, ""), false, ""},
		{"case-insensitive attribute selector", rule(domain.ObsDOM, "form[action$='login.aspx' i]", domain.OpExists, ""), true, ""},
		{"no html, no match", rule(domain.ObsDOM, "div", domain.OpExists, ""), false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			obs := o
			if tc.name == "no html, no match" {
				obs = &Observation{}
			}
			got, err := Evaluate(tc.f, obs)
			if err != nil {
				t.Fatal(err)
			}
			if got.Matched != tc.match || got.Version != tc.version {
				t.Errorf("got %+v, want match=%v version=%q", got, tc.match, tc.version)
			}
		})
	}
	// A selector that does not parse is an error about the rule, not "unsupported".
	_, err := Evaluate(rule(domain.ObsDOM, "div[", domain.OpExists, ""), o)
	if err == nil || errors.Is(err, ErrUnsupported) {
		t.Errorf("bad selector: %v", err)
	}
}

func TestResponseObservationsAndProbeTargets(t *testing.T) {
	o := &Observation{
		Status:  200,
		Headers: map[string]string{"Server": "nginx/1.25", "X-Powered-By": "PHP/8.2"},
		HTML:    "<html>Welcome to Acme</html>",
		Probes: map[string]ProbeResponse{
			"/login": {Status: 403, Headers: map[string]string{"Content-Type": "text/html", "Server": "Acme/2"}, Body: "<title>Acme Login</title>"},
			"/gone":  {Status: 404},
		},
	}
	probe := func(target string, op domain.Operator, pattern, path string) domain.Fingerprint {
		f := rule(domain.ObsProbeResponse, target, op, pattern)
		f.Probe = &domain.Probe{Method: "GET", Path: path, SafetyReview: "pending"}
		return f
	}
	cases := []struct {
		name  string
		f     domain.Fingerprint
		match bool
	}{
		{"header block, word", rule("response_headers", "", domain.OpContains, "X-Powered-By: PHP"), true},
		{"header block, name: value lines", rule("response_headers", "", domain.OpRegex, `(?s)^Server: nginx.*\nX-Powered-By`), true},
		{"header block, order is by name", rule("response_headers", "", domain.OpRegex, `(?-i)^Server: nginx/1.25\nX-Powered-By: PHP/8.2$`), true},
		{"header block, case-sensitive word", rule("response_headers", "", domain.OpContains, "x-powered-by"), false},
		{"whole response, headers then body", rule("http_response", "", domain.OpRegex, `(?s)nginx.*Welcome`), true},
		{"http status equals", rule("http_status", "", domain.OpEquals, "200"), true},
		{"http status other", rule("http_status", "", domain.OpEquals, "404"), false},
		{"http status alternatives", rule("http_status", "", domain.OpRegex, `^(200|301)$`), true},
		{"probe body, non-2xx still readable", probe("body", domain.OpContains, "Acme Login", "/login"), true},
		{"probe status is 403", probe("status", domain.OpEquals, "403", "/login"), true},
		{"probe exists means a 2xx answer", probe("status", domain.OpExists, "", "/login"), false},
		{"probe exists on a 404", probe("status", domain.OpExists, "", "/gone"), false},
		{"probe headers", probe("headers", domain.OpContains, "Content-Type: text/html", "/login"), true},
		{"probe content type", probe("content_type", domain.OpRegex, `^text/`, "/login"), true},
		{"probe server", probe("server", domain.OpRegex, `^Acme/`, "/login"), true},
		{"probe whole response", probe("response", domain.OpRegex, `(?s)Acme/2.*Acme Login`, "/login"), true},
		{"probe not recorded", probe("body", domain.OpContains, "x", "/other"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Evaluate(tc.f, o)
			if err != nil {
				t.Fatal(err)
			}
			if got.Matched != tc.match {
				t.Errorf("matched=%v, want %v", got.Matched, tc.match)
			}
		})
	}
	// An unknown probe target is reported, not guessed.
	if _, err := Evaluate(probe("cookie", domain.OpExists, "", "/login"), o); !errors.Is(err, ErrUnsupported) {
		t.Errorf("unknown probe target: %v", err)
	}
	// No status recorded, no status rule match.
	if got, _ := Evaluate(rule("http_status", "", domain.OpEquals, "200"), &Observation{}); got.Matched {
		t.Error("an observation without a status cannot match a status rule")
	}
}

func TestEvaluateGroup(t *testing.T) {
	o := &Observation{Status: 200, Headers: map[string]string{"Server": "nginx/1.25.3"}, HTML: "<html>hello</html>"}
	ver := func(f domain.Fingerprint, v string) domain.Fingerprint { f.VersionExtract = v; return f }
	server := ver(rule(domain.ObsHTTPHeader, "Server", domain.OpRegex, `nginx/([\d.]+)`), `\1`)
	status := rule("http_status", "", domain.OpEquals, "200")
	word := rule(domain.ObsHTML, "", domain.OpContains, "hello")
	miss := rule(domain.ObsHTML, "", domain.OpContains, "absent")

	got, err := EvaluateGroup([]domain.Fingerprint{status, word, server}, o)
	if err != nil || !got.Matched || got.Version != "1.25.3" {
		t.Errorf("all rules hold: %+v err=%v", got, err)
	}
	got, err = EvaluateGroup([]domain.Fingerprint{status, miss, server}, o)
	if err != nil || got.Matched || got.Version != "" {
		t.Errorf("one rule fails, the group fails and has no version: %+v err=%v", got, err)
	}
	if _, err := EvaluateGroup([]domain.Fingerprint{status, rule(domain.ObsDOM, "a::prop(x)", domain.OpExists, "")}, o); !errors.Is(err, ErrUnsupported) {
		t.Errorf("unsupported member: %v", err)
	}
	if _, err := EvaluateGroup(nil, o); err == nil {
		t.Error("an empty group is an error")
	}
}

func TestVersionRulesDoNotDetect(t *testing.T) {
	v := rule(domain.ObsHTTPHeader, "Server", domain.OpRegex, `x/([\d.]+)`)
	v.VersionExtract, v.Role = `\1`, domain.RoleVersion
	det := rule(domain.ObsHTTPHeader, "Server", domain.OpRegex, `^x`)
	o := &Observation{Headers: map[string]string{"Server": "x/1.2"}}
	if got, err := Version([]domain.Fingerprint{det, v}, o); err != nil || got != "1.2" {
		t.Errorf("version = %q err=%v (detection rules are ignored)", got, err)
	}
	if got, _ := Version([]domain.Fingerprint{v}, &Observation{Headers: map[string]string{"Server": "y/9"}}); got != "" {
		t.Errorf("no match, no version: %q", got)
	}
	w := v
	w.Pattern = `y/([\d.]+)`
	if got, _ := Version([]domain.Fingerprint{w, v}, o); got != "1.2" {
		t.Errorf("the first rule that reads a version wins: %q", got)
	}
	bad := v
	bad.RegexFlavor = domain.FlavorPCRE
	if _, err := Version([]domain.Fingerprint{bad}, o); !errors.Is(err, ErrUnsupported) {
		t.Errorf("unsupported flavor: %v", err)
	}
}

func TestOutcomeValueAndPrepared(t *testing.T) {
	o := &Observation{
		Headers: map[string]string{"Server": "nginx/1.25.3 (Ubuntu)"},
		HTML:    `<html><head><title>Acme</title></head><body><a class="x" href="/a">link</a></body></html>`,
	}
	p := Prepare(o)
	for name, tc := range map[string]struct {
		f    domain.Fingerprint
		want string
	}{
		"regex gives the matched text, not the whole value": {rule(domain.ObsHTTPHeader, "Server", domain.OpRegex, `nginx/[\d.]+`), "nginx/1.25.3"},
		"contains gives the pattern":                        {rule(domain.ObsHTTPHeader, "Server", domain.OpContains, "Ubuntu"), "Ubuntu"},
		"equals gives the value":                            {rule(domain.ObsHTTPHeader, "Server", domain.OpEquals, "nginx/1.25.3 (Ubuntu)"), "nginx/1.25.3 (Ubuntu)"},
		"exists gives the first value":                      {rule(domain.ObsHTTPHeader, "Server", domain.OpExists, ""), "nginx/1.25.3 (Ubuntu)"},
		"dom attribute":                                     {rule(domain.ObsDOM, "a.x::attr(href)", domain.OpRegex, `^/a$`), "/a"},
		"title":                                             {rule("page_title", "", domain.OpRegex, `Ac`), "Ac"},
	} {
		got, err := p.Evaluate(tc.f)
		if err != nil || !got.Matched || got.Value != tc.want {
			t.Errorf("%s: %+v err=%v, want value %q", name, got, err, tc.want)
		}
	}
	// One prepared observation serves many rules and gives what Evaluate gives.
	for i := 0; i < 3; i++ {
		a, _ := p.Evaluate(rule(domain.ObsDOM, "a.x", domain.OpExists, ""))
		b, _ := Evaluate(rule(domain.ObsDOM, "a.x", domain.OpExists, ""), o)
		if a != b || !a.Matched {
			t.Errorf("prepared %+v, plain %+v", a, b)
		}
	}
	if got, _ := p.Evaluate(rule(domain.ObsHTTPHeader, "Server", domain.OpRegex, `apache`)); got.Matched || got.Value != "" {
		t.Errorf("a miss has no value: %+v", got)
	}
}
