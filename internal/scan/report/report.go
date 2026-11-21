// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

// Package report turns a scan result into one self-contained HTML page: the stack by
// category, the infrastructure, the people and places found, the network of related
// domains and, as prominently, what the scan did not see.
//
// The page has no script, loads nothing (a Content-Security-Policy forbids it) and uses
// only system fonts, so it opens offline and cannot call anyone when it is viewed. The
// result comes from a site and from a file that may not be ours, so every value goes
// through html/template's escaping, and a link is written only for http and https URLs.
// The page is a function of the result: it never reads the clock, so the same result
// gives the same bytes.
package report

import (
	_ "embed"
	"fmt"
	"html/template"
	"io"

	"github.com/matteoredaelli/open-web-fingerprints/scan"
)

// Options tune the page.
type Options struct {
	// Title replaces the domain as the title of the page.
	Title string
}

//go:embed report.html.tmpl
var source string

var page = template.Must(template.New("report").Funcs(template.FuncMap{
	"safe": safeURL,
	"pct":  func(f float64) int { return int(f*100 + 0.5) },
}).Parse(source))

// Render writes the report for a result.
func Render(w io.Writer, r *scan.Result, opt Options) error {
	if r == nil {
		return fmt.Errorf("report: no result")
	}
	return page.Execute(w, build(r, opt))
}
