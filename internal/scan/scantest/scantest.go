// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

// Package scantest builds what scanner tests need: a registry export made from
// the source fixtures, and a local site that those fixtures recognise.
package scantest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/matteoredaelli/open-web-fingerprints/internal/curate"
	"github.com/matteoredaelli/open-web-fingerprints/internal/domain"
	"github.com/matteoredaelli/open-web-fingerprints/internal/export"
	"github.com/matteoredaelli/open-web-fingerprints/internal/extractor"
	"github.com/matteoredaelli/open-web-fingerprints/internal/extractor/nuclei"
	"github.com/matteoredaelli/open-web-fingerprints/internal/extractor/recog"
	"github.com/matteoredaelli/open-web-fingerprints/internal/extractor/wappalyzer"
	"github.com/matteoredaelli/open-web-fingerprints/internal/pipeline"
	"github.com/matteoredaelli/open-web-fingerprints/internal/repository/memory"
)

func root() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "extractor")
}

// RegistryJSON imports the fixtures of the three sources and returns them as an
// export, as `owf export --include-unreviewed` would write it.
func RegistryJSON(t testing.TB) []byte { return RegistryJSONApproving(t) }

// RegistryJSONApproving is RegistryJSON with the probes of the given paths approved, as a
// reviewer would with `owf probe review`.
func RegistryJSONApproving(t testing.TB, paths ...string) []byte {
	t.Helper()
	ex := extractor.NewRegistry()
	for _, e := range []extractor.Extractor{wappalyzer.New(), recog.New(), nuclei.New()} {
		if err := ex.Register(e); err != nil {
			t.Fatal(err)
		}
	}
	repo := memory.New()
	p := pipeline.New(ex, repo)
	for _, s := range []struct{ slug, extractor, license, dir string }{
		{"enthec-webappanalyzer", wappalyzer.ID, "GPL-3.0-only", "wappalyzer"},
		{"rapid7-recog", recog.ID, "BSD-2-Clause", "recog"},
		{"projectdiscovery-nuclei-templates", nuclei.ID, "MIT", "nuclei"},
	} {
		src := domain.Source{Slug: s.slug, Name: s.slug, ExtractorID: s.extractor, License: s.license, Redistributable: "unreviewed"}
		fsys := os.DirFS(filepath.Join(root(), s.dir, "testdata", "snapshot"))
		if _, err := p.Run(context.Background(), pipeline.Request{Source: src, Revision: "fixture", FS: fsys}); err != nil {
			t.Fatalf("%s: %v", s.slug, err)
		}
	}
	if len(paths) > 0 {
		if _, err := curate.ReviewProbes(context.Background(), repo, curate.ProbeReview{Paths: paths, Decision: curate.ProbeApproved, Note: "test"}, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	reg, err := export.Build(context.Background(), repo, time.Now(), export.Options{IncludeUnreviewed: true, Generator: "test"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := export.JSON(reg)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Page is the HTML of the test site.
const Page = `<!doctype html><html><head><title>Acme</title>
<link rel="me" href="https://mastodon.example/@acme">
<script type="application/ld+json">{"@type":"Organization","sameAs":["https://www.linkedin.com/company/acme"],"telephone":"+39 02 1234 5678"}</script>
</head><body>
<a-scene embedded></a-scene>
<p>See <a href="/4DACTION/home">home</a>, <a href="https://github.com/acme">GitHub</a>, mail <a href="mailto:info@acme.example">us</a>.</p>
</body></html>`

// Site starts a local server whose home page the fixtures recognise: PHP (header
// and cookie), 4D (a group of rules and a version), A-Frame (HTML).
func Site() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Server", "4D_V20/20.4.1")
		w.Header().Set("X-Powered-By", "PHP/8.2.1")
		http.SetCookie(w, &http.Cookie{Name: "PHPSESSID", Value: "abc", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode, Path: "/"})
		_, _ = w.Write([]byte(Page))
	}))
}
