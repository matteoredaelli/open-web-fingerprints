// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package fingerprinthub

import (
	"context"
	"os"
	"testing"
	"testing/fstest"

	"github.com/matteoredaelli/open-web-fingerprints/internal/domain"
	"github.com/matteoredaelli/open-web-fingerprints/internal/extractor"
	"github.com/matteoredaelli/open-web-fingerprints/internal/extractor/extractortest"
)

func fixtureSource() extractor.Source {
	return extractor.Source{
		ID: "0x727-fingerprinthub", URL: "https://github.com/0x727/FingerprintHub",
		Revision: "120898f", License: "MIT", FS: os.DirFS("testdata/snapshot"),
	}
}

func TestContract(t *testing.T) {
	extractortest.RunContract(t, New(), fixtureSource())
}

func TestFixtures(t *testing.T) {
	res, err := New().Extract(context.Background(), fixtureSource())
	if err != nil {
		t.Fatal(err)
	}
	var favicon, header bool
	for _, f := range res.Fingerprints {
		if f.Observation == domain.ObsFaviconHash && f.Target == "mmh3" && f.Pattern == "1895809524" {
			favicon = true
		}
		if f.Observation == "response_headers" && f.TechnologyKey == "caucho|resin" {
			header = true
		}
	}
	if !favicon || !header {
		t.Errorf("favicon=%v header=%v, want both", favicon, header)
	}
}

// The copy under 00_unknown must not hide the one that names a vendor.
func TestVendorCopyWins(t *testing.T) {
	res, err := New().Extract(context.Background(), fixtureSource())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, tc := range res.Technologies {
		if tc.Key == "adobe|coldfusion" {
			found = true
		}
		if tc.Key == "00_unknown|coldfusion" {
			t.Error("the 00_unknown copy was read instead of the vendor one")
		}
	}
	if !found {
		t.Error("adobe coldfusion not extracted")
	}
}

func TestFaviconHashForms(t *testing.T) {
	tpl := `id: x
info:
  name: x
  metadata: {product: x, vendor: v}
http:
- method: GET
  path: ['{{BaseURL}}/']
  matchers:
  - type: favicon
    hash: [F49C4A4BDE1EEC6C0B80C2277C76E3DB, '-244067125']
`
	src := extractor.Source{ID: "n", FS: fstest.MapFS{"web-fingerprint/v/x.yaml": {Data: []byte(tpl)}}}
	res, err := New().Extract(context.Background(), src)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, f := range res.Fingerprints {
		got[f.Target] = f.Pattern
	}
	if got["md5"] != "f49c4a4bde1eec6c0b80c2277c76e3db" || got["mmh3"] != "-244067125" {
		t.Errorf("got %v", got)
	}
}
