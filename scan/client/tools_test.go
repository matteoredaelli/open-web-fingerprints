// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package client_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/scantest"
	"github.com/matteoredaelli/open-web-fingerprints/scan/client"
)

func TestExtract(t *testing.T) {
	ex, err := client.Extract([]byte(`<a href="https://other.example/x">o</a><a href="/about">a</a>`), "https://www.example.org/")
	if err != nil {
		t.Fatal(err)
	}
	if len(ex.Links) != 2 || len(ex.Domains) != 2 {
		t.Errorf("links %d, domains %d", len(ex.Links), len(ex.Domains))
	}
	if _, err := client.Extract(nil, "not a url"); err == nil {
		t.Error("a page address without a host must be refused")
	}
}

func TestPartsAgainstTheTestSite(t *testing.T) {
	srv := scantest.Site()
	defer srv.Close()
	ctx := context.Background()
	opt := client.Options{AllowPrivate: true}

	if _, err := client.ReadSite(ctx, client.Options{}, srv.URL); err == nil {
		t.Error("a local address must be refused by default")
	}
	site, err := client.ReadSite(ctx, opt, srv.URL)
	if err != nil || len(site.Pages) != 1 || site.URL == "" {
		t.Fatalf("ReadSite: %+v %v", site, err)
	}

	opt.NoFavicon = true
	opt.DropHeaders = []string{"date"}
	ob, err := client.Observe(ctx, opt, srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if ob.Observation.HTML != "" || !ob.Page.HeadersFiltered {
		t.Errorf("the body must be left out and the headers filtered: %q %v", ob.Observation.HTML, ob.Page.HeadersFiltered)
	}
	if _, ok := ob.Page.Headers["date"]; ok {
		t.Error("date must be dropped")
	}
	opt.KeepHTML = true
	if ob, err = client.Observe(ctx, opt, srv.URL); err != nil || ob.Observation.HTML == "" {
		t.Errorf("KeepHTML: %v", err)
	}

	fr, err := client.Friends(ctx, opt, srv.URL)
	if err != nil || fr.Friends == nil || fr.URL == "" {
		t.Errorf("Friends: %+v %v", fr, err)
	}
}

func TestValidHealth(t *testing.T) {
	if !client.ValidHealth("ok") || client.ValidHealth("fine") {
		t.Error("health values")
	}
}

func TestRenderReportAndObservation(t *testing.T) {
	reg, err := client.ParseRegistry(scantest.RegistryJSON(t))
	if err != nil {
		t.Fatal(err)
	}
	srv := scantest.Site()
	defer srv.Close()
	res, err := client.Scan(context.Background(), reg, client.Options{AllowPrivate: true, NoFavicon: true}, srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	var a, b bytes.Buffer
	if err := client.RenderReport(&a, res, "My title"); err != nil {
		t.Fatal(err)
	}
	_ = client.RenderReport(&b, res, "My title")
	if !strings.Contains(a.String(), "My title") || strings.Contains(a.String(), "<script") || a.String() != b.String() {
		t.Error("the report must carry the title, hold no script and be deterministic")
	}
	// The observation can be named and built from outside the module.
	_ = client.Observation{Headers: map[string]string{"Server": "x"}}
}
