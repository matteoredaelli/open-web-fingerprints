// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package client_test

import (
	"context"
	"testing"

	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/scantest"
	"github.com/matteoredaelli/open-web-fingerprints/scan/client"
)

func TestScan(t *testing.T) {
	reg, err := client.ParseRegistry(scantest.RegistryJSON(t))
	if err != nil {
		t.Fatal(err)
	}
	if reg.Ref().ContentSHA256 == "" {
		t.Error("the registry reference has no hash")
	}
	srv := scantest.Site()
	defer srv.Close()

	// The test site is on a local address: refused unless asked for.
	if _, err := client.Scan(context.Background(), reg, client.Options{NoFavicon: true}, srv.URL); err == nil {
		t.Fatal("a local address must be refused by default")
	}
	res, err := client.Scan(context.Background(), reg, client.Options{AllowPrivate: true, NoFavicon: true}, srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Validate(res); err != nil {
		t.Fatalf("the result must satisfy its schema: %v", err)
	}
	found := false
	for _, tc := range res.Technologies {
		found = found || tc.Name == "PHP"
	}
	if !found {
		t.Errorf("PHP not found among %d technologies", len(res.Technologies))
	}
}

func TestScanWithoutRegistry(t *testing.T) {
	if _, err := client.Scan(context.Background(), nil, client.Options{}, "example.org"); err == nil {
		t.Error("no registry must be an error")
	}
}

// Scanning a site with a registry export written by `owf export`.
func ExampleScan() {
	reg, err := client.LoadRegistry("registry.json")
	if err != nil {
		return
	}
	res, err := client.Scan(context.Background(), reg, client.Options{DNS: true, Depth: 1}, "https://example.org")
	if err != nil {
		return
	}
	for _, tc := range res.Technologies {
		_ = tc.Name + " " + tc.Version
	}
}
