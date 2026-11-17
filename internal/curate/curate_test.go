// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package curate

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/matteoredaelli/open-web-fingerprints/internal/domain"
	"github.com/matteoredaelli/open-web-fingerprints/internal/repository"
	"github.com/matteoredaelli/open-web-fingerprints/internal/repository/memory"
)

func str(s string) *string { return &s }

func repoWithVendor(t *testing.T) *memory.Repo {
	t.Helper()
	r := memory.New()
	err := r.Apply(context.Background(), repository.ChangeSet{Upsert: domain.Records{Vendors: []domain.Vendor{{
		ID: "vnd_1", Slug: "php", Name: "Php", CPEVendor: "php",
		Provenance: []domain.Provenance{{SourceID: "src_1", State: "present"}},
	}}}})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestVendorPatch(t *testing.T) {
	ctx := context.Background()
	r := repoWithVendor(t)
	v, err := Vendor(ctx, r, "php", VendorPatch{
		Name: str("The PHP Group"), Website: str("https://www.php.net"), AddAliases: []string{"PHP", "php.net", "php"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if v.Name != "The PHP Group" || v.Website != "https://www.php.net" || !v.Curated {
		t.Errorf("vendor: %+v", v)
	}
	// "Php" (the old guess) is not an alias of itself; "php" duplicates "PHP" case-insensitively.
	if strings.Join(v.Aliases, ",") != "PHP,php.net" {
		t.Errorf("aliases: %v", v.Aliases)
	}
	// Identity fields and provenance stay.
	if v.Slug != "php" || v.CPEVendor != "php" || v.ID != "vnd_1" || len(v.Provenance) != 1 {
		t.Errorf("identity changed: %+v", v)
	}
	all, _ := r.AllRecords(ctx)
	if all.Vendors[0].Name != "The PHP Group" || !all.Vendors[0].Curated {
		t.Errorf("not stored: %+v", all.Vendors[0])
	}

	// Remove an alias, clear the website; changing only one field keeps the rest.
	v, err = Vendor(ctx, r, "php", VendorPatch{RemoveAliases: []string{"php.NET"}, Website: str("")})
	if err != nil || strings.Join(v.Aliases, ",") != "PHP" || v.Website != "" || v.Name != "The PHP Group" {
		t.Errorf("second patch: %+v err=%v", v, err)
	}
	// The new name cannot also be an alias.
	v, err = Vendor(ctx, r, "php", VendorPatch{Name: str("php")})
	if err != nil || strings.Contains(strings.Join(v.Aliases, ","), "PHP") {
		t.Errorf("name/alias overlap: %+v err=%v", v, err)
	}
}

func TestVendorPatchErrors(t *testing.T) {
	ctx := context.Background()
	r := repoWithVendor(t)
	for name, tc := range map[string]struct {
		slug string
		p    VendorPatch
	}{
		"nothing":     {"php", VendorPatch{}},
		"empty name":  {"php", VendorPatch{Name: str("  ")}},
		"empty alias": {"php", VendorPatch{AddAliases: []string{" "}}},
		"ftp website": {"php", VendorPatch{Website: str("ftp://php.net")}},
		"no host":     {"php", VendorPatch{Website: str("https://")}},
		"credentials": {"php", VendorPatch{Website: str("https://u:p@php.net")}},
		"not a url":   {"php", VendorPatch{Website: str("php.net")}},
	} {
		if _, err := Vendor(ctx, r, tc.slug, tc.p); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	if _, err := Vendor(ctx, r, "nope", VendorPatch{Name: str("x")}); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown vendor: %v", err)
	}
	// Failed patches changed nothing.
	all, _ := r.AllRecords(ctx)
	if all.Vendors[0].Name != "Php" || all.Vendors[0].Curated {
		t.Errorf("a rejected patch changed the vendor: %+v", all.Vendors[0])
	}
}
