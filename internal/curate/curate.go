// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

// Package curate applies reviewer edits to canonical records. Edits are kept
// across refreshes: imports never overwrite curated content.
package curate

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/matteoredaelli/open-web-fingerprints/internal/domain"
	"github.com/matteoredaelli/open-web-fingerprints/internal/repository"
)

// ErrNotFound means no record has the given slug.
var ErrNotFound = errors.New("not found")

// VendorPatch lists the changes to a vendor. Nil and empty fields change
// nothing.
type VendorPatch struct {
	Name          *string
	Website       *string // "" clears the website
	AddAliases    []string
	RemoveAliases []string
}

// Empty reports whether the patch changes nothing.
func (p VendorPatch) Empty() bool {
	return p.Name == nil && p.Website == nil && len(p.AddAliases) == 0 && len(p.RemoveAliases) == 0
}

// Vendor applies a patch to the vendor with the given slug and marks it as
// curated. The slug and CPE identifier never change: other records and later
// imports refer to them. Read-modify-write is not locked against a concurrent
// import; run curation and imports one at a time.
func Vendor(ctx context.Context, repo repository.Repository, slug string, p VendorPatch) (domain.Vendor, error) {
	if p.Empty() {
		return domain.Vendor{}, errors.New("curate: nothing to change")
	}
	all, err := repo.AllRecords(ctx)
	if err != nil {
		return domain.Vendor{}, fmt.Errorf("curate: %w", err)
	}
	var v *domain.Vendor
	for i := range all.Vendors {
		if all.Vendors[i].Slug == slug {
			v = &all.Vendors[i]
		}
	}
	if v == nil {
		return domain.Vendor{}, fmt.Errorf("curate: vendor %q: %w", slug, ErrNotFound)
	}

	if p.Name != nil {
		name := strings.TrimSpace(*p.Name)
		if name == "" {
			return domain.Vendor{}, errors.New("curate: the name cannot be empty")
		}
		v.Name = name
	}
	if p.Website != nil {
		w := strings.TrimSpace(*p.Website)
		if w != "" {
			if err := checkWebsite(w); err != nil {
				return domain.Vendor{}, err
			}
		}
		v.Website = w
	}
	for _, a := range p.RemoveAliases {
		v.Aliases = remove(v.Aliases, a)
	}
	for _, a := range p.AddAliases {
		a = strings.TrimSpace(a)
		switch {
		case a == "":
			return domain.Vendor{}, errors.New("curate: an alias cannot be empty")
		case strings.EqualFold(a, v.Name):
			continue // the name is already the preferred form
		case !contains(v.Aliases, a):
			v.Aliases = append(v.Aliases, a)
		}
	}
	// A renamed vendor keeps its previous guess findable.
	v.Aliases = remove(v.Aliases, v.Name)
	v.Curated = true

	if err := repo.Apply(ctx, repository.ChangeSet{Upsert: domain.Records{Vendors: []domain.Vendor{*v}}}); err != nil {
		return domain.Vendor{}, fmt.Errorf("curate: %w", err)
	}
	return *v, nil
}

func checkWebsite(w string) error {
	u, err := url.Parse(w)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil {
		return fmt.Errorf("curate: %q is not an http(s) URL without credentials", w)
	}
	return nil
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}

func remove(l []string, s string) []string {
	var out []string
	for _, x := range l {
		if !strings.EqualFold(x, s) {
			out = append(out, x)
		}
	}
	return out
}

// TechnologyPatch lists the changes to a technology. Nil fields change nothing.
type TechnologyPatch struct {
	Website     *string // "" clears the website
	Description *string
	VendorSlug  *string // "" clears the vendor
}

// Empty reports whether the patch changes nothing.
func (p TechnologyPatch) Empty() bool {
	return p.Website == nil && p.Description == nil && p.VendorSlug == nil
}

// Technology applies a patch to the technology with the given slug and
// records which fields a reviewer set, so refreshes keep them. Name, slug,
// categories and rules are not editable here: the slug is a public identifier,
// and the rest comes from the sources or from conflict review.
func Technology(ctx context.Context, repo repository.Repository, slug string, p TechnologyPatch) (domain.Technology, error) {
	if p.Empty() {
		return domain.Technology{}, errors.New("curate: nothing to change")
	}
	all, err := repo.AllRecords(ctx)
	if err != nil {
		return domain.Technology{}, fmt.Errorf("curate: %w", err)
	}
	var t *domain.Technology
	for i := range all.Technologies {
		if all.Technologies[i].Slug == slug {
			t = &all.Technologies[i]
		}
	}
	if t == nil {
		return domain.Technology{}, fmt.Errorf("curate: technology %q: %w", slug, ErrNotFound)
	}
	mark := func(f string) {
		if !contains(t.Curated, f) {
			t.Curated = append(t.Curated, f)
		}
	}
	if p.Website != nil {
		w := strings.TrimSpace(*p.Website)
		if w != "" {
			if err := checkWebsite(w); err != nil {
				return domain.Technology{}, err
			}
		}
		t.Website = w
		mark("website")
	}
	if p.Description != nil {
		t.Description = strings.TrimSpace(*p.Description)
		mark("description")
	}
	if p.VendorSlug != nil {
		t.VendorID = ""
		if *p.VendorSlug != "" {
			found := false
			for _, v := range all.Vendors {
				if v.Slug == *p.VendorSlug {
					t.VendorID, found = v.ID, true
				}
			}
			if !found {
				return domain.Technology{}, fmt.Errorf("curate: vendor %q: %w", *p.VendorSlug, ErrNotFound)
			}
		}
		mark("vendor")
	}
	sort.Strings(t.Curated)
	if err := repo.Apply(ctx, repository.ChangeSet{Upsert: domain.Records{Technologies: []domain.Technology{*t}}}); err != nil {
		return domain.Technology{}, fmt.Errorf("curate: %w", err)
	}
	return *t, nil
}
