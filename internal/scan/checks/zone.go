// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package checks

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/matteoredaelli/open-web-fingerprints/scan"
)

// DNSSECInfo is what the DNSSEC records of a zone say.
type DNSSECInfo struct {
	DNSKEY     bool     // the zone publishes keys
	DS         bool     // the parent zone holds a DS record for it (the chain is delegated)
	Validated  bool     // the resolver validated the answer (AD flag): only a validating resolver sets it
	Broken     bool     // the resolver refused the zone but answered without validation
	Algorithms []string // from the DS records
}

// Zone is the part of a DNS client that Zone needs: queries the standard library cannot make.
type Zone interface {
	CAA(ctx context.Context, domain string) ([]string, error) // "flags tag value"
	DNSSEC(ctx context.Context, domain string) (DNSSECInfo, error)
}

// Review reviews the CAA and DNSSEC records of a registrable domain. A failed lookup is a warning
// and leaves its item out. It returns nil when both failed.
func Review(ctx context.Context, z Zone, domain string) (caa *scan.CAA, sec *scan.DNSSEC, warns []scan.Warning) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	recs, err := z.CAA(ctx, domain)
	if err != nil {
		warns = append(warns, scan.Warning{Code: "check_dns_caa", Message: err.Error(), Ref: domain})
	} else {
		caa = ReadCAA(recs)
	}
	info, err := z.DNSSEC(ctx, domain)
	if err != nil {
		warns = append(warns, scan.Warning{Code: "check_dns_dnssec", Message: err.Error(), Ref: domain})
	} else {
		sec = ReadDNSSEC(info)
	}
	return caa, sec, warns
}

// ReadCAA reads the records (RFC 8659). Having a CAA record is ok; having none is only info,
// since it is a recommendation that many large sites do not follow.
func ReadCAA(records []string) *scan.CAA {
	c := &scan.CAA{Present: len(records) > 0, Records: records}
	seen := map[string]bool{}
	for _, r := range records {
		f := strings.SplitN(r, " ", 3)
		if len(f) < 3 {
			continue
		}
		tag, val := strings.ToLower(f[1]), strings.Trim(strings.TrimSpace(f[2]), `"`)
		switch tag {
		case "issue", "issuewild":
			ca, _, _ := strings.Cut(val, ";")
			ca = strings.ToLower(strings.TrimSpace(ca))
			if ca == "" {
				if tag == "issue" {
					c.NoIssue = true
				}
				continue
			}
			if tag == "issuewild" {
				ca += " (wildcard)"
			}
			if !seen[ca] {
				seen[ca] = true
				c.Issuers = append(c.Issuers, ca)
			}
		case "iodef":
			c.IODEF = true
		}
	}
	sort.Strings(c.Issuers)
	switch {
	case !c.Present:
		c.Status, c.Note = scan.CheckInfo, "no CAA record: any certificate authority may issue for this domain"
	default:
		c.Status = scan.CheckOK
		if c.NoIssue && len(c.Issuers) == 0 {
			c.Note = "issuance is forbidden by the record"
		}
	}
	return c
}

// ReadDNSSEC turns the findings into a verdict.
func ReadDNSSEC(i DNSSECInfo) *scan.DNSSEC {
	d := &scan.DNSSEC{Signed: i.DNSKEY, DS: i.DS, Validated: i.Validated, Algorithms: i.Algorithms}
	switch {
	case i.Broken:
		d.Status, d.Note = scan.CheckWeak, "the zone is signed but a validating resolver refuses it: the signatures or the DS record do not match"
	case i.DNSKEY && i.DS:
		d.Status = scan.CheckOK
		if !i.Validated {
			d.Note = "signed and delegated; the resolver used does not validate, so the signatures were not checked"
		}
	case i.DNSKEY:
		d.Status, d.Note = scan.CheckWeak, "the zone publishes keys but the parent has no DS record: the chain of trust is not complete"
	case i.DS:
		d.Status, d.Note = scan.CheckWeak, "the parent has a DS record but the zone publishes no keys"
	default:
		d.Status, d.Note = scan.CheckInfo, "the zone is not signed (DNSSEC is optional)"
	}
	return d
}
