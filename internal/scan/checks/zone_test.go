// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package checks

import (
	"context"
	"errors"
	"testing"

	"github.com/matteoredaelli/open-web-fingerprints/scan"
)

type fakeZone struct {
	caa  []string
	info DNSSECInfo
	err  error
}

func (f fakeZone) CAA(context.Context, string) ([]string, error) { return f.caa, f.err }
func (f fakeZone) DNSSEC(context.Context, string) (DNSSECInfo, error) {
	return f.info, f.err
}

func TestReadCAA(t *testing.T) {
	c := ReadCAA([]string{`0 issue letsencrypt.org`, `0 issuewild ;`, `0 issue "DigiCert.com; account=1"`, `0 iodef mailto:a@b.c`})
	if !c.Present || c.Status != scan.CheckOK || !c.IODEF {
		t.Fatalf("%+v", c)
	}
	if len(c.Issuers) != 2 || c.Issuers[0] != "digicert.com" || c.Issuers[1] != "letsencrypt.org" {
		t.Fatalf("issuers %v", c.Issuers)
	}
	if n := ReadCAA(nil); n.Present || n.Status != scan.CheckInfo {
		t.Fatalf("%+v", n)
	}
	if f := ReadCAA([]string{"0 issue ;"}); !f.NoIssue {
		t.Fatalf("%+v", f)
	}
}

func TestReadDNSSEC(t *testing.T) {
	for _, c := range []struct {
		in   DNSSECInfo
		want string
	}{
		{DNSSECInfo{DNSKEY: true, DS: true, Validated: true}, scan.CheckOK},
		{DNSSECInfo{DNSKEY: true}, scan.CheckWeak},
		{DNSSECInfo{DS: true}, scan.CheckWeak},
		{DNSSECInfo{DNSKEY: true, Broken: true}, scan.CheckWeak},
		{DNSSECInfo{}, scan.CheckInfo},
	} {
		if got := ReadDNSSEC(c.in).Status; got != c.want {
			t.Errorf("%+v: %s, want %s", c.in, got, c.want)
		}
	}
}

func TestReviewWarnings(t *testing.T) {
	caa, sec, w := Review(context.Background(), fakeZone{err: errors.New("boom")}, "example.com")
	if caa != nil || sec != nil || len(w) != 2 {
		t.Fatalf("%v %v %v", caa, sec, w)
	}
	caa, sec, w = Review(context.Background(), fakeZone{caa: []string{"0 issue x.org"}, info: DNSSECInfo{DNSKEY: true, DS: true}}, "example.com")
	if caa == nil || sec == nil || len(w) != 0 {
		t.Fatalf("%v %v %v", caa, sec, w)
	}
}
