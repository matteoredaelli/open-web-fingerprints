// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package dnsx

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// serve answers from a fixed table on a local UDP port.
func serve(t *testing.T, h dns.HandlerFunc) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skip("no local UDP:", err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: h}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

func TestCAAAndDNSSEC(t *testing.T) {
	addr := serve(t, func(w dns.ResponseWriter, q *dns.Msg) {
		r := new(dns.Msg)
		r.SetReply(q)
		hdr := func(t uint16) dns.RR_Header {
			return dns.RR_Header{Name: q.Question[0].Name, Rrtype: t, Class: dns.ClassINET, Ttl: 60}
		}
		switch q.Question[0].Qtype {
		case dns.TypeCAA:
			r.Answer = append(r.Answer, &dns.CAA{Hdr: hdr(dns.TypeCAA), Tag: "issue", Value: "letsencrypt.org"})
		case dns.TypeDNSKEY:
			r.AuthenticatedData = true
			r.Answer = append(r.Answer, &dns.DNSKEY{Hdr: hdr(dns.TypeDNSKEY), Flags: 257, Protocol: 3, Algorithm: dns.ECDSAP256SHA256, PublicKey: "AAAA"})
		case dns.TypeDS:
			r.Answer = append(r.Answer, &dns.DS{Hdr: hdr(dns.TypeDS), KeyTag: 1, Algorithm: dns.ECDSAP256SHA256, DigestType: 2, Digest: "AB"})
		}
		_ = w.WriteMsg(r)
	})
	c := Client{Servers: []string{addr}, Timeout: 2 * time.Second}
	ctx := context.Background()
	caa, err := c.CAA(ctx, "example.com")
	if err != nil || len(caa) != 1 || caa[0] != "0 issue letsencrypt.org" {
		t.Fatalf("%v %v", caa, err)
	}
	info, err := c.DNSSEC(ctx, "example.com")
	if err != nil || !info.DNSKEY || !info.DS || !info.Validated || len(info.Algorithms) != 1 {
		t.Fatalf("%+v %v", info, err)
	}
}

func TestNoServer(t *testing.T) {
	c := Client{Servers: []string{"127.0.0.1:1"}, Timeout: 200 * time.Millisecond}
	if _, err := c.CAA(context.Background(), "example.com"); err == nil {
		t.Fatal("want an error")
	}
}
