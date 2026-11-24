// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

// Package dnsx asks the DNS questions the standard library cannot: CAA and the DNSSEC
// records. It sends ordinary queries to the system's resolvers and reads nothing else.
package dnsx

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/checks"
	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/dnslimit"
)

// Client queries the resolvers of Servers (host:port); empty means the ones in /etc/resolv.conf.
type Client struct {
	Servers []string
	Timeout time.Duration // per query (0: 5s)
}

var errNoServer = errors.New("no DNS server configured")

func (c Client) servers() ([]string, error) {
	if len(c.Servers) > 0 {
		return c.Servers, nil
	}
	cfg, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil || len(cfg.Servers) == 0 {
		return nil, errNoServer
	}
	var out []string
	for _, s := range cfg.Servers {
		out = append(out, dns.Fqdn(s)[:len(dns.Fqdn(s))-1]+":"+cfg.Port)
	}
	return out, nil
}

// ask sends one query, over TCP when the UDP answer is truncated. cd asks the resolver not to
// validate.
func (c Client) ask(ctx context.Context, name string, qtype uint16, cd bool) (*dns.Msg, error) {
	servers, err := c.servers()
	if err != nil {
		return nil, err
	}
	to := c.Timeout
	if to == 0 {
		to = 5 * time.Second
	}
	release, err := dnslimit.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.SetEdns0(4096, true)
	m.RecursionDesired = true
	m.CheckingDisabled = cd
	var last error
	for _, s := range servers {
		cl := &dns.Client{Timeout: to}
		r, _, err := cl.ExchangeContext(ctx, m, s)
		if err == nil && r.Truncated {
			cl.Net = "tcp"
			r, _, err = cl.ExchangeContext(ctx, m, s)
		}
		if err != nil {
			last = err
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			continue
		}
		return r, nil
	}
	return nil, last
}

// CAA implements checks.Zone: the records at the domain, as "flags tag value".
func (c Client) CAA(ctx context.Context, domain string) ([]string, error) {
	r, err := c.ask(ctx, domain, dns.TypeCAA, false)
	if err != nil {
		return nil, err
	}
	if r.Rcode != dns.RcodeSuccess && r.Rcode != dns.RcodeNameError {
		return nil, fmt.Errorf("CAA %s: %s", domain, dns.RcodeToString[r.Rcode])
	}
	var out []string
	for _, rr := range r.Answer {
		if x, ok := rr.(*dns.CAA); ok {
			out = append(out, fmt.Sprintf("%d %s %s", x.Flag, x.Tag, x.Value))
		}
	}
	return out, nil
}

// DNSSEC implements checks.Zone.
func (c Client) DNSSEC(ctx context.Context, domain string) (checks.DNSSECInfo, error) {
	var info checks.DNSSECInfo
	key, err := c.ask(ctx, domain, dns.TypeDNSKEY, false)
	if err != nil {
		return info, err
	}
	if key.Rcode == dns.RcodeServerFailure {
		// A validating resolver answers SERVFAIL for a zone whose signatures do not verify.
		// Asking again without validation tells that apart from a resolver that is just down.
		if raw, err := c.ask(ctx, domain, dns.TypeDNSKEY, true); err == nil && hasType(raw.Answer, dns.TypeDNSKEY) {
			info.DNSKEY, info.Broken = true, true
		}
	} else {
		info.DNSKEY = hasType(key.Answer, dns.TypeDNSKEY)
		info.Validated = key.AuthenticatedData && info.DNSKEY
	}
	ds, err := c.ask(ctx, domain, dns.TypeDS, false)
	if err != nil {
		return info, err
	}
	for _, rr := range ds.Answer {
		if x, ok := rr.(*dns.DS); ok {
			info.DS = true
			info.Algorithms = appendUniq(info.Algorithms, dns.AlgorithmToString[x.Algorithm])
		}
	}
	if !info.DNSKEY && info.DS && ds.Rcode == dns.RcodeSuccess && key.Rcode == dns.RcodeServerFailure {
		info.Broken = true
	}
	return info, nil
}

func hasType(rrs []dns.RR, t uint16) bool {
	for _, rr := range rrs {
		if rr.Header().Rrtype == t {
			return true
		}
	}
	return false
}

func appendUniq(l []string, s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return l
	}
	for _, x := range l {
		if x == s {
			return l
		}
	}
	return append(l, s)
}
