// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

// Package browser runs a page in a headless Chrome so that what JavaScript does can be
// observed: global variables, the requests the page makes and the DOM after scripts ran.
//
// Running another party's JavaScript is a different act from reading its HTML, so the
// browser is held to the rules of the rest of the scanner by construction, not by
// trust: all of its traffic goes through a proxy that this package runs, and the proxy
// refuses non-public addresses at connection time (after DNS, so redirects and DNS
// rebinding do not help), counts requests and stops at a limit. Chrome is started with
// QUIC and WebRTC off and with its own DNS resolution disabled, so nothing can go around
// the proxy. Downloads, permission prompts and extensions are off, and the profile is a
// temporary directory that is removed afterwards.
package browser

import (
	"syscall"

	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/fetch"
)

// proxy is a small forward proxy: CONNECT tunnels for https, plain forwarding for http.
type proxy struct {
	allowPrivate bool
	maxRequests  int64
	requests     atomic.Int64
	blocked      atomic.Int64
	srv          *http.Server
	ln           net.Listener
	dialer       *net.Dialer
	transport    *http.Transport
	wg           sync.WaitGroup
	mu           sync.Mutex
	conns        map[net.Conn]struct{}
}

var errBlocked = errors.New("address not allowed")

func newProxy(allowPrivate bool, maxRequests int) (*proxy, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	p := &proxy{allowPrivate: allowPrivate, maxRequests: int64(maxRequests), ln: ln, conns: map[net.Conn]struct{}{}}
	p.dialer = &net.Dialer{Timeout: 15 * time.Second, Control: func(_, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return err
		}
		ip, err := netip.ParseAddr(host)
		if err != nil {
			return err
		}
		if !p.allowPrivate && !fetch.Public(ip.Unmap()) {
			p.blocked.Add(1)
			return fmt.Errorf("%w: %s", errBlocked, ip)
		}
		return nil
	}}
	p.transport = &http.Transport{
		DialContext: p.dialer.DialContext, Proxy: nil, DisableCompression: true,
		ResponseHeaderTimeout: 30 * time.Second, IdleConnTimeout: 10 * time.Second,
	}
	p.srv = &http.Server{Handler: p, ReadHeaderTimeout: 10 * time.Second}
	p.wg.Add(1)
	go func() { defer p.wg.Done(); _ = p.srv.Serve(ln) }()
	return p, nil
}

func (p *proxy) addr() string { return p.ln.Addr().String() }

func (p *proxy) close() {
	_ = p.srv.Close()
	p.mu.Lock()
	for c := range p.conns {
		_ = c.Close()
	}
	p.mu.Unlock()
	p.transport.CloseIdleConnections()
	p.wg.Wait()
}

func (p *proxy) track(c net.Conn) func() {
	p.mu.Lock()
	p.conns[c] = struct{}{}
	p.mu.Unlock()
	return func() {
		p.mu.Lock()
		delete(p.conns, c)
		p.mu.Unlock()
		_ = c.Close()
	}
}

func (p *proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if p.requests.Add(1) > p.maxRequests {
		http.Error(w, "request limit reached", http.StatusTooManyRequests)
		return
	}
	if r.Method == http.MethodConnect {
		p.connect(w, r)
		return
	}
	if r.URL.Scheme != "http" || r.URL.Host == "" {
		http.Error(w, "only absolute http URLs", http.StatusBadRequest)
		return
	}
	out := r.Clone(r.Context())
	out.RequestURI = ""
	for _, h := range []string{"Proxy-Connection", "Proxy-Authorization", "Connection", "Keep-Alive", "Te", "Trailer", "Upgrade"} {
		out.Header.Del(h)
	}
	resp, err := p.transport.RoundTrip(out)
	if err != nil {
		status := http.StatusBadGateway
		if errors.Is(err, errBlocked) {
			status = http.StatusForbidden
		}
		http.Error(w, err.Error(), status)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, io.LimitReader(resp.Body, 32<<20))
}

func (p *proxy) connect(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if !strings.Contains(host, ":") {
		host += ":443"
	}
	up, err := p.dialer.DialContext(r.Context(), "tcp", host)
	if err != nil {
		status := http.StatusBadGateway
		if errors.Is(err, errBlocked) {
			status = http.StatusForbidden
		}
		http.Error(w, err.Error(), status)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		_ = up.Close()
		http.Error(w, "no hijack", http.StatusInternalServerError)
		return
	}
	down, _, err := hj.Hijack()
	if err != nil {
		_ = up.Close()
		return
	}
	done1, done2 := p.track(up), p.track(down)
	_, _ = down.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	var once sync.WaitGroup
	once.Add(2)
	go func() { defer once.Done(); _, _ = io.Copy(up, down); _ = up.SetDeadline(time.Now()) }()
	go func() { defer once.Done(); _, _ = io.Copy(down, up); _ = down.SetDeadline(time.Now()) }()
	go func() { once.Wait(); done1(); done2() }()
}

// stats reports how many requests went through and how many connections were refused.
func (p *proxy) stats() (requests, blocked int) {
	return int(min(p.requests.Load(), p.maxRequests)), int(p.blocked.Load())
}
