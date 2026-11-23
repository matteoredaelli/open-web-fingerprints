// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package browser

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/browser"
	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

// Defaults of a run.
const (
	DefaultTimeout     = 30 * time.Second
	DefaultSettle      = 2 * time.Second
	DefaultMaxRequests = 300
)

// Options configure one browser run.
type Options struct {
	// ChromePath is the Chrome or Chromium executable; empty looks for a standard one.
	ChromePath string
	// Timeout bounds the whole run (default 30 s). The page gets Settle after it has loaded
	// for its scripts to run.
	Timeout time.Duration
	Settle  time.Duration
	// AllowPrivate lets the browser reach non-public addresses (your own network, tests).
	AllowPrivate bool
	// MaxRequests bounds the requests the page may make (default 300).
	MaxRequests int
	// Paths are the global variables to look for, as dotted paths ("jQuery.fn.jquery").
	Paths []string
	// UserAgent replaces Chrome's own; the scanner passes its identifying one.
	UserAgent string
}

// Result is what the page showed once its scripts had run.
type Result struct {
	FinalURL string
	// DOM is the serialised document after scripts ran.
	DOM string
	// Globals maps each path that exists to its value: the string form for strings, numbers
	// and booleans, empty for anything else (objects, functions).
	Globals map[string]string
	// XHR lists the URLs of the fetch and XMLHttpRequest calls the page made.
	XHR []string
	// Hosts lists the host names the page asked for, of any kind (documents, scripts,
	// images, fetch, beacons), lower-case and sorted. A request that the proxy refused is
	// included: it says what the page tried to reach.
	Hosts []string
	// Version is Chrome's version.
	Version string
	// Requests and Blocked count what went through the proxy.
	Requests, Blocked int
	// TimedOut is true when the page had not settled in time; what was seen up to then is
	// still returned.
	TimedOut bool
}

// ErrNoChrome is returned when no Chrome could be started.
var ErrNoChrome = errors.New("browser: Chrome or Chromium could not be started (install it, or give --chrome)")

const probeScript = `(paths) => {
  const out = {};
  for (const p of paths) {
    try {
      let o = window, ok = true;
      for (const k of p.split('.')) {
        if (o === null || o === undefined || !(k in Object(o))) { ok = false; break; }
        o = o[k];
      }
      if (ok) out[p] = (typeof o === 'string' || typeof o === 'number' || typeof o === 'boolean') ? String(o) : '';
    } catch (e) {}
  }
  return out;
}`

// Run opens the URL in Chrome and returns what it observed. The URL must be one the
// scanner has already decided to scan; the browser is only for what JavaScript adds.
func Run(ctx context.Context, opt Options, target string) (*Result, error) {
	u, err := url.Parse(target)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return nil, fmt.Errorf("browser: %q is not an http(s) URL", target)
	}
	if opt.Timeout <= 0 {
		opt.Timeout = DefaultTimeout
	}
	if opt.Settle <= 0 {
		opt.Settle = DefaultSettle
	}
	if opt.MaxRequests <= 0 {
		opt.MaxRequests = DefaultMaxRequests
	}
	px, err := newProxy(opt.AllowPrivate, opt.MaxRequests)
	if err != nil {
		return nil, fmt.Errorf("browser: %w", err)
	}
	defer px.close()

	profile, err := os.MkdirTemp("", "owfscan-chrome-*")
	if err != nil {
		return nil, fmt.Errorf("browser: %w", err)
	}
	defer func() { _ = os.RemoveAll(profile) }()

	flags := []chromedp.ExecAllocatorOption{
		chromedp.NoFirstRun, chromedp.NoDefaultBrowserCheck,
		chromedp.Headless,
		chromedp.UserDataDir(profile),
		chromedp.Flag("proxy-server", "http://"+px.addr()),
		// Loopback goes through the proxy too, so it can be refused there.
		chromedp.Flag("proxy-bypass-list", "<-loopback>"),
		// Chrome resolves nothing itself: every name goes to the proxy.
		chromedp.Flag("host-resolver-rules", "MAP * ~NOTFOUND , EXCLUDE 127.0.0.1"),
		// UDP and other ways around the proxy.
		chromedp.Flag("disable-quic", true),
		chromedp.Flag("force-webrtc-ip-handling-policy", "disable_non_proxied_udp"),
		chromedp.Flag("webrtc-ip-handling-policy", "disable_non_proxied_udp"),
		chromedp.Flag("dns-prefetch-disable", true),
		chromedp.Flag("disable-features", "NetworkPrediction,Translate,OptimizationHints,MediaRouter"),
		chromedp.Flag("disable-extensions", true),
		chromedp.Flag("disable-background-networking", true),
		chromedp.Flag("disable-sync", true),
		chromedp.Flag("disable-component-update", true),
		chromedp.Flag("disable-default-apps", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("mute-audio", true),
		chromedp.Flag("no-pings", true),
		chromedp.Flag("block-new-web-contents", true),
		chromedp.Flag("disk-cache-size", "1"),
		chromedp.Flag("password-store", "basic"),
		chromedp.Flag("use-mock-keychain", true),
	}
	if opt.ChromePath != "" {
		flags = append(flags, chromedp.ExecPath(opt.ChromePath))
	}
	if opt.UserAgent != "" {
		flags = append(flags, chromedp.UserAgent(opt.UserAgent))
	}
	runCtx, cancelRun := context.WithTimeout(ctx, opt.Timeout)
	defer cancelRun()
	allocCtx, cancelAlloc := chromedp.NewExecAllocator(runCtx, flags...)
	defer cancelAlloc()
	bctx, cancelB := chromedp.NewContext(allocCtx)
	// chromedp.Cancel closes the browser and waits until its process has exited, so none is
	// left running when the scan returns, also after a timeout or an interrupt.
	started := false
	defer func() {
		if started {
			_ = chromedp.Cancel(bctx)
		}
		cancelB()
	}()

	res := &Result{Globals: map[string]string{}}
	var xhr []string
	hosts := map[string]bool{}
	var mu sync.Mutex
	// Listen starts the browser, so a Chrome that cannot run is found out here.
	if err := chromedp.Listen(bctx, func(ev any) {
		e, ok := ev.(*network.EventRequestWillBeSent)
		if !ok {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if e.Type == network.ResourceTypeXHR || e.Type == network.ResourceTypeFetch {
			xhr = append(xhr, e.Request.URL)
		}
		if h := requestHost(e.Request.URL); h != "" {
			hosts[h] = true
		}
	}); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNoChrome, err)
	}
	started = true
	paths := append([]string(nil), opt.Paths...)
	sort.Strings(paths)
	pathsJSON, _ := json.Marshal(paths)

	if _, err := chromedp.Call(bctx, network.Enable, network.EnableParams{}); err != nil {
		return nil, fmt.Errorf("browser: %w", err)
	}
	// No downloads, whatever the page tries.
	if _, err := chromedp.CallBrowser(bctx, browser.SetDownloadBehavior, browser.SetDownloadBehaviorParams{Behavior: browser.SetDownloadBehaviorBehaviorDeny}); err != nil {
		return nil, fmt.Errorf("browser: %w", err)
	}

	navErr := chromedp.Do(bctx, chromedp.Navigate(target))
	if navErr != nil && runCtx.Err() != nil {
		res.TimedOut = true
	}
	if navErr == nil {
		// Scripts that start after the load event get a moment to run.
		select {
		case <-time.After(opt.Settle):
		case <-bctx.Done():
		}
	}
	// What can still be read after a timeout is returned: a slow page is not an error.
	if loc, err := chromedp.Run(bctx, chromedp.Location()); err == nil {
		res.FinalURL = loc
	}
	dom, derr := chromedp.Run(bctx, chromedp.OuterHTML(chromedp.CSS("html")))
	if derr != nil {
		if navErr != nil {
			return nil, fmt.Errorf("browser: %w", navErr)
		}
		return nil, fmt.Errorf("browser: %w", derr)
	}
	res.DOM = dom
	if g, err := chromedp.Run(bctx, chromedp.Evaluate[map[string]string]("("+probeScript+")("+string(pathsJSON)+")")); err == nil && g != nil {
		res.Globals = g
	}
	res.Requests, res.Blocked = px.stats()
	mu.Lock()
	res.XHR = dedupe(xhr)
	for h := range hosts {
		res.Hosts = append(res.Hosts, h)
	}
	sort.Strings(res.Hosts)
	mu.Unlock()
	if v, err := chromedp.CallBrowser(bctx, browser.GetVersion, cdp.Empty{}); err == nil && true {
		res.Version = v.Product
	}
	return res, nil
}

func dedupe(l []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, s := range l {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// requestHost returns the lower-case host name of an http or https URL, or "".
func requestHost(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return ""
	}
	return strings.ToLower(u.Hostname())
}
