// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package config

import (
	"fmt"
	"io"
	"strings"
)

// Write writes c as a TOML file with a comment for every value. With Default() it is
// the file `owfscan config init` creates; parsing it gives back the same Config.
func Write(w io.Writer, c Config) error {
	var b strings.Builder
	p := func(format string, a ...any) { fmt.Fprintf(&b, format+"\n", a...) }
	q := func(s string) string { return fmt.Sprintf("%q", s) }
	list := func(l []string) string {
		parts := make([]string, len(l))
		for i, s := range l {
			parts[i] = q(s)
		}
		return "[" + strings.Join(parts, ", ") + "]"
	}

	p("# owfscan configuration.")
	p("#")
	p("# Only limits and lists are set here. The things that decide whether owfscan contacts")
	p("# a site you did not name (--browser, --friends, --related, --active) and the guards")
	p("# (--allow-private, --insecure, --ignore-robots) are never read from this file: each")
	p("# run asks for them. Durations are written \"500ms\", \"20s\", \"24h\".")
	p("# Flags override this file; this file overrides the built-in values. A key that does")
	p("# not exist is an error, and every value has a ceiling (`owfscan config show` lists them).")
	p("")
	p("[fetch]")
	p("# Time allowed to each request.")
	p("timeout = %q", c.Fetch.Timeout.D().String())
	p("# Most bytes read from one response; the rest is cut.")
	p("max_body_bytes = %d", c.Fetch.MaxBodyBytes)
	p("max_redirects = %d", c.Fetch.MaxRedirects)
	p("# How long a cached response is reused. The cache is off unless cache_dir is set.")
	p("max_age = %q", c.Fetch.MaxAge.D().String())
	p("cache_dir = %s", q(c.Fetch.CacheDir))
	p("# Empty: \"owfscan (+https://github.com/matteoredaelli/open-web-fingerprints)\".")
	p("user_agent = %s", q(c.Fetch.UserAgent))
	p("")
	p("[crawl]")
	p("# --depth: most pages fetched in total, the first one included.")
	p("max_pages = %d", c.Crawl.MaxPages)
	p("# Pause before each request that is not the first, to your site and to others")
	p("# (friends, related domains, probes). A larger Crawl-delay in robots.txt wins, up to max_delay.")
	p("delay = %q", c.Crawl.Delay.D().String())
	p("max_delay = %q", c.Crawl.MaxDelay.D().String())
	p("")
	p("[friends]")
	p("# --friends: most candidate domains whose home page is read.")
	p("max = %d", c.Friends.Max)
	p("")
	p("[related]")
	p("# --related: most candidate domains whose home page is read.")
	p("max = %d", c.Related.Max)
	p("# --related-tlds: the target's name is tried under these suffixes (name.com, name.co.uk, ...).")
	p("# Giving --related-tlds on the command line is what turns it on; this is the list it uses.")
	p("tlds = %s", list(c.Related.TLDs))
	p("")
	p("[active]")
	p("# --active: most requests to fixed paths of the site (only probes a reviewer approved).")
	p("max = %d", c.Active.Max)
	p("# Most bytes kept from a probe's answer.")
	p("max_body_bytes = %d", c.Active.MaxBodyBytes)
	p("")
	p("[browser]")
	p("# --browser: time allowed to the whole run.")
	p("timeout = %q", c.Browser.Timeout.D().String())
	p("# Wait after the page has loaded, for late scripts.")
	p("settle = %q", c.Browser.Settle.D().String())
	p("# Most requests the page may make; the rest are refused.")
	p("max_requests = %d", c.Browser.MaxRequests)
	p("# Chrome or Chromium executable. Empty: the usual places (or env OWFSCAN_CHROME).")
	p("chrome_path = %s", q(c.Browser.ChromePath))
	p("")
	p("[result]")
	p("# Most matching rules listed for one technology.")
	p("max_evidence = %d", c.Result.MaxEvidence)
	_, err := io.WriteString(w, b.String())
	return err
}

// Ceilings returns the largest values the file may ask for, for `config show`.
func Ceilings() [][2]string {
	return [][2]string{
		{"fetch.timeout", maxTimeout.String()},
		{"fetch.max_body_bytes", fmt.Sprint(maxBodyBytes)},
		{"fetch.max_redirects", fmt.Sprint(maxRedirects)},
		{"fetch.max_age", maxMaxAge.String()},
		{"crawl.max_pages", fmt.Sprint(maxPages)},
		{"crawl.delay", fmt.Sprintf("%s to %s", minDelay, maxPause)},
		{"crawl.max_delay", maxPause.String()},
		{"friends.max, related.max, active.max", fmt.Sprint(maxContacts)},
		{"related.tlds", fmt.Sprintf("%d entries", maxTLDs)},
		{"active.max_body_bytes", fmt.Sprint(maxBodyBytes)},
		{"browser.timeout", maxTimeout.String()},
		{"browser.settle", maxSettle.String()},
		{"browser.max_requests", fmt.Sprint(maxBrowserReqs)},
		{"result.max_evidence", fmt.Sprint(maxEvidenceList)},
	}
}
