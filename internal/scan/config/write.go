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
	p("")
	p("[output]")
	p("# Response headers left out of the output (page.headers; for `observe` also the cookie")
	p("# values when set-cookie is listed) because they change on every call or identify the")
	p("# caller: two calls to the same site seconds apart then give the same headers. The rules")
	p("# still see all of them, so a rule on x-amz-cf-id or via keeps matching. A name, or a")
	p("# prefix ending in * (\"x-envoy-*\"); lower case. `--all-headers` keeps everything.")
	p("drop_headers = %s", multiline(c.Output.DropHeaders))
	writeBot(p, q, list, c.Bot)
	_, err := io.WriteString(w, b.String())
	return err
}

func writeBot(p func(string, ...any), q func(string) string, list func([]string) string, b Bot) {
	p("")
	p("[bot]")
	p("# `owfscan bot`: the crawler. It reads home pages only (depth 0 or 1), makes only GETs,")
	p("# honours robots.txt and never sends probes or contacts. None of that can be set here.")
	p("# SQLite file of the crawl.")
	p("db = %s", q(b.DB))
	p("workers = %d", b.Workers)
	p("# Most requests per second over all hosts.")
	p("rate = %v", b.Rate)
	p("# Pause between two requests to the same host (a larger Crawl-delay in robots.txt wins).")
	p("per_host_delay = %q", b.PerHostDelay.D().String())
	p("# Most domains scanned in one run; 0 is no limit.")
	p("budget = %d", b.Budget)
	p("# A run stops after this long; \"0s\" is no limit.")
	p("until = %q", b.Until.D().String())
	p("# 0: the home page only. 1: also the pages it links.")
	p("depth = %d", b.Depth)
	p("# Most new domains one site may add to the frontier.")
	p("max_new_per_site = %d", b.MaxNewPerSite)
	p("# Most hops from a seed; domains found at this depth are scanned, their links are not followed.")
	p("max_depth = %d", b.MaxDepth)
	p("# How long a worker keeps a domain before another may take it (a killed run loses nothing).")
	p("lease_ttl = %q", b.LeaseTTL.D().String())
	p("# Time between two visits of a domain, and the longest for a domain that does not change.")
	p("revisit = %q", b.Revisit.D().String())
	p("revisit_max = %q", b.RevisitMax.D().String())
	p("# A domain that has not changed comes back after revisit, then twice as late, up to revisit_max;")
	p("# one that changed comes back after half of revisit. Visits are spread by 10%%.")
	p("# A domain whose name does not exist is blocked for good after this many failures in a row; 0 never.")
	p("dns_failures = %d", b.DNSFailures)
	p("")
	p("[bot.filter]")
	p("# Domains on a block list are kept, marked blocked, and never scanned. A name-based filter")
	p("# has false positives and negatives: it is no guarantee about the content of a site.")
	p("mode = %q", b.Filter.Mode)
	p("# Directory of the downloaded lists (`owfscan bot filter refresh` fills it).")
	p("dir = %s", q(b.Filter.Dir))
	p("# Categories of the lists that block: %s.", strings.Join(FilterCategories, ", "))
	p("exclude_categories = %s", list(b.Filter.ExcludeCategories))
	p("refresh_every = %q", b.Filter.RefreshEvery.D().String())
	p("# true: `bot run` refuses to start with no enabled list (--no-filter is the explicit way round).")
	p("require = %v", b.Filter.Require)
	p("# No list is shipped (their licences differ). Add one, checking its licence:")
	p("#")
	p("# [[bot.filter.list]]")
	p("# name = \"example\"")
	p("# url = \"https://example.org/hosts.txt\"")
	p("# category = \"adult\"        # %s", strings.Join(FilterCategories, " | "))
	p("# format = \"hosts\"          # %s", strings.Join(FilterFormats, " | "))
	p("# enabled = true")
	for _, l := range b.Filter.Lists {
		p("")
		p("[[bot.filter.list]]")
		p("name = %s", q(l.Name))
		p("url = %s", q(l.URL))
		p("category = %s", q(l.Category))
		p("format = %s", q(l.Format))
		p("enabled = %v", l.Enabled)
	}
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
		{"output.drop_headers", fmt.Sprintf("%d entries", maxDropHeaders)},
		{"bot.workers", fmt.Sprint(maxBotWorkers)},
		{"bot.rate", fmt.Sprintf("%v requests per second", maxBotRate)},
		{"bot.per_host_delay", fmt.Sprintf("1s to %s", maxPause)},
		{"bot.budget", fmt.Sprint(maxBotBudget)},
		{"bot.until", maxBotUntil.String()},
		{"bot.depth", "1"},
		{"bot.dns_failures", fmt.Sprint(maxBotDNSFailures)},
		{"bot.max_new_per_site", fmt.Sprint(maxBotNew)},
		{"bot.max_depth", fmt.Sprint(maxBotDepth)},
		{"bot.lease_ttl", fmt.Sprintf("%s to %s", minLease, maxLease)},
		{"bot.revisit, bot.revisit_max", fmt.Sprintf("%s to %s", minRevisit, maxRevisit)},
		{"bot.filter.refresh_every", fmt.Sprintf("%s to %s", minFilterEvery, maxFilterEvery)},
		{"bot.filter.list", fmt.Sprintf("%d lists, https only", maxFilterLists)},
	}
}

// multiline writes a list of strings, several to a line.
func multiline(l []string) string {
	if len(l) == 0 {
		return "[]"
	}
	var b strings.Builder
	b.WriteString("[\n")
	line := "  "
	for _, s := range l {
		item := fmt.Sprintf("%q, ", s)
		if len(line)+len(item) > 88 {
			b.WriteString(strings.TrimRight(line, " ") + "\n")
			line = "  "
		}
		line += item
	}
	b.WriteString(strings.TrimRight(line, " ") + "\n]")
	return b.String()
}
