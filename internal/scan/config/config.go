// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

// Package config holds the limits and defaults of owfscan, in one place, and reads
// them from a TOML file.
//
// The file only changes numbers and lists: how much, how long, how often. It cannot
// turn on anything that contacts a site the user did not name (browser, friends,
// related domains, active probes), and it cannot lift the guards (private addresses,
// robots.txt, TLS verification): those stay explicit choices of each run. Every value
// is checked against a ceiling, so a typo cannot ask for ten million pages.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"

	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/browser"
	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/fetch"
	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/scanner"
	"github.com/matteoredaelli/open-web-fingerprints/scan/client"
)

// FileName is the name of the configuration file.
const FileName = "owfscan.toml"

// Duration is a time.Duration written as text ("500ms", "20s", "24h").
type Duration time.Duration

// D returns the value as a time.Duration.
func (d Duration) D() time.Duration { return time.Duration(d) }

// MarshalText implements encoding.TextMarshaler.
func (d Duration) MarshalText() ([]byte, error) { return []byte(time.Duration(d).String()), nil }

// UnmarshalText implements encoding.TextUnmarshaler.
func (d *Duration) UnmarshalText(b []byte) error {
	v, err := time.ParseDuration(string(b))
	if err != nil {
		return fmt.Errorf("%q is not a duration (examples: 500ms, 20s, 24h)", b)
	}
	*d = Duration(v)
	return nil
}

// Config is the whole configuration. A zero value is not valid: start from Default.
type Config struct {
	Fetch   Fetch   `toml:"fetch"`
	Crawl   Crawl   `toml:"crawl"`
	Friends Friends `toml:"friends"`
	Related Related `toml:"related"`
	Active  Active  `toml:"active"`
	Browser Browser `toml:"browser"`
	Result  Result  `toml:"result"`
	Output  Output  `toml:"output"`
	Bot     Bot     `toml:"bot"`
}

// Fetch limits every HTTP request.
type Fetch struct {
	Timeout      Duration `toml:"timeout"`
	MaxBodyBytes int64    `toml:"max_body_bytes"`
	MaxRedirects int      `toml:"max_redirects"`
	// MaxAge is how long a cached response is reused (the cache itself is off unless cache_dir is set).
	MaxAge    Duration `toml:"max_age"`
	CacheDir  string   `toml:"cache_dir"`
	UserAgent string   `toml:"user_agent"`
}

// Crawl limits how far --depth goes.
type Crawl struct {
	MaxPages int `toml:"max_pages"`
	// Delay is the pause before each further request, to this and to other sites.
	Delay Duration `toml:"delay"`
	// MaxDelay caps a Crawl-delay asked for by robots.txt.
	MaxDelay Duration `toml:"max_delay"`
}

// Friends limits --friends.
type Friends struct {
	Max int `toml:"max"`
}

// Related limits --related and --related-tlds.
type Related struct {
	Max  int      `toml:"max"`
	TLDs []string `toml:"tlds"`
}

// Active limits --active.
type Active struct {
	Max          int `toml:"max"`
	MaxBodyBytes int `toml:"max_body_bytes"`
}

// Browser limits --browser.
type Browser struct {
	Timeout     Duration `toml:"timeout"`
	Settle      Duration `toml:"settle"`
	MaxRequests int      `toml:"max_requests"`
	// ChromePath is the Chrome or Chromium executable; empty looks in the usual places.
	ChromePath string `toml:"chrome_path"`
}

// Result limits what a result lists.
type Result struct {
	MaxEvidence int `toml:"max_evidence"`
}

// Output says what is left out of what owfscan writes.
type Output struct {
	// DropHeaders are response headers left out of the output because they change on
	// every call. The rules still see them. A trailing * makes a prefix.
	DropHeaders []string `toml:"drop_headers"`
}

// Bot limits `owfscan bot`, the crawler. Nothing here can turn on contacts or --active:
// the crawler reads the home page only (depth 0 or 1), and never sends a probe.
type Bot struct {
	// DB is the SQLite file of the crawl.
	DB      string `toml:"db"`
	Workers int    `toml:"workers"`
	// Rate is the most requests per second, over all hosts.
	Rate float64 `toml:"rate"`
	// PerHostDelay is the pause between two requests to the same host (a larger
	// Crawl-delay in robots.txt wins, up to crawl.max_delay).
	PerHostDelay Duration `toml:"per_host_delay"`
	// Budget is the most domains scanned in one run; 0 means no limit.
	Budget int `toml:"budget"`
	// Until stops a run after this long; 0 means no limit.
	Until Duration `toml:"until"`
	// Depth is how many pages of a site are read: 0 the home page, 1 also its links.
	Depth int `toml:"depth"`
	// MaxNewPerSite is the most new domains one site may add to the frontier.
	MaxNewPerSite int `toml:"max_new_per_site"`
	// MaxDepth is the most hops from a seed: a domain found at this depth is scanned
	// but the domains it links are not added.
	MaxDepth int `toml:"max_depth"`
	// LeaseTTL is how long a worker keeps a domain before another may take it.
	LeaseTTL Duration `toml:"lease_ttl"`
	// Revisit is the base time between two visits of a domain; RevisitMax is the longest,
	// for a domain whose result does not change.
	Revisit    Duration `toml:"revisit"`
	RevisitMax Duration `toml:"revisit_max"`
	// DNSFailures blocks a domain for good after this many "no such host" in a row; 0 never.
	DNSFailures int       `toml:"dns_failures"`
	Filter      BotFilter `toml:"filter"`
}

// Filter modes, categories and list formats.
const (
	FilterMark = "mark" // a blocked domain is kept, marked blocked, and never scanned
)

// FilterCategories are the categories a list may be given.
var FilterCategories = []string{"adult", "gambling", "malware", "phishing", "ads", "tracking", "other"}

// FilterFormats are the list formats the parsers read.
var FilterFormats = []string{"hosts", "domains", "adblock"}

// BotFilter says which domains the crawler refuses to scan. The lists are files the
// user chooses (none is shipped: their licences differ).
type BotFilter struct {
	Mode string `toml:"mode"`
	// Dir is where the downloaded lists are kept (one file and one .json note per list).
	Dir               string   `toml:"dir"`
	ExcludeCategories []string `toml:"exclude_categories"`
	RefreshEvery      Duration `toml:"refresh_every"`
	// Require makes `bot run` refuse to start with no enabled list; --no-filter is the
	// explicit way round it.
	Require bool         `toml:"require"`
	Lists   []FilterList `toml:"list"`
}

// FilterList is one block list.
type FilterList struct {
	Name     string `toml:"name"`
	URL      string `toml:"url"`
	Category string `toml:"category"`
	Format   string `toml:"format"`
	Enabled  bool   `toml:"enabled"`
}

// DefaultDropHeaders are the headers that differ between two calls to the same site
// made seconds apart, or identify the caller. date, age, set-cookie, via, server-timing,
// x-amz-cf-id, x-azure-ref, x-cache, x-nf-request-id, x-request-id and x-client-ip were
// seen changing or personal on mr70.eu, pirelli.com, michelin.com and wikipedia.com;
// the rest are the usual members of the same families (request ids, cache state, caller
// addresses, validators) and are listed in advance.
var DefaultDropHeaders = []string{
	"date", "age", "expires", "last-modified", "etag", "content-length",
	"set-cookie", "via", "server-timing", "report-to", "nel",
	"x-request-id", "x-correlation-id", "x-trace-id", "x-amzn-requestid", "x-amzn-trace-id",
	"x-amz-cf-id", "x-amz-cf-pop", "x-azure-ref", "x-nf-request-id", "x-vercel-id",
	"x-github-request-id", "x-served-by", "x-timer", "x-cache", "x-cache-hits", "x-cache-status",
	"cache-status", "cf-ray", "cf-cache-status", "x-client-ip", "x-forwarded-for", "x-real-ip",
	"x-runtime", "x-envoy-upstream-service-time", "x-envoy-*", "x-edge-*",
}

// Default returns the built-in configuration. Its values are the constants of the
// packages that use them, so there is one source for each.
func Default() Config {
	return Config{
		Fetch: Fetch{
			Timeout: Duration(fetch.DefaultTimeout), MaxBodyBytes: fetch.DefaultMaxBody,
			MaxRedirects: fetch.DefaultMaxRedirects, MaxAge: Duration(fetch.DefaultMaxAge),
		},
		Crawl:   Crawl{MaxPages: scanner.DefaultMaxPages, Delay: Duration(scanner.DefaultDelay), MaxDelay: Duration(scanner.MaxDelay)},
		Friends: Friends{Max: scanner.DefaultMaxFriends},
		Related: Related{Max: scanner.DefaultMaxRelated, TLDs: append([]string(nil), scanner.DefaultRelatedTLDs...)},
		Active:  Active{Max: scanner.DefaultActiveMax, MaxBodyBytes: scanner.DefaultMaxProbeBody},
		Browser: Browser{Timeout: Duration(browser.DefaultTimeout), Settle: Duration(browser.DefaultSettle), MaxRequests: browser.DefaultMaxRequests},
		Result:  Result{MaxEvidence: 50},
		Output:  Output{DropHeaders: append([]string(nil), DefaultDropHeaders...)},
		Bot: Bot{
			DB: "bot.db", Workers: 4, Rate: 2, PerHostDelay: Duration(10 * time.Second),
			Depth: 0, MaxNewPerSite: 50, MaxDepth: 3, LeaseTTL: Duration(10 * time.Minute),
			Revisit: Duration(30 * 24 * time.Hour), RevisitMax: Duration(180 * 24 * time.Hour), DNSFailures: 3,
			Filter: BotFilter{
				Mode: FilterMark, Dir: "filters", ExcludeCategories: []string{"adult", "gambling", "malware", "phishing"},
				RefreshEvery: Duration(7 * 24 * time.Hour), Require: true,
			},
		},
	}
}

// Ceilings: the largest value the file may ask for. They are generous; they exist to
// catch typos, not to decide for the user.
const (
	maxTimeout      = 10 * time.Minute
	maxBodyBytes    = 100 << 20
	maxRedirects    = 30
	maxMaxAge       = 30 * 24 * time.Hour
	maxPages        = 200
	maxPause        = time.Minute
	minDelay        = 100 * time.Millisecond
	maxContacts     = 200
	maxTLDs         = 50
	maxBrowserReqs  = 2000
	maxSettle       = time.Minute
	maxEvidenceList = 1000
	maxDropHeaders  = 200

	maxBotWorkers     = 64
	maxBotRate        = 50.0
	maxBotBudget      = 10_000_000
	maxBotUntil       = 30 * 24 * time.Hour
	maxBotNew         = 1000
	maxBotDepth       = 20
	maxBotDNSFailures = 20
	minLease          = 30 * time.Second
	maxLease          = time.Hour
	minRevisit        = 24 * time.Hour
	maxRevisit        = 3 * 365 * 24 * time.Hour
	maxFilterLists    = 50
	maxFilterEvery    = 365 * 24 * time.Hour
	minFilterEvery    = time.Hour
	maxFilterNameLn   = 40
)

// Validate checks every value against its range and returns all the problems.
func (c Config) Validate() error {
	var errs []error
	bad := func(key, format string, a ...any) {
		errs = append(errs, fmt.Errorf("%s: %s", key, fmt.Sprintf(format, a...)))
	}
	dur := func(key string, d Duration, lo, hi time.Duration) {
		if d.D() < lo || d.D() > hi {
			bad(key, "%s is out of range (%s to %s)", d.D(), lo, hi)
		}
	}
	num := func(key string, v, lo, hi int64) {
		if v < lo || v > hi {
			bad(key, "%d is out of range (%d to %d)", v, lo, hi)
		}
	}
	dur("fetch.timeout", c.Fetch.Timeout, time.Second, maxTimeout)
	num("fetch.max_body_bytes", c.Fetch.MaxBodyBytes, 1<<10, maxBodyBytes)
	num("fetch.max_redirects", int64(c.Fetch.MaxRedirects), 0, maxRedirects)
	dur("fetch.max_age", c.Fetch.MaxAge, 0, maxMaxAge)
	num("crawl.max_pages", int64(c.Crawl.MaxPages), 1, maxPages)
	dur("crawl.delay", c.Crawl.Delay, minDelay, maxPause)
	dur("crawl.max_delay", c.Crawl.MaxDelay, minDelay, maxPause)
	if c.Crawl.MaxDelay.D() < c.Crawl.Delay.D() {
		bad("crawl.max_delay", "must not be smaller than crawl.delay")
	}
	num("friends.max", int64(c.Friends.Max), 1, maxContacts)
	num("related.max", int64(c.Related.Max), 1, maxContacts)
	num("active.max", int64(c.Active.Max), 1, maxContacts)
	num("active.max_body_bytes", int64(c.Active.MaxBodyBytes), 1<<10, maxBodyBytes)
	dur("browser.timeout", c.Browser.Timeout, time.Second, maxTimeout)
	dur("browser.settle", c.Browser.Settle, 0, maxSettle)
	num("browser.max_requests", int64(c.Browser.MaxRequests), 1, maxBrowserReqs)
	num("result.max_evidence", int64(c.Result.MaxEvidence), 1, maxEvidenceList)
	if len(c.Related.TLDs) > maxTLDs {
		bad("related.tlds", "%d entries, at most %d", len(c.Related.TLDs), maxTLDs)
	}
	for _, t := range c.Related.TLDs {
		if !validTLD(t) {
			bad("related.tlds", "%q is not a suffix like \"com\" or \"co.uk\" (lower case, no dot at the ends)", t)
		}
	}
	if len(c.Output.DropHeaders) > maxDropHeaders {
		bad("output.drop_headers", "%d entries, at most %d", len(c.Output.DropHeaders), maxDropHeaders)
	}
	for _, h := range c.Output.DropHeaders {
		if !validHeaderPattern(h) {
			bad("output.drop_headers", "%q is not a lower-case header name, or a prefix ending in *", h)
		}
	}
	if strings.ContainsAny(c.Fetch.UserAgent, "\r\n") {
		bad("fetch.user_agent", "must be a single line")
	}
	errs = append(errs, c.Bot.validate()...)
	return errors.Join(errs...)
}

func (b Bot) validate() []error {
	var errs []error
	bad := func(key, format string, a ...any) {
		errs = append(errs, fmt.Errorf("bot.%s: %s", key, fmt.Sprintf(format, a...)))
	}
	num := func(key string, v, lo, hi int64) {
		if v < lo || v > hi {
			bad(key, "%d is out of range (%d to %d)", v, lo, hi)
		}
	}
	dur := func(key string, d Duration, lo, hi time.Duration) {
		if d.D() < lo || d.D() > hi {
			bad(key, "%s is out of range (%s to %s)", d.D(), lo, hi)
		}
	}
	if strings.TrimSpace(b.DB) == "" || strings.ContainsAny(b.DB, "\r\n\x00") {
		bad("db", "must be a file name")
	}
	num("workers", int64(b.Workers), 1, maxBotWorkers)
	if b.Rate <= 0 || b.Rate > maxBotRate || b.Rate != b.Rate {
		bad("rate", "%v is out of range (above 0 to %v requests per second)", b.Rate, maxBotRate)
	}
	dur("per_host_delay", b.PerHostDelay, time.Second, maxPause)
	num("budget", int64(b.Budget), 0, maxBotBudget)
	dur("until", b.Until, 0, maxBotUntil)
	num("depth", int64(b.Depth), 0, 1)
	num("max_new_per_site", int64(b.MaxNewPerSite), 0, maxBotNew)
	num("max_depth", int64(b.MaxDepth), 0, maxBotDepth)
	dur("lease_ttl", b.LeaseTTL, minLease, maxLease)
	dur("revisit", b.Revisit, minRevisit, maxRevisit)
	dur("revisit_max", b.RevisitMax, minRevisit, maxRevisit)
	if b.RevisitMax.D() < b.Revisit.D() {
		bad("revisit_max", "must not be smaller than bot.revisit")
	}
	num("dns_failures", int64(b.DNSFailures), 0, maxBotDNSFailures)
	f := b.Filter
	if f.Mode != FilterMark {
		bad("filter.mode", "%q is not one of: %s", f.Mode, FilterMark)
	}
	if strings.TrimSpace(f.Dir) == "" || strings.ContainsAny(f.Dir, "\r\n\x00") {
		bad("filter.dir", "must be a directory name")
	}
	dur("filter.refresh_every", f.RefreshEvery, minFilterEvery, maxFilterEvery)
	for _, c := range f.ExcludeCategories {
		if !slices.Contains(FilterCategories, c) {
			bad("filter.exclude_categories", "%q is not one of: %s", c, strings.Join(FilterCategories, ", "))
		}
	}
	if len(f.Lists) > maxFilterLists {
		bad("filter.list", "%d lists, at most %d", len(f.Lists), maxFilterLists)
	}
	seen := map[string]bool{}
	for i, l := range f.Lists {
		key := fmt.Sprintf("filter.list[%d]", i)
		if !validListName(l.Name) {
			bad(key+".name", "%q must be lower case letters, digits and '-', up to %d characters", l.Name, maxFilterNameLn)
		} else if seen[l.Name] {
			bad(key+".name", "%q is used twice", l.Name)
		}
		seen[l.Name] = true
		if u, err := url.Parse(l.URL); err != nil || u.Scheme != "https" || u.Host == "" {
			bad(key+".url", "%q must be an https address", l.URL)
		}
		if !slices.Contains(FilterCategories, l.Category) {
			bad(key+".category", "%q is not one of: %s", l.Category, strings.Join(FilterCategories, ", "))
		}
		if !slices.Contains(FilterFormats, l.Format) {
			bad(key+".format", "%q is not one of: %s", l.Format, strings.Join(FilterFormats, ", "))
		}
	}
	return errs
}

func validListName(n string) bool {
	if n == "" || len(n) > maxFilterNameLn {
		return false
	}
	for _, r := range n {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
			return false
		}
	}
	return true
}

// EnabledLists returns the block lists that are switched on.
func (f BotFilter) EnabledLists() []FilterList {
	var out []FilterList
	for _, l := range f.Lists {
		if l.Enabled {
			out = append(out, l)
		}
	}
	return out
}

func validHeaderPattern(h string) bool {
	name := strings.TrimSuffix(h, "*")
	if name == "" || len(name) > 100 {
		return false
	}
	for _, r := range name {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' && r != '_' {
			return false
		}
	}
	return true
}

func validTLD(t string) bool {
	if t == "" || len(t) > 63 || strings.HasPrefix(t, ".") || strings.HasSuffix(t, ".") || strings.Contains(t, "..") {
		return false
	}
	for _, r := range t {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '.' && r != '-' {
			return false
		}
	}
	return true
}

// Parse reads a configuration from TOML. Values the file does not set keep their
// defaults; a key that does not exist is an error (it is probably a typo).
func Parse(r io.Reader) (Config, error) {
	c := Default()
	b, err := io.ReadAll(r)
	if err != nil {
		return Config{}, err
	}
	d := toml.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil {
		var se *toml.StrictMissingError
		if errors.As(err, &se) {
			return Config{}, fmt.Errorf("config: unknown key(s):\n%s", se.String())
		}
		var de *toml.DecodeError
		if errors.As(err, &de) {
			return Config{}, fmt.Errorf("config: %s", de.String())
		}
		return Config{}, fmt.Errorf("config: %w", err)
	}
	if err := c.Validate(); err != nil {
		return Config{}, fmt.Errorf("config: %w", err)
	}
	return c, nil
}

// Load reads the file at path.
func Load(path string) (Config, error) {
	f, err := os.Open(path) //nolint:gosec // the user names the file
	if err != nil {
		return Config{}, fmt.Errorf("config: %w", err)
	}
	defer func() { _ = f.Close() }()
	c, err := Parse(f)
	if err != nil {
		return Config{}, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

// Dir is the directory of the configuration: $XDG_CONFIG_HOME/owf when that is set,
// else $HOME/.config/owf (also on macOS).
func Dir() (string, error) {
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, "owf"), nil
	}
	h, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("config: no home directory: %w", err)
	}
	return filepath.Join(h, ".config", "owf"), nil
}

// DefaultPath is where the file is looked for when no path is given.
func DefaultPath() (string, error) {
	d, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, FileName), nil
}

// Resolve finds the configuration to use: an explicit path (an error if it cannot be
// read), else the default path if the file exists, else the built-in defaults. It
// returns the path used, or "" for the defaults.
func Resolve(explicit string) (Config, string, error) {
	if explicit != "" {
		c, err := Load(explicit)
		return c, explicit, err
	}
	p, err := DefaultPath()
	if err != nil {
		return Default(), "", nil //nolint:nilerr // no home directory: the defaults apply
	}
	if _, err := os.Stat(p); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Default(), "", nil
		}
		return Config{}, "", fmt.Errorf("config: %w", err)
	}
	c, err := Load(p)
	return c, p, err
}

// Apply copies the limits into scanner options. Switches and per-run choices
// (depth, browser, friends, related.tlds, ...) are not touched: the TLD list is the
// default of --related-tlds, and giving that flag is what turns the variants on.
func (c Config) Apply(o *client.Options) {
	o.Timeout = c.Fetch.Timeout.D()
	o.MaxBody = c.Fetch.MaxBodyBytes
	o.MaxRedirects = c.Fetch.MaxRedirects
	o.MaxAge = c.Fetch.MaxAge.D()
	if c.Fetch.CacheDir != "" {
		o.CacheDir = c.Fetch.CacheDir
	}
	if c.Fetch.UserAgent != "" {
		o.UserAgent = c.Fetch.UserAgent
	}
	o.MaxPages, o.Delay, o.MaxDelay = c.Crawl.MaxPages, c.Crawl.Delay.D(), c.Crawl.MaxDelay.D()
	o.FriendsMax, o.RelatedMax = c.Friends.Max, c.Related.Max
	o.ActiveMax, o.ActiveMaxBody = c.Active.Max, c.Active.MaxBodyBytes
	o.BrowserTimeout, o.BrowserSettle, o.BrowserMaxRequests = c.Browser.Timeout.D(), c.Browser.Settle.D(), c.Browser.MaxRequests
	if c.Browser.ChromePath != "" {
		o.BrowserPath = c.Browser.ChromePath
	}
	o.MaxEvidence = c.Result.MaxEvidence
	o.DropHeaders = append([]string(nil), c.Output.DropHeaders...)
}
