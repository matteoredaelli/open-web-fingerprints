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
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"

	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/browser"
	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/fetch"
	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/scanner"
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
	if strings.ContainsAny(c.Fetch.UserAgent, "\r\n") {
		bad("fetch.user_agent", "must be a single line")
	}
	return errors.Join(errs...)
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
func (c Config) Apply(o *scanner.Options) {
	o.Fetch.Timeout = c.Fetch.Timeout.D()
	o.Fetch.MaxBody = c.Fetch.MaxBodyBytes
	o.Fetch.MaxRedirects = c.Fetch.MaxRedirects
	o.Fetch.MaxAge = c.Fetch.MaxAge.D()
	if c.Fetch.CacheDir != "" {
		o.Fetch.CacheDir = c.Fetch.CacheDir
	}
	if c.Fetch.UserAgent != "" {
		o.Fetch.UserAgent = c.Fetch.UserAgent
	}
	o.MaxPages, o.Delay, o.MaxDelay = c.Crawl.MaxPages, c.Crawl.Delay.D(), c.Crawl.MaxDelay.D()
	o.FriendsMax, o.RelatedMax = c.Friends.Max, c.Related.Max
	o.ActiveMax, o.ActiveMaxBody = c.Active.Max, c.Active.MaxBodyBytes
	o.BrowserTimeout, o.BrowserSettle, o.BrowserMaxRequests = c.Browser.Timeout.D(), c.Browser.Settle.D(), c.Browser.MaxRequests
	if c.Browser.ChromePath != "" {
		o.BrowserPath = c.Browser.ChromePath
	}
	o.MaxEvidence = c.Result.MaxEvidence
}
