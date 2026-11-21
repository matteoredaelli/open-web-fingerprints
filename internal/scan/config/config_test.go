// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package config

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/scanner"
)

func TestDefaultsAreTheValuesOfToday(t *testing.T) {
	d := Default()
	if d.Fetch.Timeout.D() != 20*time.Second || d.Fetch.MaxBodyBytes != 5<<20 || d.Fetch.MaxRedirects != 10 || d.Fetch.MaxAge.D() != 24*time.Hour {
		t.Errorf("fetch: %+v", d.Fetch)
	}
	if d.Crawl.MaxPages != 8 || d.Crawl.Delay.D() != 500*time.Millisecond || d.Crawl.MaxDelay.D() != 10*time.Second {
		t.Errorf("crawl: %+v", d.Crawl)
	}
	if d.Friends.Max != 20 || d.Related.Max != 20 || d.Active.Max != 30 || d.Active.MaxBodyBytes != 1<<20 {
		t.Errorf("limits: %+v %+v %+v", d.Friends, d.Related, d.Active)
	}
	if d.Browser.Timeout.D() != 30*time.Second || d.Browser.Settle.D() != 2*time.Second || d.Browser.MaxRequests != 300 || d.Result.MaxEvidence != 50 {
		t.Errorf("browser/result: %+v %+v", d.Browser, d.Result)
	}
	want := []string{"com", "org", "net", "eu", "fr", "it", "de", "es", "co.uk", "nl"}
	if !reflect.DeepEqual(d.Related.TLDs, want) {
		t.Errorf("tlds: %v", d.Related.TLDs)
	}
	if err := d.Validate(); err != nil {
		t.Errorf("the defaults must be valid: %v", err)
	}
}

func TestWrittenDefaultsParseBackToTheSame(t *testing.T) {
	var b bytes.Buffer
	if err := Write(&b, Default()); err != nil {
		t.Fatal(err)
	}
	got, err := Parse(&b)
	if err != nil {
		t.Fatalf("%v\n%s", err, b.String())
	}
	if !reflect.DeepEqual(got, Default()) {
		t.Errorf("round trip differs:\n%+v\n%+v", got, Default())
	}
}

func TestPartialFileKeepsOtherDefaults(t *testing.T) {
	c, err := Parse(strings.NewReader("[crawl]\nmax_pages = 3\ndelay = \"2s\"\n[related]\ntlds = [\"ch\"]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Crawl.MaxPages != 3 || c.Crawl.Delay.D() != 2*time.Second || c.Crawl.MaxDelay.D() != 10*time.Second {
		t.Errorf("crawl: %+v", c.Crawl)
	}
	if !reflect.DeepEqual(c.Related.TLDs, []string{"ch"}) {
		t.Errorf("a list in the file replaces the default list: %v", c.Related.TLDs)
	}
	if c.Friends.Max != 20 {
		t.Errorf("untouched default: %d", c.Friends.Max)
	}
	empty, err := Parse(strings.NewReader(""))
	if err != nil || !reflect.DeepEqual(empty, Default()) {
		t.Errorf("an empty file is the defaults: %v", err)
	}
}

func TestMistakesAreRefused(t *testing.T) {
	cases := map[string]string{
		"unknown key":       "[crawl]\nmax_page = 3\n",
		"unknown section":   "[crawler]\nmax_pages = 3\n",
		"switch in file":    "[browser]\nenabled = true\n",
		"guard in file":     "[fetch]\nallow_private = true\n",
		"too many pages":    "[crawl]\nmax_pages = 10000000\n",
		"zero pages":        "[crawl]\nmax_pages = 0\n",
		"negative":          "[friends]\nmax = -1\n",
		"bad duration":      "[fetch]\ntimeout = \"soon\"\n",
		"duration number":   "[fetch]\ntimeout = 20\n",
		"delay too small":   "[crawl]\ndelay = \"1ms\"\n",
		"max_delay < delay": "[crawl]\ndelay = \"5s\"\nmax_delay = \"1s\"\n",
		"bad tld":           "[related]\ntlds = [\"COM\"]\n",
		"tld with dot":      "[related]\ntlds = [\".com\"]\n",
		"huge body":         "[fetch]\nmax_body_bytes = 99999999999\n",
		"newline in agent":  "[fetch]\nuser_agent = \"a\\nb\"\n",
		"not toml":          "max_pages 3",
	}
	for name, src := range cases {
		if _, err := Parse(strings.NewReader(src)); err == nil {
			t.Errorf("%s: should be refused", name)
		}
	}
}

func TestAllProblemsAreReportedTogether(t *testing.T) {
	_, err := Parse(strings.NewReader("[crawl]\nmax_pages = 0\n[friends]\nmax = 0\n"))
	if err == nil || !strings.Contains(err.Error(), "crawl.max_pages") || !strings.Contains(err.Error(), "friends.max") {
		t.Errorf("%v", err)
	}
}

func TestResolve(t *testing.T) {
	home := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", home)

	c, used, err := Resolve("")
	if err != nil || used != "" || !reflect.DeepEqual(c, Default()) {
		t.Fatalf("no file: %v %q", err, used)
	}
	p, _ := DefaultPath()
	if p != filepath.Join(home, ".config", "owf", FileName) {
		t.Errorf("default path %q", p)
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("[friends]\nmax = 5\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, used, err = Resolve("")
	if err != nil || used != p || c.Friends.Max != 5 {
		t.Fatalf("default file: %v %q %+v", err, used, c.Friends)
	}
	other := filepath.Join(t.TempDir(), "x.toml")
	if _, _, err := Resolve(other); err == nil {
		t.Error("an explicit file that does not exist is an error")
	}
	t.Setenv("XDG_CONFIG_HOME", "/xdg")
	if d, _ := Dir(); d != "/xdg/owf" {
		t.Errorf("xdg: %q", d)
	}
	if err := os.WriteFile(p, []byte("nonsense = 1"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_CONFIG_HOME", "")
	if _, _, err := Resolve(""); err == nil {
		t.Error("a broken default file must not be ignored silently")
	}
}

func TestApplyDoesNotTouchSwitches(t *testing.T) {
	c := Default()
	c.Crawl.MaxPages = 4
	c.Fetch.CacheDir = "/tmp/c"
	o := scanner.Options{Browser: false, Friends: false, Related: false, Active: false, Depth: 2}
	c.Apply(&o)
	if o.MaxPages != 4 || o.Fetch.CacheDir != "/tmp/c" || o.FriendsMax != 20 || o.ActiveMax != 30 || o.BrowserMaxRequests != 300 {
		t.Errorf("%+v", o)
	}
	if o.Browser || o.Friends || o.Related || o.Active || o.Fetch.AllowPrivate || o.Fetch.Insecure || o.IgnoreRobots || o.Depth != 2 || len(o.RelatedTLDs) != 0 {
		t.Errorf("the file must not change switches or guards: %+v", o)
	}
}
