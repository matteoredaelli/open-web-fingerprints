// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/config"
)

// withConfig runs a test with a configuration in force, and puts the previous one back.
func withConfig(t *testing.T, c config.Config, path string, err error) {
	t.Helper()
	oc, op, oe := cfg, cfgPath, cfgErr
	cfg, cfgPath, cfgErr = c, path, err
	t.Cleanup(func() { cfg, cfgPath, cfgErr = oc, op, oe })
}

func TestConfigInitStdoutIsTheDefaults(t *testing.T) {
	out, err := run(t, "", "config", "init", "--stdout")
	if err != nil {
		t.Fatal(err)
	}
	var want bytes.Buffer
	if err := config.Write(&want, config.Default()); err != nil {
		t.Fatal(err)
	}
	if out != want.String() {
		t.Errorf("stdout differs from the written defaults:\n%s", out)
	}
	if _, err := config.Parse(strings.NewReader(out)); err != nil {
		t.Errorf("what init writes must parse: %v", err)
	}
	if !strings.Contains(out, "max_pages = 8") || !strings.Contains(out, `tlds = ["com", "org"`) {
		t.Errorf("missing defaults:\n%s", out)
	}
}

func TestConfigInitWritesTheDefaultLocationAndRefusesToOverwrite(t *testing.T) {
	home := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", "")
	// run() sets HOME itself, so write with -o and also check the default path logic.
	target := filepath.Join(home, "sub", "dir", "owfscan.toml")
	out, err := run(t, "", "config", "init", "-o", target)
	if err != nil || !strings.Contains(out, "wrote "+target) {
		t.Fatalf("%v\n%s", err, out)
	}
	st, err := os.Stat(target)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("file: %v %v", err, st)
	}
	if _, err := run(t, "", "config", "init", "-o", target); err == nil || !strings.Contains(err.Error(), "--force") {
		t.Errorf("an existing file must not be overwritten: %v", err)
	}
	if err := os.WriteFile(target, []byte("[friends]\nmax = 3\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := run(t, "", "config", "init", "-o", target, "--force"); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(target)
	if !strings.Contains(string(b), "max = 20") {
		t.Errorf("--force must rewrite the defaults:\n%s", b)
	}
}

func TestConfigDefaultsOfTheFlagsComeFromTheFile(t *testing.T) {
	c := config.Default()
	c.Friends.Max, c.Crawl.MaxPages, c.Browser.MaxRequests = 5, 3, 100
	withConfig(t, c, "/x/owfscan.toml", nil)
	out, err := run(t, "", "scan", "--help")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"--friends-max int", "(default 5)", "--max-pages int", "(default 3)"} {
		if !strings.Contains(out, want) {
			t.Errorf("help lacks %q:\n%s", want, out)
		}
	}
	show, err := run(t, "", "config", "show")
	if err != nil || !strings.Contains(show, "# read from /x/owfscan.toml") || !strings.Contains(show, "max_requests = 100") {
		t.Errorf("%v\n%s", err, show)
	}
	ceil, _ := run(t, "", "config", "show", "--ceilings")
	if !strings.Contains(ceil, "crawl.max_pages") || !strings.Contains(ceil, "200") {
		t.Errorf("ceilings:\n%s", ceil)
	}
}

func TestBrokenConfigStopsTheCommandsButNotConfig(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "owfscan.toml")
	if err := os.WriteFile(bad, []byte("[crawl]\nmax_page = 3\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, p, err := loadConfig([]string{"links", "--config", bad})
	if err == nil || !strings.Contains(err.Error(), "max_page") {
		t.Fatalf("a typo in a key must be reported: %v", err)
	}
	withConfig(t, c, p, err)
	if _, err := run(t, "", "links", "https://example.org"); err == nil || !strings.Contains(err.Error(), "max_page") {
		t.Errorf("a command must not run on a broken file: %v", err)
	}
	if out, err := run(t, "", "config", "path", "--config", bad); err != nil || !strings.Contains(out, bad) {
		t.Errorf("config path must still work: %v %q", err, out)
	}
	if _, err := run(t, "", "config", "init", "--stdout"); err != nil {
		t.Errorf("config init must still work: %v", err)
	}
}

func TestConfigArg(t *testing.T) {
	t.Setenv("OWFSCAN_CONFIG", "/env.toml")
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"scan", "--config", "/a.toml", "x"}, "/a.toml"},
		{[]string{"scan", "--config=/b.toml"}, "/b.toml"},
		{[]string{"scan", "x"}, "/env.toml"},
		{[]string{"scan", "--", "--config", "/c.toml"}, "/env.toml"},
	}
	for _, c := range cases {
		if got := configArg(c.args); got != c.want {
			t.Errorf("%v: %q, want %q", c.args, got, c.want)
		}
	}
}

func TestTheFileCannotTurnOnSwitches(t *testing.T) {
	for _, key := range []string{"[scan]\nbrowser = true\n", "[browser]\nenabled = true\n", "[fetch]\nallow_private = true\n", "[crawl]\nignore_robots = true\n", "[friends]\nenabled = true\n"} {
		if _, err := config.Parse(strings.NewReader(key)); err == nil {
			t.Errorf("%q must be refused", key)
		}
	}
}
