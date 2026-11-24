// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/matteoredaelli/open-web-fingerprints/internal/builtin"
	"github.com/matteoredaelli/open-web-fingerprints/internal/fetch"
)

func gitCmd(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false"}, args...)...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL="+os.DevNull, "GIT_CONFIG_NOSYSTEM=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// localUpstream is a git repository holding the Enthec fixture, standing in
// for the real upstream.
func localUpstream(t *testing.T) (dir string, entries []builtin.Entry) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir = t.TempDir()
	gitCmd(t, dir, "init", "-q", "-b", "main")
	gitCmd(t, dir, "config", "uploadpack.allowFilter", "true")
	gitCmd(t, dir, "config", "uploadpack.allowAnySHA1InWant", "true")
	if out, err := exec.Command("cp", "-R", fixture+"/.", dir).CombinedOutput(); err != nil {
		t.Fatalf("copy fixture: %v\n%s", err, out)
	}
	if err := os.MkdirAll(filepath.Join(dir, "images"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "images", "big.svg"), []byte("<svg/>"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitCmd(t, dir, "add", "-A")
	gitCmd(t, dir, "commit", "-q", "-m", "first")

	entries = builtin.Sources()
	for i := range entries {
		if entries[i].Source.Slug == "enthec-webappanalyzer" {
			entries[i].Source.URL = "file://" + dir
		}
	}
	return dir, entries
}

func runWith(t *testing.T, o *options, db string, args ...string) (string, error) {
	t.Helper()
	cmd := newRootCmdWith(o)
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(append([]string{"--db", db}, args...))
	err := cmd.ExecuteContext(context.Background())
	return out.String(), err
}

func TestRefreshFetchesPinsAndImports(t *testing.T) {
	upstream, entries := localUpstream(t)
	o := &options{entries: entries, git: &fetch.Git{AllowLocal: true}}
	db := filepath.Join(t.TempDir(), "owf.db")
	cache := t.TempDir()
	must := func(args ...string) string {
		t.Helper()
		out, err := runWith(t, o, db, args...)
		if err != nil {
			t.Fatalf("owf %v: %v\n%s", args, err, out)
		}
		return out
	}
	must("init")
	first := gitCmd(t, upstream, "rev-parse", "HEAD")

	out := must("source", "refresh", "enthec-webappanalyzer", "--cache", cache, "--dry-run")
	if !strings.Contains(out, "branch main is at "+first) || !strings.Contains(out, "downloaded") ||
		!strings.Contains(out, "dry run") || !strings.Contains(out, "+22") {
		t.Errorf("dry run:\n%s", out)
	}
	if out := must("stats"); !strings.Contains(out, "technologies    0") {
		t.Errorf("dry run must not store: %s", out)
	}
	if _, err := os.Stat(filepath.Join(cache, "enthec-webappanalyzer", first, "images")); err == nil {
		t.Error("only the configured directories must be checked out")
	}

	out = must("source", "refresh", "enthec-webappanalyzer", "--cache", cache)
	if !strings.Contains(out, "reused from cache") || !strings.Contains(out, "applied") {
		t.Errorf("first import:\n%s", out)
	}
	out = must("source", "refresh", "enthec-webappanalyzer", "--cache", cache)
	if !strings.Contains(out, "no changes") {
		t.Errorf("same revision must change nothing:\n%s", out)
	}
	if out := must("source", "info", "enthec-webappanalyzer"); !strings.Contains(out, first[:7]) {
		t.Errorf("snapshot revision not recorded:\n%s", out)
	}

	// Upstream moves on: the new tip is imported as a reviewable diff.
	p := filepath.Join(upstream, "src", "technologies", "a.json")
	b, _ := os.ReadFile(p)
	if err := os.WriteFile(p, []byte(strings.Replace(string(b), "https://aframe.io", "https://aframe.example", 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	gitCmd(t, upstream, "add", "-A")
	gitCmd(t, upstream, "commit", "-q", "-m", "second")
	second := gitCmd(t, upstream, "rev-parse", "HEAD")

	out = must("source", "refresh", "enthec-webappanalyzer", "--cache", cache)
	if !strings.Contains(out, "branch main is at "+second) || !strings.Contains(out, "technologies   +0 ~1 -0") {
		t.Errorf("second refresh:\n%s", out)
	}
	// A pinned older revision is fetched too, without asking the branch.
	out = must("source", "refresh", "enthec-webappanalyzer", "--cache", cache, "--revision", first, "--dry-run")
	if strings.Contains(out, "branch main is at") || !strings.Contains(out, "@ "+first) {
		t.Errorf("pinned refresh:\n%s", out)
	}
	// Fetch only.
	out = must("source", "refresh", "enthec-webappanalyzer", "--cache", t.TempDir(), "--fetch-only")
	if !strings.Contains(out, "downloaded") || strings.Contains(out, "applied") {
		t.Errorf("fetch-only:\n%s", out)
	}
}

func TestRefreshErrors(t *testing.T) {
	_, entries := localUpstream(t)
	o := &options{entries: entries, git: &fetch.Git{AllowLocal: true}}
	db := filepath.Join(t.TempDir(), "owf.db")
	if _, err := runWith(t, o, db, "init"); err != nil {
		t.Fatal(err)
	}
	for name, args := range map[string][]string{
		"unknown source": {"source", "refresh", "nope"},
		"nothing given":  {"source", "refresh"},
		"both":           {"source", "refresh", "enthec-webappanalyzer", "--all"},
		"all + revision": {"source", "refresh", "--all", "--revision", "0123456789012345678901234567890123456789"},
		"short revision": {"source", "refresh", "enthec-webappanalyzer", "--revision", "abc123"},
		"unknown branch": {"source", "refresh", "enthec-webappanalyzer", "--branch", "nope", "--cache", t.TempDir()},
		"bad branch":     {"source", "refresh", "enthec-webappanalyzer", "--branch", "--evil", "--cache", t.TempDir()},
	} {
		if out, err := runWith(t, o, db, args...); err == nil {
			t.Errorf("%s: expected an error\n%s", name, out)
		}
	}
	// The real catalogue only allows https.
	if _, err := runWith(t, &options{entries: entries, git: fetch.New()}, db, "source", "refresh", "enthec-webappanalyzer", "--cache", t.TempDir()); err == nil {
		t.Error("file:// must be refused without the test opt-in")
	}
}

func TestRefreshAll(t *testing.T) {
	_, entries := localUpstream(t)
	o := &options{entries: entries, git: &fetch.Git{AllowLocal: true}}
	db := filepath.Join(t.TempDir(), "owf.db")
	if _, err := runWith(t, o, db, "init"); err != nil {
		t.Fatal(err)
	}
	out, err := runWith(t, o, db, "source", "refresh", "--all", "--cache", t.TempDir())
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !strings.Contains(out, "enthec-webappanalyzer") {
		t.Errorf("%s", out)
	}
}
