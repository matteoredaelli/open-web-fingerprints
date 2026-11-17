// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package fetch

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func needGit(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
}

// upstream builds a small local repository with two commits on branch main.
type upstream struct {
	dir        string
	first, tip string
}

func gitIn(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{
		"-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false",
	}, args...)...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL="+os.DevNull, "GIT_CONFIG_NOSYSTEM=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func write(t *testing.T, dir, rel, content string) {
	t.Helper()
	p := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func newUpstream(t *testing.T) *upstream {
	t.Helper()
	needGit(t)
	dir := t.TempDir()
	gitIn(t, dir, "init", "-q", "-b", "main")
	gitIn(t, dir, "config", "uploadpack.allowFilter", "true")
	gitIn(t, dir, "config", "uploadpack.allowAnySHA1InWant", "true")
	write(t, dir, "src/categories.json", `{"1":{"name":"CMS"}}`)
	write(t, dir, "src/technologies/a.json", `{"A":{}}`)
	write(t, dir, "images/logo.svg", "<svg/>")
	write(t, dir, "README.md", "v1")
	gitIn(t, dir, "add", "-A")
	gitIn(t, dir, "commit", "-q", "-m", "first")
	u := &upstream{dir: dir, first: gitIn(t, dir, "rev-parse", "HEAD")}
	write(t, dir, "src/technologies/a.json", `{"A":{},"B":{}}`)
	gitIn(t, dir, "add", "-A")
	gitIn(t, dir, "commit", "-q", "-m", "second")
	u.tip = gitIn(t, dir, "rev-parse", "HEAD")
	return u
}

func (u *upstream) url() string { return "file://" + u.dir }

func local() *Git { return &Git{AllowLocal: true} }

func TestResolveBranch(t *testing.T) {
	u := newUpstream(t)
	got, err := local().ResolveBranch(context.Background(), u.url(), "main")
	if err != nil || got != u.tip {
		t.Fatalf("got %q err=%v, want %s", got, err, u.tip)
	}
	for _, branch := range []string{"nope", "-x", "a..b", "", "x y", "--upload-pack=evil"} {
		if _, err := local().ResolveBranch(context.Background(), u.url(), branch); err == nil {
			t.Errorf("branch %q must fail", branch)
		}
	}
}

func TestFetchPinsOneCommitAndOnlyTheSparsePaths(t *testing.T) {
	u := newUpstream(t)
	root := t.TempDir()
	dest := filepath.Join(root, "src", u.first)
	res, err := local().Fetch(context.Background(), Request{
		URL: u.url(), SHA: u.first, Root: root, Dest: dest, Sparse: []string{"src"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Reused || res.SHA != u.first {
		t.Errorf("result: %+v", res)
	}
	// The pinned (older) commit is what is checked out, not the branch tip.
	b, _ := os.ReadFile(filepath.Join(dest, "src/technologies/a.json"))
	if strings.Contains(string(b), `"B"`) {
		t.Errorf("got content of the newer commit: %s", b)
	}
	if _, err := os.Stat(filepath.Join(dest, "images/logo.svg")); err == nil {
		t.Error("sparse checkout must leave images/ out")
	}
	if _, err := os.Stat(filepath.Join(dest, "README.md")); err != nil {
		t.Error("root files are part of a cone checkout")
	}
	if n := gitIn(t, dest, "rev-list", "--count", "HEAD"); n != "1" {
		t.Errorf("history must be shallow, got %s commits", n)
	}
	if head := gitIn(t, dest, "rev-parse", "HEAD"); head != u.first {
		t.Errorf("HEAD = %s", head)
	}
	// No leftovers in the cache.
	entries, _ := os.ReadDir(filepath.Dir(dest))
	if len(entries) != 1 {
		t.Errorf("cache entries: %v", entries)
	}
}

func TestFetchFullWithoutSparse(t *testing.T) {
	u := newUpstream(t)
	root := t.TempDir()
	dest := filepath.Join(root, "x", u.tip)
	if _, err := local().Fetch(context.Background(), Request{URL: u.url(), SHA: u.tip, Root: root, Dest: dest}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dest, "images/logo.svg")); err != nil {
		t.Error("without sparse paths everything is checked out")
	}
}

func TestFetchReusesCleanCacheWithoutNetwork(t *testing.T) {
	u := newUpstream(t)
	root := t.TempDir()
	dest := filepath.Join(root, "s", u.tip)
	req := Request{URL: u.url(), SHA: u.tip, Root: root, Dest: dest, Sparse: []string{"src"}}
	if _, err := local().Fetch(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	// The remote disappears: a clean cache must still work.
	if err := os.RemoveAll(u.dir); err != nil {
		t.Fatal(err)
	}
	res, err := local().Fetch(context.Background(), req)
	if err != nil || !res.Reused {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestFetchRepairsModifiedCache(t *testing.T) {
	u := newUpstream(t)
	root := t.TempDir()
	dest := filepath.Join(root, "s", u.tip)
	req := Request{URL: u.url(), SHA: u.tip, Root: root, Dest: dest, Sparse: []string{"src"}}
	if _, err := local().Fetch(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	write(t, dest, "src/technologies/a.json", "tampered")
	write(t, dest, "src/extra.json", "untracked")
	res, err := local().Fetch(context.Background(), req)
	if err != nil || res.Reused {
		t.Fatalf("a modified cache must be fetched again: res=%+v err=%v", res, err)
	}
	b, _ := os.ReadFile(filepath.Join(dest, "src/technologies/a.json"))
	if strings.Contains(string(b), "tampered") {
		t.Error("tampered file survived")
	}
	if _, err := os.Stat(filepath.Join(dest, "src/extra.json")); err == nil {
		t.Error("untracked file survived")
	}
}

func TestFetchValidation(t *testing.T) {
	u := newUpstream(t)
	root := t.TempDir()
	ctx := context.Background()
	ok := Request{URL: u.url(), SHA: u.tip, Root: root, Dest: filepath.Join(root, "s", u.tip)}
	cases := map[string]func(*Request){
		"short sha":        func(r *Request) { r.SHA = u.tip[:7] },
		"upper sha":        func(r *Request) { r.SHA = strings.ToUpper(u.tip) },
		"option as sha":    func(r *Request) { r.SHA = "--upload-pack=evil" },
		"dest is root":     func(r *Request) { r.Dest = root },
		"dest outside":     func(r *Request) { r.Dest = filepath.Join(root, "..", "elsewhere") },
		"sparse traversal": func(r *Request) { r.Sparse = []string{"../x"} },
		"sparse option":    func(r *Request) { r.Sparse = []string{"--x"} },
		"sparse absolute":  func(r *Request) { r.Sparse = []string{"/etc"} },
		"credentials":      func(r *Request) { r.URL = "https://user:secret@example.com/r.git" },
		"ssh":              func(r *Request) { r.URL = "ssh://git@example.com/r.git" },
		"http":             func(r *Request) { r.URL = "http://example.com/r.git" },
		"ext transport":    func(r *Request) { r.URL = "ext::sh -c evil" },
		"unknown commit":   func(r *Request) { r.SHA = strings.Repeat("0", 40) },
	}
	for name, mut := range cases {
		req := ok
		mut(&req)
		if _, err := local().Fetch(ctx, req); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	// file:// needs the explicit opt-in.
	if _, err := New().Fetch(ctx, ok); err == nil {
		t.Error("local URLs must be refused by default")
	}
	if _, err := os.Stat(filepath.Join(root, "s")); err == nil {
		entries, _ := os.ReadDir(filepath.Join(root, "s"))
		if len(entries) != 0 {
			t.Errorf("failed fetches left files behind: %v", entries)
		}
	}
}

func TestFetchHonoursCancellation(t *testing.T) {
	u := newUpstream(t)
	root := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := local().Fetch(ctx, Request{URL: u.url(), SHA: u.tip, Root: root, Dest: filepath.Join(root, "s", u.tip)})
	if err == nil {
		t.Fatal("cancelled context must fail")
	}
	if _, err := local().ResolveBranch(ctx, u.url(), "main"); err == nil {
		t.Fatal("cancelled context must fail")
	}
	// A deadline works the same way.
	ctx2, cancel2 := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel2()
	time.Sleep(time.Millisecond)
	if _, err := local().ResolveBranch(ctx2, u.url(), "main"); err == nil {
		t.Fatal("expired context must fail")
	}
}

func TestValidSHA(t *testing.T) {
	if !ValidSHA(strings.Repeat("a", 40)) || ValidSHA(strings.Repeat("a", 39)) || ValidSHA(strings.Repeat("g", 40)) {
		t.Fatal("ValidSHA is wrong")
	}
}
