// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

// Package fetch downloads pinned snapshots of upstream sources with the git
// command line. It fetches a single commit of a single branch, optionally
// limited to some directories, and never stores credentials.
package fetch

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	shaRE    = regexp.MustCompile(`^[0-9a-f]{40}$`)
	branchRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]*$`)
)

// Git runs the git binary.
type Git struct {
	// Bin is the git executable. Empty means "git".
	Bin string
	// AllowLocal permits file:// URLs. It exists for tests.
	AllowLocal bool
}

// New returns a Git that only accepts https URLs.
func New() *Git { return &Git{} }

// ValidSHA reports whether s is a full 40-character commit ID.
func ValidSHA(s string) bool { return shaRE.MatchString(s) }

func (g *Git) bin() string {
	if g.Bin != "" {
		return g.Bin
	}
	return "git"
}

// checkURL accepts https URLs without embedded credentials. Secrets must not
// end up in URLs, logs or the cache.
func (g *Git) checkURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" && u.Scheme != "file" {
		return fmt.Errorf("fetch: invalid URL %q", raw)
	}
	if u.User != nil {
		return errors.New("fetch: URLs with credentials are not allowed")
	}
	switch u.Scheme {
	case "https":
		return nil
	case "file":
		if g.AllowLocal {
			return nil
		}
	}
	return fmt.Errorf("fetch: URL scheme %q is not allowed", u.Scheme)
}

// run executes git and returns stdout. stderr is included in errors.
func (g *Git) run(ctx context.Context, dir string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, g.bin(), args...) //nolint:gosec // fixed binary, validated arguments
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_TERMINAL_PROMPT=0", // never ask for credentials
		"GIT_CONFIG_NOSYSTEM=1",
	)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return "", ctxErr
		}
		msg := strings.TrimSpace(errb.String())
		if len(msg) > 1024 {
			msg = msg[:1024] + "..."
		}
		return "", fmt.Errorf("git %s: %w: %s", args[0], err, msg)
	}
	return out.String(), nil
}

// ResolveBranch returns the commit a branch points to, without downloading
// anything.
func (g *Git) ResolveBranch(ctx context.Context, repoURL, branch string) (string, error) {
	if err := g.checkURL(repoURL); err != nil {
		return "", err
	}
	if !branchRE.MatchString(branch) || strings.Contains(branch, "..") {
		return "", fmt.Errorf("fetch: invalid branch name %q", branch)
	}
	out, err := g.run(ctx, "", "ls-remote", "--exit-code", "--", repoURL, "refs/heads/"+branch)
	if err != nil {
		return "", fmt.Errorf("fetch: resolve branch %s: %w", branch, err)
	}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && f[1] == "refs/heads/"+branch && ValidSHA(f[0]) {
			return f[0], nil
		}
	}
	return "", fmt.Errorf("fetch: branch %s not found", branch)
}

// Request describes one snapshot to fetch.
type Request struct {
	URL string
	SHA string // full commit ID
	// Root is the cache directory; Dest must be inside it.
	Root string
	Dest string
	// Sparse lists directories to check out (cone mode). Empty means all.
	Sparse []string
}

// Result describes a fetched snapshot.
type Result struct {
	Path   string
	SHA    string
	Reused bool // the cached copy was already at SHA and clean
}

// Fetch makes Dest contain exactly commit SHA of the repository. A cached,
// unmodified copy is reused without network access.
func (g *Git) Fetch(ctx context.Context, req Request) (*Result, error) {
	if err := g.checkURL(req.URL); err != nil {
		return nil, err
	}
	if !ValidSHA(req.SHA) {
		return nil, fmt.Errorf("fetch: %q is not a full 40-character commit ID", req.SHA)
	}
	rel, err := filepath.Rel(req.Root, req.Dest)
	if err != nil || rel == "." || strings.HasPrefix(rel, "..") {
		return nil, fmt.Errorf("fetch: destination %q is outside the cache %q", req.Dest, req.Root)
	}
	for _, s := range req.Sparse {
		if s == "" || strings.HasPrefix(s, "-") || strings.Contains(s, "..") || filepath.IsAbs(s) {
			return nil, fmt.Errorf("fetch: invalid sparse path %q", s)
		}
	}
	if g.cached(ctx, req.Dest, req.SHA) {
		return &Result{Path: req.Dest, SHA: req.SHA, Reused: true}, nil
	}
	if err := os.MkdirAll(filepath.Dir(req.Dest), 0o755); err != nil { //nolint:gosec // cache directory
		return nil, fmt.Errorf("fetch: create cache: %w", err)
	}
	var rnd [4]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return nil, err
	}
	tmp := req.Dest + ".tmp-" + hex.EncodeToString(rnd[:])
	defer func() { _ = os.RemoveAll(tmp) }()
	if err := os.Mkdir(tmp, 0o755); err != nil { //nolint:gosec // cache directory
		return nil, fmt.Errorf("fetch: create %s: %w", tmp, err)
	}
	quiet := []string{"-c", "gc.auto=0", "-c", "core.hooksPath=" + os.DevNull, "-c", "advice.detachedHead=false"}
	git := func(args ...string) (string, error) {
		return g.run(ctx, tmp, append(append([]string{}, quiet...), args...)...)
	}
	if _, err := git("init", "-q"); err != nil {
		return nil, err
	}
	if _, err := git("remote", "add", "origin", req.URL); err != nil {
		return nil, err
	}
	if len(req.Sparse) > 0 {
		if _, err := git(append([]string{"sparse-checkout", "set", "--cone"}, req.Sparse...)...); err != nil {
			return nil, err
		}
	}
	// Blobs are fetched lazily for the checked out paths only. Some servers
	// do not support filters, so retry in full.
	if _, err := git("fetch", "-q", "--depth", "1", "--filter=blob:none", "origin", req.SHA); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if _, err2 := git("fetch", "-q", "--depth", "1", "origin", req.SHA); err2 != nil {
			return nil, fmt.Errorf("fetch: %w", err2)
		}
	}
	if _, err := git("checkout", "-q", "--detach", "FETCH_HEAD"); err != nil {
		return nil, err
	}
	head, err := git("rev-parse", "HEAD")
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(head) != req.SHA {
		return nil, fmt.Errorf("fetch: got commit %s, wanted %s", strings.TrimSpace(head), req.SHA)
	}
	if err := os.RemoveAll(req.Dest); err != nil {
		return nil, fmt.Errorf("fetch: replace %s: %w", req.Dest, err)
	}
	if err := os.Rename(tmp, req.Dest); err != nil {
		return nil, fmt.Errorf("fetch: install snapshot: %w", err)
	}
	return &Result{Path: req.Dest, SHA: req.SHA}, nil
}

// cached reports whether dir is a clean checkout of sha.
func (g *Git) cached(ctx context.Context, dir, sha string) bool {
	if st, err := os.Stat(filepath.Join(dir, ".git")); err != nil || !st.IsDir() {
		return false
	}
	head, err := g.run(ctx, dir, "rev-parse", "HEAD")
	if err != nil || strings.TrimSpace(head) != sha {
		return false
	}
	status, err := g.run(ctx, dir, "status", "--porcelain", "--untracked-files=all")
	return err == nil && strings.TrimSpace(status) == ""
}
