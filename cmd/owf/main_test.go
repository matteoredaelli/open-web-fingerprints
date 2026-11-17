// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/matteoredaelli/open-web-fingerprints/internal/domain"
	"github.com/matteoredaelli/open-web-fingerprints/internal/repository"
	"github.com/matteoredaelli/open-web-fingerprints/internal/repository/sqlite"
	"github.com/matteoredaelli/open-web-fingerprints/schemas"
)

const fixture = "../../internal/extractor/enthec/testdata/snapshot"

// run executes the CLI in-process and returns stdout.
func run(t *testing.T, db string, args ...string) (string, error) {
	t.Helper()
	cmd := newRootCmd()
	var out, errb bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	cmd.SetArgs(append([]string{"--db", db}, args...))
	err := cmd.ExecuteContext(context.Background())
	return out.String(), err
}

func mustRun(t *testing.T, db string, args ...string) string {
	t.Helper()
	out, err := run(t, db, args...)
	if err != nil {
		t.Fatalf("owf %v: %v\n%s", args, err, out)
	}
	return out
}

func TestEndToEnd(t *testing.T) {
	nowFunc = func() time.Time { return time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC) }
	db := filepath.Join(t.TempDir(), "owf.db")

	if _, err := run(t, db, "stats"); err == nil || !strings.Contains(err.Error(), "owf init") {
		t.Fatalf("commands before init must point to `owf init`, got %v", err)
	}
	if out := mustRun(t, db, "init"); !strings.Contains(out, "ready") {
		t.Errorf("init: %s", out)
	}
	if out := mustRun(t, db, "init"); !strings.Contains(out, "ready") {
		t.Errorf("init must be repeatable: %s", out)
	}

	out := mustRun(t, db, "source", "list")
	if !strings.Contains(out, "enthec-webappanalyzer") || !strings.Contains(out, "unreviewed") {
		t.Errorf("source list: %s", out)
	}
	out = mustRun(t, db, "source", "info", "enthec-webappanalyzer")
	if !strings.Contains(out, "GPL-3.0") || !strings.Contains(out, "Capabilities") {
		t.Errorf("source info: %s", out)
	}

	imp := []string{"import", "enthec-webappanalyzer", "--snapshot", fixture, "--revision", "9e52f10"}
	out = mustRun(t, db, append(imp, "--dry-run")...)
	if !strings.Contains(out, "dry run") || !strings.Contains(out, "+22") {
		t.Errorf("dry run: %s", out)
	}
	if out := mustRun(t, db, "stats"); !strings.Contains(out, "technologies    0") {
		t.Errorf("dry run must not store: %s", out)
	}

	out = mustRun(t, db, imp...)
	if !strings.Contains(out, "applied") || !strings.Contains(out, "technologies   +22 ~0 -0") {
		t.Errorf("import: %s", out)
	}
	out = mustRun(t, db, imp...)
	if !strings.Contains(out, "no changes") {
		t.Errorf("second import must change nothing: %s", out)
	}

	out = mustRun(t, db, "stats")
	for _, want := range []string{"technologies    22", "http_header", "probe_response", "draft"} {
		if !strings.Contains(out, want) {
			t.Errorf("stats lacks %q:\n%s", want, out)
		}
	}

	out = mustRun(t, db, "technology", "list")
	if !strings.Contains(out, "a-frame") || !strings.Contains(out, "typo3-cms") {
		t.Errorf("technology list: %s", out)
	}
	out = mustRun(t, db, "technology", "show", "a-frame")
	for _, want := range []string{"A-Frame", "script_url", "Relationships (", "from:     enthec-webappanalyzer @ 9e52f10"} {
		if !strings.Contains(out, want) {
			t.Errorf("technology show lacks %q:\n%s", want, out)
		}
	}
	if _, err := run(t, db, "technology", "show", "nope"); err == nil {
		t.Error("unknown technology must fail")
	}
	out = mustRun(t, db, "fingerprint", "list", "--technology", "typo3-cms")
	if !strings.Contains(out, "probe_response") || !strings.Contains(out, "draft") {
		t.Errorf("fingerprint list: %s", out)
	}
	out = mustRun(t, db, "fingerprint", "list", "--observation", "dns_record", "--json")
	if !strings.HasPrefix(strings.TrimSpace(out), "[") {
		t.Errorf("json list: %s", out)
	}
	if out := mustRun(t, db, "fingerprint", "validate"); !strings.Contains(out, "ok:") {
		t.Errorf("validate: %s", out)
	}

	if out := mustRun(t, db, "conflict", "list"); !strings.Contains(out, "0 conflicts") {
		t.Errorf("a single source has nothing to reconcile: %s", out)
	}
	seedConflicts(t, db)
	out = mustRun(t, db, "conflict", "list")
	if !strings.Contains(out, "identity_candidate") || !strings.Contains(out, "2 conflicts") {
		t.Errorf("conflict list: %s", out)
	}
	out = mustRun(t, db, "conflict", "list", "--websites", "different", "--state", "open")
	if !strings.Contains(out, "1 conflicts") || !strings.Contains(out, "wordpress") {
		t.Errorf("filtered list: %s", out)
	}
	if out := mustRun(t, db, "stats"); !strings.Contains(out, "open conflicts  1") {
		t.Errorf("stats must count open conflicts: %s", out)
	}

	out = mustRun(t, db, "conflict", "show", "cfl_1")
	if !strings.Contains(out, "identity_candidate") || !strings.Contains(out, "websites: different") {
		t.Errorf("conflict show: %s", out)
	}
	for name, args := range map[string][]string{
		"no decision":      {"conflict", "resolve", "cfl_1"},
		"both decisions":   {"conflict", "resolve", "cfl_1", "--merge", "--keep-separate"},
		"nothing selected": {"conflict", "resolve", "--merge"},
		"bulk no filter":   {"conflict", "resolve", "--all", "--merge"},
		"ids and all":      {"conflict", "resolve", "cfl_1", "--all", "--kind", "x", "--merge"},
		"unknown":          {"conflict", "resolve", "cfl_nope", "--keep-separate"},
	} {
		if _, err := run(t, db, args...); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	out = mustRun(t, db, "conflict", "resolve", "cfl_1", "--keep-separate", "--note", "not the same")
	if !strings.Contains(out, "1 kept separate") {
		t.Errorf("resolve: %s", out)
	}
	if out := mustRun(t, db, "conflict", "list", "--state", "open"); !strings.Contains(out, "0 conflicts") {
		t.Errorf("no open conflicts must remain: %s", out)
	}
	if out := mustRun(t, db, "conflict", "show", "cfl_1"); !strings.Contains(out, "kept separate: not the same") {
		t.Errorf("resolution not shown: %s", out)
	}

	exp := filepath.Join(t.TempDir(), "registry.json")
	mustRun(t, db, "export", "--format", "json", "-o", exp)
	b, err := os.ReadFile(exp) //nolint:gosec // test temp file
	if err != nil {
		t.Fatal(err)
	}
	if err := schemas.ValidateRegistry(b); err != nil {
		t.Fatalf("export violates the schema: %v", err)
	}
	again := filepath.Join(t.TempDir(), "registry2.json")
	mustRun(t, db, "export", "-o", again)
	b2, _ := os.ReadFile(again) //nolint:gosec // test temp file
	if !bytes.Equal(b, b2) {
		t.Error("exports of the same data must be identical")
	}
}

func TestImportErrors(t *testing.T) {
	db := filepath.Join(t.TempDir(), "owf.db")
	mustRun(t, db, "init")
	for name, args := range map[string][]string{
		"unknown source":      {"import", "nope", "--snapshot", fixture, "--revision", "x"},
		"no revision":         {"import", "enthec-webappanalyzer", "--snapshot", fixture},
		"missing dir":         {"import", "enthec-webappanalyzer", "--snapshot", "/nonexistent", "--revision", "x"},
		"bad format":          {"export", "--format", "xml"},
		"unknown source info": {"source", "info", "nope"},
		"unknown category":    {"technology", "list", "--category", "nope"},
	} {
		if _, err := run(t, db, args...); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

// seedConflicts stores one open and one ignored conflict, as a second source
// would produce.
func seedConflicts(t *testing.T, db string) {
	t.Helper()
	ctx := context.Background()
	r, err := sqlite.Open(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mk := func(id, state, websites string) domain.Conflict {
		return domain.Conflict{
			ID: domain.ConflictID(id), Kind: domain.ConflictIdentityCandidate, State: state,
			RecordIDs: []string{"tech_a", "tech_b"}, SourceIDs: []domain.SourceID{"src_1", "src_2"},
			Detail: map[string]string{"identity": "wordpress", "websites": websites}, CreatedAt: now, UpdatedAt: now,
		}
	}
	if err := r.Apply(ctx, repository.ChangeSet{Conflicts: []domain.Conflict{
		mk("cfl_1", domain.ConflictOpen, "different"), mk("cfl_2", domain.ConflictIgnored, "same_domain"),
	}}); err != nil {
		t.Fatal(err)
	}
}
