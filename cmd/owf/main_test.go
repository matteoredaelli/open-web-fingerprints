// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"encoding/json"
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

const fixture = "../../internal/extractor/wappalyzer/testdata/snapshot"

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

	if out := mustRun(t, db, "vendor", "list"); !strings.Contains(out, "CPE VENDOR") || !strings.Contains(out, "typo3") {
		t.Errorf("vendor list:\n%s", out)
	}
	if out := mustRun(t, db, "technology", "show", "php"); !strings.Contains(out, "vendor:   Php (cpe: php)") {
		t.Errorf("technology show must name the vendor:\n%s", out)
	}
	// Curating a vendor: the guessed name is replaced, and a refresh keeps it.
	if out := mustRun(t, db, "vendor", "list", "--uncurated"); !strings.Contains(out, "php") || !strings.Contains(out, "false") {
		t.Errorf("uncurated list:\n%s", out)
	}
	out = mustRun(t, db, "vendor", "set", "php", "--name", "The PHP Group", "--website", "https://www.php.net", "--alias", "PHP")
	if !strings.Contains(out, `name "The PHP Group"`) || !strings.Contains(out, "curated") {
		t.Errorf("vendor set:\n%s", out)
	}
	if out := mustRun(t, db, "vendor", "show", "php"); !strings.Contains(out, "The PHP Group (php)") ||
		!strings.Contains(out, "state:    curated") || !strings.Contains(out, "Technologies (1): php") {
		t.Errorf("vendor show:\n%s", out)
	}
	if out := mustRun(t, db, "vendor", "list", "--uncurated"); strings.Contains(out, "The PHP Group") {
		t.Errorf("a curated vendor must leave the uncurated list:\n%s", out)
	}
	if out := mustRun(t, db, "import", "enthec-webappanalyzer", "--snapshot", fixture, "--revision", "9e52f10"); !strings.Contains(out, "no changes") {
		t.Errorf("re-import after curation:\n%s", out)
	}
	if out := mustRun(t, db, "technology", "show", "php"); !strings.Contains(out, "vendor:   The PHP Group (cpe: php)") {
		t.Errorf("curated name must survive:\n%s", out)
	}
	out = mustRun(t, db, "technology", "set", "php", "--website", "https://www.php.net", "--vendor", "php")
	if !strings.Contains(out, `curated [vendor, website]`) {
		t.Errorf("technology set:\n%s", out)
	}
	if out := mustRun(t, db, "import", "enthec-webappanalyzer", "--snapshot", fixture, "--revision", "9e52f10"); !strings.Contains(out, "no changes") {
		t.Errorf("re-import after curating a technology:\n%s", out)
	}
	if out := mustRun(t, db, "technology", "show", "php"); !strings.Contains(out, "https://www.php.net") {
		t.Errorf("curated website must survive:\n%s", out)
	}
	for name, args := range map[string][]string{
		"technology: nothing to change": {"technology", "set", "php"},
		"technology: unknown":           {"technology", "set", "nope", "--website", "https://a.example"},
		"technology: both flags":        {"technology", "set", "php", "--website", "https://a.example", "--clear-website"},
		"technology: unknown vendor":    {"technology", "set", "php", "--vendor", "nope"},
		"nothing to change":             {"vendor", "set", "php"},
		"unknown vendor":                {"vendor", "set", "nope", "--name", "x"},
		"bad website":                   {"vendor", "set", "php", "--website", "php.net"},
		"empty name":                    {"vendor", "set", "php", "--name", ""},
		"both website flags":            {"vendor", "set", "php", "--website", "https://a.example", "--clear-website"},
	} {
		if _, err := run(t, db, args...); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	if out := mustRun(t, db, "vendor", "set", "php", "--clear-website", "--remove-alias", "php"); !strings.Contains(out, `website ""`) {
		t.Errorf("clear website:\n%s", out)
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
	mustRun(t, db, "export", "--include-unreviewed", "--format", "json", "-o", exp)
	b, err := os.ReadFile(exp) //nolint:gosec // test temp file
	if err != nil {
		t.Fatal(err)
	}
	if err := schemas.ValidateRegistry(b); err != nil {
		t.Fatalf("export violates the schema: %v", err)
	}
	again := filepath.Join(t.TempDir(), "registry2.json")
	mustRun(t, db, "export", "--include-unreviewed", "-o", again)
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

func TestFingerprintTestAndLint(t *testing.T) {
	nowFunc = func() time.Time { return time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC) }
	db := filepath.Join(t.TempDir(), "owf.db")
	mustRun(t, db, "init")
	mustRun(t, db, "import", "enthec-webappanalyzer", "--snapshot", fixture, "--revision", "x")
	cases := "../../internal/validation/testdata/cases"

	out := mustRun(t, db, "fingerprint", "test", cases)
	if !strings.Contains(out, "19 cases: 18 pass, 0 fail, 0 error, 1 unsupported") ||
		!strings.Contains(out, "unsupported misc.json#angular-lookahead-not-evaluated") ||
		strings.Contains(out, "pass        php.json") {
		t.Errorf("test output:\n%s", out)
	}
	if out := mustRun(t, db, "stats"); strings.Contains(out, "  ok ") {
		t.Errorf("a plain test run must not store evidence:\n%s", out)
	}

	out = mustRun(t, db, "fingerprint", "test", cases, "--apply", "-v")
	if !strings.Contains(out, "pass        php.json#php-cookie-positive") || !strings.Contains(out, "evidence stored on") {
		t.Errorf("apply output:\n%s", out)
	}
	out = mustRun(t, db, "stats")
	if !strings.Contains(out, "by health") || !strings.Contains(out, "ok ") {
		t.Errorf("stats must show health:\n%s", out)
	}
	// The stored evidence is visible in the JSON of a rule and is repeatable.
	out = mustRun(t, db, "fingerprint", "list", "--technology", "php", "--json")
	if !strings.Contains(out, `"health": "ok"`) || !strings.Contains(out, `"fixture_ref": "php.json#php-cookie-positive"`) ||
		!strings.Contains(out, `"expect": "no_match"`) {
		t.Errorf("evidence missing:\n%s", out)
	}
	before := mustRun(t, db, "export", "--include-unreviewed")
	mustRun(t, db, "fingerprint", "test", cases, "--apply")
	if after := mustRun(t, db, "export", "--include-unreviewed"); after != before {
		t.Error("repeating the same tests must not change the registry")
	}
	exp := filepath.Join(t.TempDir(), "r.json")
	mustRun(t, db, "export", "--include-unreviewed", "-o", exp)
	b, _ := os.ReadFile(exp) //nolint:gosec // test temp file
	if err := schemas.ValidateRegistry(b); err != nil {
		t.Fatalf("export with test evidence violates the schema: %v", err)
	}

	// A failing case makes the command fail, and a stale one too.
	bad := t.TempDir()
	if err := os.WriteFile(filepath.Join(bad, "bad.json"), []byte(`{"schema_version":"0.1.0","cases":[
	  {"id":"wrong","rule":{"technology":"php","observation":"cookie","target":"PHPSESSID"},"input":{"cookies":{"PHPSESSID":"1"}},"expect":{"match":false}},
	  {"id":"stale","rule":{"technology":"php","observation":"cookie","target":"GONE"},"input":{},"expect":{"match":false}}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := run(t, db, "fingerprint", "test", bad, "--apply")
	if err == nil || !strings.Contains(out, "fail        bad.json#wrong") || !strings.Contains(out, "error       bad.json#stale") {
		t.Errorf("bad cases: err=%v\n%s", err, out)
	}
	if out := mustRun(t, db, "fingerprint", "list", "--technology", "php", "--json"); !strings.Contains(out, `"health": "broken"`) {
		t.Errorf("a failing case must mark the rule broken:\n%s", out)
	}
	if _, err := run(t, db, "fingerprint", "test", filepath.Join(bad, "missing.json")); err == nil {
		t.Error("missing path must fail")
	}

	out = mustRun(t, db, "fingerprint", "lint")
	if !strings.Contains(out, "findings on") {
		t.Errorf("lint:\n%s", out)
	}
	if out := mustRun(t, db, "fingerprint", "lint", "--json"); !strings.HasPrefix(strings.TrimSpace(out), "[") && !strings.HasPrefix(strings.TrimSpace(out), "null") {
		t.Errorf("lint json:\n%s", out)
	}
}

func TestExportGuardAndSourceReview(t *testing.T) {
	nowFunc = func() time.Time { return time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC) }
	db := filepath.Join(t.TempDir(), "owf.db")
	mustRun(t, db, "init")
	slug := "enthec-webappanalyzer"

	// Reviewing a source that was never imported is refused.
	if _, err := run(t, db, "source", "review", slug, "--redistributable", "yes", "--note", "x"); err == nil {
		t.Error("review before import must fail")
	}
	mustRun(t, db, "import", slug, "--snapshot", fixture, "--revision", "x")

	// Unreviewed data is not exported by default.
	out, err := run(t, db, "export")
	if err == nil || !strings.Contains(err.Error(), "enthec-webappanalyzer") || !strings.Contains(err.Error(), "--include-unreviewed") {
		t.Fatalf("export must be refused, got err=%v\n%s", err, out)
	}
	if strings.Contains(out, "technologies") {
		t.Error("a refused export must write nothing")
	}
	out = mustRun(t, db, "export", "--include-unreviewed")
	for _, want := range []string{`"include_unreviewed": true`, `"unreviewed_sources"`, "do not publish or redistribute"} {
		if !strings.Contains(out, want) {
			t.Errorf("export lacks %s", want)
		}
	}
	if err := schemas.ValidateRegistry([]byte(out)); err != nil {
		t.Fatalf("export with notice violates the schema: %v", err)
	}

	// A decision needs a basis, and has to be one of the known values.
	for name, args := range map[string][]string{
		"no note":      {"source", "review", slug, "--redistributable", "yes"},
		"blank note":   {"source", "review", slug, "--redistributable", "no", "--note", "  "},
		"bad value":    {"source", "review", slug, "--redistributable", "maybe", "--note", "x"},
		"missing flag": {"source", "review", slug},
		"unknown":      {"source", "review", "nope", "--redistributable", "yes", "--note", "x"},
	} {
		if _, err := run(t, db, args...); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}

	// "yes" opens the export; the file no longer needs the flag or the notice.
	mustRun(t, db, "source", "review", slug, "--redistributable", "yes", "--note", "legal review LR-12 by counsel, 2026-11-17")
	out = mustRun(t, db, "export")
	if strings.Contains(out, "include_unreviewed") || strings.Contains(out, "do not publish") {
		t.Errorf("a reviewed export needs no notice:\n%s", out[:200])
	}
	if !strings.Contains(out, "legal review LR-12") || !strings.Contains(out, `"reviewed_at"`) {
		t.Error("the basis of the decision must travel with the export")
	}
	if info := mustRun(t, db, "source", "info", slug); !strings.Contains(info, "Decision:        yes (reviewed 2026-11-17: legal review LR-12") {
		t.Errorf("source info:\n%s", info)
	}
	if list := mustRun(t, db, "source", "list"); !strings.Contains(list, "yes") {
		t.Errorf("source list must show the stored decision:\n%s", list)
	}

	// An import must not reset the reviewed decision.
	mustRun(t, db, "import", slug, "--snapshot", fixture, "--revision", "x")
	if _, err := run(t, db, "export"); err != nil {
		t.Errorf("decision lost after a refresh: %v", err)
	}

	// "no" excludes the source even with the flag.
	mustRun(t, db, "source", "review", slug, "--redistributable", "no", "--note", "license forbids redistribution")
	out, err = run(t, db, "export", "--include-unreviewed")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Technologies []any
		Sources      []any
		Export       struct {
			ExcludedSources []string `json:"excluded_sources"`
			ExcludedRecords int      `json:"excluded_records"`
		}
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Technologies) != 0 || len(doc.Sources) != 0 || len(doc.Export.ExcludedSources) != 1 || doc.Export.ExcludedRecords == 0 {
		t.Errorf("a source marked no must never be exported: %+v", doc)
	}

	// Withdrawing the decision makes it unreviewed again.
	mustRun(t, db, "source", "review", slug, "--redistributable", "unreviewed")
	if _, err := run(t, db, "export"); err == nil {
		t.Error("an unreviewed source must block the export again")
	}
}

func TestUpstreamExamplesAsEvidence(t *testing.T) {
	nowFunc = func() time.Time { return time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC) }
	db := filepath.Join(t.TempDir(), "owf.db")
	mustRun(t, db, "init")
	mustRun(t, db, "import", "rapid7-recog", "--snapshot", "../../internal/extractor/recog/testdata/snapshot", "--revision", "f1191e2")

	if _, err := run(t, db, "fingerprint", "test"); err == nil {
		t.Error("with neither a path nor --upstream-examples there is nothing to test")
	}
	out := mustRun(t, db, "fingerprint", "test", "--upstream-examples")
	if !strings.Contains(out, "0 fail, 0 error") || !strings.Contains(out, "upstream examples:") ||
		!strings.Contains(out, "positive and") || !strings.Contains(out, "negatives checked") {
		t.Errorf("summary:\n%s", out)
	}
	if out := mustRun(t, db, "stats"); strings.Contains(out, "ok ") && !strings.Contains(out, "unknown") {
		t.Errorf("a plain run must store nothing:\n%s", out)
	}

	out = mustRun(t, db, "fingerprint", "test", "--upstream-examples", "--apply")
	if !strings.Contains(out, "evidence stored on") {
		t.Errorf("apply:\n%s", out)
	}
	out = mustRun(t, db, "stats")
	if !strings.Contains(out, "only from upstream examples") {
		t.Errorf("stats must say that the evidence comes from the source's own examples:\n%s", out)
	}
	list := mustRun(t, db, "fingerprint", "list", "--observation", "http_header", "--json")
	for _, want := range []string{`"health": "ok"`, `"origin": "upstream_example"`, `"fixture_ref": "upstream#ex1"`, `"expect": "no_match"`} {
		if !strings.Contains(list, want) {
			t.Errorf("evidence lacks %s", want)
		}
	}
	// Repeating replaces the generated set: the export does not change.
	before := mustRun(t, db, "export", "--include-unreviewed")
	mustRun(t, db, "fingerprint", "test", "--upstream-examples", "--apply")
	if after := mustRun(t, db, "export", "--include-unreviewed"); after != before {
		t.Error("repeating the same generation must not change the registry")
	}
	if err := schemas.ValidateRegistry([]byte(before)); err != nil {
		t.Fatalf("export with upstream evidence violates the schema: %v", err)
	}
	// A re-import keeps the evidence (it belongs to the rule, not to the refresh).
	if out := mustRun(t, db, "import", "rapid7-recog", "--snapshot", "../../internal/extractor/recog/testdata/snapshot", "--revision", "f1191e2"); !strings.Contains(out, "no changes") {
		t.Errorf("re-import:\n%s", out)
	}
	if out := mustRun(t, db, "stats"); !strings.Contains(out, "only from upstream examples") {
		t.Errorf("evidence lost after a re-import:\n%s", out)
	}
}

func TestGroupCasesThroughTheCLI(t *testing.T) {
	nowFunc = func() time.Time { return time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC) }
	db := filepath.Join(t.TempDir(), "owf.db")
	mustRun(t, db, "init")
	mustRun(t, db, "import", "projectdiscovery-nuclei-templates", "--snapshot", "../../internal/extractor/nuclei/testdata/snapshot", "--revision", "91be390")
	cases := "../../internal/validation/testdata/groups"
	out := mustRun(t, db, "fingerprint", "test", cases, "--apply")
	if !strings.Contains(out, "8 cases: 8 pass") || !strings.Contains(out, "evidence stored on 5 fingerprints") {
		t.Errorf("group cases:\n%s", out)
	}
	list := mustRun(t, db, "fingerprint", "list", "--technology", "4d", "--json")
	if strings.Count(list, `"health": "ok"`) != 3 || strings.Count(list, `"health": "unknown"`) != 8 {
		t.Errorf("only the two members of the tested group are ok:\n%s", list)
	}
}

func TestExportManifestAndVerify(t *testing.T) {
	nowFunc = func() time.Time { return time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC) }
	db := filepath.Join(t.TempDir(), "owf.db")
	mustRun(t, db, "init")
	mustRun(t, db, "import", "enthec-webappanalyzer", "--snapshot", fixture, "--revision", "9e52f10")
	mustRun(t, db, "source", "review", "enthec-webappanalyzer", "--redistributable", "yes", "--note", "test")
	dir := t.TempDir()
	file := filepath.Join(dir, "registry.json")
	mustRun(t, db, "export", "-o", file)

	out := mustRun(t, db, "verify", file)
	for _, want := range []string{"ok: schema 0.2.0", "sha256:", "22 technologies", "source enthec-webappanalyzer (GPL-3.0-only, redistributable: yes) @ 9e52f10"} {
		if !strings.Contains(out, want) {
			t.Errorf("verify lacks %q:\n%s", want, out)
		}
	}
	b, err := os.ReadFile(file) //nolint:gosec // test temp file
	if err != nil {
		t.Fatal(err)
	}

	// The same data exported later has the same hash; only the time differs.
	nowFunc = func() time.Time { return time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC) }
	file2 := filepath.Join(dir, "later.json")
	mustRun(t, db, "export", "-o", file2)
	b2, _ := os.ReadFile(file2) //nolint:gosec // test temp file
	hash := func(b []byte) string {
		i := strings.Index(string(b), `"content_sha256"`)
		return string(b[i : i+100])
	}
	if hash(b) != hash(b2) || string(b) == string(b2) {
		t.Errorf("hash must be equal and the files different (generated_at)")
	}

	// Tampering is noticed, in the data and in the counts.
	tamper := func(name, from, to string) string {
		p := filepath.Join(dir, name)
		if !strings.Contains(string(b), from) {
			t.Fatalf("%q not in the export", from)
		}
		if err := os.WriteFile(p, []byte(strings.Replace(string(b), from, to, 1)), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if _, err := run(t, db, "verify", tamper("t1.json", `"name": "A-Frame"`, `"name": "B-Frame"`)); err == nil ||
		!strings.Contains(err.Error(), "content hash") {
		t.Errorf("a changed record must fail verification: %v", err)
	}
	if _, err := run(t, db, "verify", tamper("t2.json", `"technologies": 22`, `"technologies": 23`)); err == nil {
		t.Error("changed counts must fail")
	}
	if _, err := run(t, db, "verify", filepath.Join(dir, "missing.json")); err == nil {
		t.Error("missing file must fail")
	}
	// An unreviewed export says so when verified.
	mustRun(t, db, "source", "review", "enthec-webappanalyzer", "--redistributable", "unreviewed")
	file3 := filepath.Join(dir, "internal.json")
	mustRun(t, db, "export", "--include-unreviewed", "-o", file3)
	if out := mustRun(t, db, "verify", file3); !strings.Contains(out, "NOTICE:") {
		t.Errorf("verify must repeat the notice:\n%s", out)
	}
}

func TestFingerprintCorrectThroughTheCLI(t *testing.T) {
	db := filepath.Join(t.TempDir(), "owf.db")
	mustRun(t, db, "init")
	imp := []string{"import", "enthec-webappanalyzer", "--snapshot", fixture, "--revision", "x"}
	mustRun(t, db, imp...)

	var fps []struct {
		ID, Target string
	}
	if err := json.Unmarshal([]byte(mustRun(t, db, "fingerprint", "list", "--observation", "cookie", "--json")), &fps); err != nil {
		t.Fatal(err)
	}
	var id string
	for _, f := range fps {
		if f.Target == "NEXT_LOCALE" {
			id = f.ID
		}
	}
	if id == "" {
		t.Fatal("fixture has no NEXT_LOCALE cookie rule")
	}

	for name, args := range map[string][]string{
		"no reason":       {"fingerprint", "correct", id, "--value", "next_locale"},
		"unknown field":   {"fingerprint", "correct", id, "--field", "confidence", "--value", "1", "--reason", "r"},
		"unknown rule":    {"fingerprint", "correct", "fp_nope", "--value", "x", "--reason", "r"},
		"revert + value":  {"fingerprint", "correct", id, "--revert", "--value", "x"},
		"nothing to undo": {"fingerprint", "correct", id, "--revert"},
	} {
		if out, err := run(t, db, args...); err == nil {
			t.Errorf("%s: expected an error\n%s", name, out)
		}
	}

	out := mustRun(t, db, "fingerprint", "correct", id, "--value", "NEXT_LOCALE_X", "--reason", "test of the mechanism")
	if !strings.Contains(out, `"NEXT_LOCALE" -> "NEXT_LOCALE_X"`) {
		t.Errorf("correct output: %s", out)
	}
	if out := mustRun(t, db, "fingerprint", "list", "--observation", "cookie"); !strings.Contains(out, "NEXT_LOCALE_X") || !strings.Contains(out, "(corrected target)") {
		t.Errorf("the list marks a corrected rule:\n%s", out)
	}
	// A refresh with the same snapshot changes nothing and keeps the correction.
	if out := mustRun(t, db, imp...); !strings.Contains(out, "no changes") {
		t.Errorf("re-import: %s", out)
	}
	// The export carries the correction, satisfies the schema and verifies.
	file := filepath.Join(t.TempDir(), "registry.json")
	mustRun(t, db, "export", "--include-unreviewed", "-o", file)
	doc, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(doc), `"original": "NEXT_LOCALE"`) || !strings.Contains(string(doc), "test of the mechanism") {
		t.Error("the export must carry the correction with its reason")
	}
	if out := mustRun(t, db, "verify", file); !strings.Contains(out, "ok") {
		t.Errorf("verify: %s", out)
	}

	out = mustRun(t, db, "fingerprint", "correct", id, "--revert")
	if !strings.Contains(out, "back to the source's value") {
		t.Errorf("revert: %s", out)
	}
	if out := mustRun(t, db, "fingerprint", "list", "--observation", "cookie"); strings.Contains(out, "corrected") || strings.Contains(out, "NEXT_LOCALE_X") {
		t.Errorf("after revert:\n%s", out)
	}
}

func TestProbeReviewThroughTheCLI(t *testing.T) {
	db := filepath.Join(t.TempDir(), "owf.db")
	mustRun(t, db, "init")
	mustRun(t, db, "import", "projectdiscovery-nuclei-templates", "--snapshot", "../../internal/extractor/nuclei/testdata/snapshot", "--revision", "x")

	out := mustRun(t, db, "probe", "list")
	if !strings.Contains(out, "/cfadmin/") || !strings.Contains(out, "pending") || !strings.Contains(out, "Accellion") {
		t.Fatalf("list:\n%s", out)
	}
	for name, args := range map[string][]string{
		"no note":      {"probe", "review", "/cfadmin/", "--decision", "approved"},
		"no decision":  {"probe", "review", "/cfadmin/"},
		"no path":      {"probe", "review", "--decision", "approved", "--note", "n"},
		"both":         {"probe", "review", "/cfadmin/", "--all-pending", "--decision", "approved", "--note", "n"},
		"other host":   {"probe", "review", "//evil.example/", "--decision", "approved", "--note", "n"},
		"unknown path": {"probe", "review", "/nope", "--decision", "rejected", "--note", "n"},
	} {
		if out, err := run(t, db, args...); err == nil {
			t.Errorf("%s: expected an error\n%s", name, out)
		}
	}
	out = mustRun(t, db, "probe", "review", "--all-pending", "--decision", "approved", "--note", "n", "--dry-run")
	if !strings.Contains(out, "dry run") || !strings.Contains(out, "/cfadmin/") {
		t.Errorf("dry run:\n%s", out)
	}
	if out := mustRun(t, db, "probe", "list", "--state", "approved"); strings.Contains(out, "/cfadmin/") {
		t.Errorf("a dry run stores nothing:\n%s", out)
	}
	out = mustRun(t, db, "probe", "review", "/cfadmin/", "--decision", "approved", "--note", "static login page, only fetched")
	if !strings.Contains(out, "approved:") {
		t.Errorf("review: %s", out)
	}
	if out := mustRun(t, db, "probe", "list", "--state", "approved"); !strings.Contains(out, "/cfadmin/") {
		t.Errorf("approved:\n%s", out)
	}
	// The export carries the decision and satisfies the schema; a refresh keeps it.
	file := filepath.Join(t.TempDir(), "registry.json")
	mustRun(t, db, "export", "--include-unreviewed", "-o", file)
	doc, _ := os.ReadFile(file)
	if !strings.Contains(string(doc), "static login page, only fetched") || !strings.Contains(string(doc), `"reviewed_at"`) {
		t.Error("the export must carry who decided what")
	}
	if out := mustRun(t, db, "import", "projectdiscovery-nuclei-templates", "--snapshot", "../../internal/extractor/nuclei/testdata/snapshot", "--revision", "x"); !strings.Contains(out, "no changes") {
		t.Errorf("re-import: %s", out)
	}
	if out := mustRun(t, db, "probe", "list", "--state", "approved"); !strings.Contains(out, "/cfadmin/") {
		t.Errorf("the decision survives a re-import:\n%s", out)
	}
	mustRun(t, db, "probe", "review", "/cfadmin/", "--decision", "pending")
	if out := mustRun(t, db, "probe", "list", "--state", "approved"); strings.Contains(out, "/cfadmin/") {
		t.Errorf("reset:\n%s", out)
	}
}
