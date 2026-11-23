// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/config"
	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/scantest"
)

func TestBotFilterNeedsAList(t *testing.T) {
	old := cfg
	defer func() { cfg = old }()
	cfg = config.Default()
	dir := t.TempDir()
	if _, err := run(t, "", "bot", "filter", "refresh", "--dir", dir); err == nil {
		t.Error("refresh with no list succeeded")
	}
	if _, err := run(t, "", "bot", "filter", "check", "a.example", "--dir", dir); err == nil {
		t.Error("check with no list succeeded")
	}
}

func TestBotFilterCheck(t *testing.T) {
	old := cfg
	defer func() { cfg = old }()
	cfg = config.Default()
	cfg.Bot.Filter.Lists = []config.FilterList{{Name: "l", URL: "https://x.example/l", Category: "adult", Format: "hosts", Enabled: true}}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "l.list"), []byte("0.0.0.0 bad.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := run(t, "", "bot", "filter", "check", "www.bad.example", "fine.example", "--dir", dir)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "blocked  www.bad.example  list=l category=adult entry=bad.example") || !strings.Contains(out, "allowed  fine.example") {
		t.Errorf("output:\n%s", out)
	}
	out, err = run(t, "", "bot", "filter", "list", "--dir", dir)
	if err != nil || !strings.Contains(out, "yes") || !strings.Contains(out, "adult") {
		t.Errorf("list: %v\n%s", err, out)
	}
}

func botReg(t *testing.T) string {
	t.Helper()
	reg := filepath.Join(t.TempDir(), "registry.json")
	if err := os.WriteFile(reg, scantest.RegistryJSON(t), 0o600); err != nil {
		t.Fatal(err)
	}
	return reg
}

func TestBotSeedStatusExclude(t *testing.T) {
	old := cfg
	defer func() { cfg = old }()
	cfg = config.Default()
	dir := t.TempDir()
	db := filepath.Join(dir, "bot.db")
	list := filepath.Join(dir, "list.txt")
	if err := os.WriteFile(list, []byte("1,a.example\n2,b.example\nnot a host\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := run(t, "", "bot", "seed", list, "--db", db)
	if err != nil || !strings.Contains(out, "2 new") {
		t.Fatalf("%v\n%s", err, out)
	}
	if out, err = run(t, "", "bot", "exclude", "add", "www.b.example", "--db", db, "--note", "owner asked"); err != nil || !strings.Contains(out, "excluded") {
		t.Fatalf("%v\n%s", err, out)
	}
	if out, _ = run(t, "", "bot", "exclude", "list", "--db", db); !strings.Contains(out, "b.example") || !strings.Contains(out, "owner asked") {
		t.Errorf("exclude list:\n%s", out)
	}
	out, err = run(t, "", "bot", "status", "--db", db)
	if err != nil || !strings.Contains(out, "2 domains") || !strings.Contains(out, "1 blocked") || !strings.Contains(out, "opt-out") || !strings.Contains(out, "due now: 1") {
		t.Fatalf("%v\n%s", err, out)
	}
	if out, _ = run(t, "", "bot", "exclude", "remove", "b.example", "--db", db); !strings.Contains(out, "no longer excluded") {
		t.Errorf("remove:\n%s", out)
	}
}

func TestBotRunRefusesWithoutFilterAndChecksCeilings(t *testing.T) {
	old := cfg
	defer func() { cfg = old }()
	cfg = config.Default()
	reg := botReg(t)
	db := filepath.Join(t.TempDir(), "bot.db")
	if _, err := run(t, "", "bot", "run", "--registry", reg, "--db", db); err == nil || !strings.Contains(err.Error(), "no block list") {
		t.Errorf("started with no filter: %v", err)
	}
	if _, err := run(t, "", "bot", "run", "--registry", reg, "--db", db, "--no-filter", "--workers", "1000"); err == nil || !strings.Contains(err.Error(), "bot.workers") {
		t.Errorf("workers above the ceiling accepted: %v", err)
	}
	if _, err := run(t, "", "bot", "run", "--registry", reg, "--db", db, "--no-filter", "--depth", "2"); err == nil || !strings.Contains(err.Error(), "bot.depth") {
		t.Errorf("depth 2 accepted: %v", err)
	}
}

func TestBotRunWithNoFilterRecordsFailureAndStops(t *testing.T) {
	old := cfg
	defer func() { cfg = old }()
	cfg = config.Default()
	reg := botReg(t)
	dir := t.TempDir()
	db := filepath.Join(dir, "bot.db")
	list := filepath.Join(dir, "list.txt")
	_ = os.WriteFile(list, []byte("nothing.invalid\n"), 0o600)
	if _, err := run(t, "", "bot", "seed", list, "--db", db); err != nil {
		t.Fatal(err)
	}
	out, err := run(t, "", "bot", "run", "--registry", reg, "--db", db, "--no-filter", "--per-host-delay", "1s")
	if err != nil || !strings.Contains(out, "failed 1") || !strings.Contains(out, "stopped: empty") {
		t.Fatalf("%v\n%s", err, out)
	}
	// A stop file stops the run before it claims anything.
	stop := filepath.Join(dir, "stop")
	_ = os.WriteFile(stop, nil, 0o600)
	out, err = run(t, "", "bot", "run", "--registry", reg, "--db", db, "--no-filter", "--stop-file", stop)
	if err != nil || !strings.Contains(out, "stopped: kill switch") {
		t.Fatalf("%v\n%s", err, out)
	}
}
