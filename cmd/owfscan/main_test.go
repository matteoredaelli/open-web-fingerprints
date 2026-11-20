// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func run(t *testing.T, stdin string, args ...string) (string, error) {
	t.Helper()
	cmd := newRootCmd()
	var out, errb bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	cmd.SetIn(strings.NewReader(stdin))
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String() + errb.String(), err
}

const home = "../../internal/scan/web/testdata/home.html"

func TestExtractText(t *testing.T) {
	out, err := run(t, "", "extract", "--url", "https://www.tyres.example/en/", home)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"tyres.example", "linkedin", "example-tyres", "email", "press@tyres.example", "+390212345678", "warning: invalid_jsonld"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

func TestExtractJSONFromStdin(t *testing.T) {
	out, err := run(t, `<a href="https://github.com/example">x</a><a href="/a">y</a>`, "extract", "--json", "--url", "https://example.org/", "-")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Links    []map[string]any
		Socials  []map[string]any
		Contacts []any
		Domains  []map[string]any
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if len(doc.Links) != 2 || len(doc.Socials) != 1 || doc.Socials[0]["platform"] != "github" || doc.Contacts == nil {
		t.Errorf("%+v", doc)
	}
}

func TestExtractErrors(t *testing.T) {
	for name, args := range map[string][]string{
		"no url":       {"extract", home},
		"bad url":      {"extract", "--url", "::", home},
		"no host":      {"extract", "--url", "/path", home},
		"missing file": {"extract", "--url", "https://a.example/", "/nonexistent.html"},
		"no file":      {"extract", "--url", "https://a.example/"},
	} {
		if _, err := run(t, "", args...); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}
