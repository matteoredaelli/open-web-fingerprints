// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package scan_test

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"github.com/matteoredaelli/open-web-fingerprints/scan"
	"github.com/matteoredaelli/open-web-fingerprints/schemas"
)

const examplePath = "../examples/scan-result.json"

func TestExampleRoundTripsAndIsValid(t *testing.T) {
	orig, err := os.ReadFile(examplePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := schemas.ValidateScanResult(orig); err != nil {
		t.Fatalf("example must be valid: %v", err)
	}
	dec := json.NewDecoder(bytes.NewReader(orig))
	dec.DisallowUnknownFields()
	var r scan.Result
	if err := dec.Decode(&r); err != nil {
		t.Fatalf("the Go types must read the example without unknown fields: %v", err)
	}
	if r.SchemaVersion != scan.SchemaVersion {
		t.Errorf("schema version %q, constant %q", r.SchemaVersion, scan.SchemaVersion)
	}
	out, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if err := schemas.ValidateScanResult(out); err != nil {
		t.Fatalf("re-encoded result invalid: %v", err)
	}
	var a, b map[string]any
	_ = json.Unmarshal(orig, &a)
	_ = json.Unmarshal(out, &b)
	if !reflect.DeepEqual(a, b) {
		t.Fatal("round trip changed the document")
	}
}

// An empty result is still a valid result: collections are empty, not null.
func TestEmptyResultNeedsExplicitCollections(t *testing.T) {
	var r scan.Result
	b, _ := json.Marshal(r)
	if err := schemas.ValidateScanResult(b); err == nil {
		t.Fatal("null collections must not satisfy the schema")
	}
}

func mutate(t *testing.T, f func(m map[string]any)) []byte {
	t.Helper()
	b, err := os.ReadFile(examplePath)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	f(m)
	out, _ := json.Marshal(m)
	return out
}

func TestInvalidResults(t *testing.T) {
	tech := func(m map[string]any) map[string]any { return m["technologies"].([]any)[0].(map[string]any) }
	cases := map[string]func(m map[string]any){
		"unknown field":               func(m map[string]any) { m["extra"] = 1 },
		"bad version":                 func(m map[string]any) { m["schema_version"] = "v1" },
		"technology without evidence": func(m map[string]any) { tech(m)["evidence"] = []any{} },
		"technology without sources":  func(m map[string]any) { tech(m)["sources"] = []any{} },
		"confidence above 1":          func(m map[string]any) { tech(m)["confidence"] = 1.2 },
		"bad technology id":           func(m map[string]any) { tech(m)["id"] = "tech_1" },
		"bad health":                  func(m map[string]any) { tech(m)["evidence"].([]any)[0].(map[string]any)["health"] = "great" },
		"evidence without health":     func(m map[string]any) { delete(tech(m)["evidence"].([]any)[0].(map[string]any), "health") },
		"long matched value": func(m map[string]any) {
			tech(m)["evidence"].([]any)[0].(map[string]any)["matched"] = string(make([]byte, 301))
		},
		"bad link kind":        func(m map[string]any) { m["links"].([]any)[0].(map[string]any)["kind"] = "button" },
		"link without domain":  func(m map[string]any) { delete(m["links"].([]any)[0].(map[string]any), "domain") },
		"social without place": func(m map[string]any) { m["socials"].([]any)[0].(map[string]any)["found"] = []any{} },
		"bad social via": func(m map[string]any) {
			m["socials"].([]any)[0].(map[string]any)["found"].([]any)[0].(map[string]any)["via"] = "guess"
		},
		"upper case platform": func(m map[string]any) { m["socials"].([]any)[0].(map[string]any)["platform"] = "LinkedIn" },
		"bad status":          func(m map[string]any) { m["pages"].([]any)[0].(map[string]any)["status"] = 99 },
		"negative coverage":   func(m map[string]any) { m["coverage"].(map[string]any)["rules_total"] = -1 },
		"registry hash":       func(m map[string]any) { m["registry"].(map[string]any)["content_sha256"] = "abc" },
		"missing warnings":    func(m map[string]any) { delete(m, "warnings") },
		"bad scanned_at":      func(m map[string]any) { m["scanned_at"] = "yesterday" },
	}
	for name, f := range cases {
		if err := schemas.ValidateScanResult(mutate(t, f)); err == nil {
			t.Errorf("%s: expected a validation error", name)
		}
	}
	// Optional parts may be absent.
	ok := mutate(t, func(m map[string]any) {
		delete(m, "host")
		m["pages"].([]any)[0].(map[string]any)["headers"] = nil
		delete(m["pages"].([]any)[0].(map[string]any), "headers")
		delete(m["registry"].(map[string]any), "notice")
	})
	if err := schemas.ValidateScanResult(ok); err != nil {
		t.Errorf("optional parts: %v", err)
	}
}
