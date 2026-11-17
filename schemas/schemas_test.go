// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package schemas

import (
	"encoding/json"
	"os"
	"regexp"
	"testing"
)

const examplePath = "../examples/registry.json"

func loadExample(t *testing.T) map[string]any {
	t.Helper()
	b, err := os.ReadFile(examplePath)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestExampleIsValid(t *testing.T) {
	b, err := os.ReadFile(examplePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateRegistry(b); err != nil {
		t.Fatalf("example must be valid: %v", err)
	}
}

func fps(m map[string]any) []any { return m["fingerprints"].([]any) }
func fp(m map[string]any, i int) map[string]any {
	return fps(m)[i].(map[string]any)
}

// findFP returns the first fingerprint matching the observation.
func findFP(t *testing.T, m map[string]any, obs string) map[string]any {
	t.Helper()
	for _, x := range fps(m) {
		f := x.(map[string]any)
		if f["observation"] == obs {
			return f
		}
	}
	t.Fatalf("no fingerprint with observation %q in example", obs)
	return nil
}

func TestInvalidDocuments(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(t *testing.T, m map[string]any)
	}{
		{"unknown top-level field", func(_ *testing.T, m map[string]any) { m["extra"] = 1 }},
		{"bad schema_version", func(_ *testing.T, m map[string]any) { m["schema_version"] = "v1" }},
		{"technology id wrong prefix", func(_ *testing.T, m map[string]any) {
			m["technologies"].([]any)[0].(map[string]any)["id"] = "fp_0192f0a0-0000-7000-8000-000000000001"
		}},
		{"id is not uuid v7", func(_ *testing.T, m map[string]any) {
			m["technologies"].([]any)[0].(map[string]any)["id"] = "tech_0192f0a0-0000-4000-8000-000000000001"
		}},
		{"technology without provenance", func(_ *testing.T, m map[string]any) {
			delete(m["technologies"].([]any)[0].(map[string]any), "provenance")
		}},
		{"technology with empty provenance", func(_ *testing.T, m map[string]any) {
			m["technologies"].([]any)[0].(map[string]any)["provenance"] = []any{}
		}},
		{"invalid status", func(_ *testing.T, m map[string]any) {
			fp(m, 0)["status"] = "published"
		}},
		{"confidence above 1", func(_ *testing.T, m map[string]any) { fp(m, 0)["confidence"] = 1.5 }},
		{"regex without pattern", func(_ *testing.T, m map[string]any) { delete(fp(m, 0), "pattern") }},
		{"regex without flavor", func(_ *testing.T, m map[string]any) { delete(fp(m, 0), "regex_flavor") }},
		{"unknown operator", func(_ *testing.T, m map[string]any) { fp(m, 0)["operator"] = "fuzzy" }},
		{"observation not snake_case", func(_ *testing.T, m map[string]any) { fp(m, 0)["observation"] = "HTTP-Header" }},
		{"probe_response without probe", func(t *testing.T, m map[string]any) {
			delete(findFP(t, m, "probe_response"), "probe")
		}},
		{"active probe not approved", func(t *testing.T, m map[string]any) {
			findFP(t, m, "probe_response")["status"] = "active"
		}},
		{"probe with destructive method", func(t *testing.T, m map[string]any) {
			findFP(t, m, "probe_response")["probe"].(map[string]any)["method"] = "POST"
		}},
		{"probe path not absolute", func(t *testing.T, m map[string]any) {
			findFP(t, m, "probe_response")["probe"].(map[string]any)["path"] = "wp-login.php"
		}},
		{"provenance bad timestamp", func(_ *testing.T, m map[string]any) {
			fp(m, 0)["provenance"].([]any)[0].(map[string]any)["imported_at"] = "yesterday"
		}},
		{"snapshot bad checksum", func(_ *testing.T, m map[string]any) {
			m["snapshots"].([]any)[0].(map[string]any)["checksum"] = "abc"
		}},
		{"relationship with two targets", func(_ *testing.T, m map[string]any) {
			r := m["relationships"].([]any)[0].(map[string]any)
			r["to_category_id"] = "cat_0192f0a0-0000-7000-8000-000000000001"
		}},
		{"relationship with no target", func(_ *testing.T, m map[string]any) {
			delete(m["relationships"].([]any)[0].(map[string]any), "to_technology_id")
		}},
		{"source redistributable invalid", func(_ *testing.T, m map[string]any) {
			m["sources"].([]any)[0].(map[string]any)["redistributable"] = "maybe"
		}},
		{"cpe not 2.3", func(_ *testing.T, m map[string]any) {
			m["technologies"].([]any)[0].(map[string]any)["cpe"] = []any{"wordpress"}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := loadExample(t)
			tc.mutate(t, m)
			b, err := json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			if err := ValidateRegistry(b); err == nil {
				t.Fatal("expected validation error, got none")
			}
		})
	}
}

func TestValidMutations(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(t *testing.T, m map[string]any)
	}{
		{"unknown observation type is preserved", func(_ *testing.T, m map[string]any) {
			fp(m, 0)["observation"] = "future_observation"
		}},
		{"exists operator needs no pattern", func(_ *testing.T, m map[string]any) {
			f := fp(m, 0)
			f["operator"] = "exists"
			delete(f, "pattern")
			delete(f, "regex_flavor")
		}},
		{"approved probe may be active", func(t *testing.T, m map[string]any) {
			f := findFP(t, m, "probe_response")
			f["probe"].(map[string]any)["safety_review"] = "approved"
			f["status"] = "active"
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := loadExample(t)
			tc.mutate(t, m)
			b, _ := json.Marshal(m)
			if err := ValidateRegistry(b); err != nil {
				t.Fatalf("expected valid: %v", err)
			}
		})
	}
}

// The example must cover the observation types promised in the domain model.
func TestExampleCoverage(t *testing.T) {
	m := loadExample(t)
	seen := map[string]bool{}
	for _, x := range fps(m) {
		seen[x.(map[string]any)["observation"].(string)] = true
	}
	for _, want := range []string{"http_header", "cookie", "meta_tag", "script_url", "html",
		"js_global", "favicon_hash", "probe_response", "dns_record", "tls_cert"} {
		if !seen[want] {
			t.Errorf("example lacks observation type %s", want)
		}
	}
}

// Ids in the example must be unique and references must resolve.
func TestExampleReferentialIntegrity(t *testing.T) {
	b, _ := os.ReadFile(examplePath)
	ids := map[string]bool{}
	re := regexp.MustCompile(`"((?:tech|fp|cat|vnd|src|rel)_[0-9a-f-]+)"`)
	for _, k := range []string{"technologies", "fingerprints", "categories", "vendors", "sources", "relationships"} {
		for _, x := range loadExample(t)[k].([]any) {
			id := x.(map[string]any)["id"].(string)
			if ids[id] {
				t.Errorf("duplicate id %s", id)
			}
			ids[id] = true
		}
	}
	for _, m := range re.FindAllStringSubmatch(string(b), -1) {
		if !ids[m[1]] {
			t.Errorf("dangling reference %s", m[1])
		}
	}
}

func TestValidationCasesSchema(t *testing.T) {
	ok := `{"schema_version":"0.1.0","cases":[{"id":"a","rule":{"technology":"php","observation":"http_header"},"input":{"headers":{"X":"y"}},"expect":{"match":true,"version":"1"}}]}`
	if err := ValidateCases([]byte(ok)); err != nil {
		t.Fatalf("valid cases rejected: %v", err)
	}
	if len(CasesSchema()) == 0 {
		t.Fatal("schema is empty")
	}
	for name, doc := range map[string]string{
		"missing expect":  `{"schema_version":"0.1.0","cases":[{"id":"a","rule":{"technology":"php","observation":"x"},"input":{}}]}`,
		"empty cases":     `{"schema_version":"0.1.0","cases":[]}`,
		"bad header map":  `{"schema_version":"0.1.0","cases":[{"id":"a","rule":{"technology":"php","observation":"x"},"input":{"headers":{"X":1}},"expect":{"match":true}}]}`,
		"probe no status": `{"schema_version":"0.1.0","cases":[{"id":"a","rule":{"technology":"php","observation":"x"},"input":{"probes":{"/a":{}}},"expect":{"match":true}}]}`,
		"extra field":     `{"schema_version":"0.1.0","cases":[],"x":1}`,
	} {
		if err := ValidateCases([]byte(doc)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}
