// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package nuclei

import (
	"reflect"
	"testing"
)

func TestParseDSL(t *testing.T) {
	ok := map[string][]dslTerm{
		`status_code == 200`:                                    {{kind: "status", status: 200}},
		`status_code==200 && regex("a\\.b", body)`:              {{kind: "status", status: 200}, {kind: "regex", part: "body", args: []string{`a\.b`}}},
		`contains(body, "x")`:                                   {{kind: "contains", part: "body", args: []string{"x"}}},
		`contains(header, "x: y")`:                              {{kind: "contains", part: "header", args: []string{"x: y"}}},
		`contains(content_type, "json")`:                        {{kind: "contains", part: "content_type", args: []string{"json"}}},
		`contains(to_lower(body), "x")`:                         {{kind: "contains", part: "body", args: []string{"x"}, lower: true}},
		`contains(tolower(header), "x")`:                        {{kind: "contains", part: "header", args: []string{"x"}, lower: true}},
		`contains_any(body, "a", "b")`:                          {{kind: "any", part: "body", args: []string{"a", "b"}}},
		`contains_all(to_lower(body), "a", "b")`:                {{kind: "all", part: "body", args: []string{"a", "b"}, lower: true}},
		`contains(body, "say \"hi\"")`:                          {{kind: "contains", part: "body", args: []string{`say "hi"`}}},
		`contains(body, "a && b")`:                              {{kind: "contains", part: "body", args: []string{"a && b"}}},
		`status_code==200 && ("-123" == mmh3(base64_py(body)))`: {{kind: "status", status: 200}, {kind: "mmh3", part: "body", args: []string{"-123"}}},
		`(status_code == 200) && (contains(body, "x"))`:         {{kind: "status", status: 200}, {kind: "contains", part: "body", args: []string{"x"}}},
	}
	for in, want := range ok {
		got, err := parseDSL(in)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("parseDSL(%s)\n got %+v err=%v\nwant %+v", in, got, err, want)
		}
	}
	bad := []string{
		``, `status_code != 200`, `status_code == 200 || status_code == 301`, `!contains(body, "x")`,
		`compare_versions(version, "< 1.0")`, `regex("x", all_headers)`, `contains(body, x)`,
		`contains(body, "a", "b")`, `contains_any(body)`, `"h" == md5(body)`, `len(body) > 10`,
		`contains(body, "a") && foo(body)`, `contains(to_lower(body), "a" "b")`,
	}
	for _, in := range bad {
		if got, err := parseDSL(in); err == nil {
			t.Errorf("parseDSL(%q) must fail, got %+v", in, got)
		}
	}
}

func TestSplitAndRespectsQuotesAndParentheses(t *testing.T) {
	for in, want := range map[string]int{
		`a && b`: 2, `a && b && c`: 3, `contains(body, "a && b")`: 1, `f(a && b) && c`: 2, `"x\"&&y" && z`: 2, `a`: 1,
	} {
		if got := splitAnd(in); len(got) != want {
			t.Errorf("splitAnd(%q) = %q, want %d parts", in, got, want)
		}
	}
}
