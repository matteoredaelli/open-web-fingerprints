// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package blocklist

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

func parseFile(t *testing.T, format, name string) (Rules, Stats) {
	t.Helper()
	f, err := os.Open("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	r, st, err := Parse(format, f)
	if err != nil {
		t.Fatal(err)
	}
	return r, st
}

func TestParseHosts(t *testing.T) {
	r, st := parseFile(t, FormatHosts, "hosts.txt")
	want := []string{"bad.example", "two.example", "three.example"}
	if !reflect.DeepEqual(r.Block, want) {
		t.Errorf("block %v, want %v", r.Block, want)
	}
	// localhost x2, ip6-localhost, broadcasthost are not domains; one line is no hosts line.
	if st.Skipped["not a domain"] != 4 || st.Skipped["not a hosts line"] != 1 {
		t.Errorf("skipped %v", st.Skipped)
	}
}

func TestParseDomains(t *testing.T) {
	r, st := parseFile(t, FormatDomains, "domains.txt")
	want := []string{"alpha.example", "wild.example", "beta.example"}
	if !reflect.DeepEqual(r.Block, want) {
		t.Errorf("block %v, want %v", r.Block, want)
	}
	if st.Skipped["not a domain"] != 3 { // IP, two words, nodot
		t.Errorf("skipped %v", st.Skipped)
	}
}

func TestParseAdblock(t *testing.T) {
	r, st := parseFile(t, FormatAdblock, "adblock.txt")
	if want := []string{"ads.example", "tracker.example", "good.example"}; !reflect.DeepEqual(r.Block, want) {
		t.Errorf("block %v, want %v", r.Block, want)
	}
	if want := []string{"good.example"}; !reflect.DeepEqual(r.Allow, want) {
		t.Errorf("allow %v, want %v", r.Allow, want)
	}
	want := map[string]int{"options": 1, "path or pattern": 2, "regex": 1, "cosmetic": 1, "not a domain rule": 1, "not a domain": 1}
	if !reflect.DeepEqual(st.Skipped, want) {
		t.Errorf("skipped %v, want %v", st.Skipped, want)
	}
	if st.Blocked != 3 || st.Allowed != 1 {
		t.Errorf("stats %+v", st)
	}
}

func TestParseErrors(t *testing.T) {
	if _, _, err := Parse("csv", strings.NewReader("")); err == nil {
		t.Error("unknown format accepted")
	}
	if _, _, err := Parse(FormatDomains, strings.NewReader(strings.Repeat("a", maxLine+10))); err == nil {
		t.Error("giant line accepted")
	}
}

func build(t *testing.T, exclude ...string) *Filter {
	t.Helper()
	f, err := New(exclude)
	if err != nil {
		t.Fatal(err)
	}
	add := func(name, cat string, r Rules) {
		if err := f.Add(name, cat, r); err != nil {
			t.Fatal(err)
		}
	}
	add("porn", "adult", Rules{Block: []string{"adult.example", "sub.shared.example"}})
	add("adlist", "ads", Rules{Block: []string{"ads.example", "good.example"}, Allow: []string{"good.example"}})
	add("mal", "malware", Rules{Block: []string{"shared.example"}, Allow: []string{"ok.shared.example"}})
	return f
}

func TestCheck(t *testing.T) {
	f := build(t, "adult", "malware") // ads is not excluded
	for host, want := range map[string]string{
		"adult.example":          "porn",
		"WWW.Adult.Example.":     "porn",
		"a.b.adult.example":      "porn",
		"shared.example":         "mal",
		"x.shared.example":       "mal",
		"ok.shared.example":      "", // exception of the same list
		"deep.ok.shared.example": "",
		"ads.example":            "",    // category not blocked
		"sub.shared.example":     "mal", // the wider entry wins
		"example":                "",
		"notadult.example":       "", // label match, not substring
		"example.com":            "",
		"":                       "",
	} {
		if v := f.Check(host); v.List != want || v.Blocked != (want != "") {
			t.Errorf("%q: %+v, want list %q", host, v, want)
		}
	}
	if v := f.Check("a.adult.example"); v.Entry != "adult.example" || v.Category != "adult" {
		t.Errorf("entry %+v", v)
	}
}

func TestParentOfEntryIsNotBlocked(t *testing.T) {
	f := build(t, "adult")
	if f.Check("example").Blocked || f.Check("shared.example").Blocked {
		t.Error("the parent of an entry must not be blocked")
	}
}

func TestExceptionOnlyCancelsItsOwnList(t *testing.T) {
	f, _ := New([]string{"ads", "malware"})
	_ = f.Add("a", "ads", Rules{Block: []string{"x.example"}, Allow: []string{"x.example"}})
	_ = f.Add("b", "malware", Rules{Block: []string{"x.example"}})
	if v := f.Check("x.example"); !v.Blocked || v.List != "b" {
		t.Errorf("%+v", v)
	}
}

func TestAddAndNewErrors(t *testing.T) {
	if _, err := New([]string{"nope"}); err == nil {
		t.Error("unknown category accepted")
	}
	f, _ := New(nil)
	if err := f.Add("a", "nope", Rules{}); err == nil {
		t.Error("unknown list category accepted")
	}
	_ = f.Add("a", "ads", Rules{})
	if err := f.Add("a", "ads", Rules{}); err == nil {
		t.Error("duplicate name accepted")
	}
	for i := 0; i < maxLists; i++ {
		_ = f.Add(string(rune('A'+i/26))+string(rune('a'+i%26)), "ads", Rules{})
	}
	if err := f.Add("overflow", "ads", Rules{}); err == nil {
		t.Error("more than 64 lists accepted")
	}
}

func TestNormalize(t *testing.T) {
	for in, ok := range map[string]bool{"a.com": true, "A.Com.": true, "xn--bcher-kva.example": true, "a_b.com": true,
		"a": false, "1.2.3.4": false, "::1": false, "-a.com": false, "a..com": false, "a b.com": false, "*.a.com": false} {
		if _, got := Normalize(in); got != ok {
			t.Errorf("%q: %v, want %v", in, got, ok)
		}
	}
}
