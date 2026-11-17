// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package pipeline

import (
	"strings"
	"testing"
	"testing/fstest"
)

func TestChecksumSnapshot(t *testing.T) {
	base := fstest.MapFS{
		"a.json":     {Data: []byte("1")},
		"dir/b.json": {Data: []byte("2")},
		".git/HEAD":  {Data: []byte("ref")},
	}
	sum, files, err := checksumSnapshot(base, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 || !strings.HasPrefix(sum, "sha256:") {
		t.Fatalf("files=%v sum=%s", files, sum)
	}
	again, _, _ := checksumSnapshot(base, nil)
	if again != sum {
		t.Error("checksum must be deterministic")
	}

	changed := fstest.MapFS{"a.json": {Data: []byte("1")}, "dir/b.json": {Data: []byte("3")}}
	if s, _, _ := checksumSnapshot(changed, nil); s == sum {
		t.Error("content change must change the checksum")
	}
	renamed := fstest.MapFS{"a.json": {Data: []byte("1")}, "dir/c.json": {Data: []byte("2")}}
	if s, _, _ := checksumSnapshot(renamed, nil); s == sum {
		t.Error("rename must change the checksum")
	}
	onlyA, files, _ := checksumSnapshot(base, func(p string) bool { return p == "a.json" })
	if len(files) != 1 || onlyA == sum {
		t.Errorf("filter not applied: %v", files)
	}
	if _, _, err := checksumSnapshot(base, func(string) bool { return false }); err == nil {
		t.Error("empty selection must fail")
	}
}
