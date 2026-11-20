// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package observe

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"testing"
)

// Vectors computed with the reference implementation (Python mmh3 and
// hashlib) on inputs of every length modulo 4 and across the 76-character line wrap.
func TestFaviconHashesMatchReference(t *testing.T) {
	var vectors []struct {
		Hex        string `json:"hex"`
		MMH3Raw    int32  `json:"mmh3_raw"`
		MMH3Shodan int32  `json:"mmh3_shodan"`
		MD5        string `json:"md5"`
	}
	b, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) < 7 {
		t.Fatalf("vectors: %d", len(vectors))
	}
	for _, v := range vectors {
		data, _ := hex.DecodeString(v.Hex)
		if got := int32(murmur3(data)); got != v.MMH3Raw {
			t.Errorf("murmur3(%d bytes) = %d, want %d", len(data), got, v.MMH3Raw)
		}
		h := FaviconHashes(data)
		if h["mmh3"] != strconv.Itoa(int(v.MMH3Shodan)) || h["md5"] != v.MD5 {
			t.Errorf("%d bytes: %v, want mmh3 %d md5 %s", len(data), h, v.MMH3Shodan, v.MD5)
		}
	}
}

func TestShodanBase64Wrap(t *testing.T) {
	// 57 bytes encode to exactly 76 characters: one full line and its newline.
	got := string(shodanBase64(make([]byte, 57)))
	if len(got) != 77 || got[76] != '\n' {
		t.Errorf("%q", got)
	}
	if string(shodanBase64(nil)) != "" {
		t.Error("nothing encodes to nothing")
	}
	if got := string(shodanBase64([]byte("a"))); got != "YQ==\n" {
		t.Errorf("%q", got)
	}
}
