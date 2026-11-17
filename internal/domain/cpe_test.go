// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package domain

import "testing"

func TestCPEVendor(t *testing.T) {
	for in, want := range map[string]string{
		"cpe:2.3:a:adobe:experience_manager:*:*:*:*:*:*:*:*": "adobe",
		"cpe:2.3:a:F5:nginx:*:*:*:*:*:*:*:*":                 "f5",
		`cpe:2.3:a:vendor\:with\:colons:app:*:*:*:*:*:*:*:*`: "",
		"cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*":       "linux",
		"cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*":      "wordpress",
		"cpe:2.3:a:*:thing:*:*:*:*:*:*:*:*":                  "",
		"cpe:2.3:a:-:thing:*:*:*:*:*:*:*:*":                  "",
		"cpe:2.3:a::thing:*:*:*:*:*:*:*:*":                   "",
		"cpe:/a:adobe:experience_manager":                    "",
		"cpe:2.3:a:adobe":                                    "",
		"adobe":                                              "",
		"":                                                   "",
		"cpe:2.3:a:ado be:x:*:*:*:*:*:*:*:*":                 "",
	} {
		got, ok := CPEVendor(in)
		if got != want || ok != (want != "") {
			t.Errorf("CPEVendor(%q) = %q,%v want %q", in, got, ok, want)
		}
	}
}
