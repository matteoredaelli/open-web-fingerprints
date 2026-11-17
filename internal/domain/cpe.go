// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package domain

import "strings"

// CPEVendor returns the vendor field of a CPE 2.3 formatted string, for
// example "adobe" for "cpe:2.3:a:adobe:experience_manager:*:*:...". The vendor
// field is an identifier of the NVD dictionary, not a free-form name. It
// returns false for strings that are not CPE 2.3 or have no usable vendor.
func CPEVendor(cpe string) (string, bool) {
	parts := splitCPE(cpe)
	if len(parts) < 5 || parts[0] != "cpe" || parts[1] != "2.3" {
		return "", false
	}
	v := strings.ToLower(parts[3])
	if v == "" || v == "*" || v == "-" || strings.ContainsAny(v, `\ `) {
		return "", false
	}
	return v, true
}

// splitCPE splits on ':' that are not escaped with a backslash.
func splitCPE(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++ // skip the escaped character
		case ':':
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}
