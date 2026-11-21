// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package observe

import (
	"strings"
)

// Dropped reports whether a header name is on a drop list. A pattern is a lower-case
// name, or a lower-case prefix ending in "*" ("x-amz-*"). The comparison ignores case.
func Dropped(name string, drop []string) bool {
	n := strings.ToLower(name)
	for _, p := range drop {
		if strings.HasSuffix(p, "*") {
			if strings.HasPrefix(n, strings.TrimSuffix(p, "*")) {
				return true
			}
		} else if n == p {
			return true
		}
	}
	return false
}

// FilterHeaders returns a copy of h without the headers on the drop list. The rules
// are applied to the full set of headers; this is only for what is written out, so
// that headers that change on every call (date, request ids, cache hits) do not make
// two runs on the same site differ.
func FilterHeaders(h map[string]string, drop []string) map[string]string {
	if len(drop) == 0 || h == nil {
		return h
	}
	out := make(map[string]string, len(h))
	for k, v := range h {
		if !Dropped(k, drop) {
			out[k] = v
		}
	}
	return out
}
