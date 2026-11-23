// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package scanner

import (
	"testing"

	"github.com/matteoredaelli/open-web-fingerprints/scan"
)

func TestSplitDomainSignals(t *testing.T) {
	dns := scan.Technology{Name: "Atlassian Cloud", Evidence: []scan.Evidence{{Observation: "dns_record"}}}
	mixed := scan.Technology{Name: "Cloudflare", Evidence: []scan.Evidence{{Observation: "dns_record"}, {Observation: "http_header"}}}
	web := scan.Technology{Name: "PHP", Evidence: []scan.Evidence{{Observation: "http_header"}}}
	w, d := splitDomainSignals([]scan.Technology{dns, mixed, web})
	if len(w) != 2 || len(d) != 1 || d[0].Name != "Atlassian Cloud" {
		t.Errorf("web %v domain %v", w, d)
	}
}
