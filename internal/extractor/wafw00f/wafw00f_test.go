// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package wafw00f

import (
	"context"
	"os"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/matteoredaelli/open-web-fingerprints/internal/domain"
	"github.com/matteoredaelli/open-web-fingerprints/internal/extractor"
	"github.com/matteoredaelli/open-web-fingerprints/internal/extractor/extractortest"
)

func fixtureSource() extractor.Source {
	return extractor.Source{
		ID: "enablesecurity-wafw00f", URL: "https://github.com/EnableSecurity/wafw00f",
		Revision: "69fbe39", License: "BSD-3-Clause", FS: os.DirFS("testdata/snapshot"),
	}
}

func TestContract(t *testing.T) {
	extractortest.RunContract(t, New(), fixtureSource())
}

func one(t *testing.T, body string) *extractor.ExtractionResult {
	t.Helper()
	src := extractor.Source{ID: "w", FS: fstest.MapFS{"wafw00f/plugins/p.py": {Data: []byte("NAME = 'Acme WAF (Acme Inc.)'\n\n\n" + body)}}}
	res, err := New().Extract(context.Background(), src)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func skips(res *extractor.ExtractionResult) string {
	var out []string
	for _, w := range res.Warnings {
		if w.Code == "skipped" {
			out = append(out, w.Message)
		}
	}
	return strings.Join(out, "\n")
}

func TestFixtures(t *testing.T) {
	res, err := New().Extract(context.Background(), fixtureSource())
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]string{}
	for _, tc := range res.Technologies {
		names[tc.Key] = tc.Name
	}
	if names["cloudflare"] != "Cloudflare" || names["alertlogic"] != "" {
		t.Errorf("technologies: %v", names)
	}
	var cfRay, cookie, group bool
	for _, f := range res.Fingerprints {
		switch {
		case f.TechnologyKey == "cloudflare" && f.Target == "cf-ray" && f.Operator == domain.OpExists:
			cfRay = true
		case f.TechnologyKey == "cloudflare" && f.Observation == "set_cookie" && f.Pattern == "__cfduid":
			cookie = true
		case f.TechnologyKey == "f5firepass" && f.GroupKey == "f5firepass#a0":
			group = true
		}
	}
	if !cfRay || !cookie || !group {
		t.Errorf("cfRay=%v cookie=%v group=%v", cfRay, cookie, group)
	}
	if !strings.Contains(skips(res), "attack payload (matchContent)") {
		t.Errorf("attack terms not counted:\n%s", skips(res))
	}
}

func TestAttackResponseIsNeverRead(t *testing.T) {
	res := one(t, `def is_waf(self):
    if self.matchContent('blocked'):
        return True

    if self.matchHeader(('Server', 'acme'), attack=True):
        return True

    if self.matchStatus(403) and self.matchHeader(('X-Acme', '.+')):
        return True

    return False
`)
	if len(res.Technologies) != 0 || len(res.Fingerprints) != 0 {
		t.Errorf("attack-only plugin produced %d technologies, %d rules", len(res.Technologies), len(res.Fingerprints))
	}
}

func TestGuardsBecomeGroups(t *testing.T) {
	res := one(t, `def is_waf(self):
    if not self.matchCookie('^A'):
        return False

    if not self.matchHeader(('X-B', 'b')):
        return False

    return True
`)
	if len(res.Fingerprints) != 2 || res.Fingerprints[0].GroupKey == "" || res.Fingerprints[0].GroupKey != res.Fingerprints[1].GroupKey {
		t.Fatalf("want one group of two rules: %+v", res.Fingerprints)
	}
}

// A required term that cannot be read must drop the alternative: keeping the
// rest would match more than the plugin does.
func TestUnreadableRequirementDropsAlternative(t *testing.T) {
	res := one(t, `def is_waf(self):
    if self.matchHeader(('X-One', '1')):
        return True

    if not self.matchContent('x'):
        return False

    if self.matchHeader(('X-Two', '2')):
        return True

    return False
`)
	if len(res.Fingerprints) != 1 || res.Fingerprints[0].Target != "X-One" {
		t.Errorf("got %+v", res.Fingerprints)
	}
}

func TestPositiveReturnFalseStopsReading(t *testing.T) {
	res := one(t, `def is_waf(self):
    if self.matchHeader(('X-One', '1')):
        return True

    if self.matchHeader(('X-No', 'n')):
        return False

    if self.matchHeader(('X-Two', '2')):
        return True

    return False
`)
	if len(res.Fingerprints) != 1 || res.Fingerprints[0].Target != "X-One" {
		t.Errorf("got %+v", res.Fingerprints)
	}
}

func TestOrAndMultilineCondition(t *testing.T) {
	res := one(t, `def is_waf(self):
    if self.matchHeader(('A', 'a')) and \
        self.matchCookie('c'):
        return True

    if (self.matchHeader(('B', 'b'))
            or self.matchHeader(('C', 'c'))):
        return True

    return False
`)
	if len(res.Fingerprints) != 4 {
		t.Fatalf("want 1 group of 2 + 2 single rules, got %+v", res.Fingerprints)
	}
}
