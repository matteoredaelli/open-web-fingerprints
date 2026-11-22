// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package stats

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/batch"
	"github.com/matteoredaelli/open-web-fingerprints/scan"
	"github.com/matteoredaelli/open-web-fingerprints/schemas"
)

func tech(name, version string, conf float64, obs string, cats ...string) scan.Technology {
	return scan.Technology{Name: name, Version: version, Confidence: conf, Categories: cats, Evidence: []scan.Evidence{{Observation: obs}}}
}

func result(status int, techs ...scan.Technology) []byte {
	at := time.Date(2026, 11, 22, 0, 0, 0, 0, time.UTC)
	r := scan.Result{
		SchemaVersion: scan.SchemaVersion, ScannedAt: at,
		Pages:        []scan.Page{{Status: status, Headers: map[string]string{"strict-transport-security": "x"}}},
		Technologies: techs, Socials: []scan.Social{{Platform: "linkedin", Handle: "secret-handle"}},
		Contacts: []scan.Contact{{Kind: "email", Value: "private@x.example"}},
		Host:     &scan.Host{TLS: &scan.TLS{Issuer: "CN=R3,O=Let's Encrypt", NotAfter: at.Add(45 * 24 * time.Hour)}},
		Coverage: scan.Coverage{RulesTotal: 10, RulesEvaluated: 6},
		Registry: scan.RegistryRef{ContentSHA256: "sha256:abc", Sources: []string{"s"}},
	}
	b, _ := json.Marshal(r)
	return b
}

func TestCompute(t *testing.T) {
	ctx := context.Background()
	st, err := batch.Open(ctx, filepath.Join(t.TempDir(), "b.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	var sites []batch.Site
	for i, d := range []string{"a.example", "b.example", "c.example", "d.example", "e.example", "f.example"} {
		sites = append(sites, batch.Site{Domain: d, Rank: i + 1})
	}
	_, _ = st.Add(ctx, sites)
	_ = st.SetMeta(ctx, "list", "top.txt")
	now := time.Now()
	wp := func(v string) []scan.Technology {
		return []scan.Technology{tech("WordPress", v, 0.8, "html", "CMS"), tech("PHP", "", 0.7, "http_header", "Programming languages"), tech("Anthropic", "", 0.5, "dns_record", "Security")}
	}
	_ = st.SaveDone(ctx, "a.example", 200, result(200, wp("6.4")...), now)
	_ = st.SaveDone(ctx, "b.example", 200, result(200, wp("6.4")...), now)
	_ = st.SaveDone(ctx, "c.example", 200, result(200, append(wp("6.5"), tech("Rare", "", 0.9, "html", "Misc"), tech("Weak", "", 0.2, "html", "Misc"))...), now)
	_ = st.SaveDone(ctx, "d.example", 403, result(403, wp("1")...), now) // scanned, not reached
	_ = st.SaveFailed(ctx, "e.example", "dns: no such host", now)

	s, err := Compute(ctx, st, Options{MinConfidence: 0.3, MinSites: 2, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if s.Sites.Listed != 6 || s.Sites.Scanned != 4 || s.Sites.Reached != 3 || s.Sites.Failed != 1 || s.Sites.Pending != 1 {
		t.Errorf("sites %+v", s.Sites)
	}
	if len(s.Technologies) < 2 || s.Technologies[0].Name != "PHP" && s.Technologies[0].Name != "WordPress" || s.Technologies[0].Sites != 3 || s.Technologies[0].Share != 1 {
		t.Errorf("technologies %+v", s.Technologies)
	}
	var wpv []scan.StatCount
	for _, x := range s.Technologies {
		if x.Name == "WordPress" {
			wpv = x.Versions
		}
		if x.Name == "Rare" || x.Name == "Weak" || x.Name == "Anthropic" {
			t.Errorf("%s must not be a web technology listed here", x.Name)
		}
	}
	if len(wpv) != 1 || wpv[0].Name != "6.4" || wpv[0].Sites != 2 {
		t.Errorf("versions %+v (6.5 is on one site, under min_sites)", wpv)
	}
	if len(s.DomainSignals) != 1 || s.DomainSignals[0].Name != "Anthropic" {
		t.Errorf("domain signals %+v", s.DomainSignals)
	}
	if s.Other.TechnologiesHidden != 1 { // Rare: one site; Weak is under the confidence filter and not counted
		t.Errorf("hidden %d", s.Other.TechnologiesHidden)
	}
	if s.Headers[0].Name != "strict-transport-security" || s.Headers[0].Sites != 3 {
		t.Errorf("headers %+v", s.Headers)
	}
	if s.TLS.WithCertificate != 3 || s.TLS.DaysLeft[0].Name != "30 to 59 days" || s.TLS.Issuers[0].Name != "Let's Encrypt" {
		t.Errorf("tls %+v", s.TLS)
	}
	if len(s.Pairs) == 0 || s.Pairs[0].Sites != 3 {
		t.Errorf("pairs %+v", s.Pairs)
	}
	b, _ := json.Marshal(s)
	if err := schemas.ValidateStats(b); err != nil {
		t.Errorf("schema: %v", err)
	}
	for _, leak := range []string{"secret-handle", "private@x.example", "a.example", "b.example"} {
		if strings.Contains(string(b), leak) {
			t.Errorf("site-level data %q leaked into the statistics", leak)
		}
	}
	// Excluding a technology removes it.
	s2, _ := Compute(ctx, st, Options{MinSites: 2, Exclude: []string{"php"}})
	for _, x := range s2.Technologies {
		if x.Name == "PHP" {
			t.Error("excluded technology listed")
		}
	}
}
