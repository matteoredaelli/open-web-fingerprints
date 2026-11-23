// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package config

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestBotDefaults(t *testing.T) {
	b := Default().Bot
	if b.DB != "bot.db" || b.Workers != 4 || b.Depth != 0 || b.Budget != 0 || b.Until != 0 {
		t.Errorf("bot: %+v", b)
	}
	if b.Revisit.D() != 30*24*time.Hour || b.LeaseTTL.D() != 10*time.Minute || b.PerHostDelay.D() != 10*time.Second {
		t.Errorf("bot times: %+v", b)
	}
	f := b.Filter
	if f.Mode != FilterMark || !f.Require || len(f.Lists) != 0 || len(f.EnabledLists()) != 0 {
		t.Errorf("filter: %+v", f)
	}
	if !reflect.DeepEqual(f.ExcludeCategories, []string{"adult", "gambling", "malware", "phishing"}) {
		t.Errorf("categories: %v", f.ExcludeCategories)
	}
}

func TestBotFileOverridesOnlyWhatItSets(t *testing.T) {
	c, err := Parse(strings.NewReader(`
[bot]
workers = 8
revisit = "720h"
[bot.filter]
require = false
[[bot.filter.list]]
name = "one"
url = "https://example.org/hosts.txt"
category = "adult"
format = "hosts"
enabled = true
[[bot.filter.list]]
name = "two"
url = "https://example.org/ads.txt"
category = "ads"
format = "adblock"
`))
	if err != nil {
		t.Fatal(err)
	}
	if c.Bot.Workers != 8 || c.Bot.Rate != 2 || c.Bot.Filter.Require || c.Bot.Filter.Mode != FilterMark {
		t.Errorf("%+v", c.Bot)
	}
	if got := c.Bot.Filter.EnabledLists(); len(got) != 1 || got[0].Name != "one" {
		t.Errorf("enabled: %+v", got)
	}
}

func TestBotListsRoundTrip(t *testing.T) {
	c := Default()
	c.Bot.Filter.Lists = []FilterList{{Name: "a-1", URL: "https://example.org/x", Category: "malware", Format: "domains", Enabled: true}}
	var b bytes.Buffer
	if err := Write(&b, c); err != nil {
		t.Fatal(err)
	}
	got, err := Parse(&b)
	if err != nil {
		t.Fatalf("%v\n%s", err, b.String())
	}
	if !reflect.DeepEqual(got, c) {
		t.Errorf("differs:\n%+v\n%+v", got.Bot, c.Bot)
	}
}

func TestBotRejectsBadValues(t *testing.T) {
	for name, toml := range map[string]string{
		"workers":      "[bot]\nworkers = 1000",
		"rate":         "[bot]\nrate = 0",
		"rate big":     "[bot]\nrate = 1000.0",
		"depth":        "[bot]\ndepth = 2",
		"dns failures": "[bot]\ndns_failures = 99",
		"lease":        "[bot]\nlease_ttl = \"1s\"",
		"revisit":      "[bot]\nrevisit = \"1h\"",
		"revisitmax":   "[bot]\nrevisit = \"720h\"\nrevisit_max = \"48h\"",
		"mode":         "[bot.filter]\nmode = \"delete\"",
		"category":     "[bot.filter]\nexclude_categories = [\"bad\"]",
		"http":         "[[bot.filter.list]]\nname=\"a\"\nurl=\"http://x.org/l\"\ncategory=\"ads\"\nformat=\"hosts\"",
		"name":         "[[bot.filter.list]]\nname=\"A b\"\nurl=\"https://x.org/l\"\ncategory=\"ads\"\nformat=\"hosts\"",
		"format":       "[[bot.filter.list]]\nname=\"a\"\nurl=\"https://x.org/l\"\ncategory=\"ads\"\nformat=\"csv\"",
		"dup": "[[bot.filter.list]]\nname=\"a\"\nurl=\"https://x.org/l\"\ncategory=\"ads\"\nformat=\"hosts\"\n" +
			"[[bot.filter.list]]\nname=\"a\"\nurl=\"https://x.org/m\"\ncategory=\"ads\"\nformat=\"hosts\"",
		"unknown key": "[bot]\nactive = true",
		"contacts":    "[bot]\ncontacts = true",
	} {
		if _, err := Parse(strings.NewReader(toml)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
