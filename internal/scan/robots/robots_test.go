package robots

import (
	"testing"
	"time"
)

func TestAllowed(t *testing.T) {
	file := `
# comment
User-agent: *
Disallow: /private/
Disallow: /*.pdf$
Disallow: /search?
Allow: /private/public/
Crawl-delay: 2

User-agent: owfscan
Disallow: /secret
Allow: /secret/open

User-agent: otherbot
Disallow: /
`
	star := Parse(file, "mybot")
	mine := Parse(file, "owfscan/1.0")
	for _, tc := range []struct {
		r    *Rules
		url  string
		want bool
	}{
		{star, "https://e.org/", true},
		{star, "https://e.org/about", true},
		{star, "https://e.org/private/x", false},
		{star, "https://e.org/private/public/x", true}, // longest rule wins
		{star, "https://e.org/file.pdf", false},
		{star, "https://e.org/dir/file.pdf", false},
		{star, "https://e.org/file.pdf?x=1", true}, // "$" anchors the end of path and query
		{star, "https://e.org/file.pdfx", true},
		{star, "https://e.org/search?q=1", false},
		{star, "https://e.org/search", true},
		{star, "https://e.org/robots.txt", true},
		{mine, "https://e.org/private/x", true}, // its own group replaces "*"
		{mine, "https://e.org/secret", false},
		{mine, "https://e.org/secret/open", true},
		{mine, "https://e.org/secretive", false}, // prefix match
	} {
		if got := tc.r.Allowed(tc.url); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.url, got, tc.want)
		}
	}
	if star.CrawlDelay != 2*time.Second || mine.CrawlDelay != 0 {
		t.Errorf("crawl delay: %v %v", star.CrawlDelay, mine.CrawlDelay)
	}
}

func TestEdgeCases(t *testing.T) {
	var nilRules *Rules
	if !nilRules.Allowed("https://e.org/x") {
		t.Error("no rules allow everything")
	}
	for name, text := range map[string]string{
		"empty": "", "no group": "Disallow: /", "garbage": "\x00\x01 not a robots file", "empty disallow": "User-agent: *\nDisallow:",
	} {
		if !Parse(text, "owfscan").Allowed("https://e.org/x") {
			t.Errorf("%s must allow everything", name)
		}
	}
	if Parse("User-agent: *\nDisallow: /", "owfscan").Allowed("https://e.org/x") {
		t.Error("Disallow: / blocks everything")
	}
	// Several agents share one group; the order of lines and CRLF do not matter.
	multi := Parse("User-agent: a\r\nUser-agent: owfscan\r\nDisallow: /x\r\n", "owfscan")
	if multi.Allowed("https://e.org/x") || !multi.Allowed("https://e.org/y") {
		t.Error("a group can name several agents")
	}
	// The more specific agent wins over "*" and over a shorter token.
	specific := Parse("User-agent: *\nDisallow: /\nUser-agent: owf\nDisallow: /a\nUser-agent: owfscan\nDisallow: /b\n", "owfscan")
	if !specific.Allowed("https://e.org/a") || specific.Allowed("https://e.org/b") {
		t.Error("the longest matching agent token wins")
	}
	// Allow wins a tie of equal length.
	tie := Parse("User-agent: *\nDisallow: /p\nAllow: /p\n", "x")
	if !tie.Allowed("https://e.org/p") {
		t.Error("Allow wins a tie")
	}
	if !Parse("User-agent: *\nDisallow: /a\n", "x").Allowed("::bad") {
		t.Error("an unparsable URL is treated as the root")
	}
	if d := Parse("User-agent: *\nCrawl-delay: 99999\n", "x").CrawlDelay; d != 0 {
		t.Errorf("an absurd delay is ignored: %v", d)
	}
}
