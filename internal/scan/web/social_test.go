// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package web

import "testing"

type prof struct{ platform, kind, handle, url string }

func TestParseProfile(t *testing.T) {
	cases := map[string]prof{
		"https://www.linkedin.com/company/Example-Tyres/":                 {"linkedin", "company", "example-tyres", "https://www.linkedin.com/company/example-tyres"},
		"https://it.linkedin.com/in/jane-doe-123":                         {"linkedin", "user", "jane-doe-123", "https://www.linkedin.com/in/jane-doe-123"},
		"https://www.linkedin.com/school/uni-x/":                          {"linkedin", "school", "uni-x", "https://www.linkedin.com/school/uni-x"},
		"https://www.linkedin.com/showcase/product-y":                     {"linkedin", "showcase", "product-y", "https://www.linkedin.com/showcase/product-y"},
		"https://github.com/Example-Tyres":                                {"github", "account", "example-tyres", "https://github.com/example-tyres"},
		"https://github.com/example-tyres/":                               {"github", "account", "example-tyres", "https://github.com/example-tyres"},
		"https://gitlab.com/example":                                      {"gitlab", "account", "example", "https://gitlab.com/example"},
		"https://gitlab.com/groups/example-group":                         {"gitlab", "group", "example-group", "https://gitlab.com/example-group"},
		"https://bitbucket.org/example":                                   {"bitbucket", "account", "example", "https://bitbucket.org/example"},
		"https://www.facebook.com/exampletyres":                           {"facebook", "page", "exampletyres", "https://www.facebook.com/exampletyres"},
		"https://m.facebook.com/exampletyres/":                            {"facebook", "page", "exampletyres", "https://www.facebook.com/exampletyres"},
		"https://fb.com/exampletyres":                                     {"facebook", "page", "exampletyres", "https://www.facebook.com/exampletyres"},
		"https://www.facebook.com/profile.php?id=100012345678":            {"facebook", "profile", "100012345678", "https://www.facebook.com/profile.php?id=100012345678"},
		"https://www.facebook.com/groups/example.group":                   {"facebook", "group", "example.group", "https://www.facebook.com/groups/example.group"},
		"https://www.facebook.com/pg/exampletyres/posts":                  {"facebook", "page", "exampletyres", "https://www.facebook.com/exampletyres"},
		"https://www.instagram.com/example.tyres/":                        {"instagram", "user", "example.tyres", "https://www.instagram.com/example.tyres/"},
		"https://twitter.com/ExampleTyres":                                {"x", "user", "exampletyres", "https://x.com/exampletyres"},
		"https://x.com/exampletyres/":                                     {"x", "user", "exampletyres", "https://x.com/exampletyres"},
		"https://mobile.twitter.com/exampletyres":                         {"x", "user", "exampletyres", "https://x.com/exampletyres"},
		"https://www.tiktok.com/@example.tyres":                           {"tiktok", "user", "example.tyres", "https://www.tiktok.com/@example.tyres"},
		"https://www.threads.net/@exampletyres":                           {"threads", "user", "exampletyres", "https://www.threads.net/@exampletyres"},
		"https://bsky.app/profile/example.bsky.social":                    {"bluesky", "user", "example.bsky.social", "https://bsky.app/profile/example.bsky.social"},
		"https://www.snapchat.com/add/exampletyres":                       {"snapchat", "user", "exampletyres", "https://www.snapchat.com/add/exampletyres"},
		"https://www.reddit.com/r/Tyres/":                                 {"reddit", "subreddit", "tyres", "https://www.reddit.com/r/tyres"},
		"https://www.reddit.com/user/example_tyres":                       {"reddit", "user", "example_tyres", "https://www.reddit.com/user/example_tyres"},
		"https://www.pinterest.com/exampletyres/":                         {"pinterest", "user", "exampletyres", "https://www.pinterest.com/exampletyres/"},
		"https://exampletyres.tumblr.com/":                                {"tumblr", "blog", "exampletyres", "https://exampletyres.tumblr.com"},
		"https://weibo.com/u/1234567890":                                  {"weibo", "user", "1234567890", "https://weibo.com/u/1234567890"},
		"https://vk.com/exampletyres":                                     {"vk", "page", "exampletyres", "https://vk.com/exampletyres"},
		"https://www.youtube.com/@ExampleTyres":                           {"youtube", "channel", "@exampletyres", "https://www.youtube.com/@exampletyres"},
		"https://www.youtube.com/channel/UCabcdefghijklmnopqrstuv":        {"youtube", "channel", "UCabcdefghijklmnopqrstuv", "https://www.youtube.com/channel/UCabcdefghijklmnopqrstuv"},
		"https://www.youtube.com/c/ExampleTyres":                          {"youtube", "channel", "exampletyres", "https://www.youtube.com/c/exampletyres"},
		"https://www.youtube.com/user/ExampleTyres":                       {"youtube", "user", "exampletyres", "https://www.youtube.com/user/exampletyres"},
		"https://vimeo.com/exampletyres":                                  {"vimeo", "user", "exampletyres", "https://vimeo.com/exampletyres"},
		"https://www.twitch.tv/exampletyres":                              {"twitch", "channel", "exampletyres", "https://www.twitch.tv/exampletyres"},
		"https://soundcloud.com/example-tyres":                            {"soundcloud", "user", "example-tyres", "https://soundcloud.com/example-tyres"},
		"https://open.spotify.com/artist/4Z8W4fKeB5YxbusRsdQVPb":          {"spotify", "artist", "4Z8W4fKeB5YxbusRsdQVPb", "https://open.spotify.com/artist/4Z8W4fKeB5YxbusRsdQVPb"},
		"https://www.flickr.com/photos/exampletyres/":                     {"flickr", "user", "exampletyres", "https://www.flickr.com/photos/exampletyres"},
		"https://t.me/exampletyres":                                       {"telegram", "account", "exampletyres", "https://t.me/exampletyres"},
		"https://t.me/+AbCdEfGhIjKl":                                      {"telegram", "invite", "AbCdEfGhIjKl", "https://t.me/+AbCdEfGhIjKl"},
		"https://wa.me/390212345678":                                      {"whatsapp", "number", "390212345678", "https://wa.me/390212345678"},
		"https://api.whatsapp.com/send?phone=390212345678":                {"whatsapp", "number", "390212345678", "https://wa.me/390212345678"},
		"https://chat.whatsapp.com/AbCdEfGhIjKlMn":                        {"whatsapp", "invite", "AbCdEfGhIjKlMn", "https://chat.whatsapp.com/AbCdEfGhIjKlMn"},
		"https://discord.gg/exampletyres":                                 {"discord", "invite", "exampletyres", "https://discord.gg/exampletyres"},
		"https://discord.com/invite/exampletyres":                         {"discord", "invite", "exampletyres", "https://discord.gg/exampletyres"},
		"https://www.behance.net/exampletyres":                            {"behance", "user", "exampletyres", "https://www.behance.net/exampletyres"},
		"https://dribbble.com/exampletyres":                               {"dribbble", "user", "exampletyres", "https://dribbble.com/exampletyres"},
		"https://medium.com/@exampletyres":                                {"medium", "user", "exampletyres", "https://medium.com/@exampletyres"},
		"https://engineering.medium.com/":                                 {"medium", "publication", "engineering", "https://engineering.medium.com"},
		"https://stackoverflow.com/users/12345/jane-doe":                  {"stackoverflow", "user", "12345", "https://stackoverflow.com/users/12345"},
		"https://hub.docker.com/u/exampletyres":                           {"dockerhub", "user", "exampletyres", "https://hub.docker.com/u/exampletyres"},
		"https://www.npmjs.com/~exampletyres":                             {"npm", "user", "exampletyres", "https://www.npmjs.com/~exampletyres"},
		"https://pypi.org/user/exampletyres/":                             {"pypi", "user", "exampletyres", "https://pypi.org/user/exampletyres"},
		"https://www.crunchbase.com/organization/example-tyres":           {"crunchbase", "company", "example-tyres", "https://www.crunchbase.com/organization/example-tyres"},
		"https://www.xing.com/pages/exampletyres":                         {"xing", "company", "exampletyres", "https://www.xing.com/pages/exampletyres"},
		"https://ok.ru/group/123456789":                                   {"okru", "group", "123456789", "https://ok.ru/group/123456789"},
		"https://play.google.com/store/apps/details?id=com.example.tyres": {"googleplay", "app", "com.example.tyres", "https://play.google.com/store/apps/details?id=com.example.tyres"},
		"https://apps.apple.com/it/app/example-tyres/id123456789":         {"appstore", "app", "123456789", "https://apps.apple.com/app/id123456789"},
	}
	for in, want := range cases {
		got, ok := ParseProfile(in)
		if !ok || (prof{got.Platform, got.Kind, got.Handle, got.URL}) != want {
			t.Errorf("%s\n got %+v ok=%v\nwant %+v", in, got, ok, want)
		}
	}
}

// Links on a known platform that are not profiles must not be taken for one.
func TestParseProfileRejects(t *testing.T) {
	for _, in := range []string{
		"https://www.facebook.com/sharer/sharer.php?u=https%3A%2F%2Fexample.org",
		"https://www.facebook.com/sharer.php?u=x", "https://www.facebook.com/dialog/share?app_id=1", "https://www.facebook.com/plugins/like.php",
		"https://www.facebook.com/login", "https://www.facebook.com/events/123", "https://www.facebook.com/profile.php?id=abc",
		"https://www.facebook.com/", "https://facebook.com/tr?id=123",
		"https://twitter.com/intent/tweet?text=hi", "https://twitter.com/share?url=x", "https://twitter.com/home", "https://x.com/i/flow/login",
		"https://twitter.com/search?q=x", "https://twitter.com/hashtag/tyres",
		"https://www.linkedin.com/shareArticle?mini=true&url=x", "https://www.linkedin.com/sharing/share-offsite/?url=x", "https://www.linkedin.com/feed/",
		"https://www.linkedin.com/company/", "https://www.linkedin.com/jobs/view/123",
		"https://github.com/features/actions", "https://github.com/features", "https://github.com/login", "https://github.com/sponsors", "https://github.com/",
		"https://github.com/example/repo", "https://github.com/-bad", "https://github.com/topics/tyres",
		"https://www.instagram.com/p/ABC123/", "https://www.instagram.com/explore/", "https://www.instagram.com/reel/ABC/", "https://www.instagram.com/accounts/login/",
		"https://www.tiktok.com/@user/video/123", "https://www.tiktok.com/discover", "https://www.tiktok.com/tag/tyres",
		"https://www.youtube.com/watch?v=abc", "https://www.youtube.com/embed/abc", "https://youtu.be/abc", "https://www.youtube.com/results?search_query=x",
		"https://vimeo.com/123456789", "https://vimeo.com/channels", "https://www.pinterest.com/pin/123/", "https://www.pinterest.com/pin/create/button/",
		"https://t.me/share/url?url=x", "https://t.me/joinchat", "https://wa.me/", "https://wa.me/abc", "https://api.whatsapp.com/send?text=hi",
		"https://medium.com/topic/tyres", "https://www.medium.com/", "https://stackoverflow.com/questions/1/x",
		"https://www.reddit.com/r/", "https://www.reddit.com/search?q=x", "https://www.reddit.com/",
		"https://play.google.com/store", "https://play.google.com/store/apps/details?id=", "https://apps.apple.com/it/app/",
		"https://example.org/in/jane", "https://notlinkedin.com/company/x", "https://linkedin.com.evil.example/company/x", "https://evilfacebook.com/exampletyres",
		"ftp://github.com/example", "mailto:a@b.example", "javascript:alert(1)", "", "://bad", "https://",
	} {
		if got, ok := ParseProfile(in); ok {
			t.Errorf("%q must not be a profile, got %+v", in, got)
		}
	}
}

func TestMastodonOnlyWithRelMe(t *testing.T) {
	if _, ok := ParseProfile("https://mastodon.example/@exampletyres"); ok {
		t.Error("an unknown host with /@name is not a profile without rel=me")
	}
	p, ok := mastodonProfile("https://Mastodon.Example/@ExampleTyres/")
	if !ok || p.Platform != "mastodon" || p.Handle != "@exampletyres@mastodon.example" || p.URL != "https://mastodon.example/@ExampleTyres" {
		t.Errorf("%+v ok=%v", p, ok)
	}
	for _, bad := range []string{"https://mastodon.example/", "https://mastodon.example/@a/b", "ftp://x.example/@a", "https://x.example/user"} {
		if _, ok := mastodonProfile(bad); ok {
			t.Errorf("%q", bad)
		}
	}
}

func TestPlatformTable(t *testing.T) {
	ps := Platforms()
	if len(ps) < 38 {
		t.Errorf("platforms = %d", len(ps))
	}
	for _, want := range []string{"linkedin", "facebook", "tiktok", "github", "x", "instagram", "youtube", "mastodon", "bluesky", "telegram"} {
		found := false
		for _, p := range ps {
			found = found || p == want
		}
		if !found {
			t.Errorf("platform %s is missing", want)
		}
	}
	// Every rule compiles and has a URL template, a kind and a way to read the handle.
	pl, err := loadPlatforms()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range pl {
		if len(p.Rules) == 0 && !p.Subdomain {
			t.Errorf("%s has no rule", p.Platform)
		}
		for _, r := range p.Rules {
			if r.Kind == "" || r.URL == "" || (r.Query == "" && r.pathRE.NumSubexp() < 1) {
				t.Errorf("%s rule %q is incomplete", p.Platform, r.Path)
			}
		}
	}
}
