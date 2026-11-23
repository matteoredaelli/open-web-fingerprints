// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package bot

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/bot/blocklist"
	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/config"
	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/fetch"
)

// MaxListBytes is the largest list downloaded; the biggest public lists are a few tens of MB.
const MaxListBytes = 128 << 20

// ListNote is what is kept about a downloaded list, in <name>.json next to <name>.list.
type ListNote struct {
	Name      string         `json:"name"`
	URL       string         `json:"url"`
	Category  string         `json:"category"`
	Format    string         `json:"format"`
	FetchedAt time.Time      `json:"fetched_at"`
	Bytes     int64          `json:"bytes"`
	SHA256    string         `json:"sha256"`
	Blocked   int            `json:"blocked"`
	Allowed   int            `json:"allowed"`
	Skipped   map[string]int `json:"skipped,omitempty"`
}

// RefreshResult is the outcome for one list.
type RefreshResult struct {
	Name string
	Note ListNote
	Err  error
}

func listPath(dir, name string) string { return filepath.Join(dir, name+".list") }
func notePath(dir, name string) string { return filepath.Join(dir, name+".json") }

// Refresh downloads every enabled list into dir. Each file is replaced only by a list
// that downloaded whole, parsed, and has at least one entry: a failure leaves the
// previous copy in place. A failure on one list does not stop the others.
// client may be nil; then a client with a timeout is used.
func Refresh(ctx context.Context, dir string, lists []config.FilterList, client *http.Client, now func() time.Time) ([]RefreshResult, error) {
	if len(lists) == 0 {
		return nil, errors.New("bot: no filter list is enabled (see [[bot.filter.list]] in the configuration)")
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("bot: %w", err)
	}
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Minute}
	}
	if now == nil {
		now = time.Now
	}
	// Redirects must stay on https: a list is never read over a downgraded connection.
	c := *client
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if req.URL.Scheme != "https" {
			return errors.New("redirect to a non-https address")
		}
		if len(via) >= 5 {
			return errors.New("too many redirects")
		}
		return nil
	}
	out := make([]RefreshResult, 0, len(lists))
	for _, l := range lists {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		note, err := refreshOne(ctx, &c, dir, l, now())
		out = append(out, RefreshResult{Name: l.Name, Note: note, Err: err})
	}
	return out, nil
}

func refreshOne(ctx context.Context, c *http.Client, dir string, l config.FilterList, now time.Time) (ListNote, error) {
	note := ListNote{Name: l.Name, URL: l.URL, Category: l.Category, Format: l.Format, FetchedAt: now.UTC()}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, l.URL, nil)
	if err != nil {
		return note, err
	}
	req.Header.Set("User-Agent", fetch.DefaultUserAgent)
	resp, err := c.Do(req)
	if err != nil {
		return note, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return note, fmt.Errorf("status %d", resp.StatusCode)
	}
	tmp, err := os.CreateTemp(dir, l.Name+".*.tmp")
	if err != nil {
		return note, err
	}
	defer func() { _ = os.Remove(tmp.Name()) }() // no-op after a successful rename
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(resp.Body, MaxListBytes+1))
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return note, err
	}
	if n > MaxListBytes {
		return note, fmt.Errorf("larger than %d bytes", MaxListBytes)
	}
	f, err := os.Open(tmp.Name()) //nolint:gosec // our own temporary file
	if err != nil {
		return note, err
	}
	rules, st, err := blocklist.Parse(l.Format, f)
	_ = f.Close()
	if err != nil {
		return note, err
	}
	if len(rules.Block) == 0 {
		return note, fmt.Errorf("no entry read as %q (wrong format or not a list); the previous copy is kept", l.Format)
	}
	note.Bytes, note.SHA256 = n, hex.EncodeToString(h.Sum(nil))
	note.Blocked, note.Allowed, note.Skipped = st.Blocked, st.Allowed, st.Skipped
	if err := os.Rename(tmp.Name(), listPath(dir, l.Name)); err != nil {
		return note, err
	}
	b, _ := json.MarshalIndent(note, "", "  ")
	return note, os.WriteFile(notePath(dir, l.Name), append(b, '\n'), 0o600)
}

// LoadedList describes a list in a Filter.
type LoadedList struct {
	config.FilterList
	Note ListNote
}

// Load builds the filter from the downloaded copies of the enabled lists. A list with
// no copy is an error: the crawler must not start with a filter that is silently weaker
// than the one that was asked for.
func Load(dir string, f config.BotFilter) (*blocklist.Filter, []LoadedList, error) {
	flt, err := blocklist.New(f.ExcludeCategories)
	if err != nil {
		return nil, nil, err
	}
	var loaded []LoadedList
	for _, l := range f.EnabledLists() {
		fh, err := os.Open(listPath(dir, l.Name)) //nolint:gosec // dir and name come from the configuration
		if err != nil {
			return nil, nil, fmt.Errorf("bot: list %q has no downloaded copy (run `owfscan bot filter refresh`): %w", l.Name, err)
		}
		rules, _, err := blocklist.Parse(l.Format, fh)
		_ = fh.Close()
		if err != nil {
			return nil, nil, fmt.Errorf("bot: list %q: %w", l.Name, err)
		}
		if err := flt.Add(l.Name, l.Category, rules); err != nil {
			return nil, nil, err
		}
		ll := LoadedList{FilterList: l}
		if b, err := os.ReadFile(notePath(dir, l.Name)); err == nil { //nolint:gosec // as above
			_ = json.Unmarshal(b, &ll.Note)
		}
		loaded = append(loaded, ll)
	}
	sort.SliceStable(loaded, func(i, j int) bool { return loaded[i].Name < loaded[j].Name })
	return flt, loaded, nil
}
