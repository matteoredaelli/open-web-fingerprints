// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package fetch

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/matteoredaelli/open-web-fingerprints/scan"
)

// cacheEntry is the metadata of a cached response; the body is in a second file.
type cacheEntry struct {
	URL         string          `json:"url"`
	FinalURL    string          `json:"final_url"`
	Status      int             `json:"status"`
	Header      http.Header     `json:"header"`
	SetCookies  []string        `json:"set_cookies,omitempty"`
	ContentType string          `json:"content_type,omitempty"`
	Truncated   bool            `json:"truncated,omitempty"`
	Redirects   []scan.Redirect `json:"redirects,omitempty"`
	DurationMS  int64           `json:"duration_ms"`
	FetchedAt   time.Time       `json:"fetched_at"`
	TLS         *scan.TLS       `json:"tls,omitempty"`
	BodySHA256  string          `json:"body_sha256"`
}

func (f *Fetcher) path(rawURL, ext string) string {
	sum := sha256.Sum256([]byte(rawURL))
	return filepath.Join(f.opt.CacheDir, hex.EncodeToString(sum[:16])+ext)
}

// fromCache returns a fresh cached response or nil. A damaged or tampered entry
// (the body does not match its hash) is ignored and fetched again.
func (f *Fetcher) fromCache(rawURL string) *Response {
	if f.opt.CacheDir == "" {
		return nil
	}
	meta, err := os.ReadFile(f.path(rawURL, ".json")) //nolint:gosec // path built from a hash
	if err != nil {
		return nil
	}
	var e cacheEntry
	if json.Unmarshal(meta, &e) != nil || e.URL != rawURL || f.opt.Now().Sub(e.FetchedAt) > f.opt.MaxAge {
		return nil
	}
	body, err := os.ReadFile(f.path(rawURL, ".body")) //nolint:gosec // path built from a hash
	if err != nil {
		return nil
	}
	sum := sha256.Sum256(body)
	if hex.EncodeToString(sum[:]) != e.BodySHA256 {
		return nil
	}
	return &Response{
		URL: e.URL, FinalURL: e.FinalURL, Status: e.Status, Header: e.Header, SetCookies: e.SetCookies,
		ContentType: e.ContentType, Body: body, Truncated: e.Truncated, Redirects: e.Redirects,
		Duration: time.Duration(e.DurationMS) * time.Millisecond, FetchedAt: e.FetchedAt, Cached: true, TLS: e.TLS,
	}
}

// toCache stores a response. A failure to write is not an error of the fetch.
func (f *Fetcher) toCache(r *Response) {
	if f.opt.CacheDir == "" || r.Status >= 500 {
		return
	}
	if err := os.MkdirAll(f.opt.CacheDir, 0o750); err != nil {
		return
	}
	sum := sha256.Sum256(r.Body)
	e := cacheEntry{
		URL: r.URL, FinalURL: r.FinalURL, Status: r.Status, Header: r.Header, SetCookies: r.SetCookies,
		ContentType: r.ContentType, Truncated: r.Truncated, Redirects: r.Redirects,
		DurationMS: r.Duration.Milliseconds(), FetchedAt: r.FetchedAt, TLS: r.TLS, BodySHA256: hex.EncodeToString(sum[:]),
	}
	meta, err := json.Marshal(e)
	if err != nil {
		return
	}
	// The body first: an entry without a matching body is never read.
	if writeAtomic(f.path(r.URL, ".body"), r.Body) == nil {
		_ = writeAtomic(f.path(r.URL, ".json"), meta)
	}
}

func writeAtomic(path string, b []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		_ = os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(name)
		return err
	}
	return os.Rename(name, path)
}
