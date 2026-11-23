// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

package bot

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/matteoredaelli/open-web-fingerprints/internal/scan/config"
)

func listServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/hosts", func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.UserAgent(), "owfscan") {
			http.Error(w, "no ua", 400)
			return
		}
		_, _ = w.Write([]byte("0.0.0.0 bad.example\n0.0.0.0 worse.example\n"))
	})
	mux.HandleFunc("/html", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<html><body>not a list</body></html>"))
	})
	mux.HandleFunc("/gone", func(w http.ResponseWriter, _ *http.Request) { http.NotFound(w, nil) })
	s := httptest.NewTLSServer(mux)
	t.Cleanup(s.Close)
	return s
}

func TestRefreshAndLoad(t *testing.T) {
	srv := listServer(t)
	dir := filepath.Join(t.TempDir(), "filters")
	lists := []config.FilterList{
		{Name: "good", URL: srv.URL + "/hosts", Category: "adult", Format: "hosts", Enabled: true},
		{Name: "html", URL: srv.URL + "/html", Category: "adult", Format: "hosts", Enabled: true},
		{Name: "gone", URL: srv.URL + "/gone", Category: "adult", Format: "hosts", Enabled: true},
	}
	at := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	res, err := Refresh(context.Background(), dir, lists, srv.Client(), func() time.Time { return at })
	if err != nil {
		t.Fatal(err)
	}
	if res[0].Err != nil || res[0].Note.Blocked != 2 || res[0].Note.SHA256 == "" || !res[0].Note.FetchedAt.Equal(at) {
		t.Errorf("good: %+v", res[0])
	}
	if res[1].Err == nil || res[2].Err == nil {
		t.Errorf("bad lists accepted: %v / %v", res[1].Err, res[2].Err)
	}
	if _, err := os.Stat(filepath.Join(dir, "html.list")); err == nil {
		t.Error("a non-list replaced a copy")
	}
	if m, _ := filepath.Glob(filepath.Join(dir, "*.tmp")); len(m) != 0 {
		t.Errorf("temporary files left: %v", m)
	}

	f := config.Default().Bot.Filter
	f.Lists = lists[:1]
	flt, loaded, err := Load(dir, f)
	if err != nil {
		t.Fatal(err)
	}
	if !flt.Check("www.bad.example").Blocked || flt.Check("fine.example").Blocked || len(loaded) != 1 || loaded[0].Note.Blocked != 2 {
		t.Errorf("loaded %+v", loaded)
	}

	// A list with no copy is an error, not a weaker filter.
	f.Lists = lists[1:2]
	if _, _, err := Load(dir, f); err == nil {
		t.Error("missing copy accepted")
	}
}

func TestRefreshKeepsThePreviousCopy(t *testing.T) {
	srv := listServer(t)
	dir := t.TempDir()
	ok := config.FilterList{Name: "x", URL: srv.URL + "/hosts", Category: "adult", Format: "hosts", Enabled: true}
	if _, err := Refresh(context.Background(), dir, []config.FilterList{ok}, srv.Client(), nil); err != nil {
		t.Fatal(err)
	}
	ok.URL = srv.URL + "/html"
	res, _ := Refresh(context.Background(), dir, []config.FilterList{ok}, srv.Client(), nil)
	if res[0].Err == nil {
		t.Fatal("html accepted")
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "x.list")); !strings.Contains(string(b), "bad.example") {
		t.Errorf("previous copy lost: %q", b)
	}
}

func TestRefreshWithNoListFails(t *testing.T) {
	if _, err := Refresh(context.Background(), t.TempDir(), nil, nil, nil); err == nil {
		t.Error("no list accepted")
	}
}

func TestRefreshRefusesDowngradeRedirect(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("0.0.0.0 a.example\n")) }))
	defer plain.Close()
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL, http.StatusFound)
	}))
	defer tlsSrv.Close()
	l := config.FilterList{Name: "r", URL: tlsSrv.URL, Category: "adult", Format: "hosts", Enabled: true}
	res, _ := Refresh(context.Background(), t.TempDir(), []config.FilterList{l}, tlsSrv.Client(), nil)
	if res[0].Err == nil {
		t.Error("redirect to http followed")
	}
}
