// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

// Package batch scans a list of sites and keeps the results in a SQLite file, so a run
// can be stopped and resumed and statistics can be made later without new requests.
//
// It scans the home page of each site and nothing else: no crawling, friends, related
// domains, probes or browser. The store is behind the small Store type so that another
// backend could replace it if measurement ever shows SQLite to be the limit.
package batch

import (
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"fmt"
	"io"
	"net/url"
	"time"

	_ "modernc.org/sqlite" // registers the "sqlite" driver
)

// States of a site.
const (
	StatePending = "pending" // listed, not scanned (or interrupted)
	StateDone    = "done"    // scanned: the page answered
	StateFailed  = "failed"  // could not be scanned; Error says why
)

// Store is the SQLite file of a batch.
type Store struct{ db *sql.DB }

const schema = `
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sites (
  domain     TEXT PRIMARY KEY,
  rank       INTEGER,
  state      TEXT NOT NULL DEFAULT 'pending',
  http_status INTEGER,
  error      TEXT,
  attempts   INTEGER NOT NULL DEFAULT 0,
  scanned_at TEXT,
  result     BLOB
);
CREATE INDEX IF NOT EXISTS sites_state ON sites(state, rank);
`

// Open opens or creates the file. One connection serialises the writes; the scans
// themselves run in parallel and only their results are written one at a time.
func Open(ctx context.Context, path string) (*Store, error) {
	q := url.Values{}
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "busy_timeout(10000)")
	q.Add("_pragma", "synchronous(NORMAL)")
	db, err := sql.Open("sqlite", "file:"+path+"?"+q.Encode())
	if err != nil {
		return nil, fmt.Errorf("batch: %w", err)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.ExecContext(ctx, schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("batch: %w", err)
	}
	return &Store{db: db}, nil
}

// Close closes the file.
func (s *Store) Close() error { return s.db.Close() }

// SetMeta records a fact about the run (list name, registry hash, ...).
func (s *Store) SetMeta(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
	return err
}

// Meta returns the recorded facts.
func (s *Store) Meta(ctx context.Context) (map[string]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT key,value FROM meta`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		out[k] = v
	}
	return out, rows.Err()
}

// Site is one entry of the list.
type Site struct {
	Domain string
	Rank   int
}

// Add lists sites. A site already in the store keeps its state and result.
func (s *Store) Add(ctx context.Context, sites []Site) (added int, err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	for _, st := range sites {
		r, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO sites(domain,rank) VALUES(?,?)`, st.Domain, st.Rank)
		if err != nil {
			return 0, err
		}
		if n, _ := r.RowsAffected(); n > 0 {
			added++
		}
	}
	return added, tx.Commit()
}

// Todo returns the sites to scan, in rank order: the pending ones, and with retry the
// failed ones too.
func (s *Store) Todo(ctx context.Context, retryFailed bool, limit int) ([]Site, error) {
	q := `SELECT domain, COALESCE(rank,0) FROM sites WHERE state='pending'`
	if retryFailed {
		q = `SELECT domain, COALESCE(rank,0) FROM sites WHERE state IN ('pending','failed')`
	}
	q += ` ORDER BY COALESCE(rank, 1<<60), domain LIMIT ?`
	if limit <= 0 {
		limit = -1 // SQLite: no limit
	}
	rows, err := s.db.QueryContext(ctx, q, limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Site
	for rows.Next() {
		var st Site
		if err := rows.Scan(&st.Domain, &st.Rank); err != nil {
			return nil, err
		}
		out = append(out, st)
	}
	return out, rows.Err()
}

// SaveDone stores the result of a scan (gzip-compressed JSON).
func (s *Store) SaveDone(ctx context.Context, domain string, status int, resultJSON []byte, at time.Time) error {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(resultJSON); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `UPDATE sites SET state='done', http_status=?, error=NULL, attempts=attempts+1, scanned_at=?, result=? WHERE domain=?`,
		status, at.UTC().Format(time.RFC3339), buf.Bytes(), domain)
	return err
}

// SaveFailed records why a site could not be scanned.
func (s *Store) SaveFailed(ctx context.Context, domain, reason string, at time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE sites SET state='failed', error=?, attempts=attempts+1, scanned_at=?, result=NULL WHERE domain=?`,
		reason, at.UTC().Format(time.RFC3339), domain)
	return err
}

// Result returns the stored scan result JSON of a site, or nil.
func (s *Store) Result(ctx context.Context, domain string) ([]byte, error) {
	var b []byte
	err := s.db.QueryRowContext(ctx, `SELECT result FROM sites WHERE domain=?`, domain).Scan(&b)
	if err != nil || len(b) == 0 {
		return nil, err
	}
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	return io.ReadAll(io.LimitReader(zr, 256<<20))
}

// Counts is the state of the whole list.
type Counts struct {
	Total, Pending, Done, Failed int
	ByStatus                     map[int]int
	ByError                      map[string]int
}

// Counts summarises the store.
func (s *Store) Counts(ctx context.Context) (Counts, error) {
	c := Counts{ByStatus: map[int]int{}, ByError: map[string]int{}}
	rows, err := s.db.QueryContext(ctx, `SELECT state, COALESCE(http_status,0), COALESCE(error,''), COUNT(*) FROM sites GROUP BY 1,2,3`)
	if err != nil {
		return c, err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var state, e string
		var status, n int
		if err := rows.Scan(&state, &status, &e, &n); err != nil {
			return c, err
		}
		c.Total += n
		switch state {
		case StatePending:
			c.Pending += n
		case StateDone:
			c.Done += n
			c.ByStatus[status] += n
		case StateFailed:
			c.Failed += n
			c.ByError[e] += n
		}
	}
	return c, rows.Err()
}

// EachDone calls fn for every site that was scanned, in domain order, with its result JSON.
// fn must not use the store.
func (s *Store) EachDone(ctx context.Context, fn func(domain string, status int, resultJSON []byte) error) error {
	rows, err := s.db.QueryContext(ctx, `SELECT domain, COALESCE(http_status,0), result FROM sites WHERE state='done' ORDER BY domain`)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var d string
		var st int
		var b []byte
		if err := rows.Scan(&d, &st, &b); err != nil {
			return err
		}
		zr, err := gzip.NewReader(bytes.NewReader(b))
		if err != nil {
			return fmt.Errorf("batch: %s: %w", d, err)
		}
		j, err := io.ReadAll(io.LimitReader(zr, 256<<20))
		if err != nil {
			return fmt.Errorf("batch: %s: %w", d, err)
		}
		if err := fn(d, st, j); err != nil {
			return err
		}
	}
	return rows.Err()
}
