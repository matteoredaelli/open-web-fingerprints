// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

// Package bot is the crawler behind `owfscan bot`: a frontier of domains kept in SQLite,
// claimed with a lease so a run can be stopped at any moment (even kill -9) and resumed
// where it stopped, with nothing lost and nothing scanned twice.
//
// This file is phase 1 of the plan in TODO.md: the store and the frontier. It does no
// network I/O; the workers, the filters and the commands come later.
package bot

import (
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"
	_ "modernc.org/sqlite" // registers the "sqlite" driver
)

// States of a domain.
const (
	StatePending = "pending" // waiting to be scanned (new, or due for a revisit)
	StateLeased  = "leased"  // claimed by a worker until lease_until
	StateDone    = "done"    // scanned; next_visit_at says when to look again
	StateFailed  = "failed"  // last attempt failed; last_error_class says why
	StateBlocked = "blocked" // kept on purpose, never scanned (filter or opt-out)
)

const schema = `
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS domains (
  domain          TEXT PRIMARY KEY,
  state           TEXT NOT NULL DEFAULT 'pending',
  source          TEXT NOT NULL DEFAULT '',
  discovered_from TEXT NOT NULL DEFAULT '',
  depth           INTEGER NOT NULL DEFAULT 0,
  rank            INTEGER NOT NULL DEFAULT 0,
  attempts        INTEGER NOT NULL DEFAULT 0,
  last_error_class TEXT NOT NULL DEFAULT '',
  last_status     INTEGER NOT NULL DEFAULT 0,
  lease_owner     TEXT NOT NULL DEFAULT '',
  lease_until     TEXT NOT NULL DEFAULT '',
  next_visit_at   TEXT NOT NULL DEFAULT '',
  last_scanned_at TEXT NOT NULL DEFAULT '',
  last_changed_at TEXT NOT NULL DEFAULT '',
  result_json     BLOB,
  result_hash     TEXT NOT NULL DEFAULT '',
  stable_count    INTEGER NOT NULL DEFAULT 0,
  fail_streak     INTEGER NOT NULL DEFAULT 0,
  dns_failures    INTEGER NOT NULL DEFAULT 0,
  blocked_reason  TEXT NOT NULL DEFAULT '',
  blocked_list    TEXT NOT NULL DEFAULT '',
  blocked_at      TEXT NOT NULL DEFAULT '',
  created_at      TEXT NOT NULL,
  updated_at      TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS hosts (
  host              TEXT PRIMARY KEY,
  crawl_delay_ms    INTEGER NOT NULL DEFAULT 0,
  robots_fetched_at TEXT NOT NULL DEFAULT '',
  backoff_until     TEXT NOT NULL DEFAULT '',
  fail_count        INTEGER NOT NULL DEFAULT 0,
  created_at        TEXT NOT NULL,
  updated_at        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS domains_claim ON domains(state, next_visit_at, depth, rank);
CREATE INDEX IF NOT EXISTS domains_lease ON domains(state, lease_until);
`

// Store is the SQLite file of a crawl. One connection serialises every write.
type Store struct {
	db  *sql.DB
	now func() time.Time
}

// Open opens or creates the file. now may be nil (the wall clock); tests pass their own.
func Open(ctx context.Context, path string, now func() time.Time) (*Store, error) {
	q := url.Values{}
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "busy_timeout(10000)")
	q.Add("_pragma", "synchronous(NORMAL)")
	db, err := sql.Open("sqlite", "file:"+path+"?"+q.Encode())
	if err != nil {
		return nil, fmt.Errorf("bot: %w", err)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.ExecContext(ctx, schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("bot: %w", err)
	}
	if err := addMissingColumns(ctx, db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("bot: %w", err)
	}
	if now == nil {
		now = time.Now
	}
	return &Store{db: db, now: now}, nil
}

// addMissingColumns upgrades a file made by an earlier version: columns added since are
// created with their defaults. Nothing is ever dropped or rewritten.
func addMissingColumns(ctx context.Context, db *sql.DB) error {
	want := map[string]string{
		"stable_count": "INTEGER NOT NULL DEFAULT 0",
		"fail_streak":  "INTEGER NOT NULL DEFAULT 0",
		"dns_failures": "INTEGER NOT NULL DEFAULT 0",
	}
	rows, err := db.QueryContext(ctx, `PRAGMA table_info(domains)`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var cid, notnull, pk int
		var name, typ string
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
			_ = rows.Close()
			return err
		}
		delete(want, name)
	}
	_ = rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for col, ddl := range want {
		if _, err := db.ExecContext(ctx, "ALTER TABLE domains ADD COLUMN "+col+" "+ddl); err != nil {
			return err
		}
	}
	return nil
}

// Close closes the file.
func (s *Store) Close() error { return s.db.Close() }

func (s *Store) stamp() string { return s.now().UTC().Format(time.RFC3339) }

// Registrable returns the registrable domain (eTLD+1) of a host, lower case, without
// port, trailing dot or "www." handling beyond what the public suffix list gives.
// A host that is an IP address or has no registrable form is an error.
func Registrable(host string) (string, error) {
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if i := strings.LastIndex(h, ":"); i >= 0 && !strings.Contains(h[i:], "]") {
		h = h[:i]
	}
	if h == "" {
		return "", errors.New("bot: empty host")
	}
	d, err := publicsuffix.EffectiveTLDPlusOne(h)
	if err != nil {
		return "", fmt.Errorf("bot: %q: %w", host, err)
	}
	return d, nil
}

// Seed is a domain to add to the frontier.
type Seed struct {
	Host           string // any host name; reduced to its registrable domain
	Source         string // "tranco", "discovered", "manual"...
	DiscoveredFrom string // registrable domain of the page that linked it
	Depth          int    // 0 for a seed, parent depth + 1 when discovered
	Rank           int    // 0 when unknown
	// BlockedList, when set, adds the domain already blocked (by that list, for
	// BlockedReason): it is kept, never scanned.
	BlockedList, BlockedReason string
}

// Add inserts domains that are not known yet and returns how many were new. A known
// domain is never touched: the first sighting owns the row. It is one transaction.
func (s *Store) Add(ctx context.Context, seeds []Seed) (int, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	n, err := addTx(ctx, tx, seeds, s.stamp())
	if err != nil {
		return 0, err
	}
	return n, tx.Commit()
}

func addTx(ctx context.Context, tx *sql.Tx, seeds []Seed, ts string) (int, error) {
	n := 0
	for _, sd := range seeds {
		d, err := Registrable(sd.Host)
		if err != nil {
			continue // IP address, public suffix alone, junk: not a domain to crawl
		}
		state, blockedAt := StatePending, ""
		if sd.BlockedList != "" {
			state, blockedAt = StateBlocked, ts
		}
		res, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO domains
 (domain,state,source,discovered_from,depth,rank,next_visit_at,blocked_reason,blocked_list,blocked_at,created_at,updated_at)
 VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`, d, state, sd.Source, sd.DiscoveredFrom, sd.Depth, sd.Rank, ts,
			sd.BlockedReason, sd.BlockedList, blockedAt, ts, ts)
		if err != nil {
			return 0, err
		}
		c, _ := res.RowsAffected()
		n += int(c)
	}
	return n, nil
}

// Job is a claimed domain.
type Job struct {
	Domain string
	Depth  int // hops from a seed
}

// Claim leases the next domain due for a visit to owner for ttl and returns it; Domain is
// "" when nothing is due. Order: shallower depth first, then better rank (0 = unknown,
// last). Expired leases count as pending, so a worker killed in the middle loses nothing.
func (s *Store) Claim(ctx context.Context, owner string, ttl time.Duration) (Job, error) {
	now := s.now().UTC()
	ts := now.Format(time.RFC3339)
	until := now.Add(ttl).Format(time.RFC3339)
	var j Job
	err := s.db.QueryRowContext(ctx, `
UPDATE domains SET state='leased', lease_owner=?, lease_until=?, attempts=attempts+1, updated_at=?
WHERE domain = (
  SELECT domain FROM domains
  WHERE (state IN ('pending','done','failed') AND next_visit_at <= ?)
     OR (state='leased' AND lease_until <= ?)
  ORDER BY depth, CASE WHEN rank=0 THEN 1 ELSE 0 END, rank, domain LIMIT 1)
RETURNING domain, depth`, owner, until, ts, ts, ts).Scan(&j.Domain, &j.Depth)
	if errors.Is(err, sql.ErrNoRows) {
		return Job{}, nil
	}
	return j, err
}

// Release gives a domain back, as if it had not been claimed: a clean stop does this
// for the domains still in flight, so they are done first in the next run.
func (s *Store) Release(ctx context.Context, domain, owner string) error {
	ts := s.stamp()
	res, err := s.db.ExecContext(ctx, `UPDATE domains SET state='pending', lease_owner='', lease_until='',
 attempts=MAX(attempts-1,0), next_visit_at=?, updated_at=? WHERE domain=? AND state='leased' AND lease_owner=?`,
		ts, ts, domain, owner)
	return leaseResult(res, err)
}

// ErrLeaseLost is returned when the lease is no longer held by the caller.
var ErrLeaseLost = errors.New("bot: lease lost")

// Heartbeat extends a lease still held by owner.
func (s *Store) Heartbeat(ctx context.Context, domain, owner string, ttl time.Duration) error {
	now := s.now().UTC()
	res, err := s.db.ExecContext(ctx, `UPDATE domains SET lease_until=?, updated_at=?
 WHERE domain=? AND state='leased' AND lease_owner=?`,
		now.Add(ttl).Format(time.RFC3339), now.Format(time.RFC3339), domain, owner)
	return leaseResult(res, err)
}

func leaseResult(res sql.Result, err error) error {
	if err != nil {
		return err
	}
	if c, _ := res.RowsAffected(); c == 0 {
		return ErrLeaseLost
	}
	return nil
}

// Result is what a finished scan leaves behind.
type Result struct {
	Status     int    // HTTP status of the home page
	JSON       []byte // the scan result; replaces the previous one (only the last is kept)
	Hash       string // hash of the content that matters, to see whether it changed
	Discovered []Seed // domains found on the page
	// Revisit says when the domain comes back; the zero value is the default policy.
	Revisit RevisitPolicy
}

// Complete records a result in one transaction: it saves the result, inserts the
// discovered domains and schedules the next visit. If the lease was lost nothing is written.
func (s *Store) Complete(ctx context.Context, domain, owner string, r Result) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	now := s.now().UTC()
	ts := now.Format(time.RFC3339)
	var prevHash string
	var stable int
	if err := tx.QueryRowContext(ctx, `SELECT result_hash, stable_count FROM domains WHERE domain=? AND state='leased' AND lease_owner=?`,
		domain, owner).Scan(&prevHash, &stable); errors.Is(err, sql.ErrNoRows) {
		return ErrLeaseLost
	} else if err != nil {
		return err
	}
	first, changed := prevHash == "", prevHash != "" && prevHash != r.Hash
	if changed || first {
		stable = 0
	} else {
		stable++
	}
	next := r.Revisit.Next(stable, changed, first, jitterUnit(domain, ts))
	res, err := tx.ExecContext(ctx, `UPDATE domains SET
 state='done', lease_owner='', lease_until='', last_error_class='', last_status=?,
 last_changed_at=CASE WHEN result_hash<>? THEN ? ELSE last_changed_at END,
 result_json=?, result_hash=?, stable_count=?, fail_streak=0, dns_failures=0,
 last_scanned_at=?, next_visit_at=?, updated_at=?
 WHERE domain=? AND state='leased' AND lease_owner=?`,
		r.Status, r.Hash, ts, r.JSON, r.Hash, stable, ts, now.Add(next).Format(time.RFC3339), ts, domain, owner)
	if err := leaseResult(res, err); err != nil {
		return err
	}
	if _, err := addTx(ctx, tx, r.Discovered, ts); err != nil {
		return err
	}
	return tx.Commit()
}

// Fail records a failed attempt. The retry is after retryIn, doubled for each failure in a
// row and capped by p.MaxRetry. A domain whose name does not exist (class "dns") is blocked
// for good after p.BlockAfterDNS failures in a row. errorClass is a short stable word
// ("dns", "timeout", "robots"...), never a message with data.
func (s *Store) Fail(ctx context.Context, domain, owner, errorClass string, status int, retryIn time.Duration, p FailPolicy) error {
	if p.MaxRetry <= 0 {
		p.MaxRetry = 180 * 24 * time.Hour
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var streak, dns int
	if err := tx.QueryRowContext(ctx, `SELECT fail_streak, dns_failures FROM domains WHERE domain=? AND state='leased' AND lease_owner=?`,
		domain, owner).Scan(&streak, &dns); errors.Is(err, sql.ErrNoRows) {
		return ErrLeaseLost
	} else if err != nil {
		return err
	}
	streak++
	if errorClass == "dns" {
		dns++
	} else {
		dns = 0
	}
	now := s.now().UTC()
	ts := now.Format(time.RFC3339)
	if errorClass == "dns" && p.BlockAfterDNS > 0 && dns >= p.BlockAfterDNS {
		_, err = tx.ExecContext(ctx, `UPDATE domains SET state='blocked', lease_owner='', lease_until='', last_error_class=?, last_status=?,
 fail_streak=?, dns_failures=?, blocked_reason=?, blocked_list=?, blocked_at=?, updated_at=? WHERE domain=?`,
			errorClass, status, streak, dns, fmt.Sprintf("no such host %d times in a row", dns), DNSList, ts, ts, domain)
	} else {
		_, err = tx.ExecContext(ctx, `UPDATE domains SET state='failed', lease_owner='', lease_until='', last_error_class=?, last_status=?,
 fail_streak=?, dns_failures=?, next_visit_at=?, updated_at=? WHERE domain=?`,
			errorClass, status, streak, dns, now.Add(retryDelay(retryIn, streak, p.MaxRetry)).Format(time.RFC3339), ts, domain)
	}
	if err != nil {
		return err
	}
	return tx.Commit()
}

// Block marks a domain as blocked (kept, never scanned) and records why and by which list.
// It works on any state, also on a domain not seen before (it is then inserted blocked).
func (s *Store) Block(ctx context.Context, host, reason, list string) error {
	d, err := Registrable(host)
	if err != nil {
		return err
	}
	ts := s.stamp()
	_, err = s.db.ExecContext(ctx, `INSERT INTO domains(domain,state,blocked_reason,blocked_list,blocked_at,created_at,updated_at)
 VALUES(?,?,?,?,?,?,?)
 ON CONFLICT(domain) DO UPDATE SET state='blocked', lease_owner='', lease_until='',
  blocked_reason=excluded.blocked_reason, blocked_list=excluded.blocked_list,
  blocked_at=excluded.blocked_at, updated_at=excluded.updated_at`,
		d, StateBlocked, reason, list, ts, ts, ts)
	return err
}

// Counts returns the number of domains per state. Expired leases are reported as
// pending, because that is what the next Claim will treat them as.
func (s *Store) Counts(ctx context.Context) (map[string]int, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT
 CASE WHEN state='leased' AND lease_until<=? THEN 'pending' ELSE state END, COUNT(*)
 FROM domains GROUP BY 1`, s.stamp())
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := map[string]int{}
	for rows.Next() {
		var k string
		var n int
		if err := rows.Scan(&k, &n); err != nil {
			return nil, err
		}
		out[k] = n
	}
	return out, rows.Err()
}

// HostState is what the crawler remembers about a host between runs: how long it asked
// us to wait, and whether it asked us to slow down.
type HostState struct {
	Host            string
	CrawlDelay      time.Duration
	RobotsFetchedAt time.Time
	BackoffUntil    time.Time
	FailCount       int
}

// LoadHost returns the saved state of a host; ok is false when there is none.
func (s *Store) LoadHost(ctx context.Context, host string) (st HostState, ok bool, err error) {
	var delayMs int64
	var robots, backoff string
	err = s.db.QueryRowContext(ctx, `SELECT crawl_delay_ms, robots_fetched_at, backoff_until, fail_count
 FROM hosts WHERE host=?`, host).Scan(&delayMs, &robots, &backoff, &st.FailCount)
	if errors.Is(err, sql.ErrNoRows) {
		return HostState{}, false, nil
	}
	if err != nil {
		return HostState{}, false, err
	}
	st.Host, st.CrawlDelay = host, time.Duration(delayMs)*time.Millisecond
	st.RobotsFetchedAt, _ = time.Parse(time.RFC3339, robots)
	st.BackoffUntil, _ = time.Parse(time.RFC3339, backoff)
	return st, true, nil
}

// SaveHost writes the state of a host.
func (s *Store) SaveHost(ctx context.Context, st HostState) error {
	f := func(t time.Time) string {
		if t.IsZero() {
			return ""
		}
		return t.UTC().Format(time.RFC3339)
	}
	ts := s.stamp()
	_, err := s.db.ExecContext(ctx, `INSERT INTO hosts(host,crawl_delay_ms,robots_fetched_at,backoff_until,fail_count,created_at,updated_at)
 VALUES(?,?,?,?,?,?,?)
 ON CONFLICT(host) DO UPDATE SET crawl_delay_ms=excluded.crawl_delay_ms,
  robots_fetched_at=excluded.robots_fetched_at, backoff_until=excluded.backoff_until,
  fail_count=excluded.fail_count, updated_at=excluded.updated_at`,
		st.Host, st.CrawlDelay.Milliseconds(), f(st.RobotsFetchedAt), f(st.BackoffUntil), st.FailCount, ts, ts)
	return err
}

// AcquireRun takes the single-run lock: two bots on one file would only fight over the
// same domains. The lock is a lease in the file, so it also works across machines on a
// shared disk and a bot killed with kill -9 frees it when the lease ends.
func (s *Store) AcquireRun(ctx context.Context, owner string, ttl time.Duration) (bool, error) {
	now := s.now().UTC()
	res, err := s.db.ExecContext(ctx, `INSERT INTO meta(key,value) VALUES('run_lock', ?)
 ON CONFLICT(key) DO UPDATE SET value=excluded.value
 WHERE substr(meta.value, 1, instr(meta.value,'|')-1) = ?
    OR substr(meta.value, instr(meta.value,'|')+1) <= ?`,
		owner+"|"+now.Add(ttl).Format(time.RFC3339), owner, now.Format(time.RFC3339))
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// RenewRun extends the run lock held by owner.
func (s *Store) RenewRun(ctx context.Context, owner string, ttl time.Duration) error {
	ok, err := s.AcquireRun(ctx, owner, ttl)
	if err == nil && !ok {
		return ErrLeaseLost
	}
	return err
}

// ReleaseRun frees the run lock if owner holds it.
func (s *Store) ReleaseRun(ctx context.Context, owner string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM meta WHERE key='run_lock' AND substr(value,1,instr(value,'|')-1)=?`, owner)
	return err
}

// RunLock says who holds the run lock, and until when; owner is "" when it is free or expired.
func (s *Store) RunLock(ctx context.Context) (owner string, until time.Time, err error) {
	var v string
	err = s.db.QueryRowContext(ctx, `SELECT value FROM meta WHERE key='run_lock'`).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", time.Time{}, nil
	}
	if err != nil {
		return "", time.Time{}, err
	}
	o, u, _ := strings.Cut(v, "|")
	until, _ = time.Parse(time.RFC3339, u)
	if !until.After(s.now()) {
		return "", time.Time{}, nil
	}
	return o, until, nil
}

// Status summarises the file.
type Status struct {
	ByState     map[string]int
	BlockedBy   map[string]int // blocked domains per list ("opt-out" for exclusions)
	Due         int            // domains a Claim would take now
	NextDue     time.Time      // earliest visit not yet due; zero if none
	InBackoff   int            // hosts that asked us to slow down
	Rescanned   int            // domains scanned more than once
	RunLockedBy string
}

// Status counts what the crawl holds.
func (s *Store) Status(ctx context.Context) (Status, error) {
	st := Status{BlockedBy: map[string]int{}}
	var err error
	if st.ByState, err = s.Counts(ctx); err != nil {
		return st, err
	}
	ts := s.stamp()
	if err = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM domains
 WHERE (state IN ('pending','done','failed') AND next_visit_at <= ?) OR (state='leased' AND lease_until <= ?)`, ts, ts).Scan(&st.Due); err != nil {
		return st, err
	}
	var next sql.NullString
	if err = s.db.QueryRowContext(ctx, `SELECT MIN(next_visit_at) FROM domains WHERE state IN ('done','failed') AND next_visit_at > ?`, ts).Scan(&next); err != nil {
		return st, err
	}
	st.NextDue, _ = time.Parse(time.RFC3339, next.String)
	if err = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM hosts WHERE backoff_until > ?`, ts).Scan(&st.InBackoff); err != nil {
		return st, err
	}
	if err = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM domains WHERE attempts > 1 AND state='done'`).Scan(&st.Rescanned); err != nil {
		return st, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT blocked_list, COUNT(*) FROM domains WHERE state='blocked' GROUP BY 1`)
	if err != nil {
		return st, err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var l string
		var n int
		if err := rows.Scan(&l, &n); err != nil {
			return st, err
		}
		st.BlockedBy[l] = n
	}
	if err := rows.Err(); err != nil {
		return st, err
	}
	st.RunLockedBy, _, err = s.RunLock(ctx)
	return st, err
}

// OptOutList is the name recorded for domains excluded by hand; no filter refresh undoes it.
const OptOutList = "opt-out"

// ReapplyFilter re-evaluates the domains blocked by a filter list against the current
// filter: a domain no list blocks any more goes back to pending, and one now blocked by
// another list is updated. Exclusions made by hand are never touched. It returns how many
// were released.
func (s *Store) ReapplyFilter(ctx context.Context, check func(domain string) (list, category string, blocked bool)) (released int, err error) {
	rows, err := s.db.QueryContext(ctx, `SELECT domain FROM domains WHERE state='blocked' AND blocked_list NOT IN (?, ?)`, OptOutList, DNSList)
	if err != nil {
		return 0, err
	}
	var all []string
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			_ = rows.Close()
			return 0, err
		}
		all = append(all, d)
	}
	_ = rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	ts := s.stamp()
	for _, d := range all {
		if list, cat, blocked := check(d); blocked {
			if _, err := s.db.ExecContext(ctx, `UPDATE domains SET blocked_list=?, blocked_reason=?, updated_at=? WHERE domain=?`, list, "category "+cat, ts, d); err != nil {
				return released, err
			}
			continue
		}
		if _, err := s.db.ExecContext(ctx, `UPDATE domains SET state='pending', blocked_list='', blocked_reason='', blocked_at='',
 next_visit_at=?, updated_at=? WHERE domain=?`, ts, ts, d); err != nil {
			return released, err
		}
		released++
	}
	return released, nil
}

// ResultJSON returns the last result of a domain (decompressed), or nil if it has none.
func (s *Store) ResultJSON(ctx context.Context, domain string) ([]byte, error) {
	var b []byte
	err := s.db.QueryRowContext(ctx, `SELECT result_json FROM domains WHERE domain=?`, domain).Scan(&b)
	if errors.Is(err, sql.ErrNoRows) || len(b) == 0 {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	defer func() { _ = zr.Close() }()
	return io.ReadAll(io.LimitReader(zr, 256<<20))
}

// Exclusion is a domain left out on request.
type Exclusion struct {
	Domain string
	Reason string
	At     time.Time
}

// Exclude blocks a domain by hand (an owner asked to be left out): no filter refresh lifts it.
func (s *Store) Exclude(ctx context.Context, host, reason string) error {
	return s.Block(ctx, host, reason, OptOutList)
}

// Excluded lists the domains left out by hand.
func (s *Store) Excluded(ctx context.Context) ([]Exclusion, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT domain, blocked_reason, blocked_at FROM domains WHERE blocked_list=? ORDER BY domain`, OptOutList)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Exclusion
	for rows.Next() {
		var e Exclusion
		var at string
		if err := rows.Scan(&e.Domain, &e.Reason, &at); err != nil {
			return nil, err
		}
		e.At, _ = time.Parse(time.RFC3339, at)
		out = append(out, e)
	}
	return out, rows.Err()
}

// Unexclude lifts a manual exclusion; the domain is scanned again from the next run.
func (s *Store) Unexclude(ctx context.Context, host string) (bool, error) {
	d, err := Registrable(host)
	if err != nil {
		return false, err
	}
	ts := s.stamp()
	res, err := s.db.ExecContext(ctx, `UPDATE domains SET state='pending', blocked_list='', blocked_reason='', blocked_at='',
 next_visit_at=?, updated_at=? WHERE domain=? AND state='blocked' AND blocked_list=?`, ts, ts, d, OptOutList)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}
