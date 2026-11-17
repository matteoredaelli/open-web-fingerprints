// Copyright 2026 Matteo Redaelli
// SPDX-License-Identifier: GPL-3.0-or-later

// Package sqlite implements repository.Repository on SQLite using explicit
// SQL, database/sql and the pure-Go modernc.org/sqlite driver.
package sqlite

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/url"

	"github.com/pressly/goose/v3"
	_ "modernc.org/sqlite" // driver registration

	"github.com/matteoredaelli/open-web-fingerprints/internal/domain"
	"github.com/matteoredaelli/open-web-fingerprints/internal/repository"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// Repo is a SQLite-backed repository.
type Repo struct {
	db *sql.DB
}

var _ repository.Repository = (*Repo)(nil)

// Open opens (creating if needed) the database at path and applies all
// pending migrations. Use ":memory:" for a private in-memory database.
func Open(ctx context.Context, path string) (*Repo, error) {
	q := url.Values{}
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_pragma", "busy_timeout(5000)")
	if path != ":memory:" {
		q.Add("_pragma", "journal_mode(WAL)")
	}
	dsn := "file:" + path + "?" + q.Encode()
	if path == ":memory:" {
		dsn = "file::memory:?" + q.Encode()
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlite: open %s: %w", path, err)
	}
	// One connection keeps in-memory databases coherent and serializes writes.
	db.SetMaxOpenConns(1)
	r := &Repo{db: db}
	if err := r.Migrate(ctx); err != nil {
		return nil, errors.Join(err, db.Close())
	}
	return r, nil
}

// Close releases the database.
func (r *Repo) Close() error { return r.db.Close() }

func provider(db *sql.DB) (*goose.Provider, error) {
	sub, err := fs.Sub(migrationFS, "migrations")
	if err != nil {
		return nil, err
	}
	return goose.NewProvider(goose.DialectSQLite3, db, sub)
}

// Migrate applies pending migrations.
func (r *Repo) Migrate(ctx context.Context) error {
	p, err := provider(r.db)
	if err != nil {
		return fmt.Errorf("sqlite: migrations: %w", err)
	}
	if _, err := p.Up(ctx); err != nil {
		return fmt.Errorf("sqlite: migrate: %w", err)
	}
	return nil
}

// SchemaVersion returns the current migration version.
func (r *Repo) SchemaVersion(ctx context.Context) (int64, error) {
	p, err := provider(r.db)
	if err != nil {
		return 0, err
	}
	return p.GetDBVersion(ctx)
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err) // canonical records are always marshalable
	}
	return string(b)
}

// Allocate implements repository.Repository.
func (r *Repo) Allocate(kind domain.Kind, sourceID, key string) (string, error) {
	ctx := context.Background()
	var id string
	err := r.db.QueryRowContext(ctx,
		`SELECT id FROM id_map WHERE kind=? AND source_id=? AND key=?`, string(kind), sourceID, key).Scan(&id)
	if err == nil {
		return id, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("sqlite: allocate: %w", err)
	}
	fresh, err := domain.NewID(kind)
	if err != nil {
		return "", err
	}
	if _, err := r.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO id_map(kind, source_id, key, id) VALUES (?,?,?,?)`,
		string(kind), sourceID, key, fresh); err != nil {
		return "", fmt.Errorf("sqlite: allocate: %w", err)
	}
	if err := r.db.QueryRowContext(ctx,
		`SELECT id FROM id_map WHERE kind=? AND source_id=? AND key=?`, string(kind), sourceID, key).Scan(&id); err != nil {
		return "", fmt.Errorf("sqlite: allocate: %w", err)
	}
	return id, nil
}

// GetSourceBySlug implements repository.Repository.
func (r *Repo) GetSourceBySlug(ctx context.Context, slug string) (domain.Source, bool, error) {
	var data string
	err := r.db.QueryRowContext(ctx, `SELECT data FROM sources WHERE slug=?`, slug).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Source{}, false, nil
	}
	if err != nil {
		return domain.Source{}, false, fmt.Errorf("sqlite: get source: %w", err)
	}
	var s domain.Source
	if err := json.Unmarshal([]byte(data), &s); err != nil {
		return domain.Source{}, false, fmt.Errorf("sqlite: decode source: %w", err)
	}
	return s, true, nil
}

// Sources implements repository.Repository.
func (r *Repo) Sources(ctx context.Context) ([]domain.Source, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT data FROM sources ORDER BY slug`)
	if err != nil {
		return nil, fmt.Errorf("sqlite: sources: %w", err)
	}
	return scanAll[domain.Source](rows)
}

// UpsertSource implements repository.Repository.
func (r *Repo) UpsertSource(ctx context.Context, s domain.Source) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO sources(id, slug, data) VALUES (?,?,?)
		 ON CONFLICT(id) DO UPDATE SET slug=excluded.slug, data=excluded.data`,
		string(s.ID), s.Slug, mustJSON(s))
	if err != nil {
		return fmt.Errorf("sqlite: upsert source: %w", err)
	}
	return nil
}

// PutSnapshot implements repository.Repository.
func (r *Repo) PutSnapshot(ctx context.Context, s domain.Snapshot) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("sqlite: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var sum string
	err = tx.QueryRowContext(ctx,
		`SELECT checksum FROM snapshots WHERE source_id=? AND revision=?`, string(s.SourceID), s.Revision).Scan(&sum)
	switch {
	case err == nil:
		if sum != s.Checksum {
			return fmt.Errorf("snapshot %s of %s already stored with checksum %s, got %s",
				s.Revision, s.SourceID, sum, s.Checksum)
		}
		return nil
	case !errors.Is(err, sql.ErrNoRows):
		return fmt.Errorf("sqlite: check snapshot: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO snapshots(source_id, revision, checksum, retrieved_at, data) VALUES (?,?,?,?,?)`,
		string(s.SourceID), s.Revision, s.Checksum, s.RetrievedAt.UTC().Format("2006-01-02T15:04:05.999999999Z"), mustJSON(s)); err != nil {
		return fmt.Errorf("sqlite: insert snapshot: %w", err)
	}
	return tx.Commit()
}

// Snapshots implements repository.Repository.
func (r *Repo) Snapshots(ctx context.Context, id domain.SourceID) ([]domain.Snapshot, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT data FROM snapshots WHERE source_id=? ORDER BY retrieved_at, revision`, string(id))
	if err != nil {
		return nil, fmt.Errorf("sqlite: snapshots: %w", err)
	}
	return scanAll[domain.Snapshot](rows)
}

// scanAll decodes a single JSON column from every row.
func scanAll[T any](rows *sql.Rows) ([]T, error) {
	defer func() { _ = rows.Close() }()
	var out []T
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, fmt.Errorf("sqlite: scan: %w", err)
		}
		var v T
		if err := json.Unmarshal([]byte(data), &v); err != nil {
			return nil, fmt.Errorf("sqlite: decode: %w", err)
		}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite: rows: %w", err)
	}
	return out, nil
}

type queryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

func loadKind[T any](ctx context.Context, q queryer, table string, source domain.SourceID, all bool) ([]T, error) {
	var (
		rows *sql.Rows
		err  error
	)
	// table is one of four constants below, never user input.
	if all {
		rows, err = q.QueryContext(ctx, `SELECT data FROM `+table+` ORDER BY id`)
	} else {
		rows, err = q.QueryContext(ctx,
			`SELECT t.data FROM `+table+` t JOIN provenance p ON p.record_id = t.id
			 WHERE p.source_id = ? ORDER BY t.id`, string(source))
	}
	if err != nil {
		return nil, fmt.Errorf("sqlite: load %s: %w", table, err)
	}
	return scanAll[T](rows)
}

func (r *Repo) load(ctx context.Context, source domain.SourceID, all bool) (domain.Records, error) {
	var out domain.Records
	var err error
	if out.Categories, err = loadKind[domain.Category](ctx, r.db, "categories", source, all); err != nil {
		return out, err
	}
	if out.Technologies, err = loadKind[domain.Technology](ctx, r.db, "technologies", source, all); err != nil {
		return out, err
	}
	if out.Fingerprints, err = loadKind[domain.Fingerprint](ctx, r.db, "fingerprints", source, all); err != nil {
		return out, err
	}
	if out.Relationships, err = loadKind[domain.Relationship](ctx, r.db, "relationships", source, all); err != nil {
		return out, err
	}
	return out, nil
}

// SourceRecords implements repository.Repository.
func (r *Repo) SourceRecords(ctx context.Context, id domain.SourceID) (domain.Records, error) {
	return r.load(ctx, id, false)
}

// AllRecords implements repository.Repository.
func (r *Repo) AllRecords(ctx context.Context) (domain.Records, error) {
	return r.load(ctx, "", true)
}

func (r *Repo) setProvenance(ctx context.Context, tx *sql.Tx, kind domain.Kind, id string, prov []domain.Provenance) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM provenance WHERE record_id=?`, id); err != nil {
		return err
	}
	for _, p := range prov {
		if _, err := tx.ExecContext(ctx,
			`INSERT OR REPLACE INTO provenance(kind, record_id, source_id, state) VALUES (?,?,?,?)`,
			string(kind), id, string(p.SourceID), p.State); err != nil {
			return err
		}
	}
	return nil
}

// Apply implements repository.Repository. Everything runs in one transaction.
func (r *Repo) Apply(ctx context.Context, cs repository.ChangeSet) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("sqlite: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := r.apply(ctx, tx, cs); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("sqlite: commit: %w", err)
	}
	return nil
}

func (r *Repo) apply(ctx context.Context, tx *sql.Tx, cs repository.ChangeSet) error {
	wrap := func(what, id string, err error) error {
		return fmt.Errorf("sqlite: apply %s %s: %w", what, id, err)
	}
	for _, c := range cs.Upsert.Categories {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO categories(id, slug, data) VALUES (?,?,?)
			 ON CONFLICT(id) DO UPDATE SET slug=excluded.slug, data=excluded.data`,
			string(c.ID), c.Slug, mustJSON(c)); err != nil {
			return wrap("category", string(c.ID), err)
		}
		if err := r.setProvenance(ctx, tx, domain.KindCategory, string(c.ID), c.Provenance); err != nil {
			return wrap("category provenance", string(c.ID), err)
		}
	}
	for _, t := range cs.Upsert.Technologies {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO technologies(id, slug, name, status, data) VALUES (?,?,?,?,?)
			 ON CONFLICT(id) DO UPDATE SET slug=excluded.slug, name=excluded.name,
			   status=excluded.status, data=excluded.data`,
			string(t.ID), t.Slug, t.Name, string(t.Status), mustJSON(t)); err != nil {
			return wrap("technology", string(t.ID), err)
		}
		if err := r.setProvenance(ctx, tx, domain.KindTechnology, string(t.ID), t.Provenance); err != nil {
			return wrap("technology provenance", string(t.ID), err)
		}
	}
	for _, f := range cs.Upsert.Fingerprints {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO fingerprints(id, technology_id, observation, status, data) VALUES (?,?,?,?,?)
			 ON CONFLICT(id) DO UPDATE SET technology_id=excluded.technology_id,
			   observation=excluded.observation, status=excluded.status, data=excluded.data`,
			string(f.ID), string(f.TechnologyID), string(f.Observation), string(f.Status), mustJSON(f)); err != nil {
			return wrap("fingerprint", string(f.ID), err)
		}
		if err := r.setProvenance(ctx, tx, domain.KindFingerprint, string(f.ID), f.Provenance); err != nil {
			return wrap("fingerprint provenance", string(f.ID), err)
		}
	}
	for _, x := range cs.Upsert.Relationships {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO relationships(id, from_technology_id, type, data) VALUES (?,?,?,?)
			 ON CONFLICT(id) DO UPDATE SET from_technology_id=excluded.from_technology_id,
			   type=excluded.type, data=excluded.data`,
			string(x.ID), string(x.FromTechnologyID), x.Type, mustJSON(x)); err != nil {
			return wrap("relationship", string(x.ID), err)
		}
		if err := r.setProvenance(ctx, tx, domain.KindRelationship, string(x.ID), x.Provenance); err != nil {
			return wrap("relationship provenance", string(x.ID), err)
		}
	}
	return r.markRemoved(ctx, tx, cs)
}

// markRemoved flags the source's provenance entry on each listed record.
func (r *Repo) markRemoved(ctx context.Context, tx *sql.Tx, cs repository.ChangeSet) error {
	if err := markKind[domain.Category](ctx, tx, "categories", cs.SourceID, cs.RemovedUpstream.Categories,
		func(c *domain.Category) *[]domain.Provenance { return &c.Provenance }); err != nil {
		return err
	}
	if err := markKind[domain.Technology](ctx, tx, "technologies", cs.SourceID, cs.RemovedUpstream.Technologies,
		func(c *domain.Technology) *[]domain.Provenance { return &c.Provenance }); err != nil {
		return err
	}
	if err := markKind[domain.Fingerprint](ctx, tx, "fingerprints", cs.SourceID, cs.RemovedUpstream.Fingerprints,
		func(c *domain.Fingerprint) *[]domain.Provenance { return &c.Provenance }); err != nil {
		return err
	}
	return markKind[domain.Relationship](ctx, tx, "relationships", cs.SourceID, cs.RemovedUpstream.Relationships,
		func(c *domain.Relationship) *[]domain.Provenance { return &c.Provenance })
}

func markKind[T any](ctx context.Context, tx *sql.Tx, table string, sid domain.SourceID, ids []string,
	prov func(*T) *[]domain.Provenance) error {
	for _, id := range ids {
		var data string
		err := tx.QueryRowContext(ctx, `SELECT data FROM `+table+` WHERE id=?`, id).Scan(&data)
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("removed record %s does not exist in %s", id, table)
		}
		if err != nil {
			return fmt.Errorf("sqlite: load %s %s: %w", table, id, err)
		}
		var v T
		if err := json.Unmarshal([]byte(data), &v); err != nil {
			return fmt.Errorf("sqlite: decode %s %s: %w", table, id, err)
		}
		p := prov(&v)
		for i := range *p {
			if (*p)[i].SourceID == sid {
				(*p)[i].State = "removed_upstream"
			}
		}
		// table is an internal constant, never user input.
		if _, err := tx.ExecContext(ctx, `UPDATE `+table+` SET data=? WHERE id=?`, mustJSON(v), id); err != nil { //nolint:gosec
			return fmt.Errorf("sqlite: update %s %s: %w", table, id, err)
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE provenance SET state='removed_upstream' WHERE record_id=? AND source_id=?`, id, string(sid)); err != nil {
			return fmt.Errorf("sqlite: update provenance %s: %w", id, err)
		}
	}
	return nil
}
