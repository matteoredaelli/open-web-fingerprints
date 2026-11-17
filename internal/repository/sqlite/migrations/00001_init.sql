-- +goose Up
-- Each entity keeps indexed columns for queries plus the complete canonical
-- record as JSON in "data", so the public model stays the source of truth.

CREATE TABLE sources (
    id   TEXT PRIMARY KEY,
    slug TEXT NOT NULL UNIQUE,
    data TEXT NOT NULL CHECK (json_valid(data))
) STRICT;

CREATE TABLE snapshots (
    source_id    TEXT NOT NULL REFERENCES sources(id),
    revision     TEXT NOT NULL,
    checksum     TEXT NOT NULL,
    retrieved_at TEXT NOT NULL,
    data         TEXT NOT NULL CHECK (json_valid(data)),
    PRIMARY KEY (source_id, revision)
) STRICT;

-- Stable mapping from an upstream record to its canonical ID.
CREATE TABLE id_map (
    kind      TEXT NOT NULL,
    source_id TEXT NOT NULL,
    key       TEXT NOT NULL,
    id        TEXT NOT NULL UNIQUE,
    PRIMARY KEY (kind, source_id, key)
) STRICT;

CREATE TABLE categories (
    id   TEXT PRIMARY KEY,
    slug TEXT NOT NULL UNIQUE,
    data TEXT NOT NULL CHECK (json_valid(data))
) STRICT;

CREATE TABLE technologies (
    id     TEXT PRIMARY KEY,
    slug   TEXT NOT NULL UNIQUE,
    name   TEXT NOT NULL,
    status TEXT NOT NULL,
    data   TEXT NOT NULL CHECK (json_valid(data))
) STRICT;
CREATE INDEX technologies_name ON technologies(name);

CREATE TABLE fingerprints (
    id            TEXT PRIMARY KEY,
    technology_id TEXT NOT NULL REFERENCES technologies(id),
    observation   TEXT NOT NULL,
    status        TEXT NOT NULL,
    data          TEXT NOT NULL CHECK (json_valid(data))
) STRICT;
CREATE INDEX fingerprints_technology ON fingerprints(technology_id);
CREATE INDEX fingerprints_observation ON fingerprints(observation);

CREATE TABLE relationships (
    id                 TEXT PRIMARY KEY,
    from_technology_id TEXT NOT NULL REFERENCES technologies(id),
    type               TEXT NOT NULL,
    data               TEXT NOT NULL CHECK (json_valid(data))
) STRICT;
CREATE INDEX relationships_from ON relationships(from_technology_id);

-- One row per (record, source) provenance entry. Rebuilt on every upsert.
CREATE TABLE provenance (
    kind      TEXT NOT NULL,
    record_id TEXT NOT NULL,
    source_id TEXT NOT NULL,
    state     TEXT NOT NULL,
    PRIMARY KEY (record_id, source_id)
) STRICT;
CREATE INDEX provenance_source ON provenance(source_id, kind);

-- +goose Down
DROP TABLE provenance;
DROP TABLE relationships;
DROP TABLE fingerprints;
DROP TABLE technologies;
DROP TABLE categories;
DROP TABLE id_map;
DROP TABLE snapshots;
DROP TABLE sources;
