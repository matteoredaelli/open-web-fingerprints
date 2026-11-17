-- +goose Up
-- Conflicts are review items. They never change canonical records by themselves.
CREATE TABLE conflicts (
    id    TEXT PRIMARY KEY,
    kind  TEXT NOT NULL,
    state TEXT NOT NULL,
    data  TEXT NOT NULL CHECK (json_valid(data))
) STRICT;
CREATE INDEX conflicts_state ON conflicts(state, kind);

-- +goose Down
DROP TABLE conflicts;
