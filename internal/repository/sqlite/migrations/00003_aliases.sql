-- +goose Up
-- Merged-away record IDs and the record that replaced them. Imports translate
-- old IDs through this table so that a merge is not undone by a refresh.
CREATE TABLE aliases (
    old_id TEXT PRIMARY KEY,
    new_id TEXT NOT NULL,
    kind   TEXT NOT NULL
) STRICT;
CREATE INDEX aliases_new ON aliases(new_id);

-- +goose Down
DROP TABLE aliases;
