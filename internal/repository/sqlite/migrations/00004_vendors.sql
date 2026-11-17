-- +goose Up
-- Vendors are keyed across sources by the CPE vendor identifier when there is
-- one. Manually created vendors have none.
CREATE TABLE vendors (
    id         TEXT PRIMARY KEY,
    slug       TEXT NOT NULL UNIQUE,
    cpe_vendor TEXT NOT NULL DEFAULT '',
    data       TEXT NOT NULL CHECK (json_valid(data))
) STRICT;
CREATE UNIQUE INDEX vendors_cpe ON vendors(cpe_vendor) WHERE cpe_vendor <> '';

-- +goose Down
DROP TABLE vendors;
