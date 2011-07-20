
/*
** Gmail Index Database Definition
*/

PRAGMA idx.auto_vacuum        = none;
PRAGMA idx.encoding           = "UTF-8";
PRAGMA idx.legacy_file_format = 0;
PRAGMA idx.page_size          = 4096;
PRAGMA idx.user_version       = {uv};

BEGIN;

-- TABLE: map ------------------------------------------------------------------
-- Table that links gmdb and index databases.

CREATE TABLE idx.map (
	docid   INTEGER PRIMARY KEY,   -- Index into the idx.fts table
	digest  TEXT NOT NULL UNIQUE,  -- Index into the main.file table
	date    INTEGER                -- Message date header (Unix timestamp)
);

CREATE INDEX idx.map_date ON map (date);

-- VIRTUAL TABLE: fts ----------------------------------------------------------
-- Full-text search table.

CREATE VIRTUAL TABLE idx.fts USING {fts_ver} (
	from, to, subject, body,
	tokenize={tok}
);

COMMIT;
