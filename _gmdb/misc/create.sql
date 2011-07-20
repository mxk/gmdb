
/*
** Gmail Backup Database Definition
*/

PRAGMA auto_vacuum        = none;
PRAGMA encoding           = "UTF-8";
PRAGMA legacy_file_format = 0;
PRAGMA page_size          = 4096;
PRAGMA user_version       = {uv};

BEGIN;

-- TABLE: conf -----------------------------------------------------------------
-- Persistent storage for database settings.

CREATE TABLE conf (
	key    TEXT PRIMARY KEY NOT NULL,
	value  TEXT
);

-- Full account name; set by the first backup (e.g. someone@example.com)
INSERT INTO conf VALUES ('account', NULL);

-- File digest algorithm (any algorithm in hashlib.algorithms_guaranteed)
INSERT INTO conf VALUES ('digest', 'sha1');

-- Directory hierarchy levels (reduces the number of files in each directory)
INSERT INTO conf VALUES ('dir_levels',  3);

-- File compression method (none or gzip)
INSERT INTO conf VALUES ('comp_method', 'gzip');

-- File compression level when comp_method is gzip
INSERT INTO conf VALUES ('comp_level', 6);

-- How long to keep deleted messages (in seconds, default = 365 days)
INSERT INTO conf VALUES ('retention', 31536000);

-- ID of the last message successfully uploaded during a restore operation
INSERT INTO conf VALUES ('resume', NULL);

-- Indexing status, set to 1 when the most recent backup is already indexed
INSERT INTO conf VALUES ('indexed', 0);

-- TABLE: op -------------------------------------------------------------------
-- Master table that contains one row for each operation (command) performed.

CREATE TABLE op (
	op_id   INTEGER PRIMARY KEY AUTOINCREMENT,  -- Internal operation ID
	name    TEXT    NOT NULL,  -- Operation name ('backup', 'restore')
	start   INTEGER NOT NULL,  -- Start time (Unix timestamp)
	stop    INTEGER,           -- Stop time
	filter  TEXT,              -- Search string used to filter messages
	result  TEXT,              -- Result ('ok', 'abort', or 'error')
	info    TEXT               -- Additional result information
);

CREATE INDEX op_start ON op (start);

-- TABLE: file -----------------------------------------------------------------
-- Index of messages downloaded to disk.

CREATE TABLE file (
	file_id  INTEGER PRIMARY KEY,      -- Internal file ID
	op_id    INTEGER,                  -- Operation that downloaded this file
	digest   TEXT    NOT NULL UNIQUE,  -- Uncompressed file digest
	size     INTEGER NOT NULL,         -- Uncompressed file size in bytes

	FOREIGN KEY (op_id) REFERENCES op ON DELETE SET NULL
);

CREATE INDEX file_op_id ON file (op_id);

-- TABLE: flag -----------------------------------------------------------------
-- List of message flags returned by the IMAP server.

CREATE TABLE flag (
	flag_id  INTEGER PRIMARY KEY,     -- Internal flag list ID
	flags    TEXT    NOT NULL UNIQUE  -- Sorted flag list (separated by spaces)
);

-- TABLE: lbl ------------------------------------------------------------------
-- List of message labels.

CREATE TABLE lbl (
	lbl_id  INTEGER PRIMARY KEY,     -- Internal label list ID
	labels  TEXT    NOT NULL UNIQUE  -- Sorted label list (quoted strings)
);

-- TABLE: msg ------------------------------------------------------------------
-- Message index that ties all message components together.
-- The msg_id and thr_id columns contain signed 64-bit equivalents of the
-- unsigned 64-bit X-GM-MSGID and X-GM-THRID values.

CREATE TABLE msg (
	msg_id   INTEGER PRIMARY KEY,  -- External message ID (X-GM-MSGID)
	op_id    INTEGER NOT NULL,     -- The last backup to see this message
	file_id  INTEGER NOT NULL,     -- File contents
	flag_id  INTEGER,              -- Message flags  (NULL = no flags)
	lbl_id   INTEGER,              -- Message labels (NULL = no labels)
	thr_id   INTEGER NOT NULL,     -- Thread ID (X-GM-THRID)
	idate    INTEGER NOT NULL,     -- Internal date and time (Unix timestamp)

	FOREIGN KEY (op_id)   REFERENCES op   ON DELETE CASCADE,
	FOREIGN KEY (file_id) REFERENCES file ON DELETE CASCADE,
	FOREIGN KEY (flag_id) REFERENCES flag,
	FOREIGN KEY (lbl_id)  REFERENCES lbl
);

CREATE INDEX msg_op_id   ON msg (op_id);
CREATE INDEX msg_file_id ON msg (file_id);
CREATE INDEX msg_flag_id ON msg (flag_id);
CREATE INDEX msg_lbl_id  ON msg (lbl_id);
CREATE INDEX msg_thr_id  ON msg (thr_id);

-- VIEW: msg_view --------------------------------------------------------------
-- A complete overview of stored messages.

CREATE VIEW msg_view AS
	SELECT msg_id, msg.op_id, digest, size, flags, labels, thr_id, idate
	FROM msg, file USING (file_id)
	LEFT JOIN flag USING (flag_id)
	LEFT JOIN lbl  USING (lbl_id);

COMMIT;
