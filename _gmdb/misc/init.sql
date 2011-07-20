
/*
** Gmail Backup Database Initialization
*/

-- Pragmas that should be set for each database connection
PRAGMA {db}.foreign_keys  = 1;
PRAGMA {db}.journal_mode  = truncate;
PRAGMA {db}.locking_mode  = exclusive;
PRAGMA {db}.secure_delete = 0;
PRAGMA {db}.synchronous   = {sync};
PRAGMA {db}.temp_store    = memory;
