PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS vault_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    label TEXT NOT NULL CHECK (length(label) BETWEEN 1 AND 120),
    token_format TEXT NOT NULL CHECK (token_format IN ('S4S1', 'S4S2')),
    token TEXT NOT NULL CHECK (length(token) BETWEEN 6 AND 7340032),
    token_sha256 TEXT NOT NULL UNIQUE CHECK (length(token_sha256) = 64),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_vault_records_created_at
    ON vault_records (created_at DESC, id DESC);

PRAGMA user_version = 1;
