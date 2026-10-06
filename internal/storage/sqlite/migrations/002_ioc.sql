-- 002_ioc.sql
CREATE TABLE IF NOT EXISTS iocs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL,          -- ip | domain | url | hash
    value TEXT NOT NULL,
    threat TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL DEFAULT 'manual',
    action TEXT NOT NULL DEFAULT '',  -- empty = use filters.intel.on_hit
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(type, value)
);

CREATE INDEX IF NOT EXISTS idx_iocs_type_value ON iocs(type, value);
CREATE INDEX IF NOT EXISTS idx_iocs_source ON iocs(source);
CREATE INDEX IF NOT EXISTS idx_iocs_enabled ON iocs(enabled);
