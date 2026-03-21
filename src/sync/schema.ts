// CyberSync — PostgreSQL schema + migration runner

import type pg from 'pg';

const STATEMENTS: readonly string[] = [
  `CREATE TABLE IF NOT EXISTS sync_items (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tool            TEXT NOT NULL,
    category        TEXT NOT NULL,
    rel_path        TEXT NOT NULL,
    content_hash    TEXT NOT NULL,
    content         BYTEA,
    content_size    BIGINT NOT NULL DEFAULT 0,
    metadata        JSONB DEFAULT '{}',
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by_node TEXT NOT NULL,
    is_deleted      BOOLEAN DEFAULT false,
    UNIQUE(tool, rel_path)
  )`,
  `CREATE TABLE IF NOT EXISTS node_sync_state (
    node_id         TEXT NOT NULL,
    item_id         UUID NOT NULL REFERENCES sync_items(id) ON DELETE CASCADE,
    content_hash    TEXT NOT NULL,
    synced_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (node_id, item_id)
  )`,
  `CREATE TABLE IF NOT EXISTS sync_events (
    id              BIGSERIAL PRIMARY KEY,
    item_id         UUID REFERENCES sync_items(id) ON DELETE SET NULL,
    node_id         TEXT NOT NULL,
    event_type      TEXT NOT NULL,
    detail          TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
  )`,
  `CREATE TABLE IF NOT EXISTS knowledge (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_tool     TEXT NOT NULL,
    key             TEXT NOT NULL,
    value           JSONB NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
  )`,
  `CREATE TABLE IF NOT EXISTS claude_memory (
    id              BIGSERIAL PRIMARY KEY,
    node_id         TEXT NOT NULL,
    key             TEXT NOT NULL,
    value           TEXT NOT NULL,
    ingested_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(node_id, key)
  )`,
  `CREATE TABLE IF NOT EXISTS node_heartbeats (
    node_id         TEXT PRIMARY KEY,
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT now(),
    items_count     INTEGER DEFAULT 0,
    pending_sync    INTEGER DEFAULT 0
  )`,
  'CREATE INDEX IF NOT EXISTS idx_sync_items_tool ON sync_items(tool)',
  'CREATE INDEX IF NOT EXISTS idx_sync_items_updated ON sync_items(updated_at)',
  'CREATE INDEX IF NOT EXISTS idx_sync_events_node ON sync_events(node_id)',
  'CREATE INDEX IF NOT EXISTS idx_sync_events_created ON sync_events(created_at)',
  'CREATE INDEX IF NOT EXISTS idx_knowledge_key ON knowledge(key)',
  'CREATE INDEX IF NOT EXISTS idx_claude_memory_node ON claude_memory(node_id)',
  // v2.1 migrations: unique constraint for upsert + FTS index
  'CREATE UNIQUE INDEX IF NOT EXISTS idx_knowledge_tool_key ON knowledge(source_tool, key)',
  `CREATE INDEX IF NOT EXISTS idx_knowledge_fts ON knowledge USING GIN (
    to_tsvector('english', key || ' ' || value::text)
  )`,
  'CREATE INDEX IF NOT EXISTS idx_sync_events_created_desc ON sync_events(created_at DESC)',
  // v2.2 migration: encrypted flag for at-rest encryption
  `ALTER TABLE sync_items ADD COLUMN IF NOT EXISTS encrypted BOOLEAN DEFAULT false`,
];

export async function runMigrations(pool: pg.Pool): Promise<void> {
  for (const sql of STATEMENTS) {
    await pool.query(sql);
  }
}
