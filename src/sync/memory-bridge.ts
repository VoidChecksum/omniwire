// CyberSync — SQLite (Claude memory.db) -> PostgreSQL ingestion
//
// Reads Claude Code's local memory.db and ingests entries into
// the shared PostgreSQL knowledge + claude_memory tables.

import Database from 'better-sqlite3';
import { existsSync } from 'node:fs';
import type { SyncDB } from './db.js';

interface MemoryRow {
  key: string;
  value: string;
}

export class MemoryBridge {
  constructor(
    private db: SyncDB,
    private nodeId: string,
  ) {}

  // Ingest all entries from a local memory.db into PostgreSQL
  async ingest(dbPath: string): Promise<number> {
    if (!existsSync(dbPath)) return 0;

    let sqlite: Database.Database;
    try {
      sqlite = new Database(dbPath, { readonly: true });
    } catch {
      return 0;
    }

    let ingested = 0;

    try {
      // Discover tables — Claude memory.db schema may vary
      const tables = sqlite.prepare(
        "SELECT name FROM sqlite_master WHERE type='table'"
      ).all() as Array<{ name: string }>;

      for (const { name } of tables) {
        if (name.startsWith('sqlite_') || name === '_migrations') continue;

        try {
          const columns = sqlite.prepare(`PRAGMA table_info("${name}")`).all() as Array<{ name: string }>;
          const colNames = columns.map((c) => c.name);

          // Strategy 1: key-value tables
          if (colNames.includes('key') && colNames.includes('value')) {
            const rows = sqlite.prepare(`SELECT key, value FROM "${name}"`).all() as MemoryRow[];
            for (const row of rows) {
              await this.db.upsertClaudeMemory(this.nodeId, `${name}:${row.key}`, row.value);
              await this.db.upsertKnowledge('claude-code', `${name}:${row.key}`, {
                source: 'memory.db',
                table: name,
                node: this.nodeId,
                value: tryParseJson(row.value),
              });
              ingested++;
            }
            continue;
          }

          // Strategy 2: generic tables — ingest as JSON rows
          if (colNames.length > 0) {
            const rows = sqlite.prepare(`SELECT * FROM "${name}" LIMIT 1000`).all() as Record<string, unknown>[];
            for (let i = 0; i < rows.length; i++) {
              const key = `${name}:row_${i}`;
              await this.db.upsertKnowledge('claude-code', key, {
                source: 'memory.db',
                table: name,
                node: this.nodeId,
                ...rows[i],
              });
              ingested++;
            }
          }
        } catch {
          // Skip tables that fail to query
        }
      }
    } finally {
      sqlite.close();
    }

    return ingested;
  }
}

function tryParseJson(value: string): unknown {
  try {
    return JSON.parse(value);
  } catch {
    return value;
  }
}
