// CyberSync — PostgreSQL connection pool + query helpers

import pg from 'pg';
import { runMigrations } from './schema.js';
import type { SyncItem, NodeSyncState, SyncEvent, SyncEventType, KnowledgeEntry, ClaudeMemoryEntry, NodeHeartbeat, SyncConfig } from './types.js';

export class SyncDB {
  private pool: pg.Pool;

  constructor(private config: SyncConfig) {
    this.pool = new pg.Pool({
      host: config.pgHost,
      port: config.pgPort,
      database: config.pgDatabase,
      user: config.pgUser,
      password: config.pgPassword,
      max: 8,
      idleTimeoutMillis: 30_000,
      connectionTimeoutMillis: 5_000,
      statement_timeout: 10_000,
    });
  }

  async init(): Promise<void> {
    await runMigrations(this.pool);
  }

  async close(): Promise<void> {
    await this.pool.end();
  }

  // --- sync_items ---

  async upsertItem(item: {
    tool: string;
    category: string;
    relPath: string;
    contentHash: string;
    content: Buffer | null;
    contentSize: number;
    metadata: Record<string, unknown>;
    updatedByNode: string;
  }): Promise<SyncItem> {
    const { rows } = await this.pool.query(
      `INSERT INTO sync_items (tool, category, rel_path, content_hash, content, content_size, metadata, updated_by_node, is_deleted)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, false)
       ON CONFLICT (tool, rel_path) DO UPDATE SET
         content_hash = EXCLUDED.content_hash,
         content = EXCLUDED.content,
         content_size = EXCLUDED.content_size,
         metadata = EXCLUDED.metadata,
         updated_at = now(),
         updated_by_node = EXCLUDED.updated_by_node,
         is_deleted = false
       WHERE sync_items.content_hash != EXCLUDED.content_hash
       RETURNING *`,
      [item.tool, item.category, item.relPath, item.contentHash, item.content, item.contentSize, JSON.stringify(item.metadata), item.updatedByNode]
    );
    // If no rows returned, item already up-to-date — fetch existing
    if (rows.length === 0) {
      const existing = await this.pool.query(
        'SELECT * FROM sync_items WHERE tool = $1 AND rel_path = $2',
        [item.tool, item.relPath]
      );
      return this.mapSyncItem(existing.rows[0] as Record<string, unknown>);
    }
    return this.mapSyncItem(rows[0] as unknown as Record<string, unknown>);
  }

  async markDeleted(tool: string, relPath: string, nodeId: string): Promise<void> {
    await this.pool.query(
      `UPDATE sync_items SET is_deleted = true, updated_at = now(), updated_by_node = $3
       WHERE tool = $1 AND rel_path = $2`,
      [tool, relPath, nodeId]
    );
  }

  async getItem(tool: string, relPath: string): Promise<SyncItem | null> {
    const { rows } = await this.pool.query('SELECT * FROM sync_items WHERE tool = $1 AND rel_path = $2', [tool, relPath]);
    return rows.length > 0 ? this.mapSyncItem(rows[0]) : null;
  }

  async getItemsByTool(tool: string): Promise<SyncItem[]> {
    const { rows } = await this.pool.query(
      'SELECT * FROM sync_items WHERE tool = $1 AND is_deleted = false ORDER BY rel_path',
      [tool]
    );
    return rows.map((r) => this.mapSyncItem(r));
  }

  async getAllItems(): Promise<SyncItem[]> {
    const { rows } = await this.pool.query(
      'SELECT * FROM sync_items WHERE is_deleted = false ORDER BY tool, rel_path'
    );
    return rows.map((r) => this.mapSyncItem(r));
  }

  async getItemsUpdatedSince(since: Date): Promise<SyncItem[]> {
    const { rows } = await this.pool.query(
      'SELECT * FROM sync_items WHERE updated_at > $1 ORDER BY updated_at',
      [since]
    );
    return rows.map((r) => this.mapSyncItem(r));
  }

  async getItemCounts(): Promise<Array<{ tool: string; category: string; count: number }>> {
    const { rows } = await this.pool.query(
      `SELECT tool, category, count(*)::int as count
       FROM sync_items WHERE is_deleted = false
       GROUP BY tool, category ORDER BY tool, category`
    );
    return rows;
  }

  // --- node_sync_state ---

  async upsertNodeSync(nodeId: string, itemId: string, contentHash: string): Promise<void> {
    await this.pool.query(
      `INSERT INTO node_sync_state (node_id, item_id, content_hash, synced_at)
       VALUES ($1, $2, $3, now())
       ON CONFLICT (node_id, item_id) DO UPDATE SET
         content_hash = EXCLUDED.content_hash,
         synced_at = now()`,
      [nodeId, itemId, contentHash]
    );
  }

  async getNodeSyncState(nodeId: string): Promise<NodeSyncState[]> {
    const { rows } = await this.pool.query(
      'SELECT node_id as "nodeId", item_id as "itemId", content_hash as "contentHash", synced_at as "syncedAt" FROM node_sync_state WHERE node_id = $1',
      [nodeId]
    );
    return rows;
  }

  async getPendingItems(nodeId: string): Promise<SyncItem[]> {
    const { rows } = await this.pool.query(
      `SELECT si.* FROM sync_items si
       LEFT JOIN node_sync_state nss ON si.id = nss.item_id AND nss.node_id = $1
       WHERE si.is_deleted = false
         AND (nss.content_hash IS NULL OR nss.content_hash != si.content_hash)
       ORDER BY si.updated_at`,
      [nodeId]
    );
    return rows.map((r) => this.mapSyncItem(r));
  }

  // --- sync_events ---

  async logEvent(itemId: string | null, nodeId: string, eventType: SyncEventType, detail: string | null): Promise<void> {
    await this.pool.query(
      'INSERT INTO sync_events (item_id, node_id, event_type, detail) VALUES ($1, $2, $3, $4)',
      [itemId, nodeId, eventType, detail]
    );
  }

  async getEvents(opts: { nodeId?: string; eventType?: string; limit?: number }): Promise<SyncEvent[]> {
    const conditions: string[] = [];
    const params: unknown[] = [];
    let idx = 1;

    if (opts.nodeId) { conditions.push(`node_id = $${idx++}`); params.push(opts.nodeId); }
    if (opts.eventType) { conditions.push(`event_type = $${idx++}`); params.push(opts.eventType); }

    const where = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
    const limit = opts.limit ?? 50;

    const { rows } = await this.pool.query(
      `SELECT id, item_id as "itemId", node_id as "nodeId", event_type as "eventType", detail, created_at as "createdAt"
       FROM sync_events ${where} ORDER BY created_at DESC LIMIT $${idx}`,
      [...params, limit]
    );
    return rows;
  }

  // --- knowledge ---

  async upsertKnowledge(sourceTool: string, key: string, value: Record<string, unknown>): Promise<void> {
    await this.pool.query(
      `INSERT INTO knowledge (source_tool, key, value)
       VALUES ($1, $2, $3)
       ON CONFLICT (source_tool, key) DO UPDATE SET
         value = EXCLUDED.value, updated_at = now()`,
      [sourceTool, key, JSON.stringify(value)]
    );
  }

  async searchKnowledge(query: string): Promise<KnowledgeEntry[]> {
    // Try full-text search first (uses GIN index if available)
    const { rows: ftsRows } = await this.pool.query(
      `SELECT id, source_tool as "sourceTool", key, value, created_at as "createdAt", updated_at as "updatedAt"
       FROM knowledge
       WHERE to_tsvector('english', key || ' ' || value::text) @@ plainto_tsquery('english', $1)
       ORDER BY updated_at DESC LIMIT 50`,
      [query]
    ).catch(() => ({ rows: [] as KnowledgeEntry[] }));

    if (ftsRows.length > 0) return ftsRows;

    // Fallback to ILIKE for partial matches
    const { rows } = await this.pool.query(
      `SELECT id, source_tool as "sourceTool", key, value, created_at as "createdAt", updated_at as "updatedAt"
       FROM knowledge
       WHERE key ILIKE $1 OR value::text ILIKE $1
       ORDER BY updated_at DESC LIMIT 50`,
      [`%${query}%`]
    );
    return rows;
  }

  // --- claude_memory ---

  async upsertClaudeMemory(nodeId: string, key: string, value: string): Promise<void> {
    await this.pool.query(
      `INSERT INTO claude_memory (node_id, key, value)
       VALUES ($1, $2, $3)
       ON CONFLICT (node_id, key) DO UPDATE SET
         value = EXCLUDED.value,
         ingested_at = now()`,
      [nodeId, key, value]
    );
  }

  async getClaudeMemory(opts: { nodeId?: string; key?: string }): Promise<ClaudeMemoryEntry[]> {
    const conditions: string[] = [];
    const params: unknown[] = [];
    let idx = 1;

    if (opts.nodeId) { conditions.push(`node_id = $${idx++}`); params.push(opts.nodeId); }
    if (opts.key) { conditions.push(`key ILIKE $${idx++}`); params.push(`%${opts.key}%`); }

    const where = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

    const { rows } = await this.pool.query(
      `SELECT id, node_id as "nodeId", key, value, ingested_at as "ingestedAt"
       FROM claude_memory ${where} ORDER BY ingested_at DESC LIMIT 100`,
      params
    );
    return rows;
  }

  // --- heartbeats ---

  async heartbeat(nodeId: string, itemsCount: number, pendingSync: number): Promise<void> {
    await this.pool.query(
      `INSERT INTO node_heartbeats (node_id, last_seen, items_count, pending_sync)
       VALUES ($1, now(), $2, $3)
       ON CONFLICT (node_id) DO UPDATE SET
         last_seen = now(),
         items_count = EXCLUDED.items_count,
         pending_sync = EXCLUDED.pending_sync`,
      [nodeId, itemsCount, pendingSync]
    );
  }

  async getHeartbeats(): Promise<NodeHeartbeat[]> {
    const { rows } = await this.pool.query(
      `SELECT node_id as "nodeId", last_seen as "lastSeen", items_count as "itemsCount", pending_sync as "pendingSync"
       FROM node_heartbeats ORDER BY node_id`
    );
    return rows;
  }

  // --- batch operations ---

  async batchUpsertNodeSync(entries: ReadonlyArray<{ nodeId: string; itemId: string; contentHash: string }>): Promise<void> {
    if (entries.length === 0) return;
    const nodeIds = entries.map((e) => e.nodeId);
    const itemIds = entries.map((e) => e.itemId);
    const hashes = entries.map((e) => e.contentHash);
    await this.pool.query(
      `INSERT INTO node_sync_state (node_id, item_id, content_hash, synced_at)
       SELECT unnest($1::text[]), unnest($2::uuid[]), unnest($3::text[]), now()
       ON CONFLICT (node_id, item_id) DO UPDATE SET
         content_hash = EXCLUDED.content_hash, synced_at = now()`,
      [nodeIds, itemIds, hashes]
    );
  }

  async pruneEvents(keepCount: number = 5000): Promise<number> {
    const { rowCount } = await this.pool.query(
      `DELETE FROM sync_events WHERE id NOT IN (
         SELECT id FROM sync_events ORDER BY created_at DESC LIMIT $1
       )`,
      [keepCount]
    );
    return rowCount ?? 0;
  }

  // --- helpers ---

  private mapSyncItem(row: Record<string, unknown>): SyncItem {
    return {
      id: row.id as string,
      tool: row.tool as SyncItem['tool'],
      category: row.category as string,
      relPath: (row.rel_path ?? row.relPath) as string,
      contentHash: (row.content_hash ?? row.contentHash) as string,
      content: row.content as Buffer | null,
      contentSize: Number(row.content_size ?? row.contentSize ?? 0),
      metadata: (typeof row.metadata === 'string' ? JSON.parse(row.metadata) : row.metadata ?? {}) as Record<string, unknown>,
      updatedAt: new Date(row.updated_at as string ?? row.updatedAt as string),
      updatedByNode: (row.updated_by_node ?? row.updatedByNode) as string,
      isDeleted: Boolean(row.is_deleted ?? row.isDeleted),
    };
  }
}
