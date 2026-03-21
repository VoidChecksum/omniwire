// CyberSync — 8 MCP tools for sync status, control, and knowledge queries

import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { SyncDB } from '../sync/db.js';
import type { SyncEngine } from '../sync/engine.js';
import type { ToolManifest } from '../sync/types.js';
import { ALL_TOOLS } from '../sync/manifest.js';
import { SecretsManager } from '../sync/secrets.js';
import type { NodeManager } from '../nodes/manager.js';

export function registerSyncTools(
  server: McpServer,
  db: SyncDB,
  engine: SyncEngine,
  manifests: readonly ToolManifest[],
  nodeId: string,
  manager?: NodeManager,
): void {

  // --- Tool 23: cybersync_status ---
  server.tool(
    'cybersync_status',
    'CyberSync status: item counts, pending syncs, last heartbeat per node.',
    {},
    async () => {
      const heartbeats = await db.getHeartbeats();
      const counts = await db.getItemCounts();

      const lines: string[] = ['=== Node Heartbeats ==='];
      for (const hb of heartbeats) {
        lines.push(`${hb.nodeId}: last_seen=${hb.lastSeen.toISOString()}, items=${hb.itemsCount}, pending=${hb.pendingSync}`);
      }

      lines.push('', '=== Item Counts ===');
      for (const c of counts) {
        lines.push(`${c.tool}/${c.category}: ${c.count}`);
      }

      return { content: [{ type: 'text', text: lines.join('\n') }] };
    }
  );

  // --- Tool 24: cybersync_sync_now ---
  server.tool(
    'cybersync_sync_now',
    'Trigger immediate full reconciliation of all tool configs.',
    {},
    async () => {
      const result = await engine.reconcile(manifests);
      return {
        content: [{
          type: 'text',
          text: `Reconciliation complete: pushed=${result.pushed}, pulled=${result.pulled}, conflicts=${result.conflicts}`,
        }],
      };
    }
  );

  // --- Tool 25: cybersync_diff ---
  server.tool(
    'cybersync_diff',
    'Show items that differ between local node and the sync database.',
    {
      tool: z.string().optional().describe('Filter by tool name'),
    },
    async ({ tool }) => {
      const filteredManifests = tool
        ? manifests.filter((m) => m.tool === tool)
        : manifests;

      const diffs = await engine.getDiff(filteredManifests);

      if (diffs.length === 0) {
        return { content: [{ type: 'text', text: 'No differences found. All items in sync.' }] };
      }

      const lines = diffs.map((d) =>
        `[${d.direction}] ${d.tool}:${d.relPath} (local=${d.localHash?.slice(0, 8) ?? 'missing'}, remote=${d.remoteHash.slice(0, 8)})`
      );
      return { content: [{ type: 'text', text: `${diffs.length} differences:\n${lines.join('\n')}` }] };
    }
  );

  // --- Tool 26: cybersync_history ---
  server.tool(
    'cybersync_history',
    'Query sync event history.',
    {
      node: z.string().optional().describe('Filter by node'),
      event_type: z.string().optional().describe('Filter by event type (push, pull, conflict, delete, reconcile, error)'),
      limit: z.number().optional().describe('Max results (default 50)'),
    },
    async ({ node, event_type, limit }) => {
      const events = await db.getEvents({
        nodeId: node,
        eventType: event_type,
        limit: limit ?? 50,
      });

      if (events.length === 0) {
        return { content: [{ type: 'text', text: 'No events found.' }] };
      }

      const lines = events.map((e) =>
        `[${e.createdAt.toISOString()}] ${e.nodeId} ${e.eventType}: ${e.detail ?? ''}`
      );
      return { content: [{ type: 'text', text: lines.join('\n') }] };
    }
  );

  // --- Tool 27: cybersync_search_knowledge ---
  server.tool(
    'cybersync_search_knowledge',
    'Search the unified knowledge base across all AI tools and nodes.',
    {
      query: z.string().describe('Search query (matches key and value)'),
    },
    async ({ query }) => {
      const results = await db.searchKnowledge(query);

      if (results.length === 0) {
        return { content: [{ type: 'text', text: `No knowledge entries matching "${query}".` }] };
      }

      const lines = results.map((r) =>
        `[${r.sourceTool}] ${r.key}: ${JSON.stringify(r.value).slice(0, 200)}`
      );
      return { content: [{ type: 'text', text: `${results.length} results:\n${lines.join('\n')}` }] };
    }
  );

  // --- Tool 28: cybersync_get_memory ---
  server.tool(
    'cybersync_get_memory',
    'Get Claude memory entries from PostgreSQL (ingested from memory.db).',
    {
      node: z.string().optional().describe('Filter by node'),
      key: z.string().optional().describe('Search key pattern'),
    },
    async ({ node, key }) => {
      const entries = await db.getClaudeMemory({ nodeId: node, key });

      if (entries.length === 0) {
        return { content: [{ type: 'text', text: 'No memory entries found.' }] };
      }

      const lines = entries.map((e) =>
        `[${e.nodeId}] ${e.key}: ${e.value.slice(0, 300)}`
      );
      return { content: [{ type: 'text', text: `${entries.length} entries:\n${lines.join('\n')}` }] };
    }
  );

  // --- Tool 29: cybersync_manifest ---
  server.tool(
    'cybersync_manifest',
    'Show what files are tracked per AI tool.',
    {
      tool: z.string().optional().describe(`Tool name: ${ALL_TOOLS.join(', ')}`),
    },
    async ({ tool }) => {
      const filtered = tool
        ? manifests.filter((m) => m.tool === tool)
        : manifests;

      const lines: string[] = [];
      for (const m of filtered) {
        lines.push(`=== ${m.tool} ===`);
        lines.push(`Base: ${m.baseDir}`);
        lines.push(`Sync: ${m.syncGlobs.join(', ')}`);
        lines.push(`Exclude: ${m.excludeGlobs.join(', ') || '(none)'}`);
        if (m.ingestDb) lines.push(`Ingest DB: ${m.ingestDb}`);

        // Count items in DB
        const items = await db.getItemsByTool(m.tool);
        lines.push(`DB items: ${items.length}`);
        lines.push('');
      }

      return { content: [{ type: 'text', text: lines.join('\n') }] };
    }
  );

  // --- Tool 30: cybersync_force_push ---
  server.tool(
    'cybersync_force_push',
    'Force push a specific file to all online nodes, overwriting remote copies.',
    {
      tool: z.string().describe('Tool name'),
      rel_path: z.string().describe('Relative path within tool directory'),
    },
    async ({ tool, rel_path }) => {
      const manifest = manifests.find((m) => m.tool === tool);
      if (!manifest) {
        return { content: [{ type: 'text', text: `Unknown tool: ${tool}` }] };
      }

      const absPath = `${manifest.baseDir}/${rel_path}`;

      try {
        await engine.pushFile(tool, rel_path, absPath);
        return { content: [{ type: 'text', text: `Force pushed ${tool}:${rel_path} to all online nodes.` }] };
      } catch (err) {
        return { content: [{ type: 'text', text: `Error: ${(err as Error).message}` }] };
      }
    }
  );

  // --- Tool 31: omniwire_secrets ---
  server.tool(
    'omniwire_secrets',
    'Manage secrets across mesh nodes. Supports 1Password, file-based, and env backends.',
    {
      action: z.enum(['get', 'set', 'delete', 'list', 'sync', 'status']).describe('Action to perform'),
      key: z.string().optional().describe('Secret key (required for get/set/delete/sync)'),
      value: z.string().optional().describe('Secret value (required for set)'),
      nodes: z.array(z.string()).optional().describe('Target nodes for sync (all remote if omitted)'),
      backend: z.enum(['onepassword', 'file', 'env']).optional().describe('Override secrets backend'),
    },
    async ({ action, key, value, nodes: targetNodes, backend }) => {
      const secrets = new SecretsManager(backend ? { backend } : undefined);

      switch (action) {
        case 'status': {
          const opOk = await secrets.isOnePasswordAvailable();
          const items = await secrets.list();
          return { content: [{ type: 'text', text: `Backend: ${secrets.backend}\n1Password CLI: ${opOk ? 'available' : 'not found'}\nSecrets stored: ${items.length}` }] };
        }
        case 'list': {
          const items = await secrets.list();
          const text = items.length === 0
            ? 'No secrets stored'
            : items.map((i) => `  ${i.key} ${i.updatedAt ? `(${i.updatedAt})` : ''}`).join('\n');
          return { content: [{ type: 'text', text: `Secrets (${secrets.backend}):\n${text}` }] };
        }
        case 'get': {
          if (!key) return { content: [{ type: 'text', text: 'Error: key is required' }] };
          const val = await secrets.get(key);
          return { content: [{ type: 'text', text: val ? `${key} = ${val}` : `${key}: not found` }] };
        }
        case 'set': {
          if (!key || !value) return { content: [{ type: 'text', text: 'Error: key and value are required' }] };
          const ok = await secrets.set(key, value);
          return { content: [{ type: 'text', text: ok ? `Set ${key} (${secrets.backend})` : `Failed to set ${key}` }] };
        }
        case 'delete': {
          if (!key) return { content: [{ type: 'text', text: 'Error: key is required' }] };
          const ok = await secrets.delete(key);
          return { content: [{ type: 'text', text: ok ? `Deleted ${key}` : `Failed to delete ${key}` }] };
        }
        case 'sync': {
          if (!key) return { content: [{ type: 'text', text: 'Error: key is required for sync' }] };
          if (!manager) return { content: [{ type: 'text', text: 'Error: node manager not available' }] };
          const nodes = targetNodes ?? manager.getOnlineNodes().filter((id) => id !== nodeId);
          const results = await secrets.syncToNodes(key, nodes, manager);
          const text = Object.entries(results)
            .map(([n, ok]) => `  ${n}: ${ok ? 'OK' : 'FAILED'}`)
            .join('\n');
          return { content: [{ type: 'text', text: `Synced ${key} to nodes:\n${text}` }] };
        }
        default:
          return { content: [{ type: 'text', text: `Unknown action: ${action}` }] };
      }
    }
  );
}
