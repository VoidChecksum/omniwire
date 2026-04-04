// CyberSync — MCP tools for sync status, control, knowledge, and bi-directional sync

import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { SyncDB } from '../sync/db.js';
import type { SyncEngine } from '../sync/engine.js';
import type { ToolManifest } from '../sync/types.js';
import { ALL_TOOLS } from '../sync/manifest.js';
import { SecretsManager } from '../sync/secrets.js';
import { CookieManager, parseCookies } from '../sync/cookies.js';
import type { CookieFormat } from '../sync/cookies.js';
import type { NodeManager } from '../nodes/manager.js';
import type { TransferEngine } from '../nodes/transfer.js';

export function registerSyncTools(
  server: McpServer,
  db: SyncDB,
  engine: SyncEngine,
  manifests: readonly ToolManifest[],
  nodeId: string,
  manager?: NodeManager,
  transfer?: TransferEngine,
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

  // --- Tool 35: cybersync_cookies ---
  server.tool(
    'cybersync_cookies',
    'Manage browser cookies across mesh nodes with CyberBase persistence. Store/retrieve/import/export in json/header/netscape format and sync to remote nodes via SSH.',
    {
      action: z.enum(['set', 'get', 'list', 'delete', 'import', 'export', 'sync']).describe('Action to perform'),
      domain: z.string().optional().describe('Cookie domain (required for set/get/delete/sync/export)'),
      cookies: z.string().optional().describe('Cookie data: JSON array for set, raw string for import'),
      format: z.enum(['json', 'header', 'netscape']).optional().describe('Cookie format (default: json)'),
      nodes: z.array(z.string()).optional().describe('Target node ids for sync (all online if omitted)'),
    },
    async ({ action, domain, cookies: cookieData, format, nodes: targetNodes }) => {
      const cookieMgr = new CookieManager(db, manager, transfer);
      const fmt = (format ?? 'json') as CookieFormat;
      switch (action) {
        case 'list': {
          const jars = await cookieMgr.list();
          if (jars.length === 0) {
            return { content: [{ type: 'text', text: 'No cookie jars stored.' }] };
          }
          const lines = jars.map((j) =>
            '  ' + j.domain + ': ' + j.count + ' cookies, updated=' + j.updatedAt + (j.source ? ', source=' + j.source : '')
          );
          return { content: [{ type: 'text', text: jars.length + ' cookie jar(s):\n' + lines.join('\n') }] };
        }
        case 'get': {
          if (!domain) return { content: [{ type: 'text', text: 'Error: domain is required for get' }] };
          const result = await cookieMgr.get(domain, fmt);
          if (!result) return { content: [{ type: 'text', text: 'No cookies found for ' + domain }] };
          return { content: [{ type: 'text', text: result }] };
        }
        case 'set': {
          if (!domain) return { content: [{ type: 'text', text: 'Error: domain is required for set' }] };
          if (!cookieData) return { content: [{ type: 'text', text: 'Error: cookies is required for set' }] };
          const parsed = parseCookies(cookieData, fmt, domain);
          await cookieMgr.set(domain, parsed);
          return { content: [{ type: 'text', text: 'Stored ' + parsed.length + ' cookie(s) for ' + domain }] };
        }
        case 'delete': {
          if (!domain) return { content: [{ type: 'text', text: 'Error: domain is required for delete' }] };
          await cookieMgr.delete(domain);
          return { content: [{ type: 'text', text: 'Deleted cookies for ' + domain }] };
        }
        case 'import': {
          if (!cookieData) return { content: [{ type: 'text', text: 'Error: cookies is required for import' }] };
          const results = await cookieMgr.import(cookieData, fmt, domain);
          const lines = Object.entries(results).map(([d, n]) => '  ' + d + ': ' + n + ' cookie(s)');
          return { content: [{ type: 'text', text: 'Imported cookies:\n' + lines.join('\n') }] };
        }
        case 'export': {
          if (!domain) return { content: [{ type: 'text', text: 'Error: domain is required for export' }] };
          const result = await cookieMgr.get(domain, fmt);
          if (!result) return { content: [{ type: 'text', text: 'No cookies found for ' + domain }] };
          return { content: [{ type: 'text', text: result }] };
        }
        case 'sync': {
          if (!manager) return { content: [{ type: 'text', text: 'Error: node manager not available' }] };
          if (domain) {
            const results = await cookieMgr.syncToNodes(domain, targetNodes);
            const lines = Object.entries(results).map(([n, ok]) => '  ' + n + ': ' + (ok ? 'OK' : 'FAILED'));
            return { content: [{ type: 'text', text: 'Synced ' + domain + ' to nodes:\n' + lines.join('\n') }] };
          } else {
            const allResults = await cookieMgr.syncAllToNodes(targetNodes);
            const lines = Object.entries(allResults).flatMap(([dom, nodeResults]) =>
              Object.entries(nodeResults).map(([n, ok]) => '  ' + dom + ' -> ' + n + ': ' + (ok ? 'OK' : 'FAILED'))
            );
            return { content: [{ type: 'text', text: lines.length ? lines.join('\n') : 'No cookie jars to sync.' }] };
          }
        }
        default:
          return { content: [{ type: 'text', text: 'Unknown action: ' + action }] };
      }
    }
  );

  // --- Tool: omniwire_sync ---
  server.tool(
    'omniwire_sync',
    'Bi-directional sync of rules, hooks, memory, agent configs, and settings across all mesh nodes. Syncs Claude Code, OpenClaw, and all AI tool configs.',
    {
      action: z.enum(['full', 'push', 'pull', 'status', 'diff', 'watch']).describe(
        'full=bi-directional reconcile, push=local→all nodes, pull=remote→local, status=sync health, diff=show differences, watch=start file watcher'
      ),
      tool: z.string().optional().describe(`Filter by tool: ${ALL_TOOLS.join(', ')}`),
      category: z.string().optional().describe('Filter by category: rules, hooks, memory, agents, settings, skills, config'),
      nodes: z.array(z.string()).optional().describe('Target nodes (default: all online)'),
      dry_run: z.boolean().optional().describe('Preview changes without applying'),
    },
    async ({ action, tool, category, nodes: targetNodes, dry_run }) => {
      const filteredManifests = tool
        ? manifests.filter((m) => m.tool === tool)
        : manifests;

      switch (action) {
        case 'full': {
          if (dry_run) {
            const diffs = await engine.getDiff(filteredManifests);
            const filtered = category
              ? diffs.filter((d) => d.relPath.startsWith(category + '/'))
              : diffs;
            return { content: [{ type: 'text', text: `[DRY RUN] ${filtered.length} items would sync:\n${filtered.map((d) => `  [${d.direction}] ${d.tool}:${d.relPath}`).join('\n')}` }] };
          }
          const result = await engine.reconcile(filteredManifests);
          return { content: [{ type: 'text', text: `Bi-directional sync complete: pushed=${result.pushed}, pulled=${result.pulled}, conflicts=${result.conflicts}` }] };
        }
        case 'push': {
          const diffs = await engine.getDiff(filteredManifests);
          const pushable = diffs.filter((d) => d.direction === 'push');
          const filtered = category
            ? pushable.filter((d) => d.relPath.startsWith(category + '/'))
            : pushable;
          if (dry_run) {
            return { content: [{ type: 'text', text: `[DRY RUN] Would push ${filtered.length} items:\n${filtered.map((d) => `  ${d.tool}:${d.relPath}`).join('\n')}` }] };
          }
          let pushed = 0;
          for (const d of filtered) {
            const m = filteredManifests.find((mm) => mm.tool === d.tool);
            if (!m) continue;
            try {
              await engine.pushFile(d.tool, d.relPath, `${m.baseDir}/${d.relPath}`);
              pushed++;
            } catch { /* skip failed items */ }
          }
          return { content: [{ type: 'text', text: `Pushed ${pushed}/${filtered.length} items to all nodes.` }] };
        }
        case 'pull': {
          const pulled = await engine.pullPending();
          return { content: [{ type: 'text', text: `Pulled ${pulled} items from remote nodes.` }] };
        }
        case 'status': {
          const heartbeats = await db.getHeartbeats();
          const counts = await db.getItemCounts();
          const diffs = await engine.getDiff(filteredManifests);
          const lines = [
            `Nodes: ${heartbeats.length} | Items synced: ${counts.reduce((a, c) => a + c.count, 0)} | Pending: ${diffs.length}`,
            '',
            ...heartbeats.map((hb) => `  ${hb.nodeId}: seen=${hb.lastSeen.toISOString().slice(0, 19)}, items=${hb.itemsCount}, pending=${hb.pendingSync}`),
          ];
          if (category) {
            const catDiffs = diffs.filter((d) => d.relPath.startsWith(category + '/'));
            lines.push('', `Category '${category}': ${catDiffs.length} pending`);
          }
          return { content: [{ type: 'text', text: lines.join('\n') }] };
        }
        case 'diff': {
          const diffs = await engine.getDiff(filteredManifests);
          const filtered = category
            ? diffs.filter((d) => d.relPath.startsWith(category + '/'))
            : diffs;
          if (filtered.length === 0) {
            return { content: [{ type: 'text', text: 'All in sync. No differences.' }] };
          }
          const lines = filtered.map((d) =>
            `[${d.direction}] ${d.tool}:${d.relPath} (local=${d.localHash?.slice(0, 8) ?? 'missing'}, remote=${d.remoteHash.slice(0, 8)})`
          );
          return { content: [{ type: 'text', text: `${filtered.length} differences:\n${lines.join('\n')}` }] };
        }
        case 'watch': {
          return { content: [{ type: 'text', text: 'File watcher is managed by the sync engine background loop. Reconcile interval: 2 minutes.' }] };
        }
        default:
          return { content: [{ type: 'text', text: `Unknown action: ${action}` }] };
      }
    }
  );

  // --- Tool: omniwire_sync_rules ---
  server.tool(
    'omniwire_sync_rules',
    'Sync Claude Code rules (CLAUDE.md, rules/*.md, hooks/*) bi-directionally across all mesh nodes. Push local rules to all nodes or pull latest from remote.',
    {
      action: z.enum(['sync', 'push', 'pull', 'diff', 'list']).describe(
        'sync=bi-directional, push=local→remote, pull=remote→local, diff=show changes, list=show tracked rules'
      ),
      nodes: z.array(z.string()).optional().describe('Target nodes (default: all online)'),
    },
    async ({ action, nodes: targetNodes }) => {
      const ruleManifests = manifests.filter((m) => m.tool === 'claude-code');

      switch (action) {
        case 'sync': {
          const result = await engine.reconcile(ruleManifests);
          return { content: [{ type: 'text', text: `Rules sync: pushed=${result.pushed}, pulled=${result.pulled}, conflicts=${result.conflicts}` }] };
        }
        case 'push': {
          const diffs = await engine.getDiff(ruleManifests);
          const rules = diffs.filter((d) =>
            d.relPath.startsWith('rules/') || d.relPath.startsWith('hooks/') || d.relPath === 'CLAUDE.md'
          );
          let pushed = 0;
          for (const d of rules) {
            const m = ruleManifests.find((mm) => mm.tool === d.tool);
            if (!m) continue;
            try {
              await engine.pushFile(d.tool, d.relPath, `${m.baseDir}/${d.relPath}`);
              pushed++;
            } catch { /* skip failed */ }
          }
          return { content: [{ type: 'text', text: `Pushed ${pushed} rule/hook files to all nodes.` }] };
        }
        case 'pull': {
          const pulled = await engine.pullPending();
          return { content: [{ type: 'text', text: `Pulled ${pulled} items (including rules/hooks) from remote.` }] };
        }
        case 'diff': {
          const diffs = await engine.getDiff(ruleManifests);
          const rules = diffs.filter((d) =>
            d.relPath.startsWith('rules/') || d.relPath.startsWith('hooks/') || d.relPath === 'CLAUDE.md'
          );
          if (rules.length === 0) {
            return { content: [{ type: 'text', text: 'All rules and hooks in sync.' }] };
          }
          const lines = rules.map((d) =>
            `[${d.direction}] ${d.relPath} (local=${d.localHash?.slice(0, 8) ?? 'missing'}, remote=${d.remoteHash.slice(0, 8)})`
          );
          return { content: [{ type: 'text', text: `${rules.length} rule/hook differences:\n${lines.join('\n')}` }] };
        }
        case 'list': {
          const items = await db.getItemsByTool('claude-code');
          const rules = items.filter((i) =>
            i.relPath.startsWith('rules/') || i.relPath.startsWith('hooks/') || i.relPath === 'CLAUDE.md'
          );
          if (rules.length === 0) {
            return { content: [{ type: 'text', text: 'No rules/hooks tracked in sync database.' }] };
          }
          const lines = rules.map((i) =>
            `  ${i.relPath} (hash=${i.contentHash.slice(0, 8)}, node=${i.updatedByNode}, updated=${i.updatedAt.toISOString().slice(0, 19)})`
          );
          return { content: [{ type: 'text', text: `${rules.length} tracked rules/hooks:\n${lines.join('\n')}` }] };
        }
        default:
          return { content: [{ type: 'text', text: `Unknown action: ${action}` }] };
      }
    }
  );

  // --- Tool: omniwire_sync_hooks ---
  server.tool(
    'omniwire_sync_hooks',
    'Sync Claude Code hooks (hooks/*) bi-directionally across all mesh nodes.',
    {
      action: z.enum(['sync', 'push', 'pull', 'diff', 'list']).describe(
        'sync=bi-directional, push=local→remote, pull=remote→local, diff=show changes, list=show tracked hooks'
      ),
    },
    async ({ action }) => {
      const ccManifests = manifests.filter((m) => m.tool === 'claude-code');

      switch (action) {
        case 'sync': {
          const result = await engine.reconcile(ccManifests);
          return { content: [{ type: 'text', text: `Hooks sync: pushed=${result.pushed}, pulled=${result.pulled}, conflicts=${result.conflicts}` }] };
        }
        case 'push': {
          const diffs = await engine.getDiff(ccManifests);
          const hooks = diffs.filter((d) => d.relPath.startsWith('hooks/'));
          let pushed = 0;
          for (const d of hooks) {
            const m = ccManifests.find((mm) => mm.tool === d.tool);
            if (!m) continue;
            try {
              await engine.pushFile(d.tool, d.relPath, `${m.baseDir}/${d.relPath}`);
              pushed++;
            } catch { /* skip */ }
          }
          return { content: [{ type: 'text', text: `Pushed ${pushed} hook files to all nodes.` }] };
        }
        case 'pull': {
          const pulled = await engine.pullPending();
          return { content: [{ type: 'text', text: `Pulled ${pulled} items (including hooks) from remote.` }] };
        }
        case 'diff': {
          const diffs = await engine.getDiff(ccManifests);
          const hooks = diffs.filter((d) => d.relPath.startsWith('hooks/'));
          if (hooks.length === 0) {
            return { content: [{ type: 'text', text: 'All hooks in sync.' }] };
          }
          const lines = hooks.map((d) =>
            `[${d.direction}] ${d.relPath} (local=${d.localHash?.slice(0, 8) ?? 'missing'}, remote=${d.remoteHash.slice(0, 8)})`
          );
          return { content: [{ type: 'text', text: `${hooks.length} hook differences:\n${lines.join('\n')}` }] };
        }
        case 'list': {
          const items = await db.getItemsByTool('claude-code');
          const hooks = items.filter((i) => i.relPath.startsWith('hooks/'));
          if (hooks.length === 0) {
            return { content: [{ type: 'text', text: 'No hooks tracked.' }] };
          }
          const lines = hooks.map((i) =>
            `  ${i.relPath} (hash=${i.contentHash.slice(0, 8)}, node=${i.updatedByNode}, updated=${i.updatedAt.toISOString().slice(0, 19)})`
          );
          return { content: [{ type: 'text', text: `${hooks.length} tracked hooks:\n${lines.join('\n')}` }] };
        }
        default:
          return { content: [{ type: 'text', text: `Unknown action: ${action}` }] };
      }
    }
  );

  // --- Tool: omniwire_sync_memory ---
  server.tool(
    'omniwire_sync_memory',
    'Sync Claude Code memory files (memory/*) bi-directionally across all mesh nodes.',
    {
      action: z.enum(['sync', 'push', 'pull', 'diff', 'list']).describe(
        'sync=bi-directional, push=local→remote, pull=remote→local, diff=show changes, list=show tracked memory files'
      ),
    },
    async ({ action }) => {
      const ccManifests = manifests.filter((m) => m.tool === 'claude-code');

      switch (action) {
        case 'sync': {
          const result = await engine.reconcile(ccManifests);
          return { content: [{ type: 'text', text: `Memory sync: pushed=${result.pushed}, pulled=${result.pulled}, conflicts=${result.conflicts}` }] };
        }
        case 'push': {
          const diffs = await engine.getDiff(ccManifests);
          const mem = diffs.filter((d) => d.relPath.startsWith('memory/'));
          let pushed = 0;
          for (const d of mem) {
            const m = ccManifests.find((mm) => mm.tool === d.tool);
            if (!m) continue;
            try {
              await engine.pushFile(d.tool, d.relPath, `${m.baseDir}/${d.relPath}`);
              pushed++;
            } catch { /* skip */ }
          }
          return { content: [{ type: 'text', text: `Pushed ${pushed} memory files to all nodes.` }] };
        }
        case 'pull': {
          const pulled = await engine.pullPending();
          return { content: [{ type: 'text', text: `Pulled ${pulled} items (including memory) from remote.` }] };
        }
        case 'diff': {
          const diffs = await engine.getDiff(ccManifests);
          const mem = diffs.filter((d) => d.relPath.startsWith('memory/'));
          if (mem.length === 0) {
            return { content: [{ type: 'text', text: 'All memory files in sync.' }] };
          }
          const lines = mem.map((d) =>
            `[${d.direction}] ${d.relPath} (local=${d.localHash?.slice(0, 8) ?? 'missing'}, remote=${d.remoteHash.slice(0, 8)})`
          );
          return { content: [{ type: 'text', text: `${mem.length} memory differences:\n${lines.join('\n')}` }] };
        }
        case 'list': {
          const items = await db.getItemsByTool('claude-code');
          const mem = items.filter((i) => i.relPath.startsWith('memory/'));
          if (mem.length === 0) {
            return { content: [{ type: 'text', text: 'No memory files tracked.' }] };
          }
          const lines = mem.map((i) =>
            `  ${i.relPath} (hash=${i.contentHash.slice(0, 8)}, node=${i.updatedByNode}, updated=${i.updatedAt.toISOString().slice(0, 19)})`
          );
          return { content: [{ type: 'text', text: `${mem.length} tracked memory files:\n${lines.join('\n')}` }] };
        }
        default:
          return { content: [{ type: 'text', text: `Unknown action: ${action}` }] };
      }
    }
  );

  // --- Tool: omniwire_sync_agents ---
  server.tool(
    'omniwire_sync_agents',
    'Sync agent configs (agents/*, skills/*) for Claude Code, OpenClaw, and other AI tools across all mesh nodes.',
    {
      action: z.enum(['sync', 'push', 'pull', 'diff', 'list']).describe(
        'sync=bi-directional, push=local→remote, pull=remote→local, diff=show changes, list=show tracked agents'
      ),
      tool: z.string().optional().describe(`Filter by tool: ${ALL_TOOLS.join(', ')}`),
    },
    async ({ action, tool }) => {
      const filtered = tool
        ? manifests.filter((m) => m.tool === tool)
        : manifests;

      switch (action) {
        case 'sync': {
          const result = await engine.reconcile(filtered);
          return { content: [{ type: 'text', text: `Agent sync: pushed=${result.pushed}, pulled=${result.pulled}, conflicts=${result.conflicts}` }] };
        }
        case 'push': {
          const diffs = await engine.getDiff(filtered);
          const agents = diffs.filter((d) =>
            d.relPath.startsWith('agents/') || d.relPath.startsWith('skills/')
          );
          let pushed = 0;
          for (const d of agents) {
            const m = filtered.find((mm) => mm.tool === d.tool);
            if (!m) continue;
            try {
              await engine.pushFile(d.tool, d.relPath, `${m.baseDir}/${d.relPath}`);
              pushed++;
            } catch { /* skip */ }
          }
          return { content: [{ type: 'text', text: `Pushed ${pushed} agent/skill files to all nodes.` }] };
        }
        case 'pull': {
          const pulled = await engine.pullPending();
          return { content: [{ type: 'text', text: `Pulled ${pulled} items (including agents/skills) from remote.` }] };
        }
        case 'diff': {
          const diffs = await engine.getDiff(filtered);
          const agents = diffs.filter((d) =>
            d.relPath.startsWith('agents/') || d.relPath.startsWith('skills/')
          );
          if (agents.length === 0) {
            return { content: [{ type: 'text', text: 'All agents/skills in sync.' }] };
          }
          const lines = agents.map((d) =>
            `[${d.direction}] ${d.tool}:${d.relPath} (local=${d.localHash?.slice(0, 8) ?? 'missing'}, remote=${d.remoteHash.slice(0, 8)})`
          );
          return { content: [{ type: 'text', text: `${agents.length} agent/skill differences:\n${lines.join('\n')}` }] };
        }
        case 'list': {
          const allItems: { tool: string; relPath: string; contentHash: string; updatedByNode: string; updatedAt: Date }[] = [];
          for (const m of filtered) {
            const items = await db.getItemsByTool(m.tool);
            const agents = items.filter((i) =>
              i.relPath.startsWith('agents/') || i.relPath.startsWith('skills/')
            );
            allItems.push(...agents);
          }
          if (allItems.length === 0) {
            return { content: [{ type: 'text', text: 'No agents/skills tracked.' }] };
          }
          const lines = allItems.map((i) =>
            `  ${i.tool}:${i.relPath} (hash=${i.contentHash.slice(0, 8)}, node=${i.updatedByNode})`
          );
          return { content: [{ type: 'text', text: `${allItems.length} tracked agents/skills:\n${lines.join('\n')}` }] };
        }
        default:
          return { content: [{ type: 'text', text: `Unknown action: ${action}` }] };
      }
    }
  );
}
