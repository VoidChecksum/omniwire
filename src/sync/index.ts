// CyberSync — Daemon entrypoint
// Watches tool directories, syncs to PostgreSQL, bridges memory.db
//
// Usage:
//   node dist/sync/index.js --node windows                     # run daemon
//   node dist/sync/index.js --node windows --once              # single reconcile
//   node dist/sync/index.js --node windows --ingest-only       # memory.db only

import { SyncDB } from './db.js';
import { SyncEngine } from './engine.js';
import { SyncWatcher } from './watcher.js';
import { MemoryBridge } from './memory-bridge.js';
import { getManifests } from './manifest.js';
import { NodeManager } from '../nodes/manager.js';
import { TransferEngine } from '../nodes/transfer.js';
import { allNodes } from '../protocol/config.js';
import type { SyncConfig } from './types.js';
import { DEFAULT_SYNC_CONFIG } from './types.js';

function parseArgs(argv: string[]): { nodeId: string; once: boolean; ingestOnly: boolean } {
  const nodeIdx = argv.indexOf('--node');
  const nodeId = nodeIdx !== -1 && argv[nodeIdx + 1] ? argv[nodeIdx + 1] : detectNodeId();
  const once = argv.includes('--once');
  const ingestOnly = argv.includes('--ingest-only');
  return { nodeId, once, ingestOnly };
}

function detectNodeId(): string {
  if (process.platform === 'win32') return 'windows';
  return process.env.OMNIWIRE_NODE_ID ?? process.env.HOSTNAME ?? 'local';
}

async function main(): Promise<void> {
  const { nodeId, once, ingestOnly } = parseArgs(process.argv.slice(2));
  const node = allNodes().find((n) => n.id === nodeId);

  if (!node) {
    process.stderr.write(`Unknown node: ${nodeId}\n`);
    process.exit(1);
  }

  const config: SyncConfig = { ...DEFAULT_SYNC_CONFIG, nodeId };

  process.stderr.write(`CyberSync starting on ${nodeId} (${node.os})\n`);

  // Connect to PostgreSQL
  const db = new SyncDB(config);
  await db.init();
  process.stderr.write(`PostgreSQL connected (${config.pgHost}:${config.pgPort}/${config.pgDatabase})\n`);

  // Connect mesh nodes
  const manager = new NodeManager();
  await manager.connectAll();
  const transferEngine = new TransferEngine(manager);

  const os = node.os;
  const manifests = getManifests(os);

  // Memory bridge (SQLite -> PostgreSQL)
  const bridge = new MemoryBridge(db, nodeId);

  if (ingestOnly) {
    const claudeManifest = manifests.find((m) => m.tool === 'claude-code');
    if (claudeManifest?.ingestDb) {
      const count = await bridge.ingest(claudeManifest.ingestDb);
      process.stderr.write(`Ingested ${count} memory entries\n`);
    }
    await db.close();
    manager.disconnect();
    return;
  }

  // Sync engine
  const engine = new SyncEngine(db, config, manager, transferEngine);

  if (once) {
    // Single reconciliation pass
    const result = await engine.reconcile(manifests);
    process.stderr.write(`Reconcile: pushed=${result.pushed}, pulled=${result.pulled}, conflicts=${result.conflicts}\n`);

    // Also ingest memory.db
    const claudeManifest = manifests.find((m) => m.tool === 'claude-code');
    if (claudeManifest?.ingestDb) {
      const count = await bridge.ingest(claudeManifest.ingestDb);
      process.stderr.write(`Ingested ${count} memory entries\n`);
    }

    await db.close();
    manager.disconnect();
    return;
  }

  // Daemon mode: watcher + periodic reconcile
  const watcher = new SyncWatcher(manifests, config.watchDebounceMs, async (event) => {
    try {
      if (event.type === 'unlink') {
        await engine.deleteFile(event.tool, event.relPath);
        process.stderr.write(`[sync] deleted ${event.tool}:${event.relPath}\n`);
      } else {
        await engine.pushFile(event.tool, event.relPath, event.absPath);
        process.stderr.write(`[sync] pushed ${event.tool}:${event.relPath}\n`);
      }
    } catch (err) {
      process.stderr.write(`[sync] error: ${(err as Error).message}\n`);
    }
  });

  watcher.start();
  process.stderr.write(`Watchers started for ${manifests.filter((m) => m.syncGlobs.length > 0).length} tools\n`);

  // Initial reconcile
  const initial = await engine.reconcile(manifests);
  process.stderr.write(`Initial reconcile: pushed=${initial.pushed}, pulled=${initial.pulled}, conflicts=${initial.conflicts}\n`);

  // Ingest memory.db on startup
  const claudeManifest = manifests.find((m) => m.tool === 'claude-code');
  if (claudeManifest?.ingestDb) {
    const count = await bridge.ingest(claudeManifest.ingestDb);
    process.stderr.write(`Ingested ${count} memory entries\n`);
  }

  // Periodic reconciliation
  const reconcileInterval = setInterval(async () => {
    try {
      const result = await engine.reconcile(manifests);
      if (result.pushed > 0 || result.pulled > 0 || result.conflicts > 0) {
        process.stderr.write(`[reconcile] pushed=${result.pushed}, pulled=${result.pulled}, conflicts=${result.conflicts}\n`);
      }
      // heartbeat is already updated inside engine.reconcile() with real counts
    } catch (err) {
      process.stderr.write(`[reconcile] error: ${(err as Error).message}\n`);
    }
  }, config.reconcileIntervalMs);

  // Periodic memory.db ingestion (every 15 min)
  const memoryInterval = setInterval(async () => {
    if (claudeManifest?.ingestDb) {
      try {
        await bridge.ingest(claudeManifest.ingestDb);
      } catch {
        // Silent fail for memory ingestion
      }
    }
  }, 15 * 60 * 1000);

  // Graceful shutdown
  const shutdown = async (): Promise<void> => {
    process.stderr.write('CyberSync shutting down...\n');
    clearInterval(reconcileInterval);
    clearInterval(memoryInterval);
    await watcher.stop();
    await db.close();
    manager.disconnect();
    process.exit(0);
  };

  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);

  process.stderr.write(`CyberSync daemon running (reconcile every ${config.reconcileIntervalMs / 1000}s)\n`);
}

// Export engine creation for MCP tools
export { SyncDB } from './db.js';
export { SyncEngine } from './engine.js';
export { MemoryBridge } from './memory-bridge.js';
export { getManifests } from './manifest.js';
export type { SyncConfig } from './types.js';
export { DEFAULT_SYNC_CONFIG } from './types.js';

// Run if executed directly
const isDirectRun = process.argv[1]?.endsWith('sync/index.js') || process.argv[1]?.endsWith('sync\\index.js');
if (isDirectRun) {
  main().catch((err) => {
    process.stderr.write(`Fatal: ${(err as Error).message}\n`);
    process.exit(1);
  });
}
