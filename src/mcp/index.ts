#!/usr/bin/env node

// OmniWire MCP Entrypoint — dual transport: stdio + SSE
// stdio: for Claude Code subprocess spawning
// SSE (port 3200): for OpenCode, Oh-My-OpenAgent, remote HTTP clients

import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { NodeManager } from '../nodes/manager.js';
import { TransferEngine } from '../nodes/transfer.js';
import { createOmniWireServer } from './server.js';
import { registerSyncTools } from './sync-tools.js';
import { startSSEServer } from './sse.js';
import { startRESTServer } from './rest.js';
import { SyncDB } from '../sync/db.js';
import { SyncEngine } from '../sync/engine.js';
import { getManifests } from '../sync/manifest.js';
import { allNodes, getLocalNodeId } from '../protocol/config.js';
import { DEFAULT_SYNC_CONFIG } from '../sync/types.js';
import type { SyncConfig } from '../sync/types.js';
import { startEventServer, eventBus } from './events.js';

const args = process.argv.slice(2);
const useStdio = args.includes('--stdio');
const useJson = args.includes('--json');
const ssePort = parseInt(args.find((a) => a.startsWith('--sse-port='))?.split('=')[1] ?? '3200');
const restPort = parseInt(args.find((a) => a.startsWith('--rest-port='))?.split('=')[1] ?? '3201');
const eventPort = parseInt(args.find((a) => a.startsWith('--event-port='))?.split('=')[1] ?? '3202');
const bindAddr = args.find((a) => a.startsWith('--bind='))?.split('=')[1] ?? '127.0.0.1';
const noSync = args.includes('--no-sync');
const noEvents = args.includes('--no-events');

function log(msg: string, data?: Record<string, unknown>): void {
  if (useJson) {
    process.stderr.write(JSON.stringify({ msg, ...data }) + '\n');
  } else {
    process.stderr.write(msg + '\n');
  }
}

async function main(): Promise<void> {
  const manager = new NodeManager();
  await manager.connectAll();

  const transfer = new TransferEngine(manager);
  const server = createOmniWireServer(manager, transfer);

  // Initialize CyberSync if not disabled
  let syncDb: SyncDB | null = null;
  if (!noSync) {
    try {
      const nodeId = getLocalNodeId();
      const config: SyncConfig = { ...DEFAULT_SYNC_CONFIG, nodeId };
      syncDb = new SyncDB(config);
      await syncDb.init();

      const node = allNodes().find((n) => n.id === nodeId);
      const os = node?.os ?? 'linux';
      const manifests = getManifests(os);
      const engine = new SyncEngine(syncDb, config, manager, transfer);

      registerSyncTools(server, syncDb, engine, manifests, nodeId, manager, transfer);
      log('CyberSync: 17 tools registered', { tools: 17, node: nodeId });
    } catch (err) {
      log(`CyberSync init failed (continuing without sync): ${(err as Error).message}`, { error: (err as Error).message });
    }
  }

  // Start auto-update background checker (non-blocking, unref'd timer)
  const noAutoUpdate = args.includes('--no-auto-update');
  if (!noAutoUpdate) {
    try {
      const { startAutoUpdate } = await import('../update.js');
      startAutoUpdate(3_600_000, (result) => {
        if (result.updated) log(`auto-updated: ${result.message}`, { autoUpdate: true, version: result.latestVersion });
      });
      log('auto-update: enabled (1h interval)');
    } catch { /* non-critical — continue without auto-update */ }
  }

  if (useStdio) {
    const transport = new StdioServerTransport();
    await server.connect(transport);
  } else {
    startSSEServer(server, ssePort, bindAddr);
    startRESTServer(manager, transfer, restPort, bindAddr);
    if (!noEvents) {
      startEventServer(eventPort, bindAddr);
      log(`Events: WS+SSE+Webhooks on ${bindAddr}:${eventPort}`, { eventPort });
    }
    log(`OmniWire MCP: SSE on ${bindAddr}:${ssePort}, REST on ${bindAddr}:${restPort}`, { ssePort, restPort });
  }

  process.on('SIGINT', async () => {
    if (syncDb) await syncDb.close();
    manager.disconnect();
    process.exit(0);
  });
}

main().catch((err) => {
  log(`Fatal: ${(err as Error).message}`, { fatal: true, error: (err as Error).message });
  process.exit(1);
});
