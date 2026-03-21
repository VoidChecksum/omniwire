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
import { allNodes } from '../protocol/config.js';
import { DEFAULT_SYNC_CONFIG } from '../sync/types.js';
import type { SyncConfig } from '../sync/types.js';

const args = process.argv.slice(2);
const useStdio = args.includes('--stdio');
const ssePort = parseInt(args.find((a) => a.startsWith('--sse-port='))?.split('=')[1] ?? '3200');
const restPort = parseInt(args.find((a) => a.startsWith('--rest-port='))?.split('=')[1] ?? '3201');
const noSync = args.includes('--no-sync');

function detectNodeId(): string {
  if (process.platform === 'win32') return 'windows';
  const hostname = (process.env.HOSTNAME ?? '').toLowerCase();
  return 'unknown';
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
      const nodeId = detectNodeId();
      const config: SyncConfig = { ...DEFAULT_SYNC_CONFIG, nodeId };
      syncDb = new SyncDB(config);
      await syncDb.init();

      const node = allNodes().find((n) => n.id === nodeId);
      const os = node?.os ?? 'windows';
      const manifests = getManifests(os);
      const engine = new SyncEngine(syncDb, config, manager, transfer);

      registerSyncTools(server, syncDb, engine, manifests, nodeId, manager);
      process.stderr.write(`CyberSync: 9 tools registered (node=${nodeId})\n`);
    } catch (err) {
      process.stderr.write(`CyberSync init failed (continuing without sync): ${(err as Error).message}\n`);
    }
  }

  if (useStdio) {
    const transport = new StdioServerTransport();
    await server.connect(transport);
  } else {
    startSSEServer(server, ssePort);
    startRESTServer(manager, transfer, restPort);
    process.stderr.write(`OmniWire MCP: SSE on :${ssePort}, REST on :${restPort}\n`);
  }

  process.on('SIGINT', async () => {
    if (syncDb) await syncDb.close();
    manager.disconnect();
    process.exit(0);
  });
}

main().catch((err) => {
  process.stderr.write(`Fatal: ${err.message}\n`);
  process.exit(1);
});
