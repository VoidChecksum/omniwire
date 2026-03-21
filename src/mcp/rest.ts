// OmniWire REST API — simple HTTP API for non-MCP clients
// Port 3201 by default
// NOTE: Uses manager.exec() which is SSH2 client.exec(), not child_process

import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import type { NodeManager } from '../nodes/manager.js';
import type { TransferEngine } from '../nodes/transfer.js';
import { allNodes, NODE_ROLES } from '../protocol/config.js';
import { parseMeshPath } from '../protocol/paths.js';

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve) => {
    let body = '';
    req.on('data', (chunk) => { body += chunk; });
    req.on('end', () => resolve(body));
  });
}

function json(res: ServerResponse, status: number, data: unknown): void {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}

export function startRESTServer(manager: NodeManager, transfer: TransferEngine, port: number): void {
  const httpServer = createServer(async (req: IncomingMessage, res: ServerResponse) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

    const url = new URL(req.url ?? '/', `http://localhost:${port}`);
    const path = url.pathname;

    try {
      // GET /api/health
      if (req.method === 'GET' && path === '/api/health') {
        json(res, 200, { status: 'ok', online: manager.getOnlineNodes() });
        return;
      }

      // GET /api/nodes
      if (req.method === 'GET' && path === '/api/nodes') {
        const statuses = await manager.getAllStatus();
        const nodes = statuses.map((s) => ({
          ...s,
          role: NODE_ROLES[s.nodeId] ?? 'unknown',
          host: allNodes().find((n) => n.id === s.nodeId)?.host,
        }));
        json(res, 200, { nodes });
        return;
      }

      // GET /api/nodes/:id
      const nodeMatch = path.match(/^\/api\/nodes\/([^/]+)$/);
      if (req.method === 'GET' && nodeMatch) {
        const status = await manager.getNodeStatus(nodeMatch[1]);
        json(res, 200, { ...status, role: NODE_ROLES[nodeMatch[1]] ?? 'unknown' });
        return;
      }

      // POST /api/exec — { node, command } — runs command on remote node via SSH
      if (req.method === 'POST' && path === '/api/exec') {
        const body = JSON.parse(await readBody(req));
        const result = await manager.exec(body.node, body.command);
        json(res, 200, result);
        return;
      }

      // POST /api/transfer — { src, dst }
      if (req.method === 'POST' && path === '/api/transfer') {
        const body = JSON.parse(await readBody(req));
        const srcParsed = parseMeshPath(body.src);
        const dstParsed = parseMeshPath(body.dst);
        if (!srcParsed || !dstParsed) {
          json(res, 400, { error: 'Invalid path format. Use node:/path' });
          return;
        }
        const result = await transfer.transfer(
          srcParsed.nodeId, srcParsed.path,
          dstParsed.nodeId, dstParsed.path,
          body.mode ? { mode: body.mode } : undefined
        );
        json(res, 200, result);
        return;
      }

      // GET /api/nodes/:id/files/* — read file from node
      const fileReadMatch = path.match(/^\/api\/nodes\/([^/]+)\/files(\/.+)$/);
      if (req.method === 'GET' && fileReadMatch) {
        const content = await transfer.readFile(fileReadMatch[1], fileReadMatch[2]);
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end(content);
        return;
      }

      // PUT /api/nodes/:id/files/* — write file to node
      const fileWriteMatch = path.match(/^\/api\/nodes\/([^/]+)\/files(\/.+)$/);
      if (req.method === 'PUT' && fileWriteMatch) {
        const content = await readBody(req);
        await transfer.writeFile(fileWriteMatch[1], fileWriteMatch[2], content);
        json(res, 200, { written: true, path: fileWriteMatch[2], node: fileWriteMatch[1] });
        return;
      }

      json(res, 404, { error: 'Not found' });
    } catch (e) {
      json(res, 500, { error: (e as Error).message });
    }
  });

  httpServer.listen(port, '127.0.0.1');
}
