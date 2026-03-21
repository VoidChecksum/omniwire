// OmniWire SSE Transport — Server-Sent Events for remote MCP clients
// GET /sse — event stream for JSON-RPC responses
// POST /message — JSON-RPC requests

import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js';

export function startSSEServer(server: McpServer, port: number): void {
  let transport: SSEServerTransport | null = null;

  const httpServer = createServer(async (req: IncomingMessage, res: ServerResponse) => {
    // CORS headers for browser-based MCP clients
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }

    if (req.method === 'GET' && req.url === '/sse') {
      transport = new SSEServerTransport('/message', res);
      await server.connect(transport);
      return;
    }

    if (req.method === 'POST' && req.url === '/message') {
      if (!transport) {
        res.writeHead(503, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'No SSE connection active. Connect to /sse first.' }));
        return;
      }

      await transport.handlePostMessage(req, res);
      return;
    }

    // Health check
    if (req.method === 'GET' && req.url === '/health') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'ok', transport: transport ? 'connected' : 'waiting' }));
      return;
    }

    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Not found. Endpoints: GET /sse, POST /message, GET /health' }));
  });

  httpServer.listen(port, '127.0.0.1');
}
