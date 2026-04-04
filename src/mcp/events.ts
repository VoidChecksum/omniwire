// OmniWire Events — Webhook + WebSocket + SSE event bus
// Unified event system for real-time notifications across all transports

import { createServer as createHttpServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { WebSocketServer, WebSocket } from 'ws';
import { EventEmitter } from 'node:events';

// --- Types ---

export interface OmniWireEvent {
  readonly id: string;
  readonly type: OmniWireEventType;
  readonly timestamp: number;
  readonly source: string;      // node ID or 'system'
  readonly data: Record<string, unknown>;
}

export type OmniWireEventType =
  | 'exec.start' | 'exec.complete' | 'exec.error'
  | 'node.online' | 'node.offline' | 'node.health'
  | 'transfer.start' | 'transfer.complete' | 'transfer.error'
  | 'update.available' | 'update.applied'
  | 'mesh.peer-added' | 'mesh.peer-removed' | 'mesh.health'
  | 'sync.start' | 'sync.complete' | 'sync.conflict'
  | 'alert.fired' | 'alert.resolved'
  | 'firewall.blocked' | 'firewall.rule-changed'
  | 'vpn.connected' | 'vpn.disconnected'
  | 'store.set' | 'store.delete'
  | 'a2a.message' | 'a2a.task'
  | 'custom';

export interface WebhookConfig {
  readonly id: string;
  readonly url: string;
  readonly events: readonly OmniWireEventType[] | '*';  // '*' = all events
  readonly secret?: string;       // HMAC-SHA256 signing secret
  readonly headers?: Record<string, string>;
  readonly retries: number;       // Max retry attempts (default: 3)
  readonly timeoutMs: number;     // Request timeout (default: 5000)
  readonly active: boolean;
}

// --- Event Bus ---

class OmniWireEventBus extends EventEmitter {
  private sseClients: Set<ServerResponse> = new Set();
  private wsClients: Set<WebSocket> = new Set();
  private webhooks: Map<string, WebhookConfig> = new Map();
  private eventLog: OmniWireEvent[] = [];
  private maxLogSize = 1000;
  private eventCounter = 0;

  /** Emit an event to all transports */
  emit(type: string, ...args: unknown[]): boolean {
    return super.emit(type, ...args);
  }

  /** Publish an event to all connected clients (SSE, WS, webhooks) */
  publish(type: OmniWireEventType, source: string, data: Record<string, unknown> = {}): OmniWireEvent {
    const event: OmniWireEvent = {
      id: `evt-${Date.now()}-${++this.eventCounter}`,
      type,
      timestamp: Date.now(),
      source,
      data,
    };

    // Store in log (ring buffer)
    this.eventLog.push(event);
    if (this.eventLog.length > this.maxLogSize) {
      this.eventLog = this.eventLog.slice(-this.maxLogSize);
    }

    // Emit locally
    super.emit(type, event);
    super.emit('*', event);

    // Send to SSE clients
    this.broadcastSSE(event);

    // Send to WebSocket clients
    this.broadcastWS(event);

    // Send to webhooks (fire-and-forget)
    this.broadcastWebhooks(event);

    return event;
  }

  // --- SSE ---

  addSSEClient(res: ServerResponse, filter?: readonly OmniWireEventType[]): void {
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
      'Access-Control-Allow-Origin': '*',
    });

    // Send initial connection event
    const init: OmniWireEvent = {
      id: `evt-${Date.now()}-init`,
      type: 'custom',
      timestamp: Date.now(),
      source: 'system',
      data: { message: 'connected', filter: filter ?? '*' },
    };
    res.write(`data: ${JSON.stringify(init)}\n\n`);

    // Tag the response with filter for selective broadcasting
    (res as any).__omniwireFilter = filter;
    this.sseClients.add(res);

    res.on('close', () => this.sseClients.delete(res));
  }

  private broadcastSSE(event: OmniWireEvent): void {
    const payload = `id: ${event.id}\nevent: ${event.type}\ndata: ${JSON.stringify(event)}\n\n`;
    for (const client of this.sseClients) {
      const filter = (client as any).__omniwireFilter as readonly OmniWireEventType[] | undefined;
      if (!filter || filter.includes(event.type)) {
        try { client.write(payload); } catch { this.sseClients.delete(client); }
      }
    }
  }

  // --- WebSocket ---

  addWSClient(ws: WebSocket): void {
    this.wsClients.add(ws);
    ws.on('close', () => this.wsClients.delete(ws));
    ws.on('error', () => this.wsClients.delete(ws));

    // Handle incoming messages (subscriptions, commands)
    ws.on('message', (data) => {
      try {
        const msg = JSON.parse(data.toString());
        if (msg.type === 'subscribe') {
          (ws as any).__omniwireFilter = msg.events as OmniWireEventType[];
          ws.send(JSON.stringify({ type: 'subscribed', events: msg.events }));
        } else if (msg.type === 'ping') {
          ws.send(JSON.stringify({ type: 'pong', timestamp: Date.now() }));
        } else if (msg.type === 'replay') {
          // Replay recent events
          const count = Math.min(msg.count ?? 50, this.eventLog.length);
          const events = this.eventLog.slice(-count);
          ws.send(JSON.stringify({ type: 'replay', events }));
        }
      } catch { /* ignore malformed messages */ }
    });

    // Send connected event
    ws.send(JSON.stringify({ type: 'connected', timestamp: Date.now(), logSize: this.eventLog.length }));
  }

  private broadcastWS(event: OmniWireEvent): void {
    const payload = JSON.stringify(event);
    for (const ws of this.wsClients) {
      if (ws.readyState !== WebSocket.OPEN) { this.wsClients.delete(ws); continue; }
      const filter = (ws as any).__omniwireFilter as readonly OmniWireEventType[] | undefined;
      if (!filter || filter.includes(event.type)) {
        try { ws.send(payload); } catch { this.wsClients.delete(ws); }
      }
    }
  }

  // --- Webhooks ---

  addWebhook(config: WebhookConfig): void {
    this.webhooks.set(config.id, config);
  }

  removeWebhook(id: string): boolean {
    return this.webhooks.delete(id);
  }

  listWebhooks(): WebhookConfig[] {
    return [...this.webhooks.values()];
  }

  private async broadcastWebhooks(event: OmniWireEvent): Promise<void> {
    for (const webhook of this.webhooks.values()) {
      if (!webhook.active) continue;
      if (webhook.events !== '*' && !webhook.events.includes(event.type)) continue;
      // Fire-and-forget with retries
      void this.sendWebhook(webhook, event);
    }
  }

  private async sendWebhook(webhook: WebhookConfig, event: OmniWireEvent, attempt = 0): Promise<void> {
    try {
      const body = JSON.stringify(event);
      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
        'X-OmniWire-Event': event.type,
        'X-OmniWire-Event-ID': event.id,
        'X-OmniWire-Timestamp': String(event.timestamp),
        ...webhook.headers,
      };

      // HMAC signature if secret is configured
      if (webhook.secret) {
        const { createHmac } = await import('node:crypto');
        const sig = createHmac('sha256', webhook.secret).update(body).digest('hex');
        headers['X-OmniWire-Signature'] = `sha256=${sig}`;
      }

      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), webhook.timeoutMs);

      const response = await fetch(webhook.url, {
        method: 'POST',
        headers,
        body,
        signal: controller.signal,
      });
      clearTimeout(timeout);

      if (!response.ok && attempt < webhook.retries) {
        // Exponential backoff: 1s, 2s, 4s
        await new Promise((r) => setTimeout(r, 1000 * Math.pow(2, attempt)));
        return this.sendWebhook(webhook, event, attempt + 1);
      }
    } catch {
      if (attempt < webhook.retries) {
        await new Promise((r) => setTimeout(r, 1000 * Math.pow(2, attempt)));
        return this.sendWebhook(webhook, event, attempt + 1);
      }
    }
  }

  // --- Query ---

  getRecentEvents(count = 50, filter?: OmniWireEventType): readonly OmniWireEvent[] {
    const events = filter ? this.eventLog.filter((e) => e.type === filter) : this.eventLog;
    return events.slice(-count);
  }

  getStats(): { sseClients: number; wsClients: number; webhooks: number; totalEvents: number; logSize: number } {
    return {
      sseClients: this.sseClients.size,
      wsClients: this.wsClients.size,
      webhooks: this.webhooks.size,
      totalEvents: this.eventCounter,
      logSize: this.eventLog.length,
    };
  }
}

// Singleton event bus
export const eventBus = new OmniWireEventBus();

// --- HTTP + WebSocket Server ---

export function startEventServer(port: number, bind = '127.0.0.1'): void {
  const httpServer = createHttpServer((req: IncomingMessage, res: ServerResponse) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

    const url = new URL(req.url ?? '/', `http://localhost:${port}`);

    // GET /events/stream — SSE stream
    if (req.method === 'GET' && url.pathname === '/events/stream') {
      const filterParam = url.searchParams.get('filter');
      const filter = filterParam ? filterParam.split(',') as OmniWireEventType[] : undefined;
      eventBus.addSSEClient(res, filter);
      return;
    }

    // GET /events/recent — recent events
    if (req.method === 'GET' && url.pathname === '/events/recent') {
      const count = parseInt(url.searchParams.get('count') ?? '50');
      const filter = url.searchParams.get('type') as OmniWireEventType | undefined;
      const events = eventBus.getRecentEvents(count, filter || undefined);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ events }));
      return;
    }

    // GET /events/stats — event bus stats
    if (req.method === 'GET' && url.pathname === '/events/stats') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(eventBus.getStats()));
      return;
    }

    // POST /events/publish — publish custom event
    if (req.method === 'POST' && url.pathname === '/events/publish') {
      let body = '';
      req.on('data', (chunk) => { body += chunk; });
      req.on('end', () => {
        try {
          const { type, source, data } = JSON.parse(body);
          const event = eventBus.publish(type ?? 'custom', source ?? 'api', data ?? {});
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify(event));
        } catch {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Invalid JSON' }));
        }
      });
      return;
    }

    // GET /webhooks — list webhooks
    if (req.method === 'GET' && url.pathname === '/webhooks') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ webhooks: eventBus.listWebhooks() }));
      return;
    }

    // POST /webhooks — register webhook
    if (req.method === 'POST' && url.pathname === '/webhooks') {
      let body = '';
      req.on('data', (chunk) => { body += chunk; });
      req.on('end', () => {
        try {
          const config = JSON.parse(body) as Partial<WebhookConfig>;
          if (!config.url) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'url required' }));
            return;
          }
          const webhook: WebhookConfig = {
            id: config.id ?? `wh-${Date.now()}`,
            url: config.url,
            events: config.events ?? '*',
            secret: config.secret,
            headers: config.headers,
            retries: config.retries ?? 3,
            timeoutMs: config.timeoutMs ?? 5000,
            active: config.active ?? true,
          };
          eventBus.addWebhook(webhook);
          res.writeHead(201, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify(webhook));
        } catch {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Invalid JSON' }));
        }
      });
      return;
    }

    // DELETE /webhooks/:id — remove webhook
    const whMatch = url.pathname.match(/^\/webhooks\/(.+)$/);
    if (req.method === 'DELETE' && whMatch) {
      const removed = eventBus.removeWebhook(whMatch[1]);
      res.writeHead(removed ? 200 : 404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ removed }));
      return;
    }

    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Not found. Endpoints: /events/stream, /events/recent, /events/stats, /events/publish, /webhooks' }));
  });

  // WebSocket upgrade
  const wss = new WebSocketServer({ noServer: true });
  httpServer.on('upgrade', (req, socket, head) => {
    const url = new URL(req.url ?? '/', `http://localhost:${port}`);
    if (url.pathname === '/ws' || url.pathname === '/events/ws') {
      wss.handleUpgrade(req, socket, head, (ws) => {
        eventBus.addWSClient(ws);
      });
    } else {
      socket.destroy();
    }
  });

  httpServer.listen(port, bind);
}
