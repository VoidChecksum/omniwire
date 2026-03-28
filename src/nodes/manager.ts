// OmniWire Node Manager — persistent SSH connections to all mesh nodes

import { Client, type ConnectConfig } from 'ssh2';
import { readFileSync } from 'node:fs';
import { execFile } from 'node:child_process';
import type { MeshNode, NodeStatus, ExecResult } from '../protocol/types.js';
import { remoteNodes, getHostCandidates } from '../protocol/config.js';

interface NodeConnection {
  node: MeshNode;
  client: Client;
  connected: boolean;
  activeHost: string | null;
  lastPing: Date | null;
  reconnecting: boolean;
  failures: number;
  circuitOpenUntil: number;
}

type ReconnectCallback = (nodeId: string) => void;

const MAX_OUTPUT_BYTES = 2 * 1024 * 1024;
const STATUS_CACHE_TTL = 5000;
const HEALTH_PING_INTERVAL = 30_000;
const CIRCUIT_OPEN_DURATION = 15_000;      // 15s circuit breaker — faster recovery
const CIRCUIT_FAILURE_THRESHOLD = 3;
const CONNECT_TIMEOUT = 5000;              // 5s connection timeout

// Prefer fast ciphers + key exchange for lowest latency
const PREFERRED_CIPHERS = [
  'aes128-gcm@openssh.com',                // AES-NI accelerated, lowest overhead
  'chacha20-poly1305@openssh.com',          // fast on non-AES-NI CPUs
  'aes256-gcm@openssh.com',
  'aes128-ctr',
];
const PREFERRED_KEX = [
  'curve25519-sha256',                       // fastest modern key exchange
  'curve25519-sha256@libssh.org',
  'ecdh-sha2-nistp256',
];

export class NodeManager {
  private connections: Map<string, NodeConnection> = new Map();
  private reconnectCallbacks: ReconnectCallback[] = [];
  private reconnectDelays: Map<string, number> = new Map();
  private statusCache: Map<string, { status: NodeStatus; at: number }> = new Map();
  private healthTimer: ReturnType<typeof setInterval> | null = null;
  private keyCache: Map<string, Buffer> = new Map();

  private getKey(path: string): Buffer {
    let key = this.keyCache.get(path);
    if (!key) {
      key = readFileSync(path);
      this.keyCache.set(path, key);
    }
    return key;
  }

  async connectAll(): Promise<void> {
    const nodes = remoteNodes();
    await Promise.allSettled(nodes.map((node) => this.connectWithFallback(node)));
    this.startHealthPing();
  }

  private async connectWithFallback(node: MeshNode): Promise<void> {
    if (node.isLocal) return;
    const hosts = getHostCandidates(node.id);
    for (const host of hosts) {
      try {
        await this.connect(node, host);
        return;
      } catch {
        // try next host
      }
    }
  }

  private async connect(node: MeshNode, host?: string): Promise<void> {
    if (node.isLocal) return;

    const client = new Client();
    const existing = this.connections.get(node.id);
    const conn: NodeConnection = existing ?? {
      node, client, connected: false, activeHost: null,
      lastPing: null, reconnecting: false, failures: 0, circuitOpenUntil: 0,
    };
    conn.client = client;
    this.connections.set(node.id, conn);

    return new Promise<void>((resolve, reject) => {
      const timeout = setTimeout(() => {
        client.end();
        reject(new Error(`Connection to ${node.id} timed out`));
      }, CONNECT_TIMEOUT);

      client.on('ready', () => {
        clearTimeout(timeout);
        conn.connected = true;
        conn.activeHost = effectiveHost;
        conn.lastPing = new Date();
        resolve();
      });

      client.on('error', (err) => {
        clearTimeout(timeout);
        conn.connected = false;
        reject(err);
      });

      client.on('close', () => {
        conn.connected = false;
        conn.activeHost = null;
        this.scheduleReconnect(node);
      });

      const effectiveHost = host ?? node.host;
      const config: ConnectConfig = {
        host: effectiveHost,
        port: node.port,
        username: node.user,
        privateKey: this.getKey(node.identityFile),
        readyTimeout: CONNECT_TIMEOUT,
        keepaliveInterval: 2000,           // 2s keepalive — fastest dead detection
        keepaliveCountMax: 2,              // 4s total before disconnect
        algorithms: {
          cipher: PREFERRED_CIPHERS as any,
          kex: PREFERRED_KEX as any,
          compress: ['none'] as any,
        },
      };

      client.connect(config);
    });
  }

  private scheduleReconnect(node: MeshNode): void {
    const conn = this.connections.get(node.id);
    if (!conn || conn.reconnecting) return;

    conn.reconnecting = true;
    const currentDelay = this.reconnectDelays.get(node.id) ?? 300; // start at 300ms
    const jitter = Math.floor(Math.random() * 500);

    setTimeout(async () => {
      try {
        await this.connectWithFallback(node);
        conn.reconnecting = false;
        conn.failures = 0;
        conn.circuitOpenUntil = 0;
        this.reconnectDelays.set(node.id, 300);
        for (const cb of this.reconnectCallbacks) cb(node.id);
      } catch {
        conn.reconnecting = false;
        this.reconnectDelays.set(node.id, Math.min(currentDelay * 2, 10_000)); // 10s cap
        this.scheduleReconnect(node);
      }
    }, currentDelay + jitter);
  }

  getClient(nodeId: string): Client | null {
    if (nodeId === 'windows') return null;
    const conn = this.connections.get(nodeId);
    return conn?.connected ? conn.client : null;
  }

  onReconnect(cb: ReconnectCallback): void {
    this.reconnectCallbacks.push(cb);
  }

  isConnected(nodeId: string): boolean {
    if (nodeId === 'windows') return true;
    return this.connections.get(nodeId)?.connected ?? false;
  }

  getActiveHost(nodeId: string): string | null {
    return this.connections.get(nodeId)?.activeHost ?? null;
  }

  getOnlineNodes(): string[] {
    const online = ['windows'];
    for (const [id, conn] of this.connections) {
      if (conn.connected) online.push(id);
    }
    return online;
  }

  // Remote execution via SSH2 client.exec() -- NOT child_process.exec()
  async exec(nodeId: string, command: string): Promise<ExecResult> {
    const start = Date.now();

    if (nodeId === 'windows') {
      return this.execLocal(command, start);
    }

    const conn = this.connections.get(nodeId);

    if (conn && conn.circuitOpenUntil > Date.now()) {
      return { nodeId, stdout: '', stderr: `Node ${nodeId} circuit open`, code: -1, durationMs: Date.now() - start };
    }

    if (!conn?.connected) {
      return { nodeId, stdout: '', stderr: `Node ${nodeId} is offline`, code: -1, durationMs: Date.now() - start };
    }

    return new Promise<ExecResult>((resolve) => {
      const chunks: string[] = [];    // array join is faster than string concat
      const errChunks: string[] = [];
      let totalBytes = 0;
      let truncated = false;

      conn.client.exec(command, (err, stream) => {
        if (err) {
          conn.failures++;
          if (conn.failures >= CIRCUIT_FAILURE_THRESHOLD) {
            conn.circuitOpenUntil = Date.now() + CIRCUIT_OPEN_DURATION;
          }
          resolve({ nodeId, stdout: '', stderr: err.message, code: -1, durationMs: Date.now() - start });
          return;
        }

        stream.on('data', (data: Buffer) => {
          if (!truncated) {
            const str = data.toString();
            totalBytes += str.length;
            if (totalBytes < MAX_OUTPUT_BYTES) {
              chunks.push(str);
            } else {
              truncated = true;
            }
          }
        });

        stream.stderr.on('data', (data: Buffer) => {
          const str = data.toString();
          if (errChunks.join('').length < MAX_OUTPUT_BYTES) {
            errChunks.push(str);
          }
        });

        stream.on('close', (code: number) => {
          conn.lastPing = new Date();
          conn.failures = 0;
          const stdout = chunks.join('').trimEnd() + (truncated ? '\n[truncated at 2MB]' : '');
          resolve({ nodeId, stdout, stderr: errChunks.join('').trimEnd(), code: code ?? 0, durationMs: Date.now() - start });
        });
      });
    });
  }

  private execLocal(command: string, start: number): Promise<ExecResult> {
    return new Promise<ExecResult>((resolve) => {
      execFile('bash', ['-c', command], {
        timeout: 60000,
        maxBuffer: MAX_OUTPUT_BYTES,
      }, (err, stdout, stderr) => {
        resolve({
          nodeId: 'windows',
          stdout: (stdout ?? '').trimEnd(),
          stderr: (stderr ?? '').trimEnd(),
          code: err ? ((err as Record<string, unknown>).code as number | undefined) ?? 1 : 0,
          durationMs: Date.now() - start,
        });
      });
    });
  }

  async execAll(command: string): Promise<ExecResult[]> {
    return Promise.all(this.getOnlineNodes().map((id) => this.exec(id, command)));
  }

  async execRemote(command: string): Promise<ExecResult[]> {
    return Promise.all(this.getOnlineNodes().filter((id) => id !== 'windows').map((id) => this.exec(id, command)));
  }

  async execOn(nodeIds: string[], command: string): Promise<ExecResult[]> {
    return Promise.all(nodeIds.map((id) => this.exec(id, command)));
  }

  async getNodeStatus(nodeId: string): Promise<NodeStatus> {
    if (nodeId === 'windows') {
      return { nodeId: 'windows', online: true, latencyMs: 0, lastSeen: new Date(), uptime: null, loadAvg: null, memUsedPct: null, diskUsedPct: null };
    }

    const cached = this.statusCache.get(nodeId);
    if (cached && Date.now() - cached.at < STATUS_CACHE_TTL) return cached.status;

    if (!this.isConnected(nodeId)) {
      const status: NodeStatus = { nodeId, online: false, latencyMs: null, lastSeen: this.connections.get(nodeId)?.lastPing ?? null, uptime: null, loadAvg: null, memUsedPct: null, diskUsedPct: null };
      this.statusCache.set(nodeId, { status, at: Date.now() });
      return status;
    }

    const start = Date.now();
    // Single compact command — all metrics in one fork, no pipes
    const result = await this.exec(nodeId,
      "awk '{u=$2-$1;t=$2;if(t>0)printf \"%.0f\\n\",u/t*100}' /proc/stat 2>/dev/null|head -1;cat /proc/loadavg 2>/dev/null|cut -d' ' -f1-3;awk '/MemTotal/{t=$2}/MemAvailable/{a=$2}END{if(t>0)printf \"%.1f\\n\",(t-a)/t*100}' /proc/meminfo;df / 2>/dev/null|awk 'NR==2{print $5}'|tr -d '%';uptime -p 2>/dev/null"
    );
    const latency = Date.now() - start;

    const lines = result.stdout.split('\n');
    const status: NodeStatus = {
      nodeId, online: true, latencyMs: latency, lastSeen: new Date(),
      uptime: lines[4] ?? null,
      loadAvg: lines[1] ?? null,
      memUsedPct: parseFloat(lines[2]) || null,
      diskUsedPct: parseFloat(lines[3]) || null,
    };

    this.statusCache.set(nodeId, { status, at: Date.now() });
    return status;
  }

  async getAllStatus(): Promise<NodeStatus[]> {
    const ids = ['windows', ...remoteNodes().map((n) => n.id)];
    return Promise.all(ids.map((id) => this.getNodeStatus(id)));
  }

  async streamExec(
    nodeId: string,
    command: string,
    onData: (chunk: string) => void,
    onError: (chunk: string) => void
  ): Promise<number> {
    if (nodeId === 'windows') {
      return new Promise((resolve) => {
        const proc = execFile('bash', ['-c', command], { timeout: 60000 });
        proc.stdout?.on('data', (d) => onData(d.toString()));
        proc.stderr?.on('data', (d) => onError(d.toString()));
        proc.on('close', (code) => resolve(code ?? 0));
      });
    }

    const conn = this.connections.get(nodeId);
    if (!conn?.connected) {
      onError(`Node ${nodeId} is offline`);
      return -1;
    }

    return new Promise((resolve) => {
      conn.client.exec(command, (err, stream) => {
        if (err) { onError(err.message); resolve(-1); return; }
        stream.on('data', (d: Buffer) => onData(d.toString()));
        stream.stderr.on('data', (d: Buffer) => onError(d.toString()));
        stream.on('close', (code: number) => resolve(code ?? 0));
      });
    });
  }

  // Parallel health pings with minimal overhead (echo > true — avoids hash lookup)
  private startHealthPing(): void {
    this.healthTimer = setInterval(() => {
      const pings = [...this.connections.entries()]
        .filter(([, conn]) => conn.connected && conn.circuitOpenUntil <= Date.now())
        .map(async ([nodeId]) => {
          const start = Date.now();
          const result = await this.exec(nodeId, ':');  // ':' is bash builtin — zero fork
          const elapsed = Date.now() - start;
          if (elapsed > 2000 || result.code !== 0) {
            process.stderr.write(`[health] ${nodeId} degraded (${elapsed}ms)\n`);
          }
        });
      Promise.allSettled(pings);
    }, HEALTH_PING_INTERVAL);
  }

  disconnect(): void {
    if (this.healthTimer) { clearInterval(this.healthTimer); this.healthTimer = null; }
    for (const conn of this.connections.values()) { conn.client.end(); conn.connected = false; }
    this.connections.clear();
    this.statusCache.clear();
    this.keyCache.clear();
  }
}
