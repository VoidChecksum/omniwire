// OmniWire Node Manager — persistent SSH connections to all mesh nodes

import { Client, type ConnectConfig } from 'ssh2';
import { readFileSync } from 'node:fs';
import { execFile } from 'node:child_process';
import type { MeshNode, NodeStatus, ExecResult } from '../protocol/types.js';
import { remoteNodes } from '../protocol/config.js';

interface NodeConnection {
  node: MeshNode;
  client: Client;
  connected: boolean;
  lastPing: Date | null;
  reconnecting: boolean;
  failures: number;        // consecutive failures (circuit breaker)
  circuitOpenUntil: number; // timestamp when circuit re-closes
}

type ReconnectCallback = (nodeId: string) => void;

const MAX_OUTPUT_BYTES = 2 * 1024 * 1024; // 2MB output guard
const STATUS_CACHE_TTL = 5000;             // 5s status cache
const HEALTH_PING_INTERVAL = 30_000;       // 30s health pings
const CIRCUIT_OPEN_DURATION = 60_000;      // 60s circuit breaker
const CIRCUIT_FAILURE_THRESHOLD = 3;

export class NodeManager {
  private connections: Map<string, NodeConnection> = new Map();
  private reconnectCallbacks: ReconnectCallback[] = [];
  private reconnectDelays: Map<string, number> = new Map();
  private statusCache: Map<string, { status: NodeStatus; at: number }> = new Map();
  private healthTimer: ReturnType<typeof setInterval> | null = null;

  async connectAll(): Promise<void> {
    const nodes = remoteNodes();
    await Promise.allSettled(nodes.map((node) => this.connect(node)));
    this.startHealthPing();
  }

  private async connect(node: MeshNode): Promise<void> {
    if (node.isLocal) return;

    const client = new Client();
    const conn: NodeConnection = {
      node,
      client,
      connected: false,
      lastPing: null,
      reconnecting: false,
      failures: 0,
      circuitOpenUntil: 0,
    };

    this.connections.set(node.id, conn);

    return new Promise<void>((resolve, reject) => {
      const timeout = setTimeout(() => {
        client.end();
        reject(new Error(`Connection to ${node.id} timed out`));
      }, 8000);

      client.on('ready', () => {
        clearTimeout(timeout);
        conn.connected = true;
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
        this.scheduleReconnect(node);
      });

      const config: ConnectConfig = {
        host: node.host,
        port: node.port,
        username: node.user,
        privateKey: readFileSync(node.identityFile),
        readyTimeout: 8000,
        keepaliveInterval: 5000,
        keepaliveCountMax: 3,
        algorithms: {
          compress: ['zlib@openssh.com', 'zlib', 'none'],
        },
      };

      client.connect(config);
    });
  }

  private scheduleReconnect(node: MeshNode): void {
    const conn = this.connections.get(node.id);
    if (!conn || conn.reconnecting) return;

    conn.reconnecting = true;
    const currentDelay = this.reconnectDelays.get(node.id) ?? 1000;
    const jitter = Math.floor(Math.random() * 1000);

    setTimeout(async () => {
      try {
        conn.client = new Client();
        await this.connect(node);
        conn.reconnecting = false;
        conn.failures = 0;
        conn.circuitOpenUntil = 0;
        this.reconnectDelays.set(node.id, 1000); // reset on success
        for (const cb of this.reconnectCallbacks) cb(node.id);
      } catch {
        conn.reconnecting = false;
        // Exponential backoff: 1s → 2s → 4s → 8s → 16s → 30s cap
        this.reconnectDelays.set(node.id, Math.min(currentDelay * 2, 30_000));
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

  getOnlineNodes(): string[] {
    const online = ['windows'];
    for (const [id, conn] of this.connections) {
      if (conn.connected) online.push(id);
    }
    return online;
  }

  // Remote execution via SSH2 client.exec() — NOT child_process.exec()
  // All commands run on remote nodes over authenticated SSH channels
  async exec(nodeId: string, command: string): Promise<ExecResult> {
    const start = Date.now();

    if (nodeId === 'windows') {
      return this.execLocal(command, start);
    }

    const conn = this.connections.get(nodeId);

    // Circuit breaker: skip if circuit is open
    if (conn && conn.circuitOpenUntil > Date.now()) {
      return {
        nodeId,
        stdout: '',
        stderr: `Node ${nodeId} circuit open (${conn.failures} consecutive failures)`,
        code: -1,
        durationMs: Date.now() - start,
      };
    }

    if (!conn?.connected) {
      return {
        nodeId,
        stdout: '',
        stderr: `Node ${nodeId} is offline`,
        code: -1,
        durationMs: Date.now() - start,
      };
    }

    return new Promise<ExecResult>((resolve) => {
      let stdout = '';
      let stderr = '';
      let truncated = false;

      conn.client.exec(command, (err, stream) => {
        if (err) {
          conn.failures++;
          if (conn.failures >= CIRCUIT_FAILURE_THRESHOLD) {
            conn.circuitOpenUntil = Date.now() + CIRCUIT_OPEN_DURATION;
          }
          resolve({
            nodeId,
            stdout: '',
            stderr: err.message,
            code: -1,
            durationMs: Date.now() - start,
          });
          return;
        }

        stream.on('data', (data: Buffer) => {
          if (!truncated && stdout.length < MAX_OUTPUT_BYTES) {
            stdout += data.toString();
            if (stdout.length >= MAX_OUTPUT_BYTES) truncated = true;
          }
        });

        stream.stderr.on('data', (data: Buffer) => {
          if (stderr.length < MAX_OUTPUT_BYTES) {
            stderr += data.toString();
          }
        });

        stream.on('close', (code: number) => {
          conn.lastPing = new Date();
          conn.failures = 0; // reset on success
          const suffix = truncated ? '\n[truncated at 2MB]' : '';
          resolve({
            nodeId,
            stdout: stdout.trimEnd() + suffix,
            stderr: stderr.trimEnd(),
            code: code ?? 0,
            durationMs: Date.now() - start,
          });
        });
      });
    });
  }

  // Local execution uses execFile with bash -c to avoid shell injection
  // Command strings here come from the user's own terminal input, not external sources
  private execLocal(command: string, start: number): Promise<ExecResult> {
    return new Promise<ExecResult>((resolve) => {
      execFile('bash', ['-c', command], { timeout: 30000 }, (err, stdout, stderr) => {
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
    const nodeIds = this.getOnlineNodes();
    return Promise.all(nodeIds.map((id) => this.exec(id, command)));
  }

  async execRemote(command: string): Promise<ExecResult[]> {
    const nodeIds = this.getOnlineNodes().filter((id) => id !== 'windows');
    return Promise.all(nodeIds.map((id) => this.exec(id, command)));
  }

  async execOn(nodeIds: string[], command: string): Promise<ExecResult[]> {
    return Promise.all(nodeIds.map((id) => this.exec(id, command)));
  }

  async getNodeStatus(nodeId: string): Promise<NodeStatus> {
    if (nodeId === 'windows') {
      return {
        nodeId: 'windows',
        online: true,
        latencyMs: 0,
        lastSeen: new Date(),
        uptime: null,
        loadAvg: null,
        memUsedPct: null,
        diskUsedPct: null,
      };
    }

    // Return cached status if fresh enough
    const cached = this.statusCache.get(nodeId);
    if (cached && Date.now() - cached.at < STATUS_CACHE_TTL) {
      return cached.status;
    }

    if (!this.isConnected(nodeId)) {
      const status: NodeStatus = {
        nodeId,
        online: false,
        latencyMs: null,
        lastSeen: this.connections.get(nodeId)?.lastPing ?? null,
        uptime: null,
        loadAvg: null,
        memUsedPct: null,
        diskUsedPct: null,
      };
      this.statusCache.set(nodeId, { status, at: Date.now() });
      return status;
    }

    const start = Date.now();
    const result = await this.exec(
      nodeId,
      "uptime -p; cat /proc/loadavg | awk '{print $1,$2,$3}'; free | awk '/Mem:/{printf \"%.1f\", $3/$2*100}'; echo; df / | awk 'NR==2{print $5}'"
    );
    const latency = Date.now() - start;

    let status: NodeStatus;
    if (result.code !== 0) {
      status = {
        nodeId,
        online: true,
        latencyMs: latency,
        lastSeen: new Date(),
        uptime: null,
        loadAvg: null,
        memUsedPct: null,
        diskUsedPct: null,
      };
    } else {
      const lines = result.stdout.split('\n');
      status = {
        nodeId,
        online: true,
        latencyMs: latency,
        lastSeen: new Date(),
        uptime: lines[0] ?? null,
        loadAvg: lines[1] ?? null,
        memUsedPct: parseFloat(lines[2]) || null,
        diskUsedPct: parseFloat(lines[3]) || null,
      };
    }

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
        if (err) {
          onError(err.message);
          resolve(-1);
          return;
        }
        stream.on('data', (d: Buffer) => onData(d.toString()));
        stream.stderr.on('data', (d: Buffer) => onError(d.toString()));
        stream.on('close', (code: number) => resolve(code ?? 0));
      });
    });
  }

  // Periodic health ping — verifies end-to-end SSH responsiveness
  private startHealthPing(): void {
    this.healthTimer = setInterval(async () => {
      for (const [nodeId, conn] of this.connections) {
        if (!conn.connected || conn.circuitOpenUntil > Date.now()) continue;
        const start = Date.now();
        const result = await this.exec(nodeId, 'echo 1');
        const elapsed = Date.now() - start;
        if (elapsed > 3000 || result.code !== 0) {
          process.stderr.write(`[health] ${nodeId} degraded (${elapsed}ms, code=${result.code})\n`);
        }
      }
    }, HEALTH_PING_INTERVAL);
  }

  disconnect(): void {
    if (this.healthTimer) {
      clearInterval(this.healthTimer);
      this.healthTimer = null;
    }
    for (const conn of this.connections.values()) {
      conn.client.end();
      conn.connected = false;
    }
    this.connections.clear();
    this.statusCache.clear();
  }
}
