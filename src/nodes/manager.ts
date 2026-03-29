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
  totalExecs: number;
}

// Priority queue entry for deferred command execution (priority 1-2)
interface QueuedCommand {
  nodeId: string;
  command: string;
  priority: number; // 0=highest (health/immediate), 1=normal, 2=low (batch)
  resolve: (result: ExecResult) => void;
}

type ReconnectCallback = (nodeId: string) => void;

const MAX_OUTPUT_BYTES = 2 * 1024 * 1024;
const STATUS_CACHE_TTL = 5000;
const HEALTH_PING_INTERVAL = 30_000;
const CIRCUIT_OPEN_DURATION = 15_000;      // 15s circuit breaker — faster recovery
const CIRCUIT_FAILURE_THRESHOLD = 3;
const CONNECT_TIMEOUT = 5000;              // 5s connection timeout
const QUEUE_CONCURRENCY = 10;              // max concurrent execs per node through queue
const LATENCY_HISTORY_SIZE = 20;           // rolling window for avg latency

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

  // Per-node rolling latency history (capped at LATENCY_HISTORY_SIZE entries)
  private latencyHistory: Map<string, number[]> = new Map();

  // Per-node command queue and active-exec counter for priority 1-2 commands
  private commandQueues: Map<string, QueuedCommand[]> = new Map();
  private activeExecs: Map<string, number> = new Map();

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
      totalExecs: 0,
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
        // Drain any queued commands that accumulated while offline
        this.drainQueue(node.id);
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

  // ── Smart truncation ────────────────────────────────────────────────────────
  //
  // Detects output format and truncates intelligently so large results stay
  // readable without blowing up context or transport buffers.
  //
  static smartTruncate(output: string, maxChars: number = 4000): string {
    if (output.length <= maxChars) return output;

    // JSON detection — try to parse; keep first 3000 chars + item count note
    const trimmed = output.trimStart();
    if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
      try {
        const parsed = JSON.parse(output);
        const isArray = Array.isArray(parsed);
        const count = isArray ? parsed.length : Object.keys(parsed).length;
        const pretty = JSON.stringify(parsed, null, 2);
        if (pretty.length > maxChars) {
          const unit = isArray ? 'items' : 'keys';
          return pretty.slice(0, 3000) + `\n... (${count} total ${unit}, truncated)`;
        }
        return pretty;
      } catch {
        // not valid JSON — fall through
      }
    }

    const lines = output.split('\n');

    // Table detection — consistent column pattern (pipes or aligned spaces)
    // Heuristic: ≥3 lines and first two non-empty lines have the same number
    // of delimiter-separated columns
    const nonEmpty = lines.filter((l) => l.trim().length > 0);
    if (nonEmpty.length >= 3) {
      const hasPipes = nonEmpty[0].includes('|') && nonEmpty[1].includes('|');
      if (hasPipes) {
        const colCount = (s: string) => s.split('|').length;
        if (colCount(nonEmpty[0]) === colCount(nonEmpty[1])) {
          const MAX_ROWS = 30;
          const header = lines.slice(0, 2); // header + separator
          const dataRows = lines.slice(2);
          if (dataRows.length > MAX_ROWS) {
            const kept = dataRows.slice(0, MAX_ROWS);
            return [...header, ...kept, `... (${dataRows.length - MAX_ROWS} more rows)`].join('\n');
          }
        }
      }
    }

    // Log detection — lines that start with a timestamp or log-level token
    const LOG_RE = /^(\d{4}-\d{2}-\d{2}|\[\d|\d{2}:\d{2}:\d{2}|INFO|WARN|ERROR|DEBUG|TRACE|\[INFO\]|\[WARN\]|\[ERR)/;
    const logLineCount = nonEmpty.slice(0, 10).filter((l) => LOG_RE.test(l)).length;
    if (logLineCount >= 3) {
      const TAIL = 50;
      if (lines.length > TAIL) {
        const skipped = lines.length - TAIL;
        return `... (${skipped} earlier lines omitted)\n` + lines.slice(-TAIL).join('\n');
      }
    }

    // Default — keep first maxChars characters
    return output.slice(0, maxChars) + `\n... (${output.length - maxChars} more chars)`;
  }

  // ── Core exec (non-blocking — ssh2 supports multiple concurrent exec channels
  //    on a single connection natively; each call opens a separate channel and
  //    returns immediately, so concurrent calls do NOT serialize) ────────────
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

    conn.totalExecs++;

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
          const latency = Date.now() - start;
          this.recordLatency(nodeId, latency);
          const stdout = chunks.join('').trimEnd() + (truncated ? '\n[truncated at 2MB]' : '');
          resolve({ nodeId, stdout, stderr: errChunks.join('').trimEnd(), code: code ?? 0, durationMs: latency });
        });
      });
    });
  }

  // ── Priority exec ───────────────────────────────────────────────────────────
  //
  // Priority 0: executes immediately (same as exec — used for health checks and
  //             urgent commands; bypasses the queue entirely).
  // Priority 1: normal — goes through the per-node queue with QUEUE_CONCURRENCY
  //             concurrency limit.
  // Priority 2: low / batch — same queue, sorted behind priority-1 entries.
  //
  async execPriority(nodeId: string, command: string, priority: number): Promise<ExecResult> {
    if (priority === 0) {
      return this.exec(nodeId, command);
    }

    return new Promise<ExecResult>((resolve) => {
      const entry: QueuedCommand = { nodeId, command, priority, resolve };

      if (!this.commandQueues.has(nodeId)) {
        this.commandQueues.set(nodeId, []);
      }

      const queue = this.commandQueues.get(nodeId)!;
      // Insert in priority order (lower number = higher priority = earlier in array)
      let insertAt = queue.length;
      for (let i = 0; i < queue.length; i++) {
        if (queue[i].priority > priority) {
          insertAt = i;
          break;
        }
      }
      queue.splice(insertAt, 0, entry);

      this.drainQueue(nodeId);
    });
  }

  // Drain up to QUEUE_CONCURRENCY concurrent execs from the queue for a node
  private drainQueue(nodeId: string): void {
    const queue = this.commandQueues.get(nodeId);
    if (!queue || queue.length === 0) return;

    const active = this.activeExecs.get(nodeId) ?? 0;
    const slots = QUEUE_CONCURRENCY - active;
    if (slots <= 0) return;

    const toRun = queue.splice(0, slots);
    this.activeExecs.set(nodeId, active + toRun.length);

    for (const entry of toRun) {
      this.exec(entry.nodeId, entry.command).then((result) => {
        entry.resolve(result);
        this.activeExecs.set(nodeId, (this.activeExecs.get(nodeId) ?? 1) - 1);
        this.drainQueue(nodeId);
      });
    }
  }

  // ── Latency tracking ────────────────────────────────────────────────────────

  private recordLatency(nodeId: string, ms: number): void {
    const history = this.latencyHistory.get(nodeId) ?? [];
    history.push(ms);
    if (history.length > LATENCY_HISTORY_SIZE) history.shift();
    this.latencyHistory.set(nodeId, history);
  }

  private avgLatency(nodeId: string): number {
    const history = this.latencyHistory.get(nodeId);
    if (!history || history.length === 0) return Infinity;
    return history.reduce((sum, v) => sum + v, 0) / history.length;
  }

  // Returns the online node with the lowest average latency, optionally
  // excluding specified node IDs (e.g. when retrying after a failure).
  getBestNode(exclude?: string[]): string {
    const excluded = new Set(exclude ?? []);
    const candidates = this.getOnlineNodes().filter(
      (id) => id !== 'windows' && !excluded.has(id)
    );

    if (candidates.length === 0) return 'windows';

    let best = candidates[0];
    let bestAvg = this.avgLatency(best);

    for (let i = 1; i < candidates.length; i++) {
      const avg = this.avgLatency(candidates[i]);
      if (avg < bestAvg) {
        best = candidates[i];
        bestAvg = avg;
      }
    }

    return best;
  }

  // ── Connection pool stats ───────────────────────────────────────────────────

  getPoolStats(): {
    node: string;
    connected: boolean;
    activeHost: string | null;
    avgLatencyMs: number;
    failures: number;
    totalExecs: number;
  }[] {
    const stats = [];

    // Always include the local windows node
    stats.push({
      node: 'windows',
      connected: true,
      activeHost: 'localhost',
      avgLatencyMs: 0,
      failures: 0,
      totalExecs: 0,
    });

    for (const [id, conn] of this.connections) {
      const avg = this.avgLatency(id);
      stats.push({
        node: id,
        connected: conn.connected,
        activeHost: conn.activeHost,
        avgLatencyMs: avg === Infinity ? -1 : Math.round(avg),
        failures: conn.failures,
        totalExecs: conn.totalExecs,
      });
    }

    return stats;
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
          // Use priority 0 — health pings bypass the queue and execute immediately
          const start = Date.now();
          const result = await this.execPriority(nodeId, ':', 0);  // ':' is bash builtin — zero fork
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
    this.latencyHistory.clear();
    this.commandQueues.clear();
    this.activeExecs.clear();
  }
}
