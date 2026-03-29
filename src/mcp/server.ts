// OmniWire MCP Server -- 34-tool universal AI agent interface (25 core + 9 CyberSync)
// Works with Claude Code, OpenCode, Oh-My-OpenAgent, OpenClaw, and any MCP client
//
// SECURITY NOTE: This file does NOT use child_process.exec(). All remote command
// execution goes through NodeManager.exec() which uses SSH2's client.exec() over
// authenticated, encrypted SSH channels. The "exec" references below are SSH2 methods.

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import type { NodeManager } from '../nodes/manager.js';
import type { TransferEngine } from '../nodes/transfer.js';
import { ShellManager, kernelExec } from '../nodes/shell.js';
import { RealtimeChannel } from '../nodes/realtime.js';
import { TunnelManager } from '../nodes/tunnel.js';
import { openBrowser } from '../commands/browser.js';
import { allNodes, remoteNodes, findNode, NODE_ROLES, getDefaultNodeForTask } from '../protocol/config.js';
import { parseMeshPath } from '../protocol/paths.js';

// -- Output helpers -- compact, scannable output for AI agents ----------------
type McpResult = { content: [{ type: 'text'; text: string }] };

const MAX_OUTPUT = 4000;

function t(ms: number): string {
  return ms < 1000 ? `${ms}ms` : `${(ms / 1000).toFixed(1)}s`;
}

function trim(s: string): string {
  if (s.length <= MAX_OUTPUT) return s;

  // Detect JSON — show item count on truncation
  if (s.trimStart().startsWith('[') || s.trimStart().startsWith('{')) {
    try {
      const parsed = JSON.parse(s);
      const count = Array.isArray(parsed) ? parsed.length : Object.keys(parsed).length;
      return s.slice(0, MAX_OUTPUT - 50) + `\n...(truncated, ${count} items total)`;
    } catch {}
  }

  // Detect table-like output — show header + tail
  const lines = s.split('\n');
  if (lines.length > 30) {
    const header = lines.slice(0, 2).join('\n');
    const lastLines = lines.slice(-5).join('\n');
    return header + '\n...\n' + lastLines + `\n(${lines.length} lines total)`;
  }

  return s.slice(0, MAX_OUTPUT) + '\n...(truncated)';
}

function ok(node: string, ms: number, body: string, label?: string): McpResult {
  const hdr = label ? `${node} > ${label}` : node;
  return { content: [{ type: 'text' as const, text: `${hdr}  ${t(ms)}\n${trim(body)}` }] };
}

function okBrief(msg: string): McpResult {
  return { content: [{ type: 'text' as const, text: msg }] };
}

function fail(msg: string): McpResult {
  return { content: [{ type: 'text' as const, text: `ERR ${msg}` }] };
}

interface ExecOutput { code: number; stdout: string; stderr: string; durationMs: number }

function fmtExecOutput(result: ExecOutput, timeoutSec: number): string {
  if (result.code === 0) return result.stdout || '(empty)';
  if (result.code === 124) return `TIMEOUT ${timeoutSec}s\n${result.stdout || '(empty)'}`;
  return `exit ${result.code}\n${result.stderr}`;
}

function fmtJson(node: string, result: ExecOutput, label?: string): McpResult {
  return okBrief(JSON.stringify({
    node, ok: result.code === 0, code: result.code, ms: result.durationMs,
    ...(label ? { label } : {}),
    stdout: result.stdout.slice(0, MAX_OUTPUT),
    ...(result.stderr ? { stderr: result.stderr.slice(0, 1000) } : {}),
  }));
}

function multiResult(results: { nodeId: string; code: number; stdout: string; stderr: string; durationMs: number }[]): McpResult {
  const parts = results.map((r) => {
    const mark = r.code === 0 ? 'ok' : `exit ${r.code}`;
    const body = r.code === 0
      ? (r.stdout || '(empty)').split('\n').slice(0, 30).join('\n')
      : r.stderr.split('\n').slice(0, 10).join('\n');
    return `-- ${r.nodeId}  ${t(r.durationMs)}  ${mark}\n${body}`;
  });
  return okBrief(trim(parts.join('\n\n')));
}

function multiResultJson(results: { nodeId: string; code: number; stdout: string; stderr: string; durationMs: number }[]): McpResult {
  return okBrief(JSON.stringify(results.map((r) => ({
    node: r.nodeId, ok: r.code === 0, code: r.code, ms: r.durationMs,
    stdout: r.stdout.slice(0, MAX_OUTPUT),
    ...(r.stderr ? { stderr: r.stderr.slice(0, 500) } : {}),
  }))));
}

// -- VPN namespace wrapper -- routes ONLY the command through VPN, mesh stays intact
// Uses Linux network namespaces: creates isolated netns, moves VPN tunnel into it,
// runs command inside namespace. Main namespace (WireGuard mesh, SSH) is untouched.
function buildVpnWrappedCmd(vpnSpec: string, innerCmd: string): string {
  const ns = `ow-vpn-${Date.now().toString(36)}`;
  const escaped = innerCmd.replace(/'/g, "'\\''");

  // Parse spec: "mullvad", "mullvad:se", "openvpn:/path/to.conf", "wg:wg-vpn"
  const [provider, param] = vpnSpec.includes(':') ? [vpnSpec.split(':')[0], vpnSpec.split(':').slice(1).join(':')] : [vpnSpec, ''];

  if (provider === 'mullvad') {
    // Mullvad supports split tunneling natively via `mullvad-exclude`
    // OR we can use its SOCKS5 proxy (10.64.0.1:1080) when connected
    // Best approach: use mullvad split-tunnel + namespace for full isolation
    const relayCmd = param ? `mullvad relay set location ${param} 2>/dev/null;` : '';
    // Check if mullvad is already connected; if not, connect (split-tunnel safe)
    return `${relayCmd} mullvad status | grep -q Connected || mullvad connect 2>/dev/null; sleep 1; ` +
      // Create netns, veth pair, route traffic through mullvad's tun
      `ip netns add ${ns} 2>/dev/null; ` +
      `ip link add veth-${ns} type veth peer name veth-${ns}-ns; ` +
      `ip link set veth-${ns}-ns netns ${ns}; ` +
      `ip addr add 172.30.${Math.floor(Math.random() * 254) + 1}.1/30 dev veth-${ns}; ` +
      `ip link set veth-${ns} up; ` +
      `ip netns exec ${ns} ip addr add 172.30.${Math.floor(Math.random() * 254) + 1}.2/30 dev veth-${ns}-ns; ` +
      `ip netns exec ${ns} ip link set veth-${ns}-ns up; ` +
      `ip netns exec ${ns} ip link set lo up; ` +
      // Use mullvad SOCKS proxy for the namespace (simpler, no route table manipulation)
      `ip netns exec ${ns} bash -c 'export ALL_PROXY=socks5://10.64.0.1:1080; ${escaped}'; ` +
      `_rc=$?; ip netns del ${ns} 2>/dev/null; ip link del veth-${ns} 2>/dev/null; exit $_rc`;
  }

  if (provider === 'openvpn') {
    const configPath = param || '/etc/openvpn/client.conf';
    // Run OpenVPN inside a network namespace — only the command sees the tunnel
    return `ip netns add ${ns} 2>/dev/null; ` +
      `ip netns exec ${ns} ip link set lo up; ` +
      `ip netns exec ${ns} openvpn --config "${configPath}" --daemon --log /tmp/${ns}.log --writepid /tmp/${ns}.pid; ` +
      `sleep 4; ` +  // wait for tunnel
      `ip netns exec ${ns} bash -c '${escaped}'; ` +
      `_rc=$?; kill $(cat /tmp/${ns}.pid 2>/dev/null) 2>/dev/null; ip netns del ${ns} 2>/dev/null; rm -f /tmp/${ns}.log /tmp/${ns}.pid; exit $_rc`;
  }

  if (provider === 'wg' || provider === 'wireguard') {
    const iface = param || 'wg-vpn';
    // Move WireGuard VPN interface into namespace — mesh wg0 stays in main ns
    return `ip netns add ${ns} 2>/dev/null; ` +
      `ip link add ${iface}-${ns} type wireguard; ` +
      `wg setconf ${iface}-${ns} /etc/wireguard/${iface}.conf 2>/dev/null; ` +
      `ip link set ${iface}-${ns} netns ${ns}; ` +
      `ip netns exec ${ns} ip link set lo up; ` +
      `ip netns exec ${ns} ip addr add 10.66.0.2/32 dev ${iface}-${ns}; ` +
      `ip netns exec ${ns} ip link set ${iface}-${ns} up; ` +
      `ip netns exec ${ns} ip route add default dev ${iface}-${ns}; ` +
      `ip netns exec ${ns} bash -c '${escaped}'; ` +
      `_rc=$?; ip netns del ${ns} 2>/dev/null; exit $_rc`;
  }

  // Fallback: just run the command (no VPN wrapping)
  return innerCmd;
}

// -- Command safety -- block patterns that could cause irreversible system damage
const BLOCKED_PATTERNS = [
  /rm\s+-rf\s+\/(?!\w)/,                   // rm -rf / (but allow rm -rf /tmp/something)
  /dd\s+if=\/dev\/zero.*of=\/dev\/sd/,      // dd zeroing disk
  /mkfs\./,                                 // format filesystem
  /:(){ :\|:& };:/,                         // fork bomb
  />\s*\/dev\/sd/,                          // redirect to disk device
  /chmod\s+-R\s+777\s+\//,                  // chmod 777 /
];

function checkCommandSafety(cmd: string): string | null {
  for (const pattern of BLOCKED_PATTERNS) {
    if (pattern.test(cmd)) return `Blocked dangerous pattern: ${pattern.source}`;
  }
  return null;
}

// -- Agentic state -- shared across tool calls in the same MCP session --------
// Session-scoped: all keys are cleared on process restart (not persisted to disk).
const resultStore = new Map<string, string>();  // key -> value store for chaining

// -- Audit log -- circular buffer of last 1000 exec events -------------------
interface AuditEntry { ts: number; tool: string; node: string; command: string; code: number; durationMs: number }
const auditLog: AuditEntry[] = [];

// -- Alias store -- in-memory command shortcuts ------------------------------
const aliasStore = new Map<string, string>();  // name -> command template

// -- Trace store -- distributed trace spans ---------------------------------
interface TraceSpan { node: string; command: string; startMs: number; endMs: number; result: string }
interface Trace { spans: TraceSpan[]; startMs: number; done: boolean }
const traceStore = new Map<string, Trace>();

// -- Background task registry -- dispatch-and-poll for any tool ---------------
interface BgTask { id: string; node: string; label: string; startedAt: number; promise: Promise<McpResult>; result?: McpResult }
const bgTasks = new Map<string, BgTask>();

function bgId(): string { return `bg-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`; }

function dispatchBg(node: string, label: string, fn: () => Promise<McpResult>): McpResult {
  const id = bgId();
  const task: BgTask = { id, node, label, startedAt: Date.now(), promise: fn() };
  task.promise.then((r) => { task.result = r; });
  bgTasks.set(id, task);
  return okBrief(`BACKGROUND ${id} dispatched on ${node}: ${label}`);
}
// -- CyberBase persistence layer -- fire-and-forget writes to PostgreSQL ------
// All tool data auto-persists to CyberBase without blocking responses.
// Uses the SSH connection to contabo (where PostgreSQL runs).
// Category-based key-value store in sync_items table.
let cbManager: NodeManager | null = null;
const CB_QUEUE: string[] = [];
let cbDraining = false;

function cbInit(mgr: NodeManager) { cbManager = mgr; }

/** psql helper — all DB calls have 5s statement_timeout to prevent hangs */
const pgExec = (sql: string) => `psql -h 127.0.0.1 -U cyberbase -d cyberbase -c "SET statement_timeout='5s'; ${sql}" 2>/dev/null`;

/** Fire-and-forget write to CyberBase. Never blocks, never throws. */
function cb(category: string, key: string, value: string) {
  if (!cbManager) return;
  const valEsc = value.replace(/'/g, "''").slice(0, 50000);
  const keyEsc = `${category}:${key}`.replace(/'/g, "''");
  const sql = `INSERT INTO knowledge (source_tool, key, value, updated_at) VALUES ('omniwire', '${keyEsc}', jsonb_build_object('data', '${valEsc}'), NOW()) ON CONFLICT (source_tool, key) DO UPDATE SET value = jsonb_build_object('data', '${valEsc}'), updated_at = NOW();`;
  CB_QUEUE.push(sql);
  if (!cbDraining) drainCb();
}

/** Batch-drain CyberBase write queue (max 10 per flush, 5s timeout) */
async function drainCb() {
  if (!cbManager || CB_QUEUE.length === 0) { cbDraining = false; return; }
  cbDraining = true;
  const batch = CB_QUEUE.splice(0, 10);
  const combined = batch.join(' ');
  try {
    await cbManager.exec('contabo', pgExec(combined));
  } catch { /* never fail */ }
  if (CB_QUEUE.length > 0) setTimeout(drainCb, 100);
  else cbDraining = false;
}

/** Read from CyberBase knowledge table. Returns value or null. */
async function cbGet(category: string, key: string): Promise<string | null> {
  if (!cbManager) return null;
  const fullKey = `${category}:${key}`.replace(/'/g, "''");
  try {
    const r = await cbManager.exec('contabo', `psql -h 127.0.0.1 -U cyberbase -d cyberbase -t -c "SET statement_timeout='5s';SELECT value->>'data' FROM knowledge WHERE source_tool='omniwire' AND key='${fullKey}';" 2>/dev/null`);
    const val = r.stdout.trim();
    return val || null;
  } catch { return null; }
}

/** List keys in a CyberBase category (from knowledge table) */
async function cbList(category: string): Promise<string[]> {
  if (!cbManager) return [];
  const prefix = `${category}:`.replace(/'/g, "''");
  try {
    const r = await cbManager.exec('contabo', `psql -h 127.0.0.1 -U cyberbase -d cyberbase -t -c "SET statement_timeout='5s';SELECT replace(key, '${prefix}', '') FROM knowledge WHERE source_tool='omniwire' AND key LIKE '${prefix}%' ORDER BY updated_at DESC LIMIT 100;" 2>/dev/null`);
    return r.stdout.trim().split('\n').map(s => s.trim()).filter(Boolean);
  } catch { return []; }
}

/** Full-text search across CyberBase knowledge */
async function cbSearch(query: string, sourceFilter?: string): Promise<string> {
  if (!cbManager) return '';
  const srcFilter = sourceFilter ? `AND source_tool='${sourceFilter}'` : '';
  const escaped = query.replace(/'/g, "''");
  try {
    const r = await cbManager.exec('contabo',
      `psql -h 127.0.0.1 -U cyberbase -d cyberbase -t -c "SET statement_timeout='5s';SELECT source_tool, key, substring(value::text,1,200) FROM knowledge WHERE (value::text ILIKE '%${escaped}%' OR key ILIKE '%${escaped}%') ${srcFilter} ORDER BY updated_at DESC LIMIT 20;" 2>/dev/null`
    );
    return r.stdout.trim();
  } catch { return ''; }
}

/** Semantic search via pgvector (if embeddings populated) or full-text fallback */
async function cbSemanticSearch(query: string, limit: number = 10): Promise<string> {
  if (!cbManager) return '';
  const escaped = query.replace(/'/g, "''");
  try {
    // Try pgvector cosine similarity first
    const r = await cbManager.exec('contabo',
      `psql -h 127.0.0.1 -U cyberbase -d cyberbase -t -c "SET statement_timeout='5s';
        SELECT source_tool, key, substring(value::text,1,300)
        FROM knowledge
        WHERE embedding IS NOT NULL
        ORDER BY embedding <=> (SELECT embedding FROM knowledge WHERE key ILIKE '%${escaped}%' LIMIT 1)
        LIMIT ${limit};
      " 2>/dev/null`
    );
    if (r.stdout.trim()) return r.stdout.trim();
    // Fallback: ILIKE full-text
    const r2 = await cbManager.exec('contabo',
      `psql -h 127.0.0.1 -U cyberbase -d cyberbase -t -c "SET statement_timeout='5s';
        SELECT source_tool, key, substring(value::text,1,300)
        FROM knowledge
        WHERE value::text ILIKE '%${escaped}%' OR key ILIKE '%${escaped}%'
        ORDER BY updated_at DESC LIMIT ${limit};
      " 2>/dev/null`
    );
    return r2.stdout.trim();
  } catch { return ''; }
}
// -----------------------------------------------------------------------------

export function createOmniWireServer(manager: NodeManager, transfer: TransferEngine): McpServer {
  const server = new McpServer({
    name: 'omniwire',
    version: '3.0.1',
  });

  // -- Auto-inject `background` param into every tool -------------------------
  const origTool = server.tool.bind(server);
  (server as any).tool = (name: string, desc: string, schema: Record<string, any>, handler: (args: any) => Promise<McpResult>) => {
    // Skip bg meta-tool itself
    if (name === 'omniwire_bg') return origTool(name, desc, schema, handler);
    const augSchema = { ...schema, background: z.boolean().optional().describe('Run in background. Returns task ID immediately — poll with omniwire_bg.') };
    const wrappedHandler = async (args: any) => {
      if (args.background) {
        const lbl = args.label ?? args.command?.slice(0, 60) ?? name;
        const nd = args.node ?? args.src_node ?? 'omniwire';
        return dispatchBg(nd, lbl, () => handler(args));
      }
      return handler(args);
    };
    return origTool(name, desc, augSchema, wrappedHandler);
  };
  // ---------------------------------------------------------------------------

  cbInit(manager);  // Initialize CyberBase persistence layer
  const shells = new ShellManager(manager);
  const realtime = new RealtimeChannel(manager);
  const tunnels = new TunnelManager(manager);

  // --- Tool 0: omniwire_bg (background task manager) ---
  origTool(
    'omniwire_bg',
    'Poll, list, or retrieve results from background tasks dispatched with background=true on any tool.',
    {
      action: z.enum(['list', 'poll', 'result']).describe('list=show all tasks, poll=check if done, result=get output'),
      task_id: z.string().optional().describe('Task ID (required for poll/result)'),
    },
    async ({ action, task_id }: { action: string; task_id?: string }) => {
      if (action === 'list') {
        if (bgTasks.size === 0) return okBrief('No background tasks.');
        const lines = [...bgTasks.values()].map((bg) => {
          const status = bg.result ? 'DONE' : 'RUNNING';
          const elapsed = Date.now() - bg.startedAt;
          return `${bg.id}  ${status}  ${bg.node}  ${t(elapsed)}  ${bg.label}`;
        });
        return okBrief(lines.join('\n'));
      }
      if (!task_id) return fail('task_id required for poll/result');
      const task = bgTasks.get(task_id);
      if (!task) return fail(`task ${task_id} not found`);

      if (action === 'poll') {
        const status = task.result ? 'DONE' : 'RUNNING';
        const elapsed = Date.now() - task.startedAt;
        return okBrief(`${task_id} ${status} (${t(elapsed)}) ${task.label}`);
      }

      if (action === 'result') {
        if (!task.result) return okBrief(`${task_id} still RUNNING (${t(Date.now() - task.startedAt)})`);
        return task.result;
      }
      return fail('invalid action');
    }
  );

  // --- Tool 1: omniwire_exec ---
  server.tool(
    'omniwire_exec',
    'Execute a command on a mesh node. Set background=true for async. Set via_vpn to route through VPN (Mullvad/OpenVPN/WireGuard) for anonymous scanning. Supports retry, assert, JSON, store_as, {{key}}.',
    {
      node: z.string().optional().describe('Target node id (windows, contabo, hostinger, thinkpad). Auto-selects if omitted.'),
      command: z.string().optional().describe('Shell command to run. Use {{key}} to interpolate stored results from previous calls.'),
      timeout: z.number().optional().describe('Timeout in seconds (default 30)'),
      script: z.string().optional().describe('Multi-line script content. Sent as temp file via SFTP then executed.'),
      label: z.string().optional().describe('Short label for the operation. Max 60 chars.'),
      format: z.enum(['text', 'json']).optional().describe('Output format. "json" returns structured {node, ok, code, ms, stdout, stderr} for programmatic parsing.'),
      retry: z.number().optional().describe('Retry N times on failure (with 1s delay between). Default 0.'),
      assert: z.string().optional().describe('Grep pattern to assert in stdout. If not found, returns error. Use for validation in agentic chains.'),
      store_as: z.string().optional().describe('Store trimmed stdout under this key. Retrieve in subsequent calls via {{key}} in command.'),
      via_vpn: z.string().optional().describe('Route command through VPN. Values: "mullvad" (auto), "mullvad:se" (country), "openvpn:/path/to.conf", "wg:wg-vpn". Connects VPN before exec, verifies IP changed.'),
    },
    async ({ node, command, timeout, script, label, format, retry, assert: assertPattern, store_as, via_vpn }) => {
      if (!command && !script) {
        return fail('either command or script is required');
      }
      const nodeId = node ?? 'contabo';
      const timeoutSec = timeout ?? 30;
      const maxRetries = retry ?? 0;
      const useJson = format === 'json';

      let resolvedCmd = command;
      if (resolvedCmd) {
        resolvedCmd = resolvedCmd.replace(/\{\{(\w+)\}\}/g, (_, key) => resultStore.get(key) ?? `{{${key}}}`);
      }

      let effectiveCmd: string;
      if (script) {
        const tmpFile = `/tmp/.ow-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
        effectiveCmd = `cat << 'OMNIWIRE_SCRIPT_EOF' > ${tmpFile}\n${script}\nOMNIWIRE_SCRIPT_EOF\nchmod +x ${tmpFile} && timeout ${timeoutSec} ${tmpFile}; _rc=$?; rm -f ${tmpFile}; exit $_rc`;
      } else {
        effectiveCmd = timeoutSec < 300
          ? `timeout ${timeoutSec} bash -c '${resolvedCmd!.replace(/'/g, "'\\''")}'`
          : resolvedCmd!;
      }

      // VPN routing: wrap command in network namespace so only THIS command goes through VPN.
      // The mesh (WireGuard, SSH) stays on the real interface — zero disruption.
      if (via_vpn) {
        effectiveCmd = buildVpnWrappedCmd(via_vpn, effectiveCmd);
      }

      const blocked = checkCommandSafety(effectiveCmd);
      if (blocked) return fail(blocked);

      let result = await manager.exec(nodeId, effectiveCmd);
      auditLog.push({ ts: Date.now(), tool: 'exec', node: nodeId, command: resolvedCmd ?? 'script', code: result.code, durationMs: result.durationMs });
      if (auditLog.length > 1000) auditLog.shift();
      // Persist audit to CyberBase every 10 execs
      if (auditLog.length % 10 === 0) cb('audit', `batch-${Date.now()}`, JSON.stringify(auditLog.slice(-10)));

      for (let attempt = 0; attempt < maxRetries && result.code !== 0; attempt++) {
        await new Promise((r) => setTimeout(r, 1000));
        result = await manager.exec(nodeId, effectiveCmd);
        auditLog.push({ ts: Date.now(), tool: 'exec', node: nodeId, command: resolvedCmd ?? 'script', code: result.code, durationMs: result.durationMs });
        if (auditLog.length > 1000) auditLog.shift();
      }

      if (store_as && result.code === 0) {
        resultStore.set(store_as, result.stdout.trim());
        cb('store', store_as, result.stdout.trim());  // persist to CyberBase
      }

      if (assertPattern && result.code === 0) {
        const regex = new RegExp(assertPattern);
        if (!regex.test(result.stdout)) {
          return useJson
            ? okBrief(JSON.stringify({ node: nodeId, ok: false, code: -2, ms: result.durationMs, error: `assert failed: /${assertPattern}/ not found in stdout`, stdout: result.stdout.slice(0, 500) }))
            : fail(`${nodeId} assert failed: /${assertPattern}/ not found`);
        }
      }

      return useJson
        ? fmtJson(nodeId, result, label ?? undefined)
        : ok(nodeId, result.durationMs, fmtExecOutput(result, timeoutSec), label ?? undefined);
    }
  );

  // --- Tool 2: omniwire_broadcast ---
  server.tool(
    'omniwire_broadcast',
    'Execute a command on all online mesh nodes simultaneously.',
    {
      command: z.string().describe('Shell command to run on all nodes. Supports {{key}} interpolation.'),
      nodes: z.array(z.string()).optional().describe('Subset of nodes to target. All online nodes if omitted.'),
      format: z.enum(['text', 'json']).optional().describe('Output format.'),
    },
    async ({ command, nodes: targetNodes, format }) => {
      const resolved = command.replace(/\{\{(\w+)\}\}/g, (_, key) => resultStore.get(key) ?? `{{${key}}}`);
      const results = targetNodes
        ? await manager.execOn(targetNodes, resolved)
        : await manager.execAll(resolved);
      return format === 'json' ? multiResultJson(results) : multiResult(results);
    }
  );

  // --- Tool 3: omniwire_mesh_status ---
  server.tool(
    'omniwire_mesh_status',
    'Get health and resource usage for all mesh nodes.',
    {},
    async () => {
      const statuses = await manager.getAllStatus();
      const lines = statuses.map((s) => {
        const status = s.online ? '+' : '-';
        const lat = s.latencyMs !== null ? `${s.latencyMs}ms` : '--';
        const mem = s.memUsedPct !== null ? `${s.memUsedPct.toFixed(0)}%` : '--';
        const disk = s.diskUsedPct !== null ? `${s.diskUsedPct.toFixed(0)}%` : '--';
        const role = NODE_ROLES[s.nodeId] ?? '';
        return `${status} ${s.nodeId.padEnd(10)} ${role.padEnd(8)} lat=${lat.padStart(5)}  mem=${mem.padStart(4)}  disk=${disk.padStart(4)}  load=${s.loadAvg ?? '--'}`;
      });
      return okBrief(lines.join('\n'));
    }
  );

  // --- Tool 4: omniwire_node_info ---
  server.tool(
    'omniwire_node_info',
    'Get detailed information about a specific node.',
    { node: z.string().describe('Node id') },
    async ({ node }) => {
      const meshNode = findNode(node);
      if (!meshNode) return fail(`unknown node: ${node}`);
      const s = await manager.getNodeStatus(meshNode.id);
      const role = NODE_ROLES[meshNode.id] ?? '';
      const status = s.online ? 'ONLINE' : 'OFFLINE';
      const text = `${meshNode.id} (${meshNode.alias})  ${status}
role=${role}  host=${meshNode.host}:${meshNode.port}  os=${meshNode.os}
lat=${s.latencyMs ?? '--'}ms  up=${s.uptime ?? '--'}  load=${s.loadAvg ?? '--'}  mem=${s.memUsedPct !== null ? `${s.memUsedPct.toFixed(1)}%` : '--'}  disk=${s.diskUsedPct !== null ? `${s.diskUsedPct.toFixed(0)}%` : '--'}
tags: ${meshNode.tags.join(', ')}`;
      return okBrief(text);
    }
  );

  // --- Tool 5: omniwire_read_file ---
  server.tool(
    'omniwire_read_file',
    'Read a file from any mesh node. Default node: contabo (storage).',
    {
      path: z.string().describe('Absolute file path, or "node:/path" format'),
      node: z.string().optional().describe('Node id. Defaults to contabo.'),
      max_lines: z.number().optional().describe('Max lines to return (default: all)'),
    },
    async ({ path, node, max_lines }) => {
      let nodeId = node ?? getDefaultNodeForTask('storage');
      let filePath = path;
      const parsed = parseMeshPath(path);
      if (parsed) { nodeId = parsed.nodeId; filePath = parsed.path; }

      try {
        let content = await transfer.readFile(nodeId, filePath);
        if (max_lines) {
          content = content.split('\n').slice(0, max_lines).join('\n');
        }
        return okBrief(trim(content));
      } catch (e) {
        return fail((e as Error).message);
      }
    }
  );

  // --- Tool 6: omniwire_write_file ---
  server.tool(
    'omniwire_write_file',
    'Write/create a file on any mesh node. Default: contabo.',
    {
      path: z.string().describe('Absolute file path, or "node:/path" format'),
      content: z.string().describe('File content to write'),
      node: z.string().optional().describe('Node id. Defaults to contabo.'),
    },
    async ({ path, content, node }) => {
      let nodeId = node ?? getDefaultNodeForTask('storage');
      let filePath = path;
      const parsed = parseMeshPath(path);
      if (parsed) { nodeId = parsed.nodeId; filePath = parsed.path; }

      try {
        await transfer.writeFile(nodeId, filePath, content);
        return okBrief(`${nodeId}:${filePath} written`);
      } catch (e) {
        return fail((e as Error).message);
      }
    }
  );

  // --- Tool 7: omniwire_transfer_file ---
  server.tool(
    'omniwire_transfer_file',
    'Copy a file or directory between mesh nodes using fast TCP transfer (netcat/tar or aria2c).',
    {
      src: z.string().describe('Source path in "node:/path" format'),
      dst: z.string().describe('Destination path in "node:/path" format'),
      mode: z.enum(['netcat-tar', 'aria2c', 'ssh-pipe']).optional().describe('Transfer mode. Auto-selects based on file size if omitted.'),
    },
    async ({ src, dst, mode }) => {
      const srcParsed = parseMeshPath(src);
      const dstParsed = parseMeshPath(dst);
      if (!srcParsed) return fail(`invalid source: ${src} (use node:/path)`);
      if (!dstParsed) return fail(`invalid dest: ${dst} (use node:/path)`);

      try {
        const r = await transfer.transfer(
          srcParsed.nodeId, srcParsed.path,
          dstParsed.nodeId, dstParsed.path,
          mode ? { mode } : undefined
        );
        const size = r.bytesTransferred > 1048576
          ? `${(r.bytesTransferred / 1048576).toFixed(1)}MB`
          : `${(r.bytesTransferred / 1024).toFixed(0)}KB`;
        return okBrief(`${srcParsed.nodeId} -> ${dstParsed.nodeId}  ${size} via ${r.mode}  ${t(r.durationMs)}  ${r.speedMBps.toFixed(1)}MB/s`);
      } catch (e) {
        return fail((e as Error).message);
      }
    }
  );

  // --- Tool 8: omniwire_list_files ---
  server.tool(
    'omniwire_list_files',
    'List files in a directory on any mesh node.',
    {
      path: z.string().describe('Directory path, or "node:/path" format'),
      node: z.string().optional().describe('Node id. Defaults to contabo.'),
    },
    async ({ path, node }) => {
      let nodeId = node ?? getDefaultNodeForTask('storage');
      let dirPath = path;
      const parsed = parseMeshPath(path);
      if (parsed) { nodeId = parsed.nodeId; dirPath = parsed.path; }

      try {
        const entries = await transfer.readdir(nodeId, dirPath);
        const text = entries.map((e) =>
          `${e.isDirectory ? 'd' : '-'} ${e.permissions.padEnd(11)} ${String(e.size).padStart(10)} ${e.modified} ${e.name}`
        ).join('\n');
        return okBrief(trim(text || '(empty)'));
      } catch (e) {
        return fail((e as Error).message);
      }
    }
  );

  // --- Tool 9: omniwire_find_files ---
  server.tool(
    'omniwire_find_files',
    'Search for files across mesh nodes by name pattern.',
    {
      pattern: z.string().describe('File name pattern (glob)'),
      path: z.string().optional().describe('Search root path (default: /)'),
      nodes: z.array(z.string()).optional().describe('Nodes to search. All if omitted.'),
      max_results: z.number().optional().describe('Max results per node (default 20)'),
    },
    async ({ pattern, path, nodes: targetNodes, max_results }) => {
      const searchPath = path ?? '/';
      const limit = max_results ?? 20;
      const escaped = pattern.replace(/'/g, "'\\''");
      const pathEscaped = searchPath.replace(/'/g, "'\\''");
      const cmd = `find '${pathEscaped}' -name '${escaped}' -type f 2>/dev/null | head -${limit}`;

      const results = targetNodes
        ? await manager.execOn(targetNodes, cmd)
        : await manager.execAll(cmd);

      return multiResult(results);
    }
  );

  // --- Tool 10: omniwire_tail_log ---
  server.tool(
    'omniwire_tail_log',
    'Read the last N lines of a log file on a node.',
    {
      path: z.string().describe('Log file path'),
      node: z.string().describe('Node id'),
      lines: z.number().optional().describe('Number of lines (default 50)'),
    },
    async ({ path, node, lines }) => {
      const n = lines ?? 50;
      const result = await manager.exec(node, `tail -n ${n} "${path}"`);
      if (result.code !== 0) return fail(result.stderr);
      return ok(node, result.durationMs, result.stdout, `tail ${path}`);
    }
  );

  // --- Tool 11: omniwire_process_list ---
  server.tool(
    'omniwire_process_list',
    'List processes across mesh nodes, optionally filtered.',
    {
      filter: z.string().optional().describe('Process name filter'),
      nodes: z.array(z.string()).optional().describe('Nodes to query'),
    },
    async ({ filter, nodes: targetNodes }) => {
      const escaped = filter ? filter.replace(/'/g, "'\\''") : '';
      const cmd = filter
        ? `ps aux | head -1; ps aux | grep -iF '${escaped}' | grep -v grep | head -20`
        : 'ps aux --sort=-%cpu | head -15';

      const results = targetNodes
        ? await manager.execOn(targetNodes, cmd)
        : await manager.execAll(cmd);

      return multiResult(results);
    }
  );

  // --- Tool 12: omniwire_disk_usage ---
  server.tool(
    'omniwire_disk_usage',
    'Show disk usage across mesh nodes.',
    { nodes: z.array(z.string()).optional() },
    async ({ nodes: targetNodes }) => {
      const cmd = 'df -h / /home 2>/dev/null | grep -v tmpfs';
      const results = targetNodes
        ? await manager.execOn(targetNodes, cmd)
        : await manager.execAll(cmd);

      return multiResult(results);
    }
  );

  // --- Tool 13: omniwire_install_package ---
  server.tool(
    'omniwire_install_package',
    'Install a package on a node via apt, npm, or pip.',
    {
      package_name: z.string().describe('Package name'),
      manager_type: z.enum(['apt', 'npm', 'pip']).optional().describe('Package manager (default: apt)'),
      node: z.string().describe('Target node'),
    },
    async ({ package_name, manager_type, node }) => {
      const pm = manager_type ?? 'apt';
      let cmd: string;
      switch (pm) {
        case 'apt': cmd = `DEBIAN_FRONTEND=noninteractive apt-get install -y ${package_name}`; break;
        case 'npm': cmd = `npm install -g ${package_name}`; break;
        case 'pip': cmd = `pip install ${package_name}`; break;
      }
      const result = await manager.exec(node, cmd);
      return result.code === 0
        ? okBrief(`${node} installed ${package_name} (${pm})`)
        : fail(`${node} ${pm} install ${package_name}: ${result.stderr.split('\n').slice(-3).join('\n')}`);
    }
  );

  // --- Tool 14: omniwire_service_control ---
  server.tool(
    'omniwire_service_control',
    'Control systemd services on a node.',
    {
      service: z.string().describe('Service name'),
      action: z.enum(['start', 'stop', 'restart', 'status', 'enable', 'disable']).describe('Action'),
      node: z.string().describe('Target node'),
    },
    async ({ service, action, node }) => {
      const result = await manager.exec(node, `systemctl ${action} ${service}`);
      if (result.code !== 0) return fail(`${node} systemctl ${action} ${service}: ${result.stderr}`);
      const body = result.stdout || 'ok';
      return okBrief(`${node} ${action} ${service}: ${body.split('\n').slice(0, 5).join('\n')}`);
    }
  );

  // --- Tool 15: omniwire_docker ---
  server.tool(
    'omniwire_docker',
    'Run docker commands on a node. Default: contabo.',
    {
      command: z.string().describe('Docker subcommand (ps, run, logs, images, etc.)'),
      node: z.string().optional().describe('Node id (default: contabo)'),
    },
    async ({ command, node }) => {
      const nodeId = node ?? 'contabo';
      const result = await manager.exec(nodeId, `docker ${command}`);
      if (result.code !== 0) return fail(`${nodeId} docker ${command}: ${result.stderr}`);
      return ok(nodeId, result.durationMs, result.stdout, `docker ${command.split(' ')[0]}`);
    }
  );

  // --- Tool 16: omniwire_open_browser ---
  server.tool(
    'omniwire_open_browser',
    'Open a URL in a browser. Default: thinkpad (has GPU + display).',
    {
      url: z.string().describe('URL to open'),
      node: z.string().optional().describe('Node to open on (default: thinkpad)'),
    },
    async ({ url, node }) => {
      const result = await openBrowser(manager, url, node);
      return okBrief(result);
    }
  );

  // --- Tool 17: omniwire_port_forward ---
  server.tool(
    'omniwire_port_forward',
    'Create an SSH port forward tunnel to a node.',
    {
      node: z.string().describe('Node to tunnel to'),
      local_port: z.number().describe('Local port'),
      remote_port: z.number().describe('Remote port'),
      remote_host: z.string().optional().describe('Remote host (default: 127.0.0.1)'),
      action: z.enum(['create', 'list', 'close']).optional().describe('Action (default: create)'),
      tunnel_id: z.string().optional().describe('Tunnel ID (for close action)'),
    },
    async ({ node, local_port, remote_port, remote_host, action, tunnel_id }) => {
      const act = action ?? 'create';
      if (act === 'list') {
        const list = tunnels.list();
        if (list.length === 0) return okBrief('no active tunnels');
        return okBrief(list.map((tn) => `${tn.id}  :${tn.localPort} -> ${tn.nodeId}:${tn.remotePort}`).join('\n'));
      }
      if (act === 'close' && tunnel_id) {
        tunnels.close(tunnel_id);
        return okBrief(`closed ${tunnel_id}`);
      }
      try {
        const info = await tunnels.create(node, local_port, remote_port, remote_host);
        return okBrief(`tunnel ${info.id}  :${info.localPort} -> ${info.nodeId}:${info.remotePort}`);
      } catch (e) {
        return fail((e as Error).message);
      }
    }
  );

  // --- Tool 18: omniwire_deploy ---
  server.tool(
    'omniwire_deploy',
    'Deploy a file from one node to multiple destination nodes.',
    {
      src_node: z.string().describe('Source node'),
      src_path: z.string().describe('Source file path'),
      dst_path: z.string().describe('Destination path on target nodes'),
      dst_nodes: z.array(z.string()).optional().describe('Target nodes (default: all remote)'),
    },
    async ({ src_node, src_path, dst_path, dst_nodes }) => {
      const targets = (dst_nodes ?? remoteNodes().map((n) => n.id)).filter((dst) => dst !== src_node);

      const settled = await Promise.allSettled(
        targets.map(async (dst) => {
          const r = await transfer.transfer(src_node, src_path, dst, dst_path);
          return { dst, speed: r.speedMBps };
        })
      );

      const lines = settled.map((s, i) =>
        s.status === 'fulfilled'
          ? `  ${s.value.dst}  ok  ${s.value.speed.toFixed(1)}MB/s`
          : `  ${targets[i]}  FAIL  ${(s.reason as Error).message}`
      );

      return okBrief(`deploy ${src_path} -> ${dst_path}\n${lines.join('\n')}`);
    }
  );

  // --- Tool 19: omniwire_kernel ---
  server.tool(
    'omniwire_kernel',
    'Kernel-level operations: dmesg, sysctl, modprobe, lsmod, strace, perf.',
    {
      operation: z.enum(['dmesg', 'sysctl', 'modprobe', 'lsmod', 'strace', 'perf']).describe('Kernel operation'),
      args: z.string().optional().describe('Arguments for the operation'),
      node: z.string().describe('Target node'),
    },
    async ({ operation, args, node }) => {
      const output = await kernelExec(manager, node, operation, args ?? '');
      return ok(node, 0, output, `${operation} ${args ?? ''}`.trim());
    }
  );

  // --- Tool 20: omniwire_stream ---
  server.tool(
    'omniwire_stream',
    'Capture streaming command output (for tail -f, watch, etc.) for a limited duration.',
    {
      command: z.string().describe('Command to stream'),
      node: z.string().describe('Target node'),
      duration: z.number().optional().describe('Max duration in seconds (default 10)'),
    },
    async ({ command, node, duration }) => {
      const maxMs = (duration ?? 10) * 1000;
      let output = '';
      const ac = new AbortController();
      const timer = setTimeout(() => ac.abort(), maxMs);

      try {
        await realtime.stream(node, command, (chunk) => { output += chunk; }, ac.signal);
      } catch {
        // stream ended
      } finally {
        clearTimeout(timer);
      }

      return ok(node, maxMs, output, `stream`);
    }
  );

  // --- Tool 21: omniwire_shell ---
  server.tool(
    'omniwire_shell',
    'Run a sequence of commands in a persistent shell session (preserves cwd, env vars).',
    {
      commands: z.array(z.string()).describe('Commands to run in order'),
      node: z.string().describe('Target node'),
    },
    async ({ commands, node }) => {
      const session = await shells.openShell(node);
      const channel = shells.getChannel(session.id)!;

      // Set up ALL listeners BEFORE writing commands to avoid race conditions
      let output = '';
      channel.on('data', (data: Buffer) => { output += data.toString(); });
      const closePromise = new Promise<void>((resolve) => {
        channel.on('close', () => resolve());
        setTimeout(resolve, 15000);
      });

      // Small delay for login banner
      await new Promise((r) => setTimeout(r, 100));

      for (const cmd of commands) {
        channel.write(`${cmd}\n`);
      }
      channel.write('exit\n');

      await closePromise;
      shells.closeShell(session.id);
      return ok(node, 0, output, `shell (${commands.length} cmds)`);
    }
  );

  // --- Tool 22: omniwire_live_monitor ---
  server.tool(
    'omniwire_live_monitor',
    'Watch system metrics across all nodes (snapshot).',
    {
      metric: z.enum(['cpu', 'memory', 'disk', 'network', 'all']).optional().describe('Metric type (default: all)'),
    },
    async ({ metric }) => {
      const m = metric ?? 'all';
      let cmd: string;
      switch (m) {
        case 'cpu': cmd = "top -bn1 | head -5"; break;
        case 'memory': cmd = "free -h"; break;
        case 'disk': cmd = "df -h / /home 2>/dev/null"; break;
        case 'network': cmd = "ss -s"; break;
        case 'all': cmd = "echo '=CPU=' && top -bn1 | head -5 && echo '=MEM=' && free -h && echo '=DISK=' && df -h / 2>/dev/null"; break;
      }

      const results = await manager.execAll(cmd);
      return multiResult(results);
    }
  );

  // --- Tool 23: omniwire_run (compact multi-line script execution) ---
  server.tool(
    'omniwire_run',
    'Execute a multi-line script on a node. The script is written to a temp file and executed, keeping tool call display compact. Use this instead of omniwire_exec for Python scripts, heredocs, or any command >3 lines.',
    {
      node: z.string().optional().describe('Target node id. Default: contabo.'),
      interpreter: z.enum(['bash', 'python3', 'python', 'node', 'sh']).optional().describe('Script interpreter (default: bash)'),
      script: z.string().describe('Script content (multi-line)'),
      label: z.string().optional().describe('Short description shown in tool call UI (max 60 chars)'),
      timeout: z.number().optional().describe('Timeout in seconds (default 30)'),
      env: z.record(z.string(), z.string()).optional().describe('Environment variables to set'),
    },
    async ({ node, interpreter, script, label, timeout, env }) => {
      const nodeId = node ?? 'contabo';
      const interp = interpreter ?? 'bash';
      const timeoutSec = timeout ?? 30;
      const tmpFile = `/tmp/.ow-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;

      // Build env prefix
      const envPrefix = env
        ? Object.entries(env).map(([k, v]: [string, string]) => `export ${k}='${v.replace(/'/g, "'\\''")}'`).join('; ') + '; '
        : '';

      // Write script via heredoc, execute with interpreter, clean up
      const wrappedCmd = [
        `cat << 'OMNIWIRE_EOF' > ${tmpFile}`,
        script,
        'OMNIWIRE_EOF',
        `chmod +x ${tmpFile}`,
        `${envPrefix}timeout ${timeoutSec} ${interp} ${tmpFile}`,
        `_rc=$?; rm -f ${tmpFile}; exit $_rc`,
      ].join('\n');

      const result = await manager.exec(nodeId, wrappedCmd);
      return ok(nodeId, result.durationMs, fmtExecOutput(result, timeoutSec), label ?? `${interp} script`);
    }
  );

  // --- Tool 25: omniwire_batch (chaining-aware multi-command) ---
  server.tool(
    'omniwire_batch',
    'Run multiple commands in a single tool call. Supports chaining (sequential with {{prev}} interpolation), abort-on-fail, store_as, and JSON output. Use this to reduce agentic round-trips.',
    {
      commands: z.array(z.object({
        node: z.string().optional().describe('Node id (default: contabo)'),
        command: z.string().describe('Command. Use {{key}} to interpolate stored results, {{prev}} for previous command stdout.'),
        label: z.string().optional().describe('Short label'),
        store_as: z.string().optional().describe('Store stdout under this key for later use'),
      })).describe('Array of commands to execute'),
      parallel: z.boolean().optional().describe('Run in parallel (default: true). Set false for sequential chaining with {{prev}}.'),
      abort_on_fail: z.boolean().optional().describe('Stop executing remaining commands if one fails (sequential mode only). Default: false.'),
      format: z.enum(['text', 'json']).optional().describe('Output format.'),
    },
    async ({ commands, parallel, abort_on_fail, format }) => {
      const runParallel = parallel !== false;
      const useJson = format === 'json';

      if (runParallel) {
        const execute = async (item: { node?: string; command: string; label?: string; store_as?: string }) => {
          const nodeId = item.node ?? 'contabo';
          const resolved = item.command.replace(/\{\{(\w+)\}\}/g, (_, key) => resultStore.get(key) ?? `{{${key}}}`);
          const result = await manager.exec(nodeId, resolved);
          if (item.store_as && result.code === 0) resultStore.set(item.store_as, result.stdout.trim());
          if (useJson) {
            return JSON.stringify({ node: nodeId, ok: result.code === 0, code: result.code, ms: result.durationMs, label: item.label, stdout: result.stdout.slice(0, 2000), ...(result.stderr ? { stderr: result.stderr.slice(0, 500) } : {}) });
          }
          const lbl = item.label ?? item.command.slice(0, 40);
          const body = result.code === 0
            ? (result.stdout || '(empty)').split('\n').slice(0, 20).join('\n')
            : `exit ${result.code}: ${result.stderr.split('\n').slice(0, 5).join('\n')}`;
          return `-- ${nodeId} > ${lbl}  ${t(result.durationMs)}\n${body}`;
        };
        const results = await Promise.all(commands.map(execute));
        return useJson ? okBrief(`[${results.join(',')}]`) : okBrief(trim(results.join('\n\n')));
      }

      // Sequential with chaining
      const outputs: string[] = [];
      let prevStdout = '';
      for (const item of commands) {
        const nodeId = item.node ?? 'contabo';
        let resolved = item.command.replace(/\{\{prev\}\}/g, prevStdout.trim());
        resolved = resolved.replace(/\{\{(\w+)\}\}/g, (_, key) => resultStore.get(key) ?? `{{${key}}}`);
        const result = await manager.exec(nodeId, resolved);
        prevStdout = result.stdout;
        if (item.store_as && result.code === 0) resultStore.set(item.store_as, result.stdout.trim());

        if (useJson) {
          outputs.push(JSON.stringify({ node: nodeId, ok: result.code === 0, code: result.code, ms: result.durationMs, label: item.label, stdout: result.stdout.slice(0, 2000), ...(result.stderr ? { stderr: result.stderr.slice(0, 500) } : {}) }));
        } else {
          const lbl = item.label ?? item.command.slice(0, 40);
          const body = result.code === 0
            ? (result.stdout || '(empty)').split('\n').slice(0, 20).join('\n')
            : `exit ${result.code}: ${result.stderr.split('\n').slice(0, 5).join('\n')}`;
          outputs.push(`-- ${nodeId} > ${lbl}  ${t(result.durationMs)}\n${body}`);
        }

        if (abort_on_fail && result.code !== 0) {
          const msg = useJson ? `[${outputs.join(',')}]` : outputs.join('\n\n') + '\n\n-- ABORTED (command failed)';
          return okBrief(trim(msg));
        }
      }
      return useJson ? okBrief(`[${outputs.join(',')}]`) : okBrief(trim(outputs.join('\n\n')));
    }
  );

  // --- Tool 26: omniwire_update ---
  server.tool(
    'omniwire_update',
    'Check for updates and self-update OmniWire to the latest version.',
    {
      check_only: z.boolean().optional().describe('Only check for updates without installing (default: false)'),
    },
    async ({ check_only }) => {
      const { checkForUpdate, selfUpdate, getSystemInfo } = await import('../update.js');
      const info = getSystemInfo();

      if (check_only) {
        const check = await checkForUpdate();
        return check.updateAvailable
          ? okBrief(`update available: ${check.current} -> ${check.latest}  (${info.platform}/${info.arch})`)
          : okBrief(`up to date (${check.current})  ${info.platform}/${info.arch}`);
      }

      const result = await selfUpdate();
      return okBrief(`${result.message}  ${info.platform}/${info.arch}`);
    }
  );

  // --- Tool 27: omniwire_cron ---
  server.tool(
    'omniwire_cron',
    'Manage cron jobs on a node. List, add, or remove scheduled tasks.',
    {
      action: z.enum(['list', 'add', 'remove']).describe('Action'),
      node: z.string().describe('Target node'),
      schedule: z.string().optional().describe('Cron schedule (e.g., "0 */6 * * *"). Required for add.'),
      command: z.string().optional().describe('Command to schedule. Required for add.'),
      pattern: z.string().optional().describe('Pattern to match for remove (removes matching lines from crontab)'),
    },
    async ({ action, node, schedule, command, pattern }) => {
      if (action === 'list') {
        const result = await manager.exec(node, 'crontab -l 2>/dev/null || echo "(no crontab)"');
        return ok(node, result.durationMs, result.stdout, 'crontab');
      }
      if (action === 'add') {
        if (!schedule || !command) return fail('schedule and command required for add');
        const escaped = command.replace(/'/g, "'\\''");
        const result = await manager.exec(node, `(crontab -l 2>/dev/null; echo '${schedule} ${escaped}') | sort -u | crontab -`);
        return result.code === 0
          ? okBrief(`${node} cron added: ${schedule} ${command.slice(0, 50)}`)
          : fail(`${node} cron add: ${result.stderr}`);
      }
      if (action === 'remove' && pattern) {
        const esc = pattern.replace(/'/g, "'\\''");
        const result = await manager.exec(node, `crontab -l 2>/dev/null | grep -v '${esc}' | crontab -`);
        return result.code === 0
          ? okBrief(`${node} cron removed matching: ${pattern}`)
          : fail(`${node} cron remove: ${result.stderr}`);
      }
      return fail('invalid action/params');
    }
  );

  // --- Tool 28: omniwire_env ---
  server.tool(
    'omniwire_env',
    'Get or set environment variables on a node (persistent via /etc/environment).',
    {
      action: z.enum(['get', 'set', 'list']).describe('Action'),
      node: z.string().describe('Target node'),
      key: z.string().optional().describe('Variable name'),
      value: z.string().optional().describe('Variable value (for set)'),
    },
    async ({ action, node, key, value }) => {
      if (action === 'list') {
        const result = await manager.exec(node, 'cat /etc/environment 2>/dev/null; echo "---"; env | sort | head -40');
        return ok(node, result.durationMs, result.stdout, 'env list');
      }
      if (action === 'get' && key) {
        const result = await manager.exec(node, `bash -c 'source /etc/environment 2>/dev/null; echo "\${${key}}"'`);
        const val = result.stdout.trim();
        return okBrief(`${node} ${key}=${val || '(unset)'}`);
      }
      if (action === 'set' && key && value !== undefined) {
        const esc = value.replace(/'/g, "'\\''");
        const result = await manager.exec(node, `grep -q '^${key}=' /etc/environment 2>/dev/null && sed -i 's|^${key}=.*|${key}=${esc}|' /etc/environment || echo '${key}=${esc}' >> /etc/environment`);
        return result.code === 0
          ? okBrief(`${node} ${key}=${value.slice(0, 40)} (persisted)`)
          : fail(`${node} env set: ${result.stderr}`);
      }
      return fail('invalid action/params');
    }
  );

  // --- Tool 29: omniwire_network ---
  server.tool(
    'omniwire_network',
    'Network diagnostics: ping, traceroute, dns lookup, open ports, bandwidth test.',
    {
      action: z.enum(['ping', 'traceroute', 'dns', 'ports', 'speed', 'connections']).describe('Diagnostic action'),
      node: z.string().describe('Node to run from'),
      target: z.string().optional().describe('Target host/IP (required for ping, traceroute, dns)'),
    },
    async ({ action, node, target }) => {
      let cmd: string;
      switch (action) {
        case 'ping':
          if (!target) return fail('target required');
          cmd = `ping -c 4 -W 2 ${target} 2>&1 | tail -5`;
          break;
        case 'traceroute':
          if (!target) return fail('target required');
          cmd = `traceroute -m 15 -w 2 ${target} 2>&1 | head -20`;
          break;
        case 'dns':
          if (!target) return fail('target required');
          cmd = `dig +short ${target} 2>/dev/null || nslookup ${target} 2>&1 | tail -5`;
          break;
        case 'ports':
          cmd = 'ss -tlnp | head -30';
          break;
        case 'speed':
          cmd = "curl -s -o /dev/null -w 'download: %{speed_download} bytes/s\\ntime: %{time_total}s\\n' https://speed.cloudflare.com/__down?bytes=10000000 2>&1";
          break;
        case 'connections':
          cmd = 'ss -s';
          break;
      }
      const result = await manager.exec(node, cmd);
      return ok(node, result.durationMs, result.code === 0 ? result.stdout : result.stderr, `net ${action}`);
    }
  );

  // --- Tool 30: omniwire_vpn ---
  server.tool(
    'omniwire_vpn',
    'Manage VPN on mesh nodes (Mullvad/OpenVPN/WireGuard/Tailscale). Mesh-safe: split-tunnel or namespace isolation. Mullvad advanced: multi-hop, DAITA, quantum-resistant tunnels, DNS-over-HTTPS, obfuscation, kill-switch.',
    {
      action: z.enum([
        'connect', 'disconnect', 'status', 'list', 'ip', 'rotate', 'full-on', 'full-off',
        'multihop', 'daita', 'quantum', 'obfuscation', 'dns', 'killswitch', 'split-tunnel', 'relay-set', 'account', 'settings'
      ]).describe('Core: connect/disconnect/status/list/ip/rotate/full-on/full-off. Mullvad: multihop (on/off/entry:exit), daita (on/off), quantum (on/off), obfuscation (on/off/udp2tcp/shadowsocks), dns (custom/default), killswitch (on/off), split-tunnel (add/remove/list pid), relay-set (set relay constraints), account (info), settings (show all)'),
      node: z.string().optional().describe('Node to manage VPN on (default: contabo)'),
      provider: z.enum(['mullvad', 'openvpn', 'wireguard', 'tailscale']).optional().describe('VPN provider (default: auto-detect)'),
      server: z.string().optional().describe('Server/relay. Mullvad: country (se), city (se-got), relay (se-got-wg-001). OpenVPN: config path. WireGuard: interface. Tailscale: exit node.'),
      config: z.string().optional().describe('Config file path or feature value. For multihop: "entry:exit" (e.g. "se:us"). For dns: IP address. For obfuscation: "udp2tcp" or "shadowsocks". For split-tunnel: PID or process name.'),
    },
    async ({ action, node, provider, server: vpnServer, config }) => {
      const nodeId = node ?? 'contabo';

      // Auto-detect provider (prefer mullvad > tailscale > openvpn > wireguard)
      const detectCmd = 'command -v mullvad >/dev/null && echo mullvad || (command -v tailscale >/dev/null && echo tailscale || (command -v openvpn >/dev/null && echo openvpn || (command -v wg >/dev/null && echo wireguard || echo none)))';
      const detected = provider ?? (await manager.exec(nodeId, detectCmd)).stdout.trim() as any;

      if (action === 'ip') {
        const result = await manager.exec(nodeId, 'curl -s --max-time 5 https://am.i.mullvad.net/json 2>/dev/null || curl -s --max-time 5 https://ipinfo.io/json 2>/dev/null || curl -s --max-time 5 https://ifconfig.me');
        return ok(nodeId, result.durationMs, result.stdout, 'public IP');
      }

      if (detected === 'mullvad') {
        // Mullvad split-tunnel: excludes mesh interfaces (wg0, tailscale0) from VPN routing.
        // SSH connections over WireGuard mesh are preserved — only non-mesh traffic goes through Mullvad.
        const splitSetup = 'mullvad split-tunnel set state on 2>/dev/null; mullvad lan set allow 2>/dev/null;';
        switch (action) {
          case 'connect': {
            let relay = '';
            if (vpnServer) {
              relay = `mullvad relay set location ${vpnServer} && `;
            } else if (config === 'fastest' || config === 'auto' || !config) {
              // Mullvad auto-selects lowest latency relay by default when no location is set
              // Just ensure WireGuard protocol for best speed
              relay = 'mullvad relay set tunnel-protocol wireguard 2>/dev/null; ';
            }
            const result = await manager.exec(nodeId, `${splitSetup} ${relay}mullvad connect && sleep 2 && mullvad status && echo "---relay---" && mullvad relay get | head -3 && echo "---ip---" && curl -s --max-time 5 https://am.i.mullvad.net/json 2>/dev/null | grep -E "ip|country|city|mullvad_exit" && echo "---mesh---" && ip route get 10.10.0.1 2>/dev/null | head -1`);
            return ok(nodeId, result.durationMs, result.stdout, `mullvad connect${vpnServer ? ` ${vpnServer}` : ' (auto-fastest)'}`);
          }
          case 'disconnect': {
            const result = await manager.exec(nodeId, 'mullvad disconnect && mullvad status');
            return ok(nodeId, result.durationMs, result.stdout, 'mullvad disconnect');
          }
          case 'status': {
            const result = await manager.exec(nodeId, 'mullvad status && echo "---split-tunnel---" && mullvad split-tunnel get 2>/dev/null && echo "---public-ip---" && curl -s --max-time 5 https://am.i.mullvad.net/json 2>/dev/null | grep -E "ip|country|mullvad"');
            return ok(nodeId, result.durationMs, result.stdout, 'mullvad status');
          }
          case 'list': {
            const result = await manager.exec(nodeId, 'mullvad relay list 2>&1 | head -60');
            return ok(nodeId, result.durationMs, result.stdout, 'mullvad relays');
          }
          case 'rotate': {
            const result = await manager.exec(nodeId, `${splitSetup} mullvad disconnect && sleep 1 && mullvad relay set tunnel-protocol wireguard && mullvad connect && sleep 2 && mullvad status && echo "---ip---" && curl -s --max-time 5 https://am.i.mullvad.net/json | grep -E "ip|country|mullvad_exit"`);
            return ok(nodeId, result.durationMs, result.stdout, 'mullvad rotate');
          }
          case 'multihop': {
            // Multi-hop: traffic enters at one relay, exits at another. config = "entry:exit" e.g. "se:us"
            if (!config && !vpnServer) {
              // Toggle or show status
              const result = await manager.exec(nodeId, 'mullvad tunnel get | grep -i multihop');
              return ok(nodeId, result.durationMs, result.stdout, 'mullvad multihop status');
            }
            const toggle = config === 'off' ? 'off' : 'on';
            let cmd = `mullvad tunnel set wireguard --multihop=${toggle}`;
            if (toggle === 'on' && config && config.includes(':')) {
              const [entry, exit] = config.split(':');
              cmd += ` && mullvad relay set location ${exit} && mullvad relay set tunnel wireguard entry-location ${entry}`;
            } else if (vpnServer && toggle === 'on') {
              cmd += ` && mullvad relay set location ${vpnServer}`;
            }
            cmd += ' && mullvad status';
            const result = await manager.exec(nodeId, cmd);
            return ok(nodeId, result.durationMs, result.stdout, `mullvad multihop ${toggle}`);
          }
          case 'daita': {
            // DAITA: Defence Against AI-guided Traffic Analysis — pads packets to hide traffic patterns
            const toggle = config === 'off' ? 'off' : 'on';
            const result = await manager.exec(nodeId, `mullvad tunnel set wireguard --daita=${toggle} 2>&1 && mullvad tunnel get | grep -i daita && mullvad status`);
            return ok(nodeId, result.durationMs, result.stdout, `mullvad daita ${toggle}`);
          }
          case 'quantum': {
            // Quantum-resistant tunneling: post-quantum key exchange on WireGuard
            const toggle = config === 'off' ? 'off' : 'on';
            const result = await manager.exec(nodeId, `mullvad tunnel set wireguard --quantum-resistant=${toggle} 2>&1 && mullvad tunnel get | grep -i quantum && mullvad status`);
            return ok(nodeId, result.durationMs, result.stdout, `mullvad quantum ${toggle}`);
          }
          case 'obfuscation': {
            // Obfuscation: bypass DPI. Modes: auto, off, udp2tcp, shadowsocks
            const mode = config ?? 'auto';
            const result = await manager.exec(nodeId, `mullvad obfuscation set mode ${mode} 2>&1 && mullvad obfuscation get && mullvad status`);
            return ok(nodeId, result.durationMs, result.stdout, `mullvad obfuscation ${mode}`);
          }
          case 'dns': {
            // Custom DNS: set DNS server or reset to default (Mullvad DNS)
            if (!config || config === 'default') {
              const result = await manager.exec(nodeId, 'mullvad dns set default 2>&1 && mullvad dns get');
              return ok(nodeId, result.durationMs, result.stdout, 'mullvad dns default');
            }
            // config = IP address or "content-blockers" for Mullvad's ad/tracker blocking DNS
            const cmd = config === 'adblock'
              ? 'mullvad dns set custom --block-ads --block-trackers --block-malware 2>&1 && mullvad dns get'
              : `mullvad dns set custom ${config} 2>&1 && mullvad dns get`;
            const result = await manager.exec(nodeId, cmd);
            return ok(nodeId, result.durationMs, result.stdout, `mullvad dns ${config}`);
          }
          case 'killswitch': {
            // Kill switch: block all traffic if VPN disconnects
            const toggle = config === 'off' ? 'off' : 'on';
            const blockWhen = toggle === 'on' ? 'always' : 'only-when-connected';
            const result = await manager.exec(nodeId, `mullvad always-require-vpn set ${blockWhen} 2>&1 && mullvad always-require-vpn get && mullvad lan set allow`);
            return ok(nodeId, result.durationMs, result.stdout, `mullvad killswitch ${toggle}`);
          }
          case 'split-tunnel': {
            // Split tunnel: exclude specific apps/PIDs from VPN
            if (!config || config === 'list') {
              const result = await manager.exec(nodeId, 'mullvad split-tunnel get 2>&1');
              return ok(nodeId, result.durationMs, result.stdout, 'mullvad split-tunnel list');
            }
            if (config.startsWith('add:')) {
              const pid = config.slice(4);
              const result = await manager.exec(nodeId, `mullvad split-tunnel add ${pid} 2>&1 && mullvad split-tunnel get`);
              return ok(nodeId, result.durationMs, result.stdout, `mullvad split-tunnel add ${pid}`);
            }
            if (config.startsWith('remove:') || config.startsWith('del:')) {
              const pid = config.slice(config.indexOf(':') + 1);
              const result = await manager.exec(nodeId, `mullvad split-tunnel delete ${pid} 2>&1 && mullvad split-tunnel get`);
              return ok(nodeId, result.durationMs, result.stdout, `mullvad split-tunnel remove ${pid}`);
            }
            // Toggle state
            const toggle = config === 'off' ? 'off' : 'on';
            const result = await manager.exec(nodeId, `mullvad split-tunnel set state ${toggle} 2>&1 && mullvad split-tunnel get`);
            return ok(nodeId, result.durationMs, result.stdout, `mullvad split-tunnel ${toggle}`);
          }
          case 'relay-set': {
            // Set relay constraints: protocol, location, custom lists
            if (!config && !vpnServer) {
              const result = await manager.exec(nodeId, 'mullvad relay get 2>&1');
              return ok(nodeId, result.durationMs, result.stdout, 'mullvad relay config');
            }
            const loc = vpnServer ?? '';
            let cmd = '';
            if (loc) cmd += `mullvad relay set location ${loc}; `;
            if (config === 'wireguard' || config === 'wg') cmd += 'mullvad relay set tunnel-protocol wireguard; ';
            if (config === 'openvpn') cmd += 'mullvad relay set tunnel-protocol openvpn; ';
            if (config === 'any') cmd += 'mullvad relay set tunnel-protocol any; ';
            cmd += 'mullvad relay get && mullvad status';
            const result = await manager.exec(nodeId, cmd);
            return ok(nodeId, result.durationMs, result.stdout, `mullvad relay ${loc || config || 'get'}`);
          }
          case 'account': {
            const result = await manager.exec(nodeId, 'mullvad account get 2>&1');
            return ok(nodeId, result.durationMs, result.stdout, 'mullvad account');
          }
          case 'settings': {
            const result = await manager.exec(nodeId, 'mullvad status && echo "===tunnel===" && mullvad tunnel get && echo "===relay===" && mullvad relay get && echo "===dns===" && mullvad dns get && echo "===obfuscation===" && mullvad obfuscation get && echo "===split-tunnel===" && mullvad split-tunnel get 2>/dev/null && echo "===killswitch===" && mullvad always-require-vpn get 2>/dev/null');
            return ok(nodeId, result.durationMs, result.stdout, 'mullvad all settings');
          }
        }
      }

      if (detected === 'openvpn') {
        const configPath = config ?? vpnServer ?? '/etc/openvpn/client.conf';
        switch (action) {
          case 'connect': {
            const result = await manager.exec(nodeId, `openvpn --config "${configPath}" --daemon --log /tmp/openvpn.log && sleep 3 && ip addr show tun0 2>/dev/null | grep inet && curl -s --max-time 5 https://ifconfig.me`);
            return ok(nodeId, result.durationMs, result.stdout, 'openvpn connect');
          }
          case 'disconnect': {
            const result = await manager.exec(nodeId, 'pkill openvpn 2>/dev/null; sleep 1; pgrep openvpn >/dev/null && echo "still running" || echo "disconnected"');
            return ok(nodeId, result.durationMs, result.stdout, 'openvpn disconnect');
          }
          case 'status': {
            const result = await manager.exec(nodeId, 'pgrep -a openvpn 2>/dev/null || echo "not running"; ip addr show tun0 2>/dev/null | grep inet || echo "no tunnel"; tail -5 /tmp/openvpn.log 2>/dev/null');
            return ok(nodeId, result.durationMs, result.stdout, 'openvpn status');
          }
          case 'list': {
            const result = await manager.exec(nodeId, 'ls /etc/openvpn/*.conf /etc/openvpn/*.ovpn /etc/openvpn/client/*.conf /etc/openvpn/client/*.ovpn 2>/dev/null || echo "no configs found"');
            return ok(nodeId, result.durationMs, result.stdout, 'openvpn configs');
          }
          case 'rotate': {
            const result = await manager.exec(nodeId, `pkill openvpn 2>/dev/null; sleep 1; openvpn --config "${configPath}" --daemon --log /tmp/openvpn.log && sleep 3 && curl -s --max-time 5 https://ifconfig.me`);
            return ok(nodeId, result.durationMs, result.stdout, 'openvpn rotate');
          }
        }
      }

      if (detected === 'wireguard') {
        const iface = vpnServer ?? 'wg-vpn';
        switch (action) {
          case 'connect': {
            const result = await manager.exec(nodeId, `wg-quick up ${iface} 2>&1 && sleep 1 && wg show ${iface} | head -10 && curl -s --max-time 5 https://ifconfig.me`);
            return ok(nodeId, result.durationMs, result.stdout, `wg up ${iface}`);
          }
          case 'disconnect': {
            const result = await manager.exec(nodeId, `wg-quick down ${iface} 2>&1`);
            return ok(nodeId, result.durationMs, result.stdout, `wg down ${iface}`);
          }
          case 'status': {
            const result = await manager.exec(nodeId, 'wg show all 2>/dev/null || echo "no WireGuard interfaces"');
            return ok(nodeId, result.durationMs, result.stdout, 'wg status');
          }
          case 'list': {
            const result = await manager.exec(nodeId, 'ls /etc/wireguard/*.conf 2>/dev/null | sed "s|/etc/wireguard/||;s|\\.conf||" || echo "no configs"');
            return ok(nodeId, result.durationMs, result.stdout, 'wg interfaces');
          }
          case 'rotate': {
            const result = await manager.exec(nodeId, `wg-quick down ${iface} 2>/dev/null; sleep 1; wg-quick up ${iface} 2>&1 && sleep 1 && curl -s --max-time 5 https://ifconfig.me`);
            return ok(nodeId, result.durationMs, result.stdout, `wg rotate ${iface}`);
          }
        }
      }

      if (detected === 'tailscale') {
        switch (action) {
          case 'connect': {
            const exitNode = vpnServer ? `--exit-node=${vpnServer}` : '';
            const result = await manager.exec(nodeId, `tailscale up --accept-routes ${exitNode} 2>&1 && sleep 2 && tailscale status | head -15`);
            return ok(nodeId, result.durationMs, result.stdout, `tailscale connect${vpnServer ? ` via ${vpnServer}` : ''}`);
          }
          case 'disconnect': {
            const result = await manager.exec(nodeId, 'tailscale up --exit-node= 2>&1 && tailscale status | head -5');
            return ok(nodeId, result.durationMs, result.stdout, 'tailscale clear exit-node');
          }
          case 'status': {
            const result = await manager.exec(nodeId, 'tailscale status 2>&1 && echo "---ip---" && tailscale ip -4 2>/dev/null && echo "---exit---" && tailscale exit-node status 2>/dev/null');
            return ok(nodeId, result.durationMs, result.stdout, 'tailscale status');
          }
          case 'list': {
            const result = await manager.exec(nodeId, 'tailscale exit-node list 2>&1 | head -40');
            return ok(nodeId, result.durationMs, result.stdout, 'tailscale exit nodes');
          }
          case 'rotate': {
            const result = await manager.exec(nodeId, `tailscale up --exit-node= 2>/dev/null; sleep 1; ${vpnServer ? `tailscale up --exit-node=${vpnServer}` : 'tailscale up'} 2>&1 && sleep 2 && curl -s --max-time 5 https://ifconfig.me`);
            return ok(nodeId, result.durationMs, result.stdout, 'tailscale rotate');
          }
          case 'full-on': {
            const exitNode = vpnServer ?? '';
            if (!exitNode) return fail('server param required for full-on (tailscale exit node hostname)');
            const result = await manager.exec(nodeId, `tailscale up --exit-node=${exitNode} --exit-node-allow-lan-access 2>&1 && sleep 2 && tailscale status | head -10 && echo "---ip---" && curl -s --max-time 5 https://ifconfig.me`);
            return ok(nodeId, result.durationMs, result.stdout, `tailscale full-on via ${exitNode}`);
          }
          case 'full-off': {
            const result = await manager.exec(nodeId, 'tailscale up --exit-node= 2>&1 && tailscale status | head -5');
            return ok(nodeId, result.durationMs, result.stdout, 'tailscale full-off');
          }
        }
      }

      // full-on / full-off: node-wide VPN with mesh route exclusions
      if (action === 'full-on') {
        if (detected === 'mullvad') {
          const relay = vpnServer ? `mullvad relay set location ${vpnServer};` : '';
          // Mullvad full mode: enable, but add route exclusions for mesh IPs
          const result = await manager.exec(nodeId,
            `${relay} mullvad lan set allow; mullvad split-tunnel set state on; mullvad connect && sleep 2 && ` +
            // Preserve ALL mesh routes: wg0 (main mesh), wg1 (B2B), tailscale0 (TS networks)
            `ip route add 10.10.0.0/24 dev wg0 2>/dev/null; ` +     // WG mesh
            `ip route add 10.20.0.0/24 dev wg1 2>/dev/null; ` +     // WG B2B
            `ip route add 100.64.0.0/10 dev tailscale0 2>/dev/null; ` +  // Tailscale CGNAT range
            `mullvad status && echo "---mesh-check---" && ping -c1 -W2 10.10.0.1 2>/dev/null && echo "mesh: OK" || echo "mesh: WARN"`
          );
          return ok(nodeId, result.durationMs, result.stdout, 'mullvad full-on (mesh preserved)');
        }
        if (detected === 'openvpn') {
          const configPath = config ?? vpnServer ?? '/etc/openvpn/client.conf';
          // OpenVPN with route-nopull + specific routes — keeps mesh alive
          const result = await manager.exec(nodeId,
            `openvpn --config "${configPath}" --daemon --log /tmp/openvpn-full.log ` +
            `--route-nopull --route 0.0.0.0 0.0.0.0 vpn_gateway ` +
            `--route 10.10.0.0 255.255.255.0 net_gateway ` +  // wg0 mesh
            `--route 10.20.0.0 255.255.255.0 net_gateway ` +  // wg1 B2B
            `--route 100.64.0.0 255.192.0.0 net_gateway ` +   // tailscale CGNAT
            `&& sleep 4 && ip addr show tun0 2>/dev/null | grep inet && curl -s --max-time 5 https://ifconfig.me && ` +
            `echo "---mesh---" && ping -c1 -W2 10.10.0.1 2>/dev/null && echo "mesh: OK" || echo "mesh: WARN"`
          );
          return ok(nodeId, result.durationMs, result.stdout, 'openvpn full-on (mesh preserved)');
        }
        return fail(`full-on not supported for ${detected}. Use mullvad, openvpn, or tailscale.`);
      }

      if (action === 'full-off') {
        if (detected === 'mullvad') {
          const result = await manager.exec(nodeId, 'mullvad disconnect && mullvad status');
          return ok(nodeId, result.durationMs, result.stdout, 'mullvad full-off');
        }
        if (detected === 'openvpn') {
          const result = await manager.exec(nodeId, 'pkill openvpn 2>/dev/null; sleep 1; echo "disconnected" && curl -s --max-time 5 https://ifconfig.me');
          return ok(nodeId, result.durationMs, result.stdout, 'openvpn full-off');
        }
        return fail(`full-off not supported for ${detected}`);
      }

      return fail(`No VPN provider found on ${nodeId}. Install mullvad, tailscale, openvpn, or wireguard.`);
    }
  );

  // --- Tool 31: omniwire_firewall ---
  server.tool(
    'omniwire_firewall',
    'Firewall engine for mesh nodes. Hardens external-facing security while keeping mesh traffic at full speed. Uses nftables (zero-copy, kernel-level). Mesh interfaces (wg0, wg1, tailscale0) are always whitelisted.',
    {
      action: z.enum([
        'status', 'harden', 'unharden', 'rule-add', 'rule-del', 'rule-list',
        'rate-limit', 'geo-block', 'port-knock', 'whitelist', 'blacklist',
        'preset', 'flush', 'save', 'restore', 'audit', 'ban', 'unban'
      ]).describe('status=show rules, harden=apply security preset, unharden=remove hardening, rule-add/del/list=manual rules, rate-limit=configure, geo-block=by country, port-knock=setup, whitelist/blacklist=IP lists, preset=named configs, flush=clear all, save/restore=persist, audit=show blocked traffic log, ban/unban=IP'),
      node: z.string().optional().describe('Target node (default: contabo). Use "all" for all nodes.'),
      rule: z.string().optional().describe('Rule spec. For rule-add: "input tcp 8080 accept", "input tcp 22 drop src=1.2.3.4", "output udp 53 accept". For rate-limit: "ssh 5/min", "http 100/sec". For geo-block: "CN,RU,KP" (ISO codes). For port-knock: "7000,8000,9000->22". For ban/unban: IP address. For preset: "paranoid", "server", "minimal", "pentest".'),
      config: z.string().optional().describe('Additional config. For whitelist/blacklist: IP or CIDR. For preset: override options.'),
    },
    async ({ action, node, rule, config }) => {
      const targetNodes = node === 'all' ? manager.getOnlineNodes().filter(n => n !== 'windows') : [node ?? 'contabo'];

      // Mesh-safe preamble: ALWAYS allow mesh traffic before any hardening
      const meshWhitelist = [
        'nft add rule inet omniwire input iifname "wg0" accept 2>/dev/null',
        'nft add rule inet omniwire input iifname "wg1" accept 2>/dev/null',
        'nft add rule inet omniwire input iifname "tailscale0" accept 2>/dev/null',
        'nft add rule inet omniwire input ip saddr 10.10.0.0/24 accept 2>/dev/null',
        'nft add rule inet omniwire input ip saddr 10.20.0.0/24 accept 2>/dev/null',
        'nft add rule inet omniwire input ip saddr 100.64.0.0/10 accept 2>/dev/null',
        'nft add rule inet omniwire output oifname "wg0" accept 2>/dev/null',
        'nft add rule inet omniwire output oifname "wg1" accept 2>/dev/null',
        'nft add rule inet omniwire output oifname "tailscale0" accept 2>/dev/null',
      ].join('; ');

      const ensureTable = 'nft list table inet omniwire >/dev/null 2>&1 || nft add table inet omniwire; ' +
        'nft list chain inet omniwire input >/dev/null 2>&1 || nft add chain inet omniwire input { type filter hook input priority 0\\; policy accept\\; }; ' +
        'nft list chain inet omniwire output >/dev/null 2>&1 || nft add chain inet omniwire output { type filter hook output priority 0\\; policy accept\\; }; ' +
        'nft list chain inet omniwire forward >/dev/null 2>&1 || nft add chain inet omniwire forward { type filter hook forward priority 0\\; policy accept\\; }';

      if (action === 'status') {
        const results = await Promise.all(targetNodes.map(async (n) => {
          const r = await manager.exec(n, 'nft list table inet omniwire 2>/dev/null || echo "no omniwire table"; echo "---iptables---"; iptables -L -n --line-numbers 2>/dev/null | head -30');
          return { ...r, nodeId: n };
        }));
        return multiResult(results);
      }

      if (action === 'harden') {
        const preset = rule ?? 'server';
        const presets: Record<string, string> = {
          // Server preset: SSH rate-limit, drop invalid, allow established, block common attack ports
          server: [
            ensureTable,
            meshWhitelist,
            // Allow loopback
            'nft add rule inet omniwire input iifname "lo" accept',
            // Allow established/related
            'nft add rule inet omniwire input ct state established,related accept',
            // Drop invalid
            'nft add rule inet omniwire input ct state invalid drop',
            // SSH rate limit: 5 new connections per minute per source IP
            'nft add rule inet omniwire input tcp dport 22 ct state new meter ssh-meter { ip saddr limit rate 5/minute } accept',
            'nft add rule inet omniwire input tcp dport 22 ct state new drop',
            // Allow HTTP/HTTPS
            'nft add rule inet omniwire input tcp dport { 80, 443 } accept',
            // Allow DNS
            'nft add rule inet omniwire input udp dport 53 accept',
            'nft add rule inet omniwire input tcp dport 53 accept',
            // Allow ICMP (ping) rate-limited
            'nft add rule inet omniwire input icmp type echo-request limit rate 10/second accept',
            'nft add rule inet omniwire input icmp type echo-request drop',
            // Drop port scans (SYN without ACK to closed ports)
            'nft add rule inet omniwire input tcp flags syn / syn,ack,fin,rst ct state new log prefix "SYN-SCAN: " limit rate 5/minute drop',
            // Block common attack ports
            'nft add rule inet omniwire input tcp dport { 23, 445, 1433, 1521, 3306, 3389, 5432, 6379, 9200, 27017 } drop',
            // Log and drop everything else
            'nft add rule inet omniwire input log prefix "FW-DROP: " limit rate 10/minute drop',
            // Set default policy to drop
            'nft chain inet omniwire input { policy drop\\; }',
          ].join('; '),

          // Paranoid: everything blocked except mesh + SSH
          paranoid: [
            ensureTable,
            'nft flush chain inet omniwire input 2>/dev/null',
            meshWhitelist,
            'nft add rule inet omniwire input iifname "lo" accept',
            'nft add rule inet omniwire input ct state established,related accept',
            'nft add rule inet omniwire input ct state invalid drop',
            'nft add rule inet omniwire input tcp dport 22 ct state new meter ssh-paranoid { ip saddr limit rate 3/minute } accept',
            'nft add rule inet omniwire input tcp dport 22 ct state new drop',
            'nft add rule inet omniwire input icmp type echo-request limit rate 2/second accept',
            'nft add rule inet omniwire input log prefix "PARANOID-DROP: " limit rate 5/minute drop',
            'nft chain inet omniwire input { policy drop\\; }',
          ].join('; '),

          // Minimal: just rate-limiting and invalid drop, no policy change
          minimal: [
            ensureTable,
            meshWhitelist,
            'nft add rule inet omniwire input ct state invalid drop',
            'nft add rule inet omniwire input tcp dport 22 ct state new meter ssh-min { ip saddr limit rate 10/minute } accept',
            'nft add rule inet omniwire input icmp type echo-request limit rate 20/second accept',
          ].join('; '),

          // Pentest: allow all outbound, harden inbound, keep common tool ports open
          pentest: [
            ensureTable,
            meshWhitelist,
            'nft add rule inet omniwire input iifname "lo" accept',
            'nft add rule inet omniwire input ct state established,related accept',
            'nft add rule inet omniwire input ct state invalid drop',
            'nft add rule inet omniwire input tcp dport 22 ct state new meter ssh-pt { ip saddr limit rate 5/minute } accept',
            'nft add rule inet omniwire input tcp dport 22 ct state new drop',
            // Allow callback ports for reverse shells during pentests
            'nft add rule inet omniwire input tcp dport { 80, 443, 4444, 8080, 8443, 9001 } accept',
            'nft add rule inet omniwire input udp dport { 53, 69 } accept',
            // Allow all outbound (needed for scanning)
            'nft add rule inet omniwire output accept',
            'nft add rule inet omniwire input log prefix "PT-DROP: " limit rate 10/minute drop',
            'nft chain inet omniwire input { policy drop\\; }',
          ].join('; '),
        };

        const presetCmd = presets[preset];
        if (!presetCmd) return fail(`Unknown preset: ${preset}. Available: server, paranoid, minimal, pentest`);

        const results = await Promise.all(targetNodes.map(async (n) => {
          const r = await manager.exec(n, presetCmd + '; echo "---status---"; nft list chain inet omniwire input 2>/dev/null | wc -l');
          return { ...r, nodeId: n };
        }));
        return multiResult(results);
      }

      if (action === 'unharden') {
        const results = await Promise.all(targetNodes.map(async (n) => {
          const r = await manager.exec(n, 'nft flush table inet omniwire 2>/dev/null; nft chain inet omniwire input { policy accept\\; } 2>/dev/null; nft chain inet omniwire output { policy accept\\; } 2>/dev/null; nft chain inet omniwire forward { policy accept\\; } 2>/dev/null; echo "firewall relaxed"');
          return { ...r, nodeId: n };
        }));
        return multiResult(results);
      }

      if (action === 'rule-add' && rule) {
        // Parse: "input tcp 8080 accept" or "input tcp 22 drop src=1.2.3.4"
        const parts = rule.split(/\s+/);
        const chain = parts[0] ?? 'input'; // input/output/forward
        const proto = parts[1] ?? 'tcp';
        const port = parts[2] ?? '';
        const verdict = parts[3] ?? 'accept';
        const srcMatch = rule.match(/src=(\S+)/);

        let nftCmd = `${ensureTable}; ${meshWhitelist}; nft add rule inet omniwire ${chain}`;
        if (proto) nftCmd += ` ${proto} dport ${port}`;
        if (srcMatch) nftCmd += ` ip saddr ${srcMatch[1]}`;
        nftCmd += ` ${verdict}`;

        const results = await Promise.all(targetNodes.map(async (n) => {
          const r = await manager.exec(n, nftCmd);
          return { ...r, nodeId: n };
        }));
        return multiResult(results);
      }

      if (action === 'rule-del' && rule) {
        // rule = handle number or pattern
        const results = await Promise.all(targetNodes.map(async (n) => {
          const r = await manager.exec(n, `nft -a list chain inet omniwire input 2>/dev/null | grep "${rule}" | awk '{print $NF}' | while read h; do nft delete rule inet omniwire input handle "$h"; done; echo "deleted rules matching: ${rule}"`);
          return { ...r, nodeId: n };
        }));
        return multiResult(results);
      }

      if (action === 'rule-list') {
        const results = await Promise.all(targetNodes.map(async (n) => {
          const r = await manager.exec(n, 'nft -a list table inet omniwire 2>/dev/null || echo "no rules"');
          return { ...r, nodeId: n };
        }));
        return multiResult(results);
      }

      if (action === 'rate-limit' && rule) {
        // rule = "ssh 5/min" or "http 100/sec"
        const [service, rate] = rule.split(/\s+/);
        const portMap: Record<string, string> = { ssh: '22', http: '80', https: '443', dns: '53', smtp: '25' };
        const port = portMap[service] ?? service;
        const nftCmd = `${ensureTable}; ${meshWhitelist}; nft add rule inet omniwire input tcp dport ${port} ct state new meter rate-${service} { ip saddr limit rate ${rate} } accept; nft add rule inet omniwire input tcp dport ${port} ct state new drop`;

        const results = await Promise.all(targetNodes.map(async (n) => {
          const r = await manager.exec(n, nftCmd);
          return { ...r, nodeId: n };
        }));
        return multiResult(results);
      }

      if (action === 'geo-block' && rule) {
        // rule = "CN,RU,KP" — uses ipset with country IP ranges
        const countries = rule.toUpperCase().split(',').map(c => c.trim());
        const geoScript = countries.map(cc =>
          `curl -sf "https://www.ipdeny.com/ipblocks/data/aggregated/${cc.toLowerCase()}-aggregated-zone" 2>/dev/null | while read cidr; do nft add element inet omniwire geoblock { "$cidr" } 2>/dev/null; done`
        ).join('; ');

        const cmd = `${ensureTable}; nft add set inet omniwire geoblock { type ipv4_addr\\; flags interval\\; } 2>/dev/null; ${geoScript}; nft add rule inet omniwire input ip saddr @geoblock drop 2>/dev/null; echo "geo-blocked: ${countries.join(',')}"`;

        const results = await Promise.all(targetNodes.map(async (n) => {
          const r = await manager.exec(n, cmd);
          return { ...r, nodeId: n };
        }));
        return multiResult(results);
      }

      if (action === 'port-knock' && rule) {
        // rule = "7000,8000,9000->22" — knock sequence to open SSH
        const match = rule.match(/^([\d,]+)->(\d+)$/);
        if (!match) return fail('Format: "port1,port2,port3->target_port" e.g. "7000,8000,9000->22"');
        const ports = match[1].split(',');
        const target = match[2];

        // Uses nftables recent match simulation with sets and timeouts
        const knockScript = `${ensureTable};
nft add set inet omniwire knock1 { type ipv4_addr\\; timeout 10s\\; } 2>/dev/null;
nft add set inet omniwire knock2 { type ipv4_addr\\; timeout 10s\\; } 2>/dev/null;
nft add set inet omniwire knock3 { type ipv4_addr\\; timeout 15s\\; } 2>/dev/null;
nft add rule inet omniwire input tcp dport ${ports[0]} add @knock1 { ip saddr } drop 2>/dev/null;
nft add rule inet omniwire input ip saddr @knock1 tcp dport ${ports[1]} add @knock2 { ip saddr } drop 2>/dev/null;
nft add rule inet omniwire input ip saddr @knock2 tcp dport ${ports[2]} add @knock3 { ip saddr } drop 2>/dev/null;
nft add rule inet omniwire input ip saddr @knock3 tcp dport ${target} accept 2>/dev/null;
echo "port-knock configured: ${ports.join(' -> ')} -> port ${target}"`;

        const results = await Promise.all(targetNodes.map(async (n) => {
          const r = await manager.exec(n, knockScript.replace(/\n/g, ' '));
          return { ...r, nodeId: n };
        }));
        return multiResult(results);
      }

      if (action === 'whitelist' && (rule || config)) {
        const ip = rule ?? config!;
        const cmd = `${ensureTable}; ${meshWhitelist}; nft add rule inet omniwire input ip saddr ${ip} accept; echo "whitelisted ${ip}"`;
        const results = await Promise.all(targetNodes.map(async (n) => {
          const r = await manager.exec(n, cmd);
          return { ...r, nodeId: n };
        }));
        return multiResult(results);
      }

      if (action === 'blacklist' && (rule || config)) {
        const ip = rule ?? config!;
        const cmd = `${ensureTable}; nft insert rule inet omniwire input ip saddr ${ip} drop; echo "blacklisted ${ip}"`;
        const results = await Promise.all(targetNodes.map(async (n) => {
          const r = await manager.exec(n, cmd);
          return { ...r, nodeId: n };
        }));
        return multiResult(results);
      }

      if (action === 'ban' && rule) {
        const cmd = `${ensureTable}; nft insert rule inet omniwire input ip saddr ${rule} counter drop; nft insert rule inet omniwire output ip daddr ${rule} counter drop; echo "banned ${rule} (in+out)"`;
        const results = await Promise.all(targetNodes.map(async (n) => {
          const r = await manager.exec(n, cmd);
          return { ...r, nodeId: n };
        }));
        return multiResult(results);
      }

      if (action === 'unban' && rule) {
        const cmd = `nft -a list table inet omniwire 2>/dev/null | grep "${rule}" | awk '{print $NF}' | while read h; do for chain in input output forward; do nft delete rule inet omniwire "$chain" handle "$h" 2>/dev/null; done; done; echo "unbanned ${rule}"`;
        const results = await Promise.all(targetNodes.map(async (n) => {
          const r = await manager.exec(n, cmd);
          return { ...r, nodeId: n };
        }));
        return multiResult(results);
      }

      if (action === 'flush') {
        const results = await Promise.all(targetNodes.map(async (n) => {
          const r = await manager.exec(n, 'nft flush table inet omniwire 2>/dev/null; echo "flushed all rules"');
          return { ...r, nodeId: n };
        }));
        return multiResult(results);
      }

      if (action === 'save') {
        const results = await Promise.all(targetNodes.map(async (n) => {
          const r = await manager.exec(n, 'nft list table inet omniwire > /etc/omniwire/firewall.nft 2>/dev/null && echo "saved to /etc/omniwire/firewall.nft" || echo "no rules to save"');
          return { ...r, nodeId: n };
        }));
        return multiResult(results);
      }

      if (action === 'restore') {
        const results = await Promise.all(targetNodes.map(async (n) => {
          const r = await manager.exec(n, 'nft -f /etc/omniwire/firewall.nft 2>/dev/null && echo "restored" || echo "no saved rules"');
          return { ...r, nodeId: n };
        }));
        return multiResult(results);
      }

      if (action === 'audit') {
        const results = await Promise.all(targetNodes.map(async (n) => {
          const r = await manager.exec(n, 'journalctl -k --no-pager -n 50 2>/dev/null | grep -E "FW-DROP|SYN-SCAN|PARANOID|PT-DROP" | tail -20 || dmesg | grep -E "FW-DROP|SYN-SCAN" | tail -20 || echo "no blocked traffic logged"');
          return { ...r, nodeId: n };
        }));
        return multiResult(results);
      }

      if (action === 'preset') {
        return okBrief('Available presets:\n- server: SSH rate-limit, drop invalid, block DB ports, allow HTTP/HTTPS\n- paranoid: block everything except mesh + SSH (3/min)\n- minimal: just rate-limiting, no policy change\n- pentest: harden inbound, allow outbound + callback ports (4444, 8080, etc)');
      }

      return fail('Invalid action or missing params');
    }
  );

  // --- Tool 32: omniwire_cookies ---
  server.tool(
    'omniwire_cookies',
    'Cookie management across mesh nodes. Import/export/convert between JSON, Header string, and Netscape cookies.txt formats. Sync cookies between nodes. Extract from Chrome/Firefox.',
    {
      action: z.enum(['get', 'set', 'export', 'import', 'convert', 'sync', 'extract', 'clear', 'list', 'cyberbase-get', 'cyberbase-set', '1password-get', '1password-set']).describe('get/set/export/import/convert/sync/extract/clear/list + cyberbase-get/set (PostgreSQL), 1password-get/set (op CLI)'),
      node: z.string().optional().describe('Node (default: contabo)'),
      domain: z.string().optional().describe('Domain filter (e.g. "github.com")'),
      format: z.enum(['json', 'header', 'netscape']).optional().describe('json=[{name,value,domain,...}], header="name=val; name2=val2", netscape=cookies.txt (curl/wget)'),
      cookies: z.string().optional().describe('Cookie data for set/import/convert. Format auto-detected.'),
      file: z.string().optional().describe('File path (default: /tmp/.omniwire-cookies/<domain>.txt)'),
      target_format: z.enum(['json', 'header', 'netscape']).optional().describe('Target format for convert'),
      dst_nodes: z.array(z.string()).optional().describe('Destination nodes for sync'),
    },
    async ({ action, node, domain, format: fmt, cookies: cookieData, file, target_format, dst_nodes }) => {
      const nodeId = node ?? 'contabo';
      const cookieDir = '/tmp/.omniwire-cookies';
      const cookieFile = file ?? (domain ? `${cookieDir}/${domain.replace(/\./g, '_')}.txt` : `${cookieDir}/all.txt`);

      const jsonToHeader = `python3 -c "import json,sys;c=json.load(sys.stdin);c=c if isinstance(c,list) else [c];print('; '.join(f\\"{x['name']}={x['value']}\\" for x in c))"`;
      const jsonToNetscape = `python3 -c "import json,sys;c=json.load(sys.stdin);c=c if isinstance(c,list) else [c];print('# Netscape HTTP Cookie File');[print(f\\"{x.get('domain','.')}\t{'TRUE' if x.get('domain','').startswith('.') else 'FALSE'}\t{x.get('path','/')}\t{'TRUE' if x.get('secure') else 'FALSE'}\t{x.get('expires',0)}\t{x['name']}\t{x['value']}\\") for x in c]"`;
      const headerToJson = `python3 -c "import json,sys;h=sys.stdin.read().strip();print(json.dumps([{'name':p.split('=',1)[0].strip(),'value':p.split('=',1)[1].strip(),'domain':'','path':'/','secure':False} for p in h.split(';') if '=' in p],indent=2))"`;
      const netscapeToJson = `python3 -c "import json,sys;cookies=[];[cookies.append({'domain':p[0],'path':p[2],'secure':p[3]=='TRUE','expires':int(p[4]) if p[4].isdigit() else 0,'name':p[5],'value':p[6]}) for line in sys.stdin if not line.startswith('#') and line.strip() for p in [line.strip().split('\t')] if len(p)>=7];print(json.dumps(cookies,indent=2))"`;

      const detectFmt = (d: string) => {
        const t = d.trim();
        if (t.startsWith('[') || t.startsWith('{')) return 'json';
        if (t.includes('\t') && (t.includes('TRUE') || t.includes('FALSE'))) return 'netscape';
        return 'header';
      };

      if (action === 'list') {
        const r = await manager.exec(nodeId, `mkdir -p ${cookieDir}; ls -la ${cookieDir}/ 2>/dev/null | tail -n +2 || echo "(empty)"`);
        return ok(nodeId, r.durationMs, r.stdout, 'cookie files');
      }
      if (action === 'get') {
        const r = await manager.exec(nodeId, `cat "${cookieFile}" 2>/dev/null || echo "no cookies at ${cookieFile}"`);
        return ok(nodeId, r.durationMs, r.stdout, `cookies ${domain ?? 'all'}`);
      }
      if (action === 'set' && cookieData) {
        const inFmt = fmt ?? detectFmt(cookieData);
        const esc = cookieData.replace(/'/g, "'\\''");
        const cmd = inFmt === 'json'
          ? `mkdir -p ${cookieDir}; echo '${esc}' > "${cookieFile}"`
          : inFmt === 'header'
            ? `mkdir -p ${cookieDir}; echo '${esc}' | ${headerToJson} > "${cookieFile}"`
            : `mkdir -p ${cookieDir}; echo '${esc}' | ${netscapeToJson} > "${cookieFile}"`;
        const r = await manager.exec(nodeId, cmd);
        return r.code === 0 ? okBrief(`Cookies saved to ${nodeId}:${cookieFile} (from ${inFmt})`) : fail(r.stderr);
      }
      if (action === 'convert' && cookieData && target_format) {
        const inFmt = fmt ?? detectFmt(cookieData);
        if (inFmt === target_format) return okBrief(cookieData);
        const esc = cookieData.replace(/'/g, "'\\''");
        const toJson = inFmt === 'header' ? `echo '${esc}' | ${headerToJson}` : inFmt === 'netscape' ? `echo '${esc}' | ${netscapeToJson}` : `echo '${esc}'`;
        const cmd = target_format === 'json' ? toJson : target_format === 'header' ? `${toJson} | ${jsonToHeader}` : `${toJson} | ${jsonToNetscape}`;
        const r = await manager.exec(nodeId, cmd);
        return ok(nodeId, r.durationMs, r.stdout, `${inFmt} → ${target_format}`);
      }
      if (action === 'export') {
        const outFmt = fmt ?? 'json';
        const cmd = outFmt === 'header' ? `cat "${cookieFile}" | ${jsonToHeader}` : outFmt === 'netscape' ? `cat "${cookieFile}" | ${jsonToNetscape}` : `cat "${cookieFile}"`;
        const r = await manager.exec(nodeId, cmd);
        return ok(nodeId, r.durationMs, r.stdout, `export ${outFmt}`);
      }
      if (action === 'import' && cookieData) {
        const inFmt = fmt ?? detectFmt(cookieData);
        const esc = cookieData.replace(/'/g, "'\\''");
        const cmd = `mkdir -p ${cookieDir}; echo '${esc}' ${inFmt !== 'json' ? `| ${inFmt === 'header' ? headerToJson : netscapeToJson}` : ''} > "${cookieFile}"`;
        const r = await manager.exec(nodeId, cmd);
        return r.code === 0 ? okBrief(`Imported to ${nodeId}:${cookieFile}`) : fail(r.stderr);
      }
      if (action === 'extract') {
        const domFilter = domain ? `WHERE host_key LIKE '%${domain}%'` : '';
        const domFilter2 = domain ? `WHERE host LIKE '%${domain}%'` : '';
        const cmd = `FOUND=0; for db in ~/.config/google-chrome/Default/Cookies ~/.config/chromium/Default/Cookies; do [ -f "$db" ] && { echo "--- Chrome: $db ---"; sqlite3 "$db" "SELECT host_key,name,value,path,expires_utc,is_secure FROM cookies ${domFilter} LIMIT 100;" 2>/dev/null; FOUND=1; }; done; for db in ~/.mozilla/firefox/*/cookies.sqlite; do [ -f "$db" ] && { echo "--- Firefox: $db ---"; sqlite3 "$db" "SELECT host,name,value,path,expiry,isSecure FROM moz_cookies ${domFilter2} LIMIT 100;" 2>/dev/null; FOUND=1; }; done; [ $FOUND -eq 0 ] && echo "No browser DBs found"`;
        const r = await manager.exec(nodeId, cmd);
        return ok(nodeId, r.durationMs, r.stdout, `extract ${domain ?? 'all'}`);
      }
      if (action === 'sync') {
        const targets = dst_nodes ?? manager.getOnlineNodes().filter(n => n !== nodeId && n !== 'windows');
        const src = await manager.exec(nodeId, `cat "${cookieFile}" 2>/dev/null`);
        if (src.code !== 0) return fail(`No cookies at ${cookieFile}`);
        const b64 = Buffer.from(src.stdout).toString('base64');

        // 1. Sync to mesh nodes
        const nodeResults = await Promise.all(targets.map(async (dst) => {
          const r = await manager.exec(dst, `mkdir -p ${cookieDir}; echo '${b64}' | base64 -d > "${cookieFile}"`);
          return { ...r, nodeId: dst };
        }));

        // 2. Sync to CyberBase (PostgreSQL on contabo)
        const domainKey = domain ?? 'all';
        const pgEscaped = src.stdout.replace(/'/g, "''");
        const cyberbaseResult = await manager.exec('contabo',
          `psql -h 127.0.0.1 -U cyberbase -d cyberbase -c "SET statement_timeout='5s'; INSERT INTO sync_items (category, key, value, updated_at) VALUES ('cookies', '${domainKey}', '${pgEscaped}', NOW()) ON CONFLICT (category, key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW();" 2>/dev/null && echo "cyberbase: synced" || echo "cyberbase: skipped (no DB)"`
        );

        // 3. Sync to 1Password (if op CLI available)
        const opResult = await manager.exec(nodeId,
          `command -v op >/dev/null 2>&1 && { ` +
            `op item get "OmniWire Cookies - ${domainKey}" --vault "CyberBase" >/dev/null 2>&1 && ` +
            `op item edit "OmniWire Cookies - ${domainKey}" --vault "CyberBase" "notesPlain=$(cat "${cookieFile}")" 2>/dev/null || ` +
            `op item create --category=SecureNote --vault="CyberBase" --title="OmniWire Cookies - ${domainKey}" "notesPlain=$(cat "${cookieFile}")" 2>/dev/null; ` +
            `echo "1password: synced"; } || echo "1password: op not available"`
        );

        const parts = nodeResults.map(r => `${r.nodeId}: ${r.code === 0 ? 'ok' : 'fail'}`);
        parts.push(cyberbaseResult.stdout.trim());
        parts.push(opResult.stdout.trim());
        return okBrief(`Cookie sync: ${parts.join(' | ')}`);
      }
      if (action === 'clear') {
        const r = await manager.exec(nodeId, `rm -f ${domain ? cookieFile : `${cookieDir}/*`} 2>/dev/null; echo "cleared"`);
        return ok(nodeId, r.durationMs, r.stdout, 'clear cookies');
      }

      if (action === 'cyberbase-get') {
        const domainKey = domain ?? 'all';
        const r = await manager.exec('contabo',
          `psql -h 127.0.0.1 -U cyberbase -d cyberbase -t -c "SET statement_timeout='5s';SELECT value FROM sync_items WHERE category='cookies' AND key='${domainKey}';" 2>/dev/null`
        );
        if (!r.stdout.trim()) return fail(`No cookies for '${domainKey}' in CyberBase`);
        return ok('contabo', r.durationMs, r.stdout.trim(), `cyberbase cookies: ${domainKey}`);
      }

      if (action === 'cyberbase-set' && cookieData) {
        const domainKey = domain ?? 'all';
        const pgEsc = cookieData.replace(/'/g, "''");
        const r = await manager.exec('contabo',
          `psql -h 127.0.0.1 -U cyberbase -d cyberbase -c "SET statement_timeout='5s'; INSERT INTO sync_items (category, key, value, updated_at) VALUES ('cookies', '${domainKey}', '${pgEsc}', NOW()) ON CONFLICT (category, key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW();" 2>/dev/null`
        );
        return r.code === 0 ? okBrief(`Cookies stored in CyberBase: ${domainKey}`) : fail(r.stderr);
      }

      if (action === '1password-get') {
        const domainKey = domain ?? 'all';
        const r = await manager.exec(nodeId,
          `op item get "OmniWire Cookies - ${domainKey}" --vault "CyberBase" --fields notesPlain 2>/dev/null || echo "not found in 1Password"`
        );
        return ok(nodeId, r.durationMs, r.stdout, `1password cookies: ${domainKey}`);
      }

      if (action === '1password-set' && cookieData) {
        const domainKey = domain ?? 'all';
        const esc = cookieData.replace(/'/g, "'\\''");
        const r = await manager.exec(nodeId,
          `command -v op >/dev/null || { echo "op CLI not installed"; exit 1; }; ` +
          `op item get "OmniWire Cookies - ${domainKey}" --vault "CyberBase" >/dev/null 2>&1 && ` +
          `op item edit "OmniWire Cookies - ${domainKey}" --vault "CyberBase" "notesPlain=${esc}" 2>/dev/null || ` +
          `op item create --category=SecureNote --vault="CyberBase" --title="OmniWire Cookies - ${domainKey}" "notesPlain=${esc}" 2>/dev/null`
        );
        return r.code === 0 ? okBrief(`Cookies stored in 1Password: ${domainKey}`) : fail(r.stderr || r.stdout);
      }

      return fail('Invalid action or missing params');
    }
  );

  // --- Tool 33: omniwire_cdp ---
  server.tool(
    'omniwire_cdp',
    'Chrome DevTools Protocol browser control on mesh nodes. Launch headless Chrome, navigate, screenshot, extract DOM/cookies, save PDF. For scraping, testing, recon.',
    {
      action: z.enum(['launch', 'navigate', 'screenshot', 'html', 'pdf', 'cookies', 'tabs', 'close', 'list']).describe('launch=start Chrome, navigate=open URL, screenshot=capture, html=dump DOM, pdf=save PDF, cookies=extract, tabs=list tabs, close=kill, list=sessions'),
      node: z.string().optional().describe('Node (default: contabo)'),
      url: z.string().optional().describe('URL for navigate/screenshot/html/pdf'),
      file: z.string().optional().describe('Output path for screenshot/pdf'),
      session_id: z.string().optional().describe('Session ID from launch'),
    },
    async ({ action, node, url, file: outFile, session_id }) => {
      const nodeId = node ?? 'contabo';
      const sdir = '/tmp/.omniwire-cdp';

      if (action === 'launch') {
        const id = `cdp-${Date.now().toString(36)}`;
        const port = 9222 + Math.floor(Math.random() * 100);
        const cmd = `mkdir -p ${sdir}; command -v google-chrome >/dev/null || command -v chromium-browser >/dev/null || { echo "chrome not installed"; exit 1; }; ` +
          `CHROME=$(command -v google-chrome || command -v chromium-browser); ` +
          `$CHROME --headless --disable-gpu --no-sandbox --remote-debugging-port=${port} --user-data-dir=${sdir}/${id} ${url ? `"${url}"` : 'about:blank'} &>/dev/null & ` +
          `echo $! > ${sdir}/${id}.pid; echo ${port} > ${sdir}/${id}.port; sleep 1; ` +
          `echo "session=${id} port=${port} pid=$(cat ${sdir}/${id}.pid)"`;
        const r = await manager.exec(nodeId, cmd);
        if (r.code === 0) resultStore.set('cdp_session', id);
        return ok(nodeId, r.durationMs, r.stdout, 'chrome launch');
      }

      const sid = session_id ?? resultStore.get('cdp_session') ?? '';

      if (action === 'navigate' && url) {
        const cmd = `PORT=$(cat ${sdir}/${sid}.port 2>/dev/null); curl -sf "http://localhost:$PORT/json/new?${encodeURIComponent(url)}" 2>/dev/null | python3 -c "import json,sys;d=json.load(sys.stdin);print(f\\"tab={d.get('id','')} url={d.get('url','')}\\")" 2>/dev/null || echo "opened ${url}"`;
        const r = await manager.exec(nodeId, cmd);
        return ok(nodeId, r.durationMs, r.stdout, `navigate`);
      }

      if (action === 'screenshot') {
        const output = outFile ?? `/tmp/screenshot-${Date.now()}.png`;
        const target = url ?? (sid ? `$(curl -sf http://localhost:$(cat ${sdir}/${sid}.port)/json/list 2>/dev/null | python3 -c "import json,sys;print(json.load(sys.stdin)[0]['url'])" 2>/dev/null)` : 'about:blank');
        const cmd = `CHROME=$(command -v google-chrome || command -v chromium-browser); $CHROME --headless --no-sandbox --disable-gpu --screenshot="${output}" --window-size=1920,1080 "${target}" 2>/dev/null && echo "saved: ${output} ($(du -h "${output}" | cut -f1))"`;
        const r = await manager.exec(nodeId, cmd);
        return ok(nodeId, r.durationMs, r.stdout, 'screenshot');
      }

      if (action === 'html') {
        const target = url ?? 'about:blank';
        const cmd = `CHROME=$(command -v google-chrome || command -v chromium-browser); $CHROME --headless --no-sandbox --disable-gpu --dump-dom "${target}" 2>/dev/null | head -200`;
        const r = await manager.exec(nodeId, cmd);
        return ok(nodeId, r.durationMs, r.stdout, 'html');
      }

      if (action === 'pdf') {
        const output = outFile ?? `/tmp/page-${Date.now()}.pdf`;
        const target = url ?? 'about:blank';
        const cmd = `CHROME=$(command -v google-chrome || command -v chromium-browser); $CHROME --headless --no-sandbox --disable-gpu --print-to-pdf="${output}" --no-pdf-header-footer "${target}" 2>/dev/null && echo "saved: ${output} ($(du -h "${output}" | cut -f1))"`;
        const r = await manager.exec(nodeId, cmd);
        return ok(nodeId, r.durationMs, r.stdout, 'pdf');
      }

      if (action === 'cookies') {
        const cmd = `find ${sdir}/${sid}/ -name "Cookies" 2>/dev/null | head -1 | xargs -I{} sqlite3 "{}" "SELECT host_key,name,value,path,expires_utc FROM cookies LIMIT 50;" 2>/dev/null || echo "no cookies DB"`;
        const r = await manager.exec(nodeId, cmd);
        return ok(nodeId, r.durationMs, r.stdout, 'cdp cookies');
      }

      if (action === 'tabs') {
        const cmd = `PORT=$(cat ${sdir}/${sid}.port 2>/dev/null); curl -sf http://localhost:$PORT/json/list 2>/dev/null | python3 -c "import json,sys;[print(f\\"{t['id'][:8]}  {t.get('url','')}\\" ) for t in json.load(sys.stdin)]" 2>/dev/null || echo "no tabs"`;
        const r = await manager.exec(nodeId, cmd);
        return ok(nodeId, r.durationMs, r.stdout, 'tabs');
      }

      if (action === 'close') {
        const cmd = `PID=$(cat ${sdir}/${sid}.pid 2>/dev/null); [ -n "$PID" ] && kill $PID 2>/dev/null && rm -rf ${sdir}/${sid}* && echo "closed ${sid}" || echo "not found"`;
        const r = await manager.exec(nodeId, cmd);
        return ok(nodeId, r.durationMs, r.stdout, 'close');
      }

      if (action === 'list') {
        const cmd = `ls ${sdir}/*.pid 2>/dev/null | while read f; do id=$(basename "$f" .pid); port=$(cat ${sdir}/$id.port 2>/dev/null); pid=$(cat "$f"); ps -p $pid >/dev/null 2>&1 && s="running" || s="dead"; echo "$id  port=$port  pid=$pid  $s"; done || echo "no sessions"`;
        const r = await manager.exec(nodeId, cmd);
        return ok(nodeId, r.durationMs, r.stdout, 'cdp sessions');
      }

      return fail('Invalid action or missing params');
    }
  );

  // --- Tool 34: omniwire_proxy ---
  server.tool(
    'omniwire_proxy',
    'HTTP/SOCKS proxy management on mesh nodes. Start HTTP proxies, SOCKS tunnels via SSH -D, or socat TCP forwarders. Actions: start, stop, status, list.',
    {
      action: z.enum(['start', 'stop', 'status', 'list']).describe('Action'),
      node: z.string().optional().describe('Target node (default: contabo)'),
      type: z.enum(['http', 'socks', 'forward']).optional().describe('http=python http.server, socks=SSH -D SOCKS5, forward=socat TCP forwarder'),
      port: z.number().optional().describe('Local port to listen on'),
      target: z.string().optional().describe('Target for forward type (host:port)'),
    },
    async ({ action, node, type, port, target }) => {
      const nodeId = node ?? 'contabo';
      const pd = '/tmp/.omniwire-proxies';

      if (action === 'list' || action === 'status') {
        const result = await manager.exec(nodeId, `mkdir -p ${pd}; ls ${pd}/*.pid 2>/dev/null | while read f; do id=$(basename "$f" .pid); pid=$(cat "$f" 2>/dev/null); ptype=$(cat "${pd}/$id.type" 2>/dev/null); pport=$(cat "${pd}/$id.port" 2>/dev/null); alive=$(kill -0 "$pid" 2>/dev/null && echo running || echo dead); echo "$id  $ptype  :$pport  pid=$pid  $alive"; done || echo "(none)"; ss -tlnp 2>/dev/null | grep LISTEN | head -20`);
        return ok(nodeId, result.durationMs, result.stdout, 'proxy status');
      }

      if (action === 'start') {
        const proxyType = type ?? 'http';
        const listenPort = port ?? (proxyType === 'http' ? 8888 : proxyType === 'socks' ? 1080 : 9090);
        const id = `ow-proxy-${proxyType}-${listenPort}`;
        let startCmd: string;
        if (proxyType === 'http') {
          startCmd = `cd /tmp && python3 -m http.server ${listenPort} --bind 0.0.0.0 >/tmp/${id}.log 2>&1 & echo $! > ${pd}/${id}.pid`;
        } else if (proxyType === 'socks') {
          startCmd = `ssh -D 0.0.0.0:${listenPort} -N -f -o StrictHostKeyChecking=no -o ExitOnForwardFailure=yes localhost 2>/dev/null; pgrep -f "ssh -D.*${listenPort}" | head -1 > ${pd}/${id}.pid`;
        } else {
          if (!target) return fail('target (host:port) required for forward type');
          const et = target.replace(/'/g, "'\\''");
          startCmd = `socat TCP-LISTEN:${listenPort},fork,reuseaddr TCP:${et} >/tmp/${id}.log 2>&1 & echo $! > ${pd}/${id}.pid`;
        }
        const result = await manager.exec(nodeId, `mkdir -p ${pd}; ${startCmd}; echo "${proxyType}" > ${pd}/${id}.type; echo "${listenPort}" > ${pd}/${id}.port; sleep 0.5; pid=$(cat ${pd}/${id}.pid 2>/dev/null); kill -0 "$pid" 2>/dev/null && echo "started: ${id} on :${listenPort} pid=$pid" || echo "WARN: check /tmp/${id}.log"`);
        return ok(nodeId, result.durationMs, result.stdout, `proxy start ${proxyType}:${listenPort}`);
      }

      if (action === 'stop') {
        const listenPort = port ?? 0;
        const stopCmd = listenPort
          ? `for f in ${pd}/*.port; do p=$(cat "$f" 2>/dev/null); if [ "$p" = "${listenPort}" ]; then id=$(basename "$f" .port); pid=$(cat "${pd}/$id.pid" 2>/dev/null); kill "$pid" 2>/dev/null; rm -f "${pd}/$id."*; echo "stopped $id"; fi; done`
          : `for f in ${pd}/*.pid; do pid=$(cat "$f" 2>/dev/null); kill "$pid" 2>/dev/null; done; rm -f ${pd}/*.pid ${pd}/*.type ${pd}/*.port; echo "all proxies stopped"`;
        const result = await manager.exec(nodeId, `mkdir -p ${pd}; ${stopCmd}`);
        return ok(nodeId, result.durationMs, result.stdout, 'proxy stop');
      }

      return fail('invalid action');
    }
  );

  // --- Tool 35: omniwire_dns ---
  server.tool(
    'omniwire_dns',
    'DNS management on mesh nodes. Resolve hostnames, switch DNS servers, flush caches, manage /etc/hosts entries.',
    {
      action: z.enum(['resolve', 'set-server', 'flush-cache', 'zone-add', 'zone-list', 'block-domain']).describe('Action'),
      node: z.string().optional().describe('Target node (default: contabo)'),
      domain: z.string().optional().describe('Domain to resolve or block'),
      server: z.string().optional().describe('DNS server IP for set-server (e.g., 1.1.1.1)'),
      ip: z.string().optional().describe('IP for zone-add or block-domain override (default: 0.0.0.0)'),
    },
    async ({ action, node, domain, server, ip }) => {
      const nodeId = node ?? 'contabo';

      if (action === 'resolve') {
        if (!domain) return fail('domain required');
        const d = domain.replace(/'/g, "'\\''");
        const result = await manager.exec(nodeId, `dig +short '${d}' 2>/dev/null || nslookup '${d}' 2>&1 | grep -E 'Address:|Name:' | tail -5`);
        return ok(nodeId, result.durationMs, result.stdout || '(no result)', `resolve ${domain}`);
      }

      if (action === 'set-server') {
        if (!server) return fail('server IP required');
        const result = await manager.exec(nodeId, `printf 'nameserver ${server}\nsearch %s\n' "$(hostname -d 2>/dev/null || echo local)" | tee /etc/resolv.conf; echo "DNS set to ${server}"; dig +short google.com @${server} 2>/dev/null | head -3`);
        return ok(nodeId, result.durationMs, result.stdout, `dns set-server ${server}`);
      }

      if (action === 'flush-cache') {
        const result = await manager.exec(nodeId, 'systemd-resolve --flush-caches 2>/dev/null && echo "flushed via systemd-resolve" || resolvectl flush-caches 2>/dev/null && echo "flushed via resolvectl" || (service nscd restart 2>/dev/null && echo "nscd restarted") || echo "no cache daemon found"');
        return ok(nodeId, result.durationMs, result.stdout, 'dns flush-cache');
      }

      if (action === 'block-domain') {
        if (!domain) return fail('domain required');
        const blockIp = ip ?? '0.0.0.0';
        const d = domain.replace(/'/g, "'\\''");
        const result = await manager.exec(nodeId, `grep -qF '${d}' /etc/hosts 2>/dev/null && echo "already in /etc/hosts" || (echo "${blockIp} ${d}" | tee -a /etc/hosts && echo "blocked ${domain} -> ${blockIp}")`);
        return ok(nodeId, result.durationMs, result.stdout, `dns block ${domain}`);
      }

      if (action === 'zone-add') {
        if (!domain || !ip) return fail('domain and ip required for zone-add');
        const d = domain.replace(/'/g, "'\\''");
        const result = await manager.exec(nodeId, `grep -qF '${d}' /etc/hosts 2>/dev/null && sed -i "s/.*${d}.*/${ip} ${d}/" /etc/hosts && echo "updated ${domain}" || (echo "${ip} ${d}" >> /etc/hosts && echo "added ${domain} -> ${ip}")`);
        return ok(nodeId, result.durationMs, result.stdout, `dns zone-add ${domain}`);
      }

      if (action === 'zone-list') {
        const result = await manager.exec(nodeId, "grep -v '^#' /etc/hosts | grep -v '^$' | sort");
        return ok(nodeId, result.durationMs, result.stdout, 'dns zone-list');
      }

      return fail('invalid action');
    }
  );

  // --- Tool 36: omniwire_backup ---
  server.tool(
    'omniwire_backup',
    'Snapshot and restore paths on mesh nodes. Creates timestamped tarballs in /var/backups/omniwire/. Actions: snapshot, restore, list, diff, cleanup.',
    {
      action: z.enum(['snapshot', 'restore', 'list', 'diff', 'cleanup']).describe('Action'),
      node: z.string().optional().describe('Target node (default: contabo)'),
      path: z.string().optional().describe('Path to snapshot or restore to'),
      backup_id: z.string().optional().describe('Backup filename (for restore/diff). Use list to find IDs.'),
      retention_days: z.number().optional().describe('Days to keep for cleanup (default: 30)'),
    },
    async ({ action, node, path, backup_id, retention_days }) => {
      const nodeId = node ?? 'contabo';
      const bd = '/var/backups/omniwire';

      if (action === 'snapshot') {
        if (!path) return fail('path required');
        const p = path.replace(/'/g, "'\\''");
        const result = await manager.exec(nodeId, `mkdir -p ${bd}; ts=\$(date +%s); host=\$(hostname); out="${bd}/\${host}-\${ts}.tar.gz"; tar czf "$out" '${p}' 2>&1 && ls -lh "$out" && echo "snapshot: $out" || echo "snapshot failed"`);
        return ok(nodeId, result.durationMs, result.stdout, `backup snapshot ${path}`);
      }

      if (action === 'list') {
        const result = await manager.exec(nodeId, `ls -lht ${bd}/ 2>/dev/null | head -30 || echo "(no backups)"`);
        return ok(nodeId, result.durationMs, result.stdout, 'backup list');
      }

      if (action === 'restore') {
        if (!backup_id || !path) return fail('backup_id and path required');
        const p = path.replace(/'/g, "'\\''");
        const bid = backup_id.replace(/'/g, "'\\''");
        const result = await manager.exec(nodeId, `mkdir -p '${p}'; tar xzf '${bd}/${bid}' -C '${p}' 2>&1 && echo "restored to ${path}" || echo "restore failed"`);
        return ok(nodeId, result.durationMs, result.stdout, `backup restore ${backup_id}`);
      }

      if (action === 'diff') {
        if (!backup_id || !path) return fail('backup_id and path required for diff');
        const p = path.replace(/'/g, "'\\''");
        const bid = backup_id.replace(/'/g, "'\\''");
        const tmpDir = `/tmp/.ow-diff-${Date.now().toString(36)}`;
        const result = await manager.exec(nodeId, `mkdir -p ${tmpDir}; tar xzf '${bd}/${bid}' -C ${tmpDir} 2>/dev/null; diff -rq '${p}' ${tmpDir} 2>&1 | head -40; rm -rf ${tmpDir}`);
        return ok(nodeId, result.durationMs, result.stdout || '(no differences)', `backup diff ${backup_id}`);
      }

      if (action === 'cleanup') {
        const days = retention_days ?? 30;
        const result = await manager.exec(nodeId, `find ${bd}/ -name '*.tar.gz' -mtime +${days} -print -delete 2>/dev/null | wc -l | xargs -I{} echo "removed {} backups older than ${days} days"`);
        return ok(nodeId, result.durationMs, result.stdout, `backup cleanup >${days}d`);
      }

      return fail('invalid action');
    }
  );

  // --- Tool 37: omniwire_container ---
  server.tool(
    'omniwire_container',
    'Full Docker container lifecycle management. Actions: compose-up, compose-down, build, push, logs, ps, prune, stats, inspect.',
    {
      action: z.enum(['compose-up', 'compose-down', 'build', 'push', 'logs', 'ps', 'prune', 'stats', 'inspect']).describe('Action'),
      node: z.string().optional().describe('Target node (default: contabo)'),
      container: z.string().optional().describe('Container name or ID (for logs, inspect)'),
      file: z.string().optional().describe('docker-compose file path'),
      tag: z.string().optional().describe('Image tag for build/push'),
      context: z.string().optional().describe('Build context path (default: .)'),
      tail_lines: z.number().optional().describe('Log lines to tail (default: 50)'),
    },
    async ({ action, node, container, file, tag, context, tail_lines }) => {
      const nodeId = node ?? 'contabo';

      if (action === 'compose-up') {
        const cf = file ? `-f '${file.replace(/'/g, "'\\''")}'` : '';
        const result = await manager.exec(nodeId, `docker compose ${cf} up -d 2>&1`);
        return ok(nodeId, result.durationMs, result.stdout + result.stderr, 'compose up');
      }

      if (action === 'compose-down') {
        const cf = file ? `-f '${file.replace(/'/g, "'\\''")}'` : '';
        const result = await manager.exec(nodeId, `docker compose ${cf} down 2>&1`);
        return ok(nodeId, result.durationMs, result.stdout + result.stderr, 'compose down');
      }

      if (action === 'build') {
        if (!tag) return fail('tag required for build');
        const ctx = context ?? '.';
        const result = await manager.exec(nodeId, `docker build -t '${tag.replace(/'/g, "'\\''")}' '${ctx.replace(/'/g, "'\\''")}' 2>&1 | tail -20`);
        return ok(nodeId, result.durationMs, result.stdout, `docker build ${tag}`);
      }

      if (action === 'push') {
        if (!tag) return fail('tag required for push');
        const result = await manager.exec(nodeId, `docker push '${tag.replace(/'/g, "'\\''")}' 2>&1`);
        return ok(nodeId, result.durationMs, result.stdout + result.stderr, `docker push ${tag}`);
      }

      if (action === 'logs') {
        if (!container) return fail('container required for logs');
        const lines = tail_lines ?? 50;
        const result = await manager.exec(nodeId, `docker logs --tail ${lines} '${container.replace(/'/g, "'\\''")}' 2>&1`);
        return ok(nodeId, result.durationMs, result.stdout + result.stderr, `docker logs ${container}`);
      }

      if (action === 'ps') {
        const result = await manager.exec(nodeId, `docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" 2>&1`);
        return ok(nodeId, result.durationMs, result.stdout, 'docker ps');
      }

      if (action === 'prune') {
        const result = await manager.exec(nodeId, 'docker system prune -af --volumes 2>&1 | tail -10');
        return ok(nodeId, result.durationMs, result.stdout, 'docker prune');
      }

      if (action === 'stats') {
        const result = await manager.exec(nodeId, `docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}" 2>&1`);
        return ok(nodeId, result.durationMs, result.stdout, 'docker stats');
      }

      if (action === 'inspect') {
        if (!container) return fail('container required for inspect');
        const result = await manager.exec(nodeId, `docker inspect '${container.replace(/'/g, "'\\''")}' 2>&1 | head -60`);
        return ok(nodeId, result.durationMs, result.stdout, `docker inspect ${container}`);
      }

      return fail('invalid action');
    }
  );

  // --- Tool 38: omniwire_cert ---
  server.tool(
    'omniwire_cert',
    'TLS certificate management. List, issue via certbot, renew, check expiry, inspect cert details, or generate self-signed certs.',
    {
      action: z.enum(['list', 'issue', 'renew', 'check-expiry', 'info', 'generate-self-signed']).describe('Action'),
      node: z.string().optional().describe('Target node (default: contabo)'),
      domain: z.string().optional().describe('Domain name'),
      email: z.string().optional().describe('Email for certbot ACME registration'),
      path: z.string().optional().describe('Certificate file path (for info action)'),
    },
    async ({ action, node, domain, email, path }) => {
      const nodeId = node ?? 'contabo';

      if (action === 'list') {
        const result = await manager.exec(nodeId, "ls /etc/letsencrypt/live/ 2>/dev/null && echo '---pem---' && ls /etc/ssl/certs/*.pem 2>/dev/null | head -20 || echo '(no certs found)'");
        return ok(nodeId, result.durationMs, result.stdout, 'cert list');
      }

      if (action === 'issue') {
        if (!domain) return fail('domain required');
        if (!email) return fail('email required for certbot');
        const d = domain.replace(/'/g, "'\\''");
        const e = email.replace(/'/g, "'\\''");
        const result = await manager.exec(nodeId, `certbot certonly --standalone -d '${d}' --non-interactive --agree-tos -m '${e}' 2>&1 | tail -20`);
        return ok(nodeId, result.durationMs, result.stdout, `cert issue ${domain}`);
      }

      if (action === 'renew') {
        const result = await manager.exec(nodeId, 'certbot renew 2>&1 | tail -20');
        return ok(nodeId, result.durationMs, result.stdout, 'cert renew');
      }

      if (action === 'check-expiry') {
        if (!domain) return fail('domain required');
        const d = domain.replace(/'/g, "'\\''");
        const result = await manager.exec(nodeId, `echo | openssl s_client -connect '${d}':443 -servername '${d}' 2>/dev/null | openssl x509 -noout -dates 2>/dev/null || echo "could not connect to ${domain}:443"`);
        return ok(nodeId, result.durationMs, result.stdout, `cert expiry ${domain}`);
      }

      if (action === 'info') {
        if (!path) return fail('path required for info');
        const p = path.replace(/'/g, "'\\''");
        const result = await manager.exec(nodeId, `openssl x509 -in '${p}' -noout -text 2>&1 | head -30`);
        return ok(nodeId, result.durationMs, result.stdout, `cert info ${path}`);
      }

      if (action === 'generate-self-signed') {
        if (!domain) return fail('domain required');
        const d = domain.replace(/'/g, "'\\''");
        const outDir = '/etc/ssl/omniwire';
        const result = await manager.exec(nodeId, `mkdir -p ${outDir}; openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout ${outDir}/${d}.key -out ${outDir}/${d}.crt -subj "/CN=${d}/O=OmniWire/C=NO" 2>&1 && echo "generated: ${outDir}/${d}.crt + .key" && openssl x509 -in ${outDir}/${d}.crt -noout -dates`);
        return ok(nodeId, result.durationMs, result.stdout, `cert self-signed ${domain}`);
      }

      return fail('invalid action');
    }
  );

  // --- Tool 39: omniwire_user ---
  server.tool(
    'omniwire_user',
    'User and SSH key management on mesh nodes. Actions: list, add, remove, add-key, remove-key, sudo-add, sudo-remove, passwd.',
    {
      action: z.enum(['list', 'add', 'remove', 'add-key', 'remove-key', 'sudo-add', 'sudo-remove', 'passwd']).describe('Action'),
      node: z.string().optional().describe('Target node (default: contabo)'),
      username: z.string().optional().describe('Username to operate on'),
      ssh_key: z.string().optional().describe('SSH public key string (for add-key/remove-key)'),
      password: z.string().optional().describe('Password for passwd action'),
    },
    async ({ action, node, username, ssh_key, password }) => {
      const nodeId = node ?? 'contabo';

      if (action === 'list') {
        const result = await manager.exec(nodeId, "getent passwd | grep -v '/sbin/nologin\|/bin/false\|/usr/sbin/nologin' | awk -F: '{print $1, $3, $6}' | column -t");
        return ok(nodeId, result.durationMs, result.stdout, 'user list');
      }

      if (action === 'add') {
        if (!username) return fail('username required');
        const u = username.replace(/'/g, "'\\''");
        const result = await manager.exec(nodeId, `useradd -m -s /bin/bash '${u}' 2>&1 && echo "user ${username} created" || echo "user may already exist"`);
        return ok(nodeId, result.durationMs, result.stdout, `user add ${username}`);
      }

      if (action === 'remove') {
        if (!username) return fail('username required');
        const u = username.replace(/'/g, "'\\''");
        const result = await manager.exec(nodeId, `userdel -r '${u}' 2>&1 && echo "user ${username} removed" || echo "failed to remove user"`);
        return ok(nodeId, result.durationMs, result.stdout, `user remove ${username}`);
      }

      if (action === 'add-key') {
        if (!username || !ssh_key) return fail('username and ssh_key required');
        const u = username.replace(/'/g, "'\\''");
        const k = ssh_key.replace(/'/g, "'\\''");
        const result = await manager.exec(nodeId, `homedir=$(getent passwd '${u}' | cut -d: -f6); mkdir -p "$homedir/.ssh"; chmod 700 "$homedir/.ssh"; grep -qF '${k}' "$homedir/.ssh/authorized_keys" 2>/dev/null && echo "key already present" || (echo '${k}' >> "$homedir/.ssh/authorized_keys" && chmod 600 "$homedir/.ssh/authorized_keys" && chown -R '${u}' "$homedir/.ssh" && echo "key added for ${username}")`);
        return ok(nodeId, result.durationMs, result.stdout, `user add-key ${username}`);
      }

      if (action === 'remove-key') {
        if (!username || !ssh_key) return fail('username and ssh_key required');
        const u = username.replace(/'/g, "'\\''");
        const k = ssh_key.replace(/'/g, "'\\''");
        const result = await manager.exec(nodeId, `homedir=$(getent passwd '${u}' | cut -d: -f6); grep -vF '${k}' "$homedir/.ssh/authorized_keys" 2>/dev/null > /tmp/.ow-keys.tmp && mv /tmp/.ow-keys.tmp "$homedir/.ssh/authorized_keys" && echo "key removed for ${username}" || echo "failed"`);
        return ok(nodeId, result.durationMs, result.stdout, `user remove-key ${username}`);
      }

      if (action === 'sudo-add') {
        if (!username) return fail('username required');
        const u = username.replace(/'/g, "'\\''");
        const result = await manager.exec(nodeId, `echo '${u} ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/${u} && chmod 440 /etc/sudoers.d/${u} && echo "sudo added for ${username}"`);
        return ok(nodeId, result.durationMs, result.stdout, `user sudo-add ${username}`);
      }

      if (action === 'sudo-remove') {
        if (!username) return fail('username required');
        const u = username.replace(/'/g, "'\\''");
        const result = await manager.exec(nodeId, `rm -f '/etc/sudoers.d/${u}' && echo "sudo removed for ${username}"`);
        return ok(nodeId, result.durationMs, result.stdout, `user sudo-remove ${username}`);
      }

      if (action === 'passwd') {
        if (!username || !password) return fail('username and password required');
        const u = username.replace(/'/g, "'\\''");
        const pw = password.replace(/'/g, "'\\''");
        const result = await manager.exec(nodeId, `echo '${u}:${pw}' | chpasswd 2>&1 && echo "password updated for ${username}" || echo "chpasswd failed"`);
        return ok(nodeId, result.durationMs, result.stdout, `user passwd ${username}`);
      }

      return fail('invalid action');
    }
  );

  // --- Tool 40: omniwire_schedule ---
  server.tool(
    'omniwire_schedule',
    'Distributed cron scheduling with failover. Stores schedule JSON, writes crontab entries on preferred node, supports fallback nodes. Actions: add, remove, list, run-now, history.',
    {
      action: z.enum(['add', 'remove', 'list', 'run-now', 'history']).describe('Action'),
      node: z.string().optional().describe('Preferred node for execution (default: contabo)'),
      schedule_id: z.string().optional().describe('Schedule identifier'),
      command: z.string().optional().describe('Command to schedule (for add)'),
      cron_expr: z.string().optional().describe('Cron expression (e.g. "0 */6 * * *")'),
      fallback_nodes: z.array(z.string()).optional().describe('Fallback nodes if primary is offline'),
    },
    async ({ action, node, schedule_id, command, cron_expr, fallback_nodes }) => {
      const nodeId = node ?? 'contabo';
      const sd = '/etc/omniwire/schedules';

      if (action === 'list') {
        const result = await manager.exec(nodeId, `mkdir -p ${sd}; ls ${sd}/*.json 2>/dev/null | while read f; do id=$(basename "$f" .json); echo "--- $id ---"; cat "$f" 2>/dev/null | grep -E '"command"|"cron_expr"|"node"'; done || echo "(no schedules)"; echo "=== crontab ==="; crontab -l 2>/dev/null | grep omniwire || echo "(none)"`);
        return ok(nodeId, result.durationMs, result.stdout, 'schedule list');
      }

      if (action === 'add') {
        if (!schedule_id || !command || !cron_expr) return fail('schedule_id, command, and cron_expr required');
        const sid = schedule_id.replace(/'/g, "'\\''");
        const cmd = command.replace(/'/g, "'\\''");
        const meta = JSON.stringify({ id: schedule_id, command, cron_expr, node: nodeId, fallback_nodes: fallback_nodes ?? [], created: Date.now() });
        const metaEsc = meta.replace(/'/g, "'\\''");
        const result = await manager.exec(nodeId, `mkdir -p ${sd}; echo '${metaEsc}' > ${sd}/${sid}.json; (crontab -l 2>/dev/null; echo '# omniwire:${sid}'; echo '${cron_expr} ${cmd}') | crontab -; echo "schedule ${schedule_id} added: ${cron_expr}"`);
        return ok(nodeId, result.durationMs, result.stdout, `schedule add ${schedule_id}`);
      }

      if (action === 'remove') {
        if (!schedule_id) return fail('schedule_id required');
        const sid = schedule_id.replace(/'/g, "'\\''");
        const result = await manager.exec(nodeId, `rm -f ${sd}/${sid}.json; crontab -l 2>/dev/null | grep -v 'omniwire:${sid}' | crontab -; echo "schedule ${schedule_id} removed"`);
        return ok(nodeId, result.durationMs, result.stdout, `schedule remove ${schedule_id}`);
      }

      if (action === 'run-now') {
        if (!schedule_id) return fail('schedule_id required');
        const sid = schedule_id.replace(/'/g, "'\\''");
        const result = await manager.exec(nodeId, `cmd=$(python3 -c "import json,sys; d=json.load(open('${sd}/${sid}.json')); print(d['command'])" 2>/dev/null); if [ -z "$cmd" ]; then echo "schedule ${schedule_id} not found"; exit 1; fi; echo "running: $cmd"; bash -c "$cmd" 2>&1`);
        return ok(nodeId, result.durationMs, result.stdout, `schedule run-now ${schedule_id}`);
      }

      if (action === 'history') {
        if (!schedule_id) return fail('schedule_id required');
        const sid = schedule_id.replace(/'/g, "'\\''");
        const result = await manager.exec(nodeId, `journalctl --no-pager -n 20 --grep='${sid}' 2>/dev/null || grep '${sid}' /var/log/syslog 2>/dev/null | tail -20 || echo "(no history found)"`);
        return ok(nodeId, result.durationMs, result.stdout, `schedule history ${schedule_id}`);
      }

      return fail('invalid action');
    }
  );

  // --- Tool 41: omniwire_alert ---
  server.tool(
    'omniwire_alert',
    'Threshold alerting for mesh nodes. Fire when disk/mem/load exceeds threshold or service goes down. Destinations: webhook or local log. Actions: set, remove, list, test, history.',
    {
      action: z.enum(['set', 'remove', 'list', 'test', 'history']).describe('Action'),
      node: z.string().optional().describe('Node to monitor (default: contabo)'),
      alert_id: z.string().optional().describe('Alert rule identifier'),
      metric: z.enum(['disk', 'mem', 'load', 'offline', 'service']).optional().describe('Metric to monitor'),
      threshold: z.number().optional().describe('Threshold value (disk/mem: %, load: float)'),
      webhook_url: z.string().optional().describe('Webhook URL to POST alert payload to'),
    },
    async ({ action, node, alert_id, metric, threshold, webhook_url }) => {
      const nodeId = node ?? 'contabo';
      const ad = '/tmp/.omniwire-alerts';
      const fd = `${ad}/fired`;

      if (action === 'list') {
        const result = await manager.exec(nodeId, `mkdir -p ${ad}; ls ${ad}/*.json 2>/dev/null | while read f; do echo "$(basename $f .json):"; cat "$f" | grep -E '"metric"|"threshold"|"webhook"'; done || echo "(no alerts configured)"`);
        return ok(nodeId, result.durationMs, result.stdout, 'alert list');
      }

      if (action === 'set') {
        if (!alert_id || !metric) return fail('alert_id and metric required');
        const aid = alert_id.replace(/'/g, "'\\''");
        const thresh = threshold ?? (metric === 'load' ? 4 : 90);
        const rule = JSON.stringify({ id: alert_id, node: nodeId, metric, threshold: thresh, webhook_url: webhook_url ?? null, created: Date.now() });
        const ruleEsc = rule.replace(/'/g, "'\\''");

        const checkScript = metric === 'disk'
          ? `val=$(df / --output=pcent | tail -1 | tr -d ' %'); [ "$val" -gt '${thresh}' ] && echo ALERT`
          : metric === 'mem'
          ? `val=$(free | awk '/Mem:/{printf "%.0f", $3/$2*100}'); [ "$val" -gt '${thresh}' ] && echo ALERT`
          : metric === 'load'
          ? `val=$(awk '{print $1}' /proc/loadavg); awk "BEGIN{exit ($val > ${thresh}) ? 0 : 1}" && echo ALERT`
          : metric === 'service'
          ? `systemctl is-active '${aid}' >/dev/null 2>&1 || echo ALERT`
          : `ping -c1 -W2 127.0.0.1 >/dev/null 2>&1 || echo ALERT`;

        const wh = webhook_url ? webhook_url.replace(/'/g, "'\\''") : '';
        const fireCmd = webhook_url
          ? `curl -s -X POST '${wh}' -H 'Content-Type: application/json' -d '{"alert":"${aid}","node":"${nodeId}","metric":"${metric}"}' 2>/dev/null`
          : `mkdir -p ${fd}; echo "$(date -Iseconds) ${aid} ${nodeId} ${metric}" >> ${fd}/events.log`;

        const cronLine = `* * * * * bash -c '${checkScript.replace(/'/g, "'\\''")}' 2>/dev/null | grep -q ALERT && ${fireCmd}`;
        const result = await manager.exec(nodeId, `mkdir -p ${ad}; echo '${ruleEsc}' > ${ad}/${aid}.json; (crontab -l 2>/dev/null | grep -v 'omniwire-alert:${aid}'; echo '# omniwire-alert:${aid}'; echo '${cronLine.replace(/'/g, "'\\''")}') | crontab -; echo "alert ${alert_id} set (${metric} threshold=${thresh})"`);
        return ok(nodeId, result.durationMs, result.stdout, `alert set ${alert_id}`);
      }

      if (action === 'remove') {
        if (!alert_id) return fail('alert_id required');
        const aid = alert_id.replace(/'/g, "'\\''");
        const result = await manager.exec(nodeId, `rm -f ${ad}/${aid}.json; crontab -l 2>/dev/null | grep -v 'omniwire-alert:${aid}' | crontab -; echo "alert ${alert_id} removed"`);
        return ok(nodeId, result.durationMs, result.stdout, `alert remove ${alert_id}`);
      }

      if (action === 'test') {
        if (!alert_id) return fail('alert_id required');
        const aid = alert_id.replace(/'/g, "'\\''");
        const ruleResult = await manager.exec(nodeId, `cat ${ad}/${aid}.json 2>/dev/null`);
        let fireCmd: string;
        try {
          const parsed = JSON.parse(ruleResult.stdout);
          fireCmd = parsed.webhook_url
            ? `curl -s -X POST '${parsed.webhook_url}' -H 'Content-Type: application/json' -d '{"alert":"${aid}","node":"${nodeId}","test":true}' && echo "test alert sent"`
            : `mkdir -p ${fd}; echo "$(date -Iseconds) TEST ${aid} ${nodeId}" >> ${fd}/events.log && echo "test alert written to events.log"`;
        } catch {
          fireCmd = `mkdir -p ${fd}; echo "$(date -Iseconds) TEST ${aid} ${nodeId}" >> ${fd}/events.log && echo "test alert written to events.log"`;
        }
        const result = await manager.exec(nodeId, fireCmd);
        return ok(nodeId, result.durationMs, result.stdout, `alert test ${alert_id}`);
      }

      if (action === 'history') {
        const filterPart = alert_id ? `| grep '${alert_id.replace(/'/g, "'\\''")}'` : '';
        const result = await manager.exec(nodeId, `cat ${fd}/events.log 2>/dev/null ${filterPart} | tail -30 || echo "(no fired alerts)"`);
        return ok(nodeId, result.durationMs, result.stdout, 'alert history');
      }

      return fail('invalid action');
    }
  );

  // --- Tool 42: omniwire_log_aggregate ---
  server.tool(
    'omniwire_log_aggregate',
    'Cross-node log search and aggregation. Run grep/journalctl across all nodes in parallel, merge results with node prefix. Actions: search, tail, count.',
    {
      action: z.enum(['search', 'tail', 'count']).describe('search=grep pattern, tail=last N lines, count=count matches per node'),
      pattern: z.string().optional().describe('Search/grep pattern'),
      nodes: z.array(z.string()).optional().describe('Nodes to search (default: all online)'),
      source: z.enum(['journalctl', 'syslog', 'file']).optional().describe('Log source (default: journalctl)'),
      file_path: z.string().optional().describe('Log file path (required when source=file)'),
      limit: z.number().optional().describe('Max lines per node (default: 50)'),
    },
    async ({ action, pattern, nodes: targetNodes, source, file_path, limit }) => {
      const logLimit = limit ?? 50;
      const logSource = source ?? 'journalctl';
      const nodeIds = targetNodes ?? manager.getOnlineNodes();

      function buildCmd(act: string): string {
        if (logSource === 'journalctl') {
          const gp = pattern ? `--grep='${pattern.replace(/'/g, "'\\''")}' ` : '';
          if (act === 'count') return `journalctl --no-pager ${gp}-q 2>/dev/null | wc -l`;
          return `journalctl --no-pager -n ${logLimit} ${gp}2>/dev/null`;
        }
        if (logSource === 'syslog') {
          const lf = '/var/log/syslog';
          if (act === 'count') return pattern
            ? `grep -cE '${pattern.replace(/'/g, "'\\''")}' ${lf} 2>/dev/null || echo 0`
            : `wc -l < ${lf} 2>/dev/null || echo 0`;
          return pattern
            ? `grep -E '${pattern.replace(/'/g, "'\\''")}' ${lf} 2>/dev/null | tail -${logLimit}`
            : `tail -${logLimit} ${lf} 2>/dev/null`;
        }
        if (!file_path) return "echo '(file_path required for source=file)'";
        const fp = file_path.replace(/'/g, "'\\''");
        if (act === 'count') return pattern
          ? `grep -cE '${pattern.replace(/'/g, "'\\''")}' '${fp}' 2>/dev/null || echo 0`
          : `wc -l < '${fp}' 2>/dev/null || echo 0`;
        return pattern
          ? `grep -E '${pattern.replace(/'/g, "'\\''")}' '${fp}' 2>/dev/null | tail -${logLimit}`
          : `tail -${logLimit} '${fp}' 2>/dev/null`;
      }

      const cmd = buildCmd(action);
      const results = await Promise.all(
        nodeIds.map(async (id) => ({ ...await manager.exec(id, cmd), nodeId: id }))
      );

      if (action === 'count') {
        const lines = results.map((r) => `${r.nodeId.padEnd(12)} ${r.stdout.trim() || '0'}`);
        return okBrief(lines.join('\n'));
      }

      return multiResult(results);
    }
  );

  // --- Tool 43: omniwire_benchmark ---
  server.tool(
    'omniwire_benchmark',
    'Node performance benchmarking. CPU, memory, disk I/O, and network throughput. Actions: cpu, memory, disk, network, all.',
    {
      action: z.enum(['cpu', 'memory', 'disk', 'network', 'all']).describe('"all" runs cpu+memory+disk and returns comparison table across nodes'),
      node: z.string().optional().describe('Target node (default: all online for cpu/mem/disk/all)'),
      target_node: z.string().optional().describe('Second node for network test (required for action=network)'),
    },
    async ({ action, node, target_node }) => {
      const cpuCmd = `sysbench cpu --time=5 run 2>&1 | grep 'events per second' || (dd if=/dev/zero bs=1M count=500 2>/dev/null | md5sum | awk '{print "md5-throughput OK"}')`;

      const memCmd = "sysbench memory --time=5 run 2>&1 | grep transferred || (dd if=/dev/zero of=/dev/null bs=1M count=1000 2>&1 | grep -E 'MB/s|GB/s|copied')";
      const diskCmd = "dd if=/dev/zero of=/tmp/.ow-bench bs=1M count=100 oflag=direct 2>&1 | grep -E 'MB/s|GB/s|copied'; rm -f /tmp/.ow-bench";

      if (action === 'network') {
        if (!target_node) return fail('target_node required for network benchmark');
        const srcNode = node ?? 'contabo';
        const bport = 19876;
        await manager.exec(target_node, `nc -l -p ${bport} > /dev/null &`);
        await new Promise((r) => setTimeout(r, 500));
        const targetInfo = await manager.exec(target_node, "hostname -I | awk '{print $1}'");
        const targetIp = targetInfo.stdout.trim();
        if (!targetIp) return fail(`could not resolve IP for ${target_node}`);
        const sendResult = await manager.exec(srcNode, `dd if=/dev/zero bs=1M count=100 2>/dev/null | nc -w 5 ${targetIp} ${bport} 2>&1 | grep -E 'MB/s|GB/s|copied'; echo "network test: ${srcNode} -> ${target_node}"`);
        await manager.exec(target_node, `pkill -f 'nc -l -p ${bport}' 2>/dev/null; true`);
        return ok(srcNode, sendResult.durationMs, sendResult.stdout, `network bench ${srcNode}->${target_node}`);
      }

      const targetNodes = node ? [node] : manager.getOnlineNodes();

      if (action === 'cpu') {
        const results = await Promise.all(targetNodes.map(async (id) => ({ ...await manager.exec(id, cpuCmd), nodeId: id })));
        return multiResult(results);
      }

      if (action === 'memory') {
        const results = await Promise.all(targetNodes.map(async (id) => ({ ...await manager.exec(id, memCmd), nodeId: id })));
        return multiResult(results);
      }

      if (action === 'disk') {
        const results = await Promise.all(targetNodes.map(async (id) => ({ ...await manager.exec(id, diskCmd), nodeId: id })));
        return multiResult(results);
      }

      const allResults = await Promise.all(targetNodes.map(async (id) => {
        const [cpuR, memR, diskR] = await Promise.all([
          manager.exec(id, cpuCmd),
          manager.exec(id, memCmd),
          manager.exec(id, diskCmd),
        ]);
        const cpuVal = cpuR.stdout.match(/[\d.]+ events per second/)?.[0] ?? cpuR.stdout.split('\n')[0]?.slice(0, 35) ?? '--';
        const memVal = memR.stdout.match(/[\d.]+ \w+B transferred/)?.[0] ?? memR.stdout.split('\n')[0]?.slice(0, 35) ?? '--';
        const diskVal = diskR.stdout.match(/[\d.]+ \w+B\/s/)?.[0] ?? diskR.stdout.split('\n')[0]?.slice(0, 25) ?? '--';
        return `${id.padEnd(12)} cpu: ${cpuVal.padEnd(35)}  mem: ${memVal.padEnd(35)}  disk: ${diskVal}`;
      }));

      return okBrief(`benchmark results (cpu / mem / disk)\n${allResults.join('\n')}`);
    }
  );

  // --- Tool 34: omniwire_clipboard ---
  server.tool(
    'omniwire_clipboard',
    'Copy text between nodes via a shared clipboard buffer.',
    {
      action: z.enum(['copy', 'paste', 'clear']).describe('Action'),
      content: z.string().optional().describe('Text to copy (for copy action)'),
      node: z.string().optional().describe('Node for paste (default: all)'),
    },
    async ({ action, content, node }) => {
      const clipPath = '/tmp/.omniwire-clipboard';
      if (action === 'copy' && content) {
        const results = await manager.execAll(`cat << 'OW_CLIP' > ${clipPath}\n${content}\nOW_CLIP`);
        const ok_count = results.filter((r) => r.code === 0).length;
        return okBrief(`clipboard set on ${ok_count} nodes (${content.length} chars)`);
      }
      if (action === 'paste') {
        const nodeId = node ?? 'contabo';
        const result = await manager.exec(nodeId, `cat ${clipPath} 2>/dev/null || echo '(empty)'`);
        return ok(nodeId, result.durationMs, result.stdout, 'clipboard');
      }
      if (action === 'clear') {
        await manager.execAll(`rm -f ${clipPath}`);
        return okBrief('clipboard cleared');
      }
      return fail('invalid action');
    }
  );

  // --- Tool 31: omniwire_git ---
  server.tool(
    'omniwire_git',
    'Run git commands on a repository on any node.',
    {
      command: z.string().describe('Git subcommand (status, log --oneline -5, pull, etc.)'),
      path: z.string().describe('Repository path on the node'),
      node: z.string().optional().describe('Node (default: contabo)'),
    },
    async ({ command, path, node }) => {
      const nodeId = node ?? 'contabo';
      const result = await manager.exec(nodeId, `cd "${path}" && git ${command}`);
      const shortCmd = command.split(' ').slice(0, 2).join(' ');
      if (result.code !== 0) return fail(`${nodeId} git ${shortCmd}: ${result.stderr}`);
      return ok(nodeId, result.durationMs, result.stdout, `git ${shortCmd}`);
    }
  );

  // --- Tool 32: omniwire_syslog ---
  server.tool(
    'omniwire_syslog',
    'Query system logs via journalctl on a node.',
    {
      node: z.string().describe('Target node'),
      unit: z.string().optional().describe('Systemd unit to filter (e.g., nginx, docker)'),
      lines: z.number().optional().describe('Number of lines (default 30)'),
      since: z.string().optional().describe('Time filter (e.g., "1 hour ago", "today")'),
      priority: z.enum(['emerg', 'alert', 'crit', 'err', 'warning', 'notice', 'info', 'debug']).optional(),
    },
    async ({ node, unit, lines, since, priority }) => {
      const parts = ['journalctl --no-pager'];
      if (unit) parts.push(`-u ${unit}`);
      if (lines) parts.push(`-n ${lines}`);
      else parts.push('-n 30');
      if (since) parts.push(`--since '${since}'`);
      if (priority) parts.push(`-p ${priority}`);
      const result = await manager.exec(node, parts.join(' '));
      const label = unit ? `syslog ${unit}` : 'syslog';
      return ok(node, result.durationMs, result.code === 0 ? result.stdout : result.stderr, label);
    }
  );

  // =========================================================================
  // AGENTIC / A2A / MULTI-AGENT TOOLS
  // =========================================================================

  // --- Tool 33: omniwire_store ---
  server.tool(
    'omniwire_store',
    'Key-value store for chaining results. Auto-persists to CyberBase. On get, checks memory first then CyberBase fallback. Keys survive across sessions via CyberBase.',
    {
      action: z.enum(['get', 'set', 'delete', 'list', 'clear']).describe('Action'),
      key: z.string().optional().describe('Key name (required for get/set/delete)'),
      value: z.string().optional().describe('Value to store (for set)'),
    },
    async ({ action, key, value }) => {
      switch (action) {
        case 'get':
          if (!key) return fail('key required');
          // Memory first, CyberBase fallback
          let val = resultStore.get(key);
          if (!val) { val = await cbGet('store', key) ?? undefined; if (val) resultStore.set(key, val); }
          return okBrief(val ?? '(not found)');
        case 'set':
          if (!key || value === undefined) return fail('key and value required');
          resultStore.set(key, value);
          cb('store', key, value);  // persist to CyberBase
          return okBrief(`stored ${key} (${value.length} chars) [memory + cyberbase]`);
        case 'delete':
          if (!key) return fail('key required');
          resultStore.delete(key);
          cb('store', key, '');  // mark deleted in CyberBase
          return okBrief(`deleted ${key}`);
        case 'list': {
          // Merge memory + CyberBase keys
          const memKeys = [...resultStore.entries()].map(([k, v]) => `${k} = ${v.slice(0, 80)}${v.length > 80 ? '...' : ''}`);
          const cbKeys = await cbList('store');
          const extra = cbKeys.filter(k => !resultStore.has(k)).map(k => `${k} (cyberbase)`);
          const all = [...memKeys, ...extra];
          return okBrief(all.length > 0 ? all.join('\n') : '(empty store)');
        }
        case 'clear':
          resultStore.clear();
          return okBrief('memory store cleared (CyberBase entries preserved)');
      }
    }
  );

  // --- Tool 34: omniwire_pipeline ---
  server.tool(
    'omniwire_pipeline',
    'Execute a multi-step pipeline across nodes. Each step can depend on previous step output. Steps run sequentially on potentially different nodes. Pipeline aborts on first failure unless ignore_errors is set. Designed for multi-agent orchestration.',
    {
      steps: z.array(z.object({
        node: z.string().optional().describe('Node (default: contabo)'),
        command: z.string().describe('Command. Use {{prev}} for previous stdout, {{stepN}} for step N output, {{key}} for store.'),
        label: z.string().optional().describe('Step label'),
        store_as: z.string().optional().describe('Store stdout under this key'),
        on_fail: z.enum(['abort', 'skip', 'continue']).optional().describe('Behavior on failure (default: abort)'),
      })).describe('Pipeline steps'),
      format: z.enum(['text', 'json']).optional(),
    },
    async ({ steps, format }) => {
      const useJson = format === 'json';
      const stepOutputs: string[] = [];
      const results: { step: number; node: string; label?: string; ok: boolean; code: number; ms: number; stdout: string; stderr?: string }[] = [];
      let prevStdout = '';

      for (let i = 0; i < steps.length; i++) {
        const step = steps[i];
        const nodeId = step.node ?? 'contabo';
        let cmd = step.command
          .replace(/\{\{prev\}\}/g, prevStdout.trim())
          .replace(/\{\{step(\d+)\}\}/g, (_, n) => stepOutputs[parseInt(n)] ?? '')
          .replace(/\{\{(\w+)\}\}/g, (_, key) => resultStore.get(key) ?? `{{${key}}}`);

        const result = await manager.exec(nodeId, cmd);
        prevStdout = result.stdout;
        stepOutputs[i] = result.stdout.trim();
        if (step.store_as && result.code === 0) resultStore.set(step.store_as, result.stdout.trim());

        results.push({
          step: i, node: nodeId, label: step.label, ok: result.code === 0,
          code: result.code, ms: result.durationMs,
          stdout: result.stdout.slice(0, 2000),
          ...(result.stderr ? { stderr: result.stderr.slice(0, 500) } : {}),
        });

        if (result.code !== 0) {
          const onFail = step.on_fail ?? 'abort';
          if (onFail === 'abort') break;
          if (onFail === 'skip') { prevStdout = ''; continue; }
        }
      }

      if (useJson) return okBrief(JSON.stringify(results));

      const lines = results.map((r) => {
        const status = r.ok ? 'ok' : `exit ${r.code}`;
        const lbl = r.label ?? `step ${r.step}`;
        const body = r.ok ? r.stdout.split('\n').slice(0, 10).join('\n') : (r.stderr ?? '').split('\n').slice(0, 5).join('\n');
        return `[${r.step}] ${r.node} > ${lbl}  ${t(r.ms)}  ${status}\n${body}`;
      });
      return okBrief(trim(lines.join('\n\n')));
    }
  );

  // --- Tool 35: omniwire_watch ---
  server.tool(
    'omniwire_watch',
    'Poll a command until a condition is met or timeout. Useful for waiting on deployments, services starting, builds completing. Returns when the assert pattern matches stdout.',
    {
      node: z.string().optional().describe('Node (default: contabo)'),
      command: z.string().describe('Command to poll'),
      assert: z.string().describe('Regex pattern to match in stdout. Returns success when found.'),
      interval: z.number().optional().describe('Poll interval in seconds (default: 3)'),
      timeout: z.number().optional().describe('Max wait in seconds (default: 60)'),
      label: z.string().optional(),
      store_as: z.string().optional().describe('Store matching stdout on success'),
    },
    async ({ node, command, assert: pattern, interval, timeout, label, store_as }) => {
      const nodeId = node ?? 'contabo';
      const intervalMs = (interval ?? 3) * 1000;
      const timeoutMs = (timeout ?? 60) * 1000;
      const regex = new RegExp(pattern);
      const start = Date.now();

      while (Date.now() - start < timeoutMs) {
        const result = await manager.exec(nodeId, command);
        if (result.code === 0 && regex.test(result.stdout)) {
          if (store_as) resultStore.set(store_as, result.stdout.trim());
          return ok(nodeId, Date.now() - start, result.stdout, label ?? `watch (matched after ${t(Date.now() - start)})`);
        }
        await new Promise((r) => setTimeout(r, intervalMs));
      }

      return fail(`${nodeId} watch timeout after ${t(timeoutMs)}: /${pattern}/ never matched`);
    }
  );

  // --- Tool 36: omniwire_healthcheck ---
  server.tool(
    'omniwire_healthcheck',
    'Run a comprehensive health check across all nodes. Returns structured per-node status with connectivity, disk, memory, load, and service checks. Single tool call replaces 4+ individual calls.',
    {
      checks: z.array(z.enum(['connectivity', 'disk', 'memory', 'load', 'docker', 'services'])).optional().describe('Which checks to run (default: all)'),
      nodes: z.array(z.string()).optional().describe('Nodes to check (default: all online)'),
      format: z.enum(['text', 'json']).optional(),
    },
    async ({ checks, nodes: targetNodes, format }) => {
      const checkList = checks ?? ['connectivity', 'disk', 'memory', 'load'];
      const useJson = format === 'json';

      const parts: string[] = [];
      if (checkList.includes('connectivity')) parts.push("echo 'CONN:ok'");
      if (checkList.includes('disk')) parts.push("echo -n 'DISK:'; df / --output=pcent | tail -1 | tr -d ' %'");
      if (checkList.includes('memory')) parts.push("echo -n 'MEM:'; free | awk '/Mem:/{printf \"%.0f\", $3/$2*100}'");
      if (checkList.includes('load')) parts.push("echo -n 'LOAD:'; cat /proc/loadavg | awk '{print $1}'");
      if (checkList.includes('docker')) parts.push("echo -n 'DOCKER:'; docker ps -q 2>/dev/null | wc -l | tr -d ' '");
      if (checkList.includes('services')) parts.push("echo -n 'SVCFAIL:'; systemctl --failed --no-legend 2>/dev/null | wc -l | tr -d ' '");
      const cmd = parts.join('; echo; ');

      const nodeIds = targetNodes ?? manager.getOnlineNodes();
      const results = await Promise.all(nodeIds.map((id) => manager.exec(id, cmd)));

      if (useJson) {
        const parsed = results.map((r) => {
          const data: Record<string, string | number | boolean> = { node: r.nodeId, online: r.code !== -1 };
          for (const line of r.stdout.split('\n')) {
            const [k, v] = line.split(':');
            if (k && v) data[k.toLowerCase()] = isNaN(Number(v)) ? v : Number(v);
          }
          data.ms = r.durationMs;
          return data;
        });
        return okBrief(JSON.stringify(parsed));
      }

      const lines = results.map((r) => {
        if (r.code === -1) return `- ${r.nodeId.padEnd(10)} OFFLINE`;
        const metrics = r.stdout.split('\n').filter(Boolean).join('  ');
        return `+ ${r.nodeId.padEnd(10)} ${t(r.durationMs).padStart(6)}  ${metrics}`;
      });
      return okBrief(lines.join('\n'));
    }
  );

  // --- Tool 37: omniwire_agent_task ---
  server.tool(
    'omniwire_agent_task',
    'Dispatch a task to a specific node for background execution and retrieve results later. Creates a task file on the node, runs it in background, and provides a task ID for polling. Designed for A2A (agent-to-agent) workflows where one agent dispatches work and another retrieves results.',
    {
      action: z.enum(['dispatch', 'status', 'result', 'list', 'cancel', 'dlq']).describe('Action. dlq=list tasks that failed (non-zero exit).'),
      node: z.string().optional().describe('Node (default: contabo)'),
      command: z.string().optional().describe('Command to dispatch (for dispatch action)'),
      task_id: z.string().optional().describe('Task ID (for status/result/cancel)'),
      label: z.string().optional(),
    },
    async ({ action, node, command, task_id, label }) => {
      const nodeId = node ?? 'contabo';
      const taskDir = '/tmp/.omniwire-tasks';

      if (action === 'dispatch') {
        if (!command) return fail('command required');
        const id = `ow-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`;
        const escaped = command.replace(/'/g, "'\\''");
        // On non-zero exit, copy task files to DLQ for later inspection
        const dlqCmd = `mkdir -p ${taskDir}/dlq && cp ${taskDir}/${id}.* ${taskDir}/dlq/ 2>/dev/null`;
        const script = `mkdir -p ${taskDir} && echo 'running' > ${taskDir}/${id}.status && echo '${label ?? command.slice(0, 60)}' > ${taskDir}/${id}.label && (bash -c '${escaped}' > ${taskDir}/${id}.stdout 2> ${taskDir}/${id}.stderr; _rc=$?; echo $_rc > ${taskDir}/${id}.exit; if [ $_rc -ne 0 ]; then ${dlqCmd}; fi; echo 'done' > ${taskDir}/${id}.status) &`;
        const result = await manager.exec(nodeId, script);
        return result.code === 0
          ? okBrief(`${nodeId} task dispatched: ${id}`)
          : fail(`dispatch failed: ${result.stderr}`);
      }

      if (action === 'status' && task_id) {
        const result = await manager.exec(nodeId, `cat ${taskDir}/${task_id}.status 2>/dev/null || echo 'not found'`);
        return okBrief(`${nodeId} ${task_id}: ${result.stdout.trim()}`);
      }

      if (action === 'result' && task_id) {
        const result = await manager.exec(nodeId, `echo "EXIT:$(cat ${taskDir}/${task_id}.exit 2>/dev/null)"; echo "---STDOUT---"; cat ${taskDir}/${task_id}.stdout 2>/dev/null; echo "---STDERR---"; cat ${taskDir}/${task_id}.stderr 2>/dev/null`);
        return ok(nodeId, result.durationMs, result.stdout, `task ${task_id}`);
      }

      if (action === 'list') {
        const result = await manager.exec(nodeId, `for f in ${taskDir}/*.status 2>/dev/null; do id=$(basename "$f" .status); echo "$id $(cat "$f") $(cat ${taskDir}/$id.label 2>/dev/null)"; done 2>/dev/null | tail -20`);
        return ok(nodeId, result.durationMs, result.stdout || '(no tasks)', 'task list');
      }

      if (action === 'cancel' && task_id) {
        await manager.exec(nodeId, `echo 'cancelled' > ${taskDir}/${task_id}.status`);
        return okBrief(`${nodeId} ${task_id} cancelled`);
      }

      if (action === 'dlq') {
        const result = await manager.exec(nodeId, `for f in ${taskDir}/dlq/*.status 2>/dev/null; do [ -f "$f" ] || continue; id=$(basename "$f" .status); rc=$(cat ${taskDir}/dlq/$id.exit 2>/dev/null || echo '?'); lbl=$(cat ${taskDir}/dlq/$id.label 2>/dev/null); echo "$id exit=$rc $lbl"; done 2>/dev/null | tail -20 || echo '(empty DLQ)'`);
        return ok(nodeId, result.durationMs, result.stdout || '(empty DLQ)', 'task DLQ');
      }

      return fail('invalid action/params');
    }
  );

  // --- Tool 38: omniwire_a2a_message ---
  server.tool(
    'omniwire_a2a_message',
    'Agent-to-agent messaging via shared message queues on mesh nodes. Agents can send/receive typed messages, enabling multi-agent coordination without direct coupling. Messages are stored on disk and survive process restarts.',
    {
      action: z.enum(['send', 'receive', 'peek', 'list_channels', 'clear']).describe('Action'),
      channel: z.string().optional().describe('Message channel name (e.g., "recon-results", "scan-tasks")'),
      node: z.string().optional().describe('Node hosting the queue (default: contabo)'),
      message: z.string().optional().describe('Message content (for send). Can be JSON.'),
      sender: z.string().optional().describe('Sender agent name (for send)'),
      count: z.number().optional().describe('Number of messages to receive (default: 1). Messages are dequeued on receive.'),
      schema: z.enum(['text', 'json', 'any']).optional().describe('Message format validation. json=must be valid JSON, text=plain string, any=no validation (default).'),
    },
    async ({ action, channel, node, message, sender, count, schema }) => {
      const nodeId = node ?? 'contabo';
      const queueDir = '/tmp/.omniwire-a2a';

      if (action === 'send') {
        if (!channel || !message) return fail('channel and message required');
        // Schema validation
        if (schema === 'json') {
          try { JSON.parse(message); } catch { return fail('schema=json but message is not valid JSON'); }
        }
        const ts = Date.now();
        const id = `${ts}-${Math.random().toString(36).slice(2, 6)}`;
        const payload = JSON.stringify({ id, ts, sender: sender ?? 'unknown', schema: schema ?? 'any', message });
        const escaped = payload.replace(/'/g, "'\\''");
        const result = await manager.exec(nodeId, `mkdir -p ${queueDir}/${channel} && echo '${escaped}' >> ${queueDir}/${channel}/queue`);
        return result.code === 0
          ? okBrief(`${channel}: message sent (${message.length} chars)`)
          : fail(result.stderr);
      }

      if (action === 'receive') {
        if (!channel) return fail('channel required');
        const n = count ?? 1;
        const result = await manager.exec(nodeId, `head -${n} ${queueDir}/${channel}/queue 2>/dev/null && sed -i '1,${n}d' ${queueDir}/${channel}/queue 2>/dev/null || echo '(empty queue)'`);
        return ok(nodeId, result.durationMs, result.stdout, `a2a recv ${channel}`);
      }

      if (action === 'peek') {
        if (!channel) return fail('channel required');
        const n = count ?? 5;
        const result = await manager.exec(nodeId, `head -${n} ${queueDir}/${channel}/queue 2>/dev/null || echo '(empty queue)'`);
        return ok(nodeId, result.durationMs, result.stdout, `a2a peek ${channel}`);
      }

      if (action === 'list_channels') {
        const result = await manager.exec(nodeId, `ls -1 ${queueDir}/ 2>/dev/null || echo '(no channels)'`);
        return ok(nodeId, result.durationMs, result.stdout, 'a2a channels');
      }

      if (action === 'clear') {
        if (!channel) return fail('channel required');
        await manager.exec(nodeId, `rm -f ${queueDir}/${channel}/queue`);
        return okBrief(`${channel}: cleared`);
      }

      return fail('invalid action');
    }
  );

  // --- Tool 39: omniwire_semaphore ---
  server.tool(
    'omniwire_semaphore',
    'Distributed locking / semaphore for multi-agent coordination. Prevents race conditions when multiple agents operate on the same resource. Uses atomic file-based locks on mesh nodes.',
    {
      action: z.enum(['acquire', 'release', 'status', 'list']).describe('Action'),
      lock_name: z.string().optional().describe('Lock name (e.g., "deploy-prod", "db-migration")'),
      node: z.string().optional().describe('Node hosting the lock (default: contabo)'),
      owner: z.string().optional().describe('Owner/agent name (for acquire)'),
      ttl: z.number().optional().describe('Lock TTL in seconds (default: 300). Auto-releases after TTL.'),
    },
    async ({ action, lock_name, node, owner, ttl }) => {
      const nodeId = node ?? 'contabo';
      const lockDir = '/tmp/.omniwire-locks';
      const ttlSec = ttl ?? 300;

      if (action === 'acquire') {
        if (!lock_name) return fail('lock_name required');
        const lockFile = `${lockDir}/${lock_name}.lock`;
        const ownerName = owner ?? 'agent';
        const now = Date.now();
        // Simple atomic lock: mkdir as atomic test-and-set, write owner info inside
        const acquireScript = [
          `mkdir -p ${lockDir}`,
          `if mkdir ${lockFile}.d 2>/dev/null; then`,
          `  echo '${ownerName}:${now}:${ttlSec}' > ${lockFile}`,
          `  echo 'acquired'`,
          `else`,
          `  cat ${lockFile} 2>/dev/null || echo 'locked (unknown owner)'`,
          `fi`,
        ].join('\n');
        const result = await manager.exec(nodeId, acquireScript);
        return okBrief(`${lock_name}: ${result.stdout.trim()}`);
      }

      if (action === 'release') {
        if (!lock_name) return fail('lock_name required');
        await manager.exec(nodeId, `rm -f ${lockDir}/${lock_name}.lock && rmdir ${lockDir}/${lock_name}.lock.d 2>/dev/null`);
        return okBrief(`${lock_name}: released`);
      }

      if (action === 'status') {
        if (!lock_name) return fail('lock_name required');
        const result = await manager.exec(nodeId, `cat ${lockDir}/${lock_name}.lock 2>/dev/null || echo '(unlocked)'`);
        return okBrief(`${lock_name}: ${result.stdout.trim()}`);
      }

      if (action === 'list') {
        const cmd = "for f in " + lockDir + "/*.lock 2>/dev/null; do [ -f \"$f\" ] && echo \"$(basename $f .lock): $(cat $f)\"; done 2>/dev/null || echo '(no locks)'";
        const result = await manager.exec(nodeId, cmd);
        return ok(nodeId, result.durationMs, result.stdout, 'locks');
      }

      return fail('invalid action');
    }
  );

  // --- Tool 40: omniwire_event ---
  server.tool(
    'omniwire_event',
    'Publish/subscribe events for agent coordination. Agents can emit events and other agents can poll for them. Events are timestamped and stored in a log for audit. Supports the ACP/A2A event-driven pattern.',
    {
      action: z.enum(['emit', 'poll', 'history', 'clear']).describe('Action'),
      topic: z.string().optional().describe('Event topic (e.g., "deploy.complete", "scan.found-vuln")'),
      node: z.string().optional().describe('Node hosting events (default: contabo)'),
      data: z.string().optional().describe('Event data/payload (for emit). Can be JSON.'),
      source: z.string().optional().describe('Source agent name (for emit)'),
      since: z.string().optional().describe('Only return events after this timestamp (epoch ms) for poll'),
      limit: z.number().optional().describe('Max events to return (default: 10)'),
      filter: z.string().optional().describe('Regex filter applied to event data during poll. Only matching events returned.'),
    },
    async ({ action, topic, node, data, source, since, limit, filter }) => {
      const nodeId = node ?? 'contabo';
      const eventDir = '/tmp/.omniwire-events';
      const n = limit ?? 10;

      if (action === 'emit') {
        if (!topic) return fail('topic required');
        const event = JSON.stringify({ ts: Date.now(), topic, source: source ?? 'agent', data: data ?? '' });
        const escaped = event.replace(/'/g, "'\\''");
        await manager.exec(nodeId, `mkdir -p ${eventDir} && echo '${escaped}' >> ${eventDir}/events.log`);
        return okBrief(`event emitted: ${topic}`);
      }

      if (action === 'poll') {
        let cmd: string;
        if (topic && since) {
          cmd = `grep '"topic":"${topic}"' ${eventDir}/events.log 2>/dev/null | awk -F'"ts":' '{split($2,a,","); if(a[1]>${since}) print}' | tail -${n}`;
        } else if (topic) {
          cmd = `grep '"topic":"${topic}"' ${eventDir}/events.log 2>/dev/null | tail -${n}`;
        } else if (since) {
          cmd = `awk -F'"ts":' '{split($2,a,","); if(a[1]>${since}) print}' ${eventDir}/events.log 2>/dev/null | tail -${n}`;
        } else {
          cmd = `tail -${n} ${eventDir}/events.log 2>/dev/null || echo '(no events)'`;
        }
        // Apply regex filter on event data if specified
        if (filter) {
          const escapedFilter = filter.replace(/'/g, "'\\''");
          cmd = `(${cmd}) | grep -E '${escapedFilter}' 2>/dev/null`;
        }
        const result = await manager.exec(nodeId, cmd);
        return ok(nodeId, result.durationMs, result.stdout || '(no events)', `events ${topic ?? 'all'}`);
      }

      if (action === 'history') {
        const result = await manager.exec(nodeId, `wc -l ${eventDir}/events.log 2>/dev/null | awk '{print $1}'`);
        const count = result.stdout.trim() || '0';
        return okBrief(`${count} events total`);
      }

      if (action === 'clear') {
        await manager.exec(nodeId, `rm -f ${eventDir}/events.log`);
        return okBrief('events cleared');
      }

      return fail('invalid action');
    }
  );

  // --- Tool 41: omniwire_workflow ---
  server.tool(
    'omniwire_workflow',
    'Define and execute a named workflow (DAG of steps) that can be reused. Workflows are stored on disk and can be triggered by any agent. Supports conditional steps, fan-out/fan-in, and cross-node orchestration.',
    {
      action: z.enum(['define', 'run', 'list', 'get', 'delete']).describe('Action'),
      name: z.string().optional().describe('Workflow name'),
      node: z.string().optional().describe('Node to store/run workflow (default: contabo)'),
      definition: z.string().optional().describe('JSON workflow definition for define action. Format: {steps: [{node, command, label, depends_on?, store_as?}]}'),
      format: z.enum(['text', 'json']).optional(),
    },
    async ({ action, name, node, definition, format }) => {
      const nodeId = node ?? 'contabo';
      const wfDir = '/tmp/.omniwire-workflows';
      const useJson = format === 'json';

      if (action === 'define') {
        if (!name || !definition) return fail('name and definition required');
        const escaped = definition.replace(/'/g, "'\\''");
        const result = await manager.exec(nodeId, `mkdir -p ${wfDir} && echo '${escaped}' > ${wfDir}/${name}.json`);
        return result.code === 0 ? okBrief(`workflow ${name} defined`) : fail(result.stderr);
      }

      if (action === 'run') {
        if (!name) return fail('name required');
        const readResult = await manager.exec(nodeId, `cat ${wfDir}/${name}.json 2>/dev/null`);
        if (readResult.code !== 0) return fail(`workflow ${name} not found`);

        let wf: { steps: Array<{ node?: string; command: string; label?: string; depends_on?: number[]; store_as?: string }> };
        try { wf = JSON.parse(readResult.stdout); } catch { return fail('invalid workflow definition'); }

        const stepResults: string[] = [];
        const stepOutputs: string[] = [];

        for (let i = 0; i < wf.steps.length; i++) {
          const step = wf.steps[i];
          const stepNode = step.node ?? nodeId;
          let cmd = step.command
            .replace(/\{\{step(\d+)\}\}/g, (_, n) => stepOutputs[parseInt(n)] ?? '')
            .replace(/\{\{(\w+)\}\}/g, (_, key) => resultStore.get(key) ?? `{{${key}}}`);

          const result = await manager.exec(stepNode, cmd);
          stepOutputs[i] = result.stdout.trim();
          if (step.store_as && result.code === 0) resultStore.set(step.store_as, result.stdout.trim());

          const status = result.code === 0 ? 'ok' : `exit ${result.code}`;
          stepResults.push(useJson
            ? JSON.stringify({ step: i, node: stepNode, label: step.label, ok: result.code === 0, code: result.code, ms: result.durationMs, stdout: result.stdout.slice(0, 1000) })
            : `[${i}] ${stepNode} > ${step.label ?? `step ${i}`}  ${t(result.durationMs)}  ${status}\n${result.stdout.split('\n').slice(0, 5).join('\n')}`);

          if (result.code !== 0) break;
        }

        return useJson ? okBrief(`[${stepResults.join(',')}]`) : okBrief(trim(stepResults.join('\n\n')));
      }

      if (action === 'list') {
        const result = await manager.exec(nodeId, `ls -1 ${wfDir}/*.json 2>/dev/null | xargs -I{} basename {} .json || echo '(no workflows)'`);
        return ok(nodeId, result.durationMs, result.stdout, 'workflows');
      }

      if (action === 'get') {
        if (!name) return fail('name required');
        const result = await manager.exec(nodeId, `cat ${wfDir}/${name}.json 2>/dev/null || echo 'not found'`);
        return ok(nodeId, result.durationMs, result.stdout, `workflow ${name}`);
      }

      if (action === 'delete') {
        if (!name) return fail('name required');
        await manager.exec(nodeId, `rm -f ${wfDir}/${name}.json`);
        return okBrief(`workflow ${name} deleted`);
      }

      return fail('invalid action');
    }
  );

  // --- Tool 42: omniwire_agent_registry ---
  server.tool(
    'omniwire_agent_registry',
    'Register/discover agents on the mesh. Agents announce their capabilities and other agents can discover them. Enables dynamic A2A routing and capability-based task delegation.',
    {
      action: z.enum(['register', 'deregister', 'discover', 'list', 'heartbeat']).describe('Action'),
      node: z.string().optional().describe('Node hosting registry (default: contabo)'),
      agent_id: z.string().optional().describe('Unique agent ID'),
      capabilities: z.array(z.string()).optional().describe('Agent capabilities (e.g., ["scan", "exploit", "report"])'),
      metadata: z.string().optional().describe('JSON metadata about the agent'),
      capability: z.string().optional().describe('Capability to search for (discover action)'),
    },
    async ({ action, node, agent_id, capabilities, metadata, capability }) => {
      const nodeId = node ?? 'contabo';
      const regDir = '/tmp/.omniwire-agents';

      if (action === 'register') {
        if (!agent_id) return fail('agent_id required');
        const entry = JSON.stringify({ id: agent_id, capabilities: capabilities ?? [], metadata: metadata ?? '{}', ts: Date.now(), node: nodeId });
        const escaped = entry.replace(/'/g, "'\\''");
        await manager.exec(nodeId, `mkdir -p ${regDir} && echo '${escaped}' > ${regDir}/${agent_id}.json`);
        return okBrief(`agent ${agent_id} registered (${(capabilities ?? []).join(', ')})`);
      }

      if (action === 'deregister') {
        if (!agent_id) return fail('agent_id required');
        await manager.exec(nodeId, `rm -f ${regDir}/${agent_id}.json`);
        return okBrief(`agent ${agent_id} deregistered`);
      }

      if (action === 'heartbeat') {
        if (!agent_id) return fail('agent_id required');
        await manager.exec(nodeId, `[ -f ${regDir}/${agent_id}.json ] && tmp=$(cat ${regDir}/${agent_id}.json) && echo "$tmp" | sed 's/"ts":[0-9]*/"ts":${Date.now()}/' > ${regDir}/${agent_id}.json`);
        return okBrief(`agent ${agent_id} heartbeat`);
      }

      if (action === 'discover' && capability) {
        const result = await manager.exec(nodeId, `grep -l '"${capability}"' ${regDir}/*.json 2>/dev/null | xargs -I{} cat {} 2>/dev/null`);
        return ok(nodeId, result.durationMs, result.stdout || '(no agents with that capability)', `discover ${capability}`);
      }

      if (action === 'list') {
        const result = await manager.exec(nodeId, `cat ${regDir}/*.json 2>/dev/null || echo '(no agents)'`);
        return ok(nodeId, result.durationMs, result.stdout, 'agent registry');
      }

      return fail('invalid action');
    }
  );

  // --- Tool 43: omniwire_blackboard ---
  server.tool(
    'omniwire_blackboard',
    'Shared blackboard for multi-agent collaboration. Agents post findings, hypotheses, and decisions to topic-scoped boards. Other agents read and build on them. Classic AI blackboard architecture for agent swarms.',
    {
      action: z.enum(['post', 'read', 'topics', 'clear', 'search']).describe('Action'),
      node: z.string().optional(),
      topic: z.string().optional().describe('Board topic (e.g., "recon-findings", "vuln-analysis")'),
      content: z.string().optional().describe('Content to post'),
      author: z.string().optional().describe('Author agent ID'),
      query: z.string().optional().describe('Search query (grep pattern) for search action'),
      limit: z.number().optional().describe('Max entries (default: 20)'),
    },
    async ({ action, node, topic, content, author, query, limit }) => {
      const nodeId = node ?? 'contabo';
      const bbDir = '/tmp/.omniwire-blackboard';
      const n = limit ?? 20;

      if (action === 'post') {
        if (!topic || !content) return fail('topic and content required');
        const entry = JSON.stringify({ ts: Date.now(), author: author ?? 'agent', content });
        const escaped = entry.replace(/'/g, "'\\''");
        await manager.exec(nodeId, `mkdir -p ${bbDir} && echo '${escaped}' >> ${bbDir}/${topic}.log`);
        cb('blackboard', `${topic}:${Date.now()}`, entry);  // persist to CyberBase
        return okBrief(`posted to ${topic} (${content.length} chars) [node + cyberbase]`);
      }

      if (action === 'read') {
        if (!topic) return fail('topic required');
        const result = await manager.exec(nodeId, `tail -${n} ${bbDir}/${topic}.log 2>/dev/null || echo '(empty board)'`);
        return ok(nodeId, result.durationMs, result.stdout, `board:${topic}`);
      }

      if (action === 'topics') {
        const result = await manager.exec(nodeId, `ls -1 ${bbDir}/*.log 2>/dev/null | xargs -I{} sh -c 'echo "$(basename {} .log) $(wc -l < {})"' 2>/dev/null || echo '(no topics)'`);
        return ok(nodeId, result.durationMs, result.stdout, 'blackboard topics');
      }

      if (action === 'search' && query) {
        const escaped = query.replace(/'/g, "'\\''");
        const topicFilter = topic ? `${bbDir}/${topic}.log` : `${bbDir}/*.log`;
        const result = await manager.exec(nodeId, `grep -h '${escaped}' ${topicFilter} 2>/dev/null | tail -${n}`);
        return ok(nodeId, result.durationMs, result.stdout || '(no matches)', `search:${query}`);
      }

      if (action === 'clear') {
        if (!topic) return fail('topic required');
        await manager.exec(nodeId, `rm -f ${bbDir}/${topic}.log`);
        return okBrief(`board ${topic} cleared`);
      }

      return fail('invalid action');
    }
  );

  // --- Tool 44: omniwire_task_queue ---
  server.tool(
    'omniwire_task_queue',
    'Distributed task queue for agent swarms. Producers enqueue tasks, consumer agents dequeue and process them. Supports priorities, deadlines, and result reporting. Core A2A work distribution primitive.',
    {
      action: z.enum(['enqueue', 'dequeue', 'complete', 'fail', 'status', 'pending']).describe('Action'),
      node: z.string().optional(),
      queue: z.string().optional().describe('Queue name (default: "default")'),
      task: z.string().optional().describe('Task payload (JSON) for enqueue'),
      priority: z.number().optional().describe('Priority 0-9, higher = more urgent (default: 5)'),
      task_id: z.string().optional().describe('Task ID for complete/fail'),
      result: z.string().optional().describe('Result data for complete'),
      error: z.string().optional().describe('Error message for fail'),
    },
    async ({ action, node, queue, task, priority, task_id, result: taskResult, error: taskError }) => {
      const nodeId = node ?? 'contabo';
      const qName = queue ?? 'default';
      const qDir = `/tmp/.omniwire-taskq/${qName}`;

      if (action === 'enqueue') {
        if (!task) return fail('task required');
        const id = `t-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`;
        const pri = priority ?? 5;
        const entry = JSON.stringify({ id, priority: pri, ts: Date.now(), status: 'pending', task: JSON.parse(task) });
        const escaped = entry.replace(/'/g, "'\\''");
        await manager.exec(nodeId, `mkdir -p ${qDir} && echo '${escaped}' > ${qDir}/${pri}_${id}.task`);
        return okBrief(`enqueued ${id} (priority ${pri})`);
      }

      if (action === 'dequeue') {
        // Take highest priority task (9 first, then 8, ...)
        const result = await manager.exec(nodeId, `f=$(ls -r ${qDir}/*.task 2>/dev/null | head -1); [ -n "$f" ] && cat "$f" && rm -f "$f" || echo '(empty queue)'`);
        return ok(nodeId, result.durationMs, result.stdout, `dequeue:${qName}`);
      }

      if (action === 'complete' && task_id) {
        const entry = JSON.stringify({ id: task_id, status: 'complete', ts: Date.now(), result: taskResult ?? '' });
        const escaped = entry.replace(/'/g, "'\\''");
        await manager.exec(nodeId, `mkdir -p ${qDir}/done && echo '${escaped}' > ${qDir}/done/${task_id}.result`);
        return okBrief(`task ${task_id} completed`);
      }

      if (action === 'fail' && task_id) {
        const entry = JSON.stringify({ id: task_id, status: 'failed', ts: Date.now(), error: taskError ?? 'unknown' });
        const escaped = entry.replace(/'/g, "'\\''");
        await manager.exec(nodeId, `mkdir -p ${qDir}/failed && echo '${escaped}' > ${qDir}/failed/${task_id}.result`);
        return okBrief(`task ${task_id} failed`);
      }

      if (action === 'status') {
        const result = await manager.exec(nodeId, `echo "pending: $(ls ${qDir}/*.task 2>/dev/null | wc -l)"; echo "done: $(ls ${qDir}/done/*.result 2>/dev/null | wc -l)"; echo "failed: $(ls ${qDir}/failed/*.result 2>/dev/null | wc -l)"`);
        return ok(nodeId, result.durationMs, result.stdout, `queue:${qName}`);
      }

      if (action === 'pending') {
        const result = await manager.exec(nodeId, `cat ${qDir}/*.task 2>/dev/null | head -20 || echo '(empty)'`);
        return ok(nodeId, result.durationMs, result.stdout, `pending:${qName}`);
      }

      return fail('invalid action');
    }
  );

  // --- Tool 45: omniwire_capability ---
  server.tool(
    'omniwire_capability',
    'Query node capabilities for intelligent task routing. Returns what tools, runtimes, and resources each node has. Agents use this to decide WHERE to dispatch tasks.',
    {
      node: z.string().optional().describe('Specific node (default: all online)'),
      check: z.array(z.string()).optional().describe('Specific capabilities to check (e.g., ["docker", "python3", "gpu", "nmap"])'),
    },
    async ({ node, check }) => {
      const checks = check ?? ['docker', 'python3', 'node', 'go', 'nmap', 'ffuf', 'git', 'psql', 'lz4', 'aria2c', 'gcc'];
      const cmd = checks.map((c) => `command -v ${c} >/dev/null 2>&1 && echo "${c}:yes" || echo "${c}:no"`).join('; ');

      if (node) {
        const result = await manager.exec(node, cmd);
        return ok(node, result.durationMs, result.stdout, 'capabilities');
      }

      const results = await manager.execAll(cmd);
      return multiResult(results);
    }
  );

  // --- Tool 46: omniwire_snippet ---
  server.tool(
    'omniwire_snippet',
    'Saved command templates on a node. Save reusable snippets with {{var}} placeholders, then run them with variable substitution.',
    {
      action: z.enum(['save', 'run', 'list', 'delete']).describe('save=store template, run=execute with var substitution, list=show all, delete=remove'),
      node: z.string().describe('Target node'),
      name: z.string().optional().describe('Snippet name (required for save/run/delete)'),
      command: z.string().optional().describe('Command template for save. Use {{var}} for placeholders.'),
      vars: z.string().optional().describe('Key=value pairs for run substitution, space-separated. E.g. "host=1.2.3.4 port=8080"'),
    },
    async ({ action, node, name, command, vars }) => {
      const snippetDir = '/tmp/.omniwire-snippets';

      if (action === 'list') {
        const result = await manager.exec(node, `mkdir -p ${snippetDir} && ls ${snippetDir}/ 2>/dev/null || echo '(no snippets)'`);
        return ok(node, result.durationMs, result.stdout, 'snippets');
      }

      if (action === 'save') {
        if (!name || !command) return fail('name and command required for save');
        const escaped = command.replace(/'/g, "'\\''");
        const result = await manager.exec(node, `mkdir -p ${snippetDir} && echo '${escaped}' > ${snippetDir}/${name}.sh && chmod +x ${snippetDir}/${name}.sh`);
        return result.code === 0
          ? okBrief(`${node} snippet saved: ${name}`)
          : fail(`${node} snippet save: ${result.stderr}`);
      }

      if (action === 'run') {
        if (!name) return fail('name required for run');
        const readResult = await manager.exec(node, `cat ${snippetDir}/${name}.sh 2>/dev/null`);
        if (readResult.code !== 0) return fail(`snippet ${name} not found`);

        let template = readResult.stdout.trim();
        if (vars) {
          for (const pair of vars.split(/\s+/)) {
            const eqIdx = pair.indexOf('=');
            if (eqIdx < 0) continue;
            const k = pair.slice(0, eqIdx);
            const v = pair.slice(eqIdx + 1);
            template = template.replace(new RegExp(`\\{\\{${k}\\}\\}`, 'g'), v);
          }
        }

        const result = await manager.exec(node, template);
        return ok(node, result.durationMs, fmtExecOutput(result, 30), `snippet:${name}`);
      }

      if (action === 'delete') {
        if (!name) return fail('name required for delete');
        const result = await manager.exec(node, `rm -f ${snippetDir}/${name}.sh`);
        return result.code === 0
          ? okBrief(`${node} snippet deleted: ${name}`)
          : fail(`${node} snippet delete: ${result.stderr}`);
      }

      return fail('invalid action');
    }
  );

  // --- Tool 47: omniwire_alias ---
  server.tool(
    'omniwire_alias',
    'In-session command shortcuts. Set short aliases for long commands, then run them by alias name on any node.',
    {
      action: z.enum(['set', 'get', 'list', 'delete', 'run']).describe('set=define alias, get=show command, list=all aliases, delete=remove, run=execute alias on node'),
      name: z.string().optional().describe('Alias name (required for set/get/delete/run)'),
      command: z.string().optional().describe('Command to alias (for set). Supports {{key}} interpolation.'),
      node: z.string().optional().describe('Node to run alias on (for run action). Default: contabo.'),
    },
    async ({ action, name, command, node }) => {
      if (action === 'list') {
        if (aliasStore.size === 0) return okBrief('(no aliases)');
        return okBrief([...aliasStore.entries()].map(([k, v]) => `${k} = ${v}`).join('\n'));
      }

      if (action === 'set') {
        if (!name || !command) return fail('name and command required');
        aliasStore.set(name, command);
        return okBrief(`alias set: ${name} = ${command.slice(0, 80)}`);
      }

      if (action === 'get') {
        if (!name) return fail('name required');
        const cmd = aliasStore.get(name);
        return cmd ? okBrief(`${name} = ${cmd}`) : fail(`alias ${name} not found`);
      }

      if (action === 'delete') {
        if (!name) return fail('name required');
        aliasStore.delete(name);
        return okBrief(`alias ${name} deleted`);
      }

      if (action === 'run') {
        if (!name) return fail('name required');
        const template = aliasStore.get(name);
        if (!template) return fail(`alias ${name} not found`);
        const nodeId = node ?? 'contabo';
        const resolved = template.replace(/\{\{(\w+)\}\}/g, (_, key) => resultStore.get(key) ?? `{{${key}}}`);
        const result = await manager.exec(nodeId, resolved);
        return ok(nodeId, result.durationMs, fmtExecOutput(result, 30), `alias:${name}`);
      }

      return fail('invalid action');
    }
  );

  // --- Tool 48: omniwire_trace ---
  server.tool(
    'omniwire_trace',
    'Distributed tracing across mesh nodes. Start a trace, record spans with timing, view a waterfall breakdown of where time was spent.',
    {
      action: z.enum(['start', 'stop', 'view']).describe('start=create trace, stop=mark complete, view=show all spans with waterfall'),
      trace_id: z.string().optional().describe('Trace ID (required for stop/view). Returned by start.'),
      node: z.string().optional().describe('Node where the span ran (for start)'),
      command: z.string().optional().describe('Command/label for this trace (for start)'),
    },
    async ({ action, trace_id, node, command }) => {
      if (action === 'start') {
        const id = `tr-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`;
        const nodeId = node ?? 'local';
        const startMs = Date.now();
        const span: TraceSpan = { node: nodeId, command: command ?? 'trace-start', startMs, endMs: startMs, result: 'started' };
        traceStore.set(id, { spans: [span], startMs, done: false });
        return okBrief(`trace started: ${id}`);
      }

      if (action === 'stop') {
        if (!trace_id) return fail('trace_id required');
        const trace = traceStore.get(trace_id);
        if (!trace) return fail(`trace ${trace_id} not found`);
        traceStore.set(trace_id, { ...trace, done: true });
        return okBrief(`trace ${trace_id} stopped (${t(Date.now() - trace.startMs)} total)`);
      }

      if (action === 'view') {
        if (!trace_id) {
          if (traceStore.size === 0) return okBrief('(no traces)');
          const traceList = [...traceStore.entries()].map(([id, tr]) =>
            `${id}  ${tr.done ? 'done' : 'running'}  ${tr.spans.length} spans  ${t(Date.now() - tr.startMs)}`
          );
          return okBrief(traceList.join('\n'));
        }
        const trace = traceStore.get(trace_id);
        if (!trace) return fail(`trace ${trace_id} not found`);
        const lastSpan = trace.spans[trace.spans.length - 1];
        const totalMs = (trace.done && lastSpan ? lastSpan.endMs : Date.now()) - trace.startMs || 1;
        const lines = [`trace ${trace_id}  ${trace.done ? 'done' : 'running'}  total: ${t(totalMs)}`, ''];
        for (const span of trace.spans) {
          const spanMs = span.endMs - span.startMs;
          const startOffset = span.startMs - trace.startMs;
          const barWidth = Math.max(1, Math.round((spanMs / totalMs) * 40));
          const padLeft = Math.round((startOffset / totalMs) * 40);
          const bar = ' '.repeat(padLeft) + '='.repeat(barWidth);
          lines.push(`${span.node.padEnd(12)} ${t(spanMs).padStart(7)}  |${bar}|  ${span.command.slice(0, 50)}`);
        }
        return okBrief(lines.join('\n'));
      }

      return fail('invalid action');
    }
  );

  // --- Tool 49: omniwire_doctor ---
  server.tool(
    'omniwire_doctor',
    'Full health diagnostic for mesh nodes. Checks SSH connectivity, disk, memory, load, Docker, nftables, WireGuard, required tools, OmniWire version, and CyberBase reachability.',
    {
      node: z.string().optional().describe('Target node id. Omit to check all online nodes.'),
    },
    async ({ node }) => {
      const diagnosticCmd = [
        `disk=$(df / --output=pcent | tail -1 | tr -d ' %'); [ "\${disk}" -lt 80 ] && echo "PASS disk \${disk}%" || { [ "\${disk}" -lt 90 ] && echo "WARN disk \${disk}%" || echo "FAIL disk \${disk}%"; }`,
        `mem=$(free | awk '/Mem:/{printf "%.0f", $3/$2*100}'); [ "\${mem}" -lt 85 ] && echo "PASS mem \${mem}%" || { [ "\${mem}" -lt 95 ] && echo "WARN mem \${mem}%" || echo "FAIL mem \${mem}%"; }`,
        `load=$(cat /proc/loadavg | awk '{print $1}'); norm=$(echo "$load" | awk '{printf "%.1f", $1}'); echo "$norm" | awk '{if($1<1.5) print "PASS load " $1; else if($1<4) print "WARN load " $1; else print "FAIL load " $1}'`,
        `docker info >/dev/null 2>&1 && echo "PASS docker running" || echo "WARN docker not running"`,
        `nft list tables >/dev/null 2>&1 && echo "PASS nftables loaded" || echo "WARN nftables not loaded"`,
        `ip link show wg0 >/dev/null 2>&1 && echo "PASS wireguard wg0 up" || echo "WARN wireguard wg0 not found"`,
        `for tool in curl tar gzip lz4 nc; do command -v $tool >/dev/null 2>&1 && echo "PASS tool:$tool" || echo "FAIL tool:$tool missing"; done`,
        `omniwire --version >/dev/null 2>&1 && echo "PASS omniwire installed" || echo "WARN omniwire binary not in PATH"`,
        `timeout 3 bash -c 'echo "" | nc -w2 10.10.0.1 5432' 2>/dev/null && echo "PASS cyberbase reachable" || echo "WARN cyberbase 10.10.0.1:5432 unreachable"`,
      ].join('; ');

      const targetNodes = node ? [node] : manager.getOnlineNodes();
      const results = await Promise.all(targetNodes.map(async (n) => {
        const r = await manager.exec(n, diagnosticCmd);
        return { ...r, nodeId: n };
      }));

      const parts = results.map((r) => {
        if (r.code === -1) return `-- ${r.nodeId}\nFAIL ssh connectivity`;
        const lines = r.stdout.split('\n').filter(Boolean);
        const pass = lines.filter((l) => l.startsWith('PASS')).length;
        const warn = lines.filter((l) => l.startsWith('WARN')).length;
        const failCount = lines.filter((l) => l.startsWith('FAIL')).length;
        return `-- ${r.nodeId}  pass=${pass} warn=${warn} fail=${failCount}  ${t(r.durationMs)}\n${lines.join('\n')}`;
      });

      return okBrief(trim(parts.join('\n\n')));
    }
  );

  // --- Tool 50: omniwire_metrics ---
  server.tool(
    'omniwire_metrics',
    'Collect and export Prometheus-compatible metrics from mesh nodes. Scrape returns current values; export formats as Prometheus text exposition.',
    {
      action: z.enum(['scrape', 'export']).describe('scrape=collect current metrics, export=Prometheus text format'),
      node: z.string().optional().describe('Specific node to scrape (default: all online nodes)'),
    },
    async ({ action, node }) => {
      const metricsCmd = [
        `echo "uptime_seconds=$(cat /proc/uptime | awk '{print int($1)}')"`,
        `echo "mem_used_pct=$(free | awk '/Mem:/{printf \"%.1f\", $3/$2*100}')"`,
        `echo "disk_used_pct=$(df / --output=pcent | tail -1 | tr -d ' %')"`,
        `echo "load_1m=$(cat /proc/loadavg | awk '{print $1}')"`,
        `echo "tcp_connections=$(ss -s | awk '/TCP:/{print $2}')"`,
        `echo "docker_containers=$(docker ps -q 2>/dev/null | wc -l | tr -d ' ')"`,
      ].join('; ');

      const parseMetrics = (raw: string): Record<string, string> =>
        Object.fromEntries(
          raw.split('\n').filter(Boolean).map((l) => {
            const idx = l.indexOf('=');
            return [l.slice(0, idx), l.slice(idx + 1)] as [string, string];
          })
        );

      const targetNodes = node ? [node] : manager.getOnlineNodes();
      const nodeResults = await Promise.all(targetNodes.map(async (n) => {
        const start = Date.now();
        const r = await manager.exec(n, metricsCmd);
        return { nodeId: n, raw: r.stdout, latencyMs: Date.now() - start, ok: r.code === 0 };
      }));

      if (action === 'scrape') {
        const parts = nodeResults.map((r) => {
          if (!r.ok) return `-- ${r.nodeId}  OFFLINE`;
          const m = parseMetrics(r.raw);
          return `-- ${r.nodeId}  lat=${r.latencyMs}ms\n` +
            `   mem=${m['mem_used_pct'] ?? '--'}%  disk=${m['disk_used_pct'] ?? '--'}%  ` +
            `load=${m['load_1m'] ?? '--'}  tcp=${m['tcp_connections'] ?? '--'}  ` +
            `docker=${m['docker_containers'] ?? '--'}  uptime=${m['uptime_seconds'] ?? '--'}s`;
        });
        return okBrief(parts.join('\n'));
      }

      // Prometheus text exposition format
      const promLines: string[] = [
        '# HELP omniwire_node_latency_ms SSH round-trip latency in milliseconds',
        '# TYPE omniwire_node_latency_ms gauge',
        ...nodeResults.map((r) => `omniwire_node_latency_ms{node="${r.nodeId}"} ${r.latencyMs}`),
      ];
      const metricDefs: Array<{ key: string; name: string; help: string; metricType: string }> = [
        { key: 'mem_used_pct', name: 'omniwire_node_mem_used_pct', help: 'Memory used percentage', metricType: 'gauge' },
        { key: 'disk_used_pct', name: 'omniwire_node_disk_used_pct', help: 'Disk used percentage on /', metricType: 'gauge' },
        { key: 'load_1m', name: 'omniwire_node_load_1m', help: '1-minute load average', metricType: 'gauge' },
        { key: 'tcp_connections', name: 'omniwire_node_tcp_connections', help: 'Total TCP connections', metricType: 'gauge' },
        { key: 'docker_containers', name: 'omniwire_node_docker_containers', help: 'Running Docker containers', metricType: 'gauge' },
        { key: 'uptime_seconds', name: 'omniwire_node_uptime_seconds', help: 'Node uptime in seconds', metricType: 'counter' },
      ];
      for (const def of metricDefs) {
        promLines.push(`# HELP ${def.name} ${def.help}`, `# TYPE ${def.name} ${def.metricType}`);
        for (const r of nodeResults) {
          if (!r.ok) continue;
          const val = parseMetrics(r.raw)[def.key];
          if (val !== undefined) promLines.push(`${def.name}{node="${r.nodeId}"} ${val}`);
        }
      }
      return okBrief(promLines.join('\n'));
    }
  );

  // --- Tool 51: omniwire_audit ---
  server.tool(
    'omniwire_audit',
    'View and search the command audit log. All omniwire_exec calls are automatically logged. Supports viewing recent entries, filtering, and computing stats.',
    {
      action: z.enum(['view', 'search', 'clear', 'stats']).describe('view=last N entries, search=filter by node/tool/pattern, clear=wipe log, stats=count/duration/error rate'),
      limit: z.number().optional().describe('Number of entries to show (default 50)'),
      node_filter: z.string().optional().describe('Filter by node name'),
      pattern: z.string().optional().describe('Regex pattern to match against command string'),
    },
    async ({ action, limit, node_filter, pattern }) => {
      if (action === 'clear') {
        auditLog.length = 0;
        return okBrief('audit log cleared');
      }

      if (action === 'stats') {
        if (auditLog.length === 0) return okBrief('audit log empty');
        const byNode = new Map<string, { count: number; errors: number; totalMs: number }>();
        for (const entry of auditLog) {
          const s = byNode.get(entry.node) ?? { count: 0, errors: 0, totalMs: 0 };
          s.count++;
          if (entry.code !== 0) s.errors++;
          s.totalMs += entry.durationMs;
          byNode.set(entry.node, s);
        }
        const statLines = [`audit log: ${auditLog.length} entries`, ''];
        for (const [n, s] of [...byNode.entries()].sort((a, b) => b[1].count - a[1].count)) {
          const errRate = ((s.errors / s.count) * 100).toFixed(1);
          const avgMs = (s.totalMs / s.count).toFixed(0);
          statLines.push(`${n.padEnd(12)}  calls=${s.count}  errors=${s.errors} (${errRate}%)  avg=${avgMs}ms`);
        }
        return okBrief(statLines.join('\n'));
      }

      let entries = [...auditLog];
      if (node_filter) entries = entries.filter((e) => e.node === node_filter);
      if (pattern) {
        const regex = new RegExp(pattern, 'i');
        entries = entries.filter((e) => regex.test(e.command));
      }

      const n = limit ?? 50;
      const slice = entries.slice(-n);
      if (slice.length === 0) return okBrief('(no entries)');

      const entryLines = slice.map((e) => {
        const ts = new Date(e.ts).toISOString().slice(11, 19);
        const status = e.code === 0 ? 'ok' : `exit ${e.code}`;
        return `${ts}  ${e.node.padEnd(10)}  ${e.tool.padEnd(6)}  ${status.padEnd(8)}  ${t(e.durationMs).padStart(6)}  ${e.command.slice(0, 60)}`;
      });
      return okBrief(entryLines.join('\n'));
    }
  );

  // --- Tool 52: omniwire_plugin ---
  server.tool(
    'omniwire_plugin',
    'Plugin system loader. Scan and inspect JS plugin files in /etc/omniwire/plugins/ or ~/.omniwire/plugins/ on any node.',
    {
      action: z.enum(['list', 'load', 'unload', 'info']).describe('list=scan plugin dirs, load=mark plugin active (future), unload=mark inactive, info=show plugin header'),
      node: z.string().optional().describe('Target node (default: contabo)'),
      plugin_name: z.string().optional().describe('Plugin file name without .js extension (for load/unload/info)'),
    },
    async ({ action, node, plugin_name }) => {
      const nodeId = node ?? 'contabo';
      const pluginDirs = ['/etc/omniwire/plugins', '~/.omniwire/plugins'];

      if (action === 'list') {
        const scanCmd = pluginDirs
          .map((dir) => `[ -d "${dir}" ] && for f in "${dir}"/*.js; do [ -f "$f" ] || continue; name=$(basename "$f" .js); desc=$(head -1 "$f" | sed 's|^// *||;s|^/\\* *||;s| *\\*/$||'); echo "$name  $dir  $desc"; done`)
          .join('; ');
        const result = await manager.exec(nodeId, `(${scanCmd}) 2>/dev/null || echo "(no plugins found)"`);
        return ok(nodeId, result.durationMs, result.stdout || '(no plugins found)', 'plugins');
      }

      if (action === 'info') {
        if (!plugin_name) return fail('plugin_name required');
        const findCmd = pluginDirs.map((dir) => `[ -f "${dir}/${plugin_name}.js" ] && echo "${dir}/${plugin_name}.js"`).join('; ');
        const pathResult = await manager.exec(nodeId, `(${findCmd}) 2>/dev/null | head -1`);
        const pluginPath = pathResult.stdout.trim();
        if (!pluginPath) return fail(`plugin ${plugin_name} not found in plugin dirs`);
        const result = await manager.exec(nodeId, `head -20 "${pluginPath}"`);
        return ok(nodeId, result.durationMs, result.stdout, `plugin:${plugin_name}`);
      }

      if (action === 'load') {
        if (!plugin_name) return fail('plugin_name required');
        const findCmd = pluginDirs.map((dir) => `[ -f "${dir}/${plugin_name}.js" ] && echo "${dir}/${plugin_name}.js"`).join('; ');
        const pathResult = await manager.exec(nodeId, `(${findCmd}) 2>/dev/null | head -1`);
        const pluginPath = pathResult.stdout.trim();
        if (!pluginPath) return fail(`plugin ${plugin_name} not found`);
        return okBrief(`plugin ${plugin_name} located at ${pluginPath} — dynamic load pending runtime support`);
      }

      if (action === 'unload') {
        if (!plugin_name) return fail('plugin_name required');
        return okBrief(`plugin ${plugin_name} unloaded (in-memory only — no persistent state)`);
      }

      return fail('invalid action');
    }
  );

  return server;
}
