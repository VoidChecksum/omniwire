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
  return s.length > MAX_OUTPUT ? s.slice(0, MAX_OUTPUT) + '\n...(truncated)' : s;
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

// -- Agentic state -- shared across tool calls in the same MCP session --------
const resultStore = new Map<string, string>();  // key -> value store for chaining

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
// -----------------------------------------------------------------------------

export function createOmniWireServer(manager: NodeManager, transfer: TransferEngine): McpServer {
  const server = new McpServer({
    name: 'omniwire',
    version: '2.6.0',
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

      let result = await manager.exec(nodeId, effectiveCmd);
      for (let attempt = 0; attempt < maxRetries && result.code !== 0; attempt++) {
        await new Promise((r) => setTimeout(r, 1000));
        result = await manager.exec(nodeId, effectiveCmd);
      }

      if (store_as && result.code === 0) {
        resultStore.set(store_as, result.stdout.trim());
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
    'Manage VPN on mesh nodes (Mullvad/OpenVPN/WireGuard). SAFE: uses split-tunneling or network namespaces — mesh connectivity (WireGuard, SSH) is never disrupted. Use via_vpn on omniwire_exec to route individual commands through VPN.',
    {
      action: z.enum(['connect', 'disconnect', 'status', 'list', 'ip', 'rotate', 'full-on', 'full-off']).describe('connect=start VPN (split-tunnel, mesh safe), disconnect=stop, status=current state, list=servers/relays, ip=public IP, rotate=new exit, full-on=node-wide VPN with mesh exclusions, full-off=restore default routing'),
      node: z.string().optional().describe('Node to manage VPN on (default: contabo)'),
      provider: z.enum(['mullvad', 'openvpn', 'wireguard', 'tailscale']).optional().describe('VPN provider (default: auto-detect)'),
      server: z.string().optional().describe('Server/relay to connect to. Mullvad: country code (us, de, se) or relay name. OpenVPN: config file path. WireGuard: interface name. Tailscale: exit node hostname.'),
      config: z.string().optional().describe('OpenVPN config file path (for openvpn provider)'),
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
            const relay = vpnServer ? `mullvad relay set location ${vpnServer} && ` : '';
            const result = await manager.exec(nodeId, `${splitSetup} ${relay}mullvad connect && sleep 2 && mullvad status && echo "--- mesh check ---" && ip route get 10.10.0.1 2>/dev/null | head -1`);
            return ok(nodeId, result.durationMs, result.stdout, `mullvad connect${vpnServer ? ` ${vpnServer}` : ''}`);
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

  // --- Tool 31: omniwire_clipboard ---
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
    'Key-value store for chaining results across tool calls in the same session. Agents can store intermediate results and retrieve them later. Keys persist until session ends.',
    {
      action: z.enum(['get', 'set', 'delete', 'list', 'clear']).describe('Action'),
      key: z.string().optional().describe('Key name (required for get/set/delete)'),
      value: z.string().optional().describe('Value to store (for set)'),
    },
    async ({ action, key, value }) => {
      switch (action) {
        case 'get':
          if (!key) return fail('key required');
          return okBrief(resultStore.get(key) ?? '(not found)');
        case 'set':
          if (!key || value === undefined) return fail('key and value required');
          resultStore.set(key, value);
          return okBrief(`stored ${key} (${value.length} chars)`);
        case 'delete':
          if (!key) return fail('key required');
          resultStore.delete(key);
          return okBrief(`deleted ${key}`);
        case 'list':
          if (resultStore.size === 0) return okBrief('(empty store)');
          return okBrief([...resultStore.entries()].map(([k, v]) => `${k} = ${v.slice(0, 80)}${v.length > 80 ? '...' : ''}`).join('\n'));
        case 'clear':
          resultStore.clear();
          return okBrief('store cleared');
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
      action: z.enum(['dispatch', 'status', 'result', 'list', 'cancel']).describe('Action'),
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
        const script = `mkdir -p ${taskDir} && echo 'running' > ${taskDir}/${id}.status && echo '${label ?? command.slice(0, 60)}' > ${taskDir}/${id}.label && (bash -c '${escaped}' > ${taskDir}/${id}.stdout 2> ${taskDir}/${id}.stderr; echo $? > ${taskDir}/${id}.exit; echo 'done' > ${taskDir}/${id}.status) &`;
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
    },
    async ({ action, channel, node, message, sender, count }) => {
      const nodeId = node ?? 'contabo';
      const queueDir = '/tmp/.omniwire-a2a';

      if (action === 'send') {
        if (!channel || !message) return fail('channel and message required');
        const ts = Date.now();
        const id = `${ts}-${Math.random().toString(36).slice(2, 6)}`;
        const payload = JSON.stringify({ id, ts, sender: sender ?? 'unknown', message });
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
    },
    async ({ action, topic, node, data, source, since, limit }) => {
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
        return okBrief(`posted to ${topic} (${content.length} chars)`);
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

  return server;
}
