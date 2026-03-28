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

function fmtExecOutput(result: { code: number; stdout: string; stderr: string }, timeoutSec: number): string {
  if (result.code === 0) return result.stdout || '(empty)';
  if (result.code === 124) return `TIMEOUT ${timeoutSec}s\n${result.stdout || '(empty)'}`;
  return `exit ${result.code}\n${result.stderr}`;
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
// -----------------------------------------------------------------------------

export function createOmniWireServer(manager: NodeManager, transfer: TransferEngine): McpServer {
  const server = new McpServer({
    name: 'omniwire',
    version: '2.3.0',
  });

  const shells = new ShellManager(manager);
  const realtime = new RealtimeChannel(manager);
  const tunnels = new TunnelManager(manager);

  // --- Tool 1: omniwire_exec ---
  server.tool(
    'omniwire_exec',
    'Execute a command on a specific mesh node. Defaults to auto-selecting based on command context.',
    {
      node: z.string().optional().describe('Target node id (windows, contabo, hostinger, thinkpad). Auto-selects if omitted.'),
      command: z.string().optional().describe('Shell command to run on the remote node via SSH'),
      timeout: z.number().optional().describe('Timeout in seconds (default 30)'),
      script: z.string().optional().describe('Multi-line script content. Sent as temp file via SFTP then executed. Use this instead of command for scripts >3 lines to keep tool calls compact.'),
      label: z.string().optional().describe('Short label for the operation (shown in tool call UI instead of full command). Max 60 chars.'),
    },
    // Remote SSH2 execution -- manager.exec() uses ssh2 client.exec(), not child_process
    async ({ node, command, timeout, script, label }) => {
      if (!command && !script) {
        return fail('either command or script is required');
      }
      const nodeId = node ?? 'contabo';
      const timeoutSec = timeout ?? 30;

      let effectiveCmd: string;

      if (script) {
        const tmpFile = `/tmp/.ow-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
        effectiveCmd = `cat << 'OMNIWIRE_SCRIPT_EOF' > ${tmpFile}\n${script}\nOMNIWIRE_SCRIPT_EOF\nchmod +x ${tmpFile} && timeout ${timeoutSec} ${tmpFile}; _rc=$?; rm -f ${tmpFile}; exit $_rc`;
      } else {
        effectiveCmd = timeoutSec < 300
          ? `timeout ${timeoutSec} bash -c '${command!.replace(/'/g, "'\\''")}'`
          : command!;
      }

      const result = await manager.exec(nodeId, effectiveCmd);
      return ok(nodeId, result.durationMs, fmtExecOutput(result, timeoutSec), label ?? undefined);
    }
  );

  // --- Tool 2: omniwire_broadcast ---
  server.tool(
    'omniwire_broadcast',
    'Execute a command on all online mesh nodes simultaneously.',
    {
      command: z.string().describe('Shell command to run on all nodes'),
      nodes: z.array(z.string()).optional().describe('Subset of nodes to target. All online nodes if omitted.'),
    },
    async ({ command, nodes: targetNodes }) => {
      const results = targetNodes
        ? await manager.execOn(targetNodes, command)
        : await manager.execAll(command);
      return multiResult(results);
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

  // --- Tool 25: omniwire_batch (multiple commands, single tool call) ---
  server.tool(
    'omniwire_batch',
    'Run multiple commands on one or more nodes in a single tool call. Returns all results. Use this to avoid multiple sequential omniwire_exec calls.',
    {
      commands: z.array(z.object({
        node: z.string().optional().describe('Node id (default: contabo)'),
        command: z.string().describe('Command to run'),
        label: z.string().optional().describe('Short label for this command'),
      })).describe('Array of commands to execute'),
      parallel: z.boolean().optional().describe('Run all commands in parallel (default: true)'),
    },
    async ({ commands, parallel }) => {
      const runParallel = parallel !== false;

      const execute = async (item: { node?: string; command: string; label?: string }) => {
        const nodeId = item.node ?? 'contabo';
        const result = await manager.exec(nodeId, item.command);
        const lbl = item.label ?? item.command.slice(0, 40);
        const body = result.code === 0
          ? (result.stdout || '(empty)').split('\n').slice(0, 20).join('\n')
          : `exit ${result.code}: ${result.stderr.split('\n').slice(0, 5).join('\n')}`;
        return `-- ${nodeId} > ${lbl}  ${t(result.durationMs)}\n${body}`;
      };

      const results = runParallel
        ? await Promise.all(commands.map(execute))
        : await commands.reduce<Promise<string[]>>(async (acc, cmd) => {
            const prev = await acc;
            const result = await execute(cmd);
            return [...prev, result];
          }, Promise.resolve([]));

      return okBrief(trim(results.join('\n\n')));
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

  // --- Tool 30: omniwire_clipboard ---
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

  return server;
}
