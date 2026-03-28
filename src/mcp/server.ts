// OmniWire MCP Server â 34-tool universal AI agent interface (25 core + 9 CyberSync)
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

// Compact output helpers  keeps Claude Code tool results clean
function ok(node: string, ms: number, body: string, label?: string): { content: [{ type: 'text'; text: string }] } {
  const tag = label ?? node;
  return { content: [{ type: 'text' as const, text: `[${tag}] (${ms}ms)
${body}` }] };
}

function fail(msg: string): { content: [{ type: 'text'; text: string }] } {
  return { content: [{ type: 'text' as const, text: msg }] };
}

export function createOmniWireServer(manager: NodeManager, transfer: TransferEngine): McpServer {
  const server = new McpServer({
    name: 'omniwire',
    version: '2.2.1',
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
    // Remote SSH2 execution â manager.exec() uses ssh2 client.exec(), not child_process
    async ({ node, command, timeout, script, label }) => {
      if (!command && !script) {
        return fail('Error: either command or script is required');
      }
      const nodeId = node ?? 'contabo';
      const timeoutSec = timeout ?? 30;

      let effectiveCmd: string;

      if (script) {
        // Multi-line script: write to temp file via SSH, execute, clean up
        const tmpFile = `/tmp/.ow-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
        effectiveCmd = `cat << 'OMNIWIRE_SCRIPT_EOF' > ${tmpFile}\n${script}\nOMNIWIRE_SCRIPT_EOF\nchmod +x ${tmpFile} && timeout ${timeoutSec} ${tmpFile}; _rc=$?; rm -f ${tmpFile}; exit $_rc`;
      } else {
        effectiveCmd = timeoutSec < 300
          ? `timeout ${timeoutSec} bash -c '${command!.replace(/'/g, "'\\''")}'`
          : command!;
      }

      const result = await manager.exec(nodeId, effectiveCmd);
      const output = result.code === 0
        ? result.stdout || '(no output)'
        : result.code === 124
          ? `Timeout after ${timeoutSec}s: ${result.stdout || '(no output)'}`
          : `Error (exit ${result.code}): ${result.stderr}`;
      return ok(nodeId, result.durationMs, output, label ?? undefined);
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
      const text = results.map((r) => {
        const body = r.code === 0 ? r.stdout || '(no output)' : `Error: ${r.stderr}`;
        return `[${r.nodeId}] (${r.durationMs}ms)\n${body}`;
      }).join('\n\n');
      return { content: [{ type: 'text', text }] };
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
        const node = allNodes().find((n) => n.id === s.nodeId);
        const role = NODE_ROLES[s.nodeId] ?? 'unknown';
        const status = s.online ? 'ONLINE' : 'OFFLINE';
        const lat = s.latencyMs !== null ? `${s.latencyMs}ms` : '-';
        const mem = s.memUsedPct !== null ? `${s.memUsedPct.toFixed(0)}%` : '-';
        const disk = s.diskUsedPct !== null ? `${s.diskUsedPct.toFixed(0)}%` : '-';
        return `${s.nodeId} (${role}) | ${node?.host ?? '-'} | ${status} | lat=${lat} | load=${s.loadAvg ?? '-'} | mem=${mem} | disk=${disk}`;
      });
      return { content: [{ type: 'text', text: lines.join('\n') }] };
    }
  );

  // --- Tool 4: omniwire_node_info ---
  server.tool(
    'omniwire_node_info',
    'Get detailed information about a specific node.',
    { node: z.string().describe('Node id') },
    async ({ node }) => {
      const meshNode = findNode(node);
      if (!meshNode) return { content: [{ type: 'text', text: `Unknown node: ${node}` }] };
      const status = await manager.getNodeStatus(meshNode.id);
      const role = NODE_ROLES[meshNode.id] ?? 'unknown';
      const text = [
        `Node: ${meshNode.id} (${meshNode.alias})`,
        `Role: ${role}`,
        `Host: ${meshNode.host}:${meshNode.port}`,
        `OS: ${meshNode.os}`,
        `Tags: ${meshNode.tags.join(', ')}`,
        `Status: ${status.online ? 'ONLINE' : 'OFFLINE'}`,
        `Latency: ${status.latencyMs ?? '-'}ms`,
        `Uptime: ${status.uptime ?? '-'}`,
        `Load: ${status.loadAvg ?? '-'}`,
        `Memory: ${status.memUsedPct !== null ? `${status.memUsedPct.toFixed(1)}%` : '-'}`,
        `Disk: ${status.diskUsedPct !== null ? `${status.diskUsedPct.toFixed(0)}%` : '-'}`,
      ].join('\n');
      return { content: [{ type: 'text', text }] };
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
        return { content: [{ type: 'text', text: content }] };
      } catch (e) {
        return { content: [{ type: 'text', text: `Error: ${(e as Error).message}` }] };
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
        return { content: [{ type: 'text', text: `Written ${filePath} on ${nodeId}` }] };
      } catch (e) {
        return { content: [{ type: 'text', text: `Error: ${(e as Error).message}` }] };
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
      if (!srcParsed) return { content: [{ type: 'text', text: `Invalid source path: ${src}. Use node:/path format.` }] };
      if (!dstParsed) return { content: [{ type: 'text', text: `Invalid dest path: ${dst}. Use node:/path format.` }] };

      try {
        const result = await transfer.transfer(
          srcParsed.nodeId, srcParsed.path,
          dstParsed.nodeId, dstParsed.path,
          mode ? { mode } : undefined
        );
        return { content: [{ type: 'text', text: `Transferred ${result.bytesTransferred} bytes via ${result.mode} in ${result.durationMs}ms (${result.speedMBps.toFixed(1)} MB/s)` }] };
      } catch (e) {
        return { content: [{ type: 'text', text: `Transfer error: ${(e as Error).message}` }] };
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
        return { content: [{ type: 'text', text: text || '(empty directory)' }] };
      } catch (e) {
        return { content: [{ type: 'text', text: `Error: ${(e as Error).message}` }] };
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

      const text = results.map((r) => {
        const body = r.code === 0 ? r.stdout || '(no matches)' : `Error: ${r.stderr}`;
        return `[${r.nodeId}]\n${body}`;
      }).join('\n\n');
      return { content: [{ type: 'text', text }] };
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
      const text = result.code === 0 ? result.stdout : `Error: ${result.stderr}`;
      return { content: [{ type: 'text', text: `[${node}] ${path} (last ${n} lines)\n${text}` }] };
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

      const text = results.map((r) => `[${r.nodeId}]\n${r.stdout}`).join('\n\n');
      return { content: [{ type: 'text', text }] };
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

      const text = results.map((r) => `[${r.nodeId}]\n${r.stdout}`).join('\n\n');
      return { content: [{ type: 'text', text }] };
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
      const text = result.code === 0
        ? `Installed ${package_name} via ${pm} on ${node}`
        : `Install failed: ${result.stderr}`;
      return { content: [{ type: 'text', text }] };
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
      const text = result.code === 0 ? result.stdout || `${action} ${service}: OK` : `Error: ${result.stderr}`;
      return { content: [{ type: 'text', text: `[${node}] ${text}` }] };
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
      const text = result.code === 0 ? result.stdout : `Error: ${result.stderr}`;
      return { content: [{ type: 'text', text: `[${nodeId}] docker ${command}\n${text}` }] };
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
      return { content: [{ type: 'text', text: result }] };
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
        const text = list.length === 0
          ? 'No active tunnels'
          : list.map((t) => `${t.id}: localhost:${t.localPort} â ${t.nodeId}:${t.remotePort}`).join('\n');
        return { content: [{ type: 'text', text }] };
      }
      if (act === 'close' && tunnel_id) {
        tunnels.close(tunnel_id);
        return { content: [{ type: 'text', text: `Closed tunnel ${tunnel_id}` }] };
      }
      try {
        const info = await tunnels.create(node, local_port, remote_port, remote_host);
        return { content: [{ type: 'text', text: `Tunnel ${info.id}: localhost:${info.localPort} â ${info.nodeId}:${info.remotePort}` }] };
      } catch (e) {
        return { content: [{ type: 'text', text: `Error: ${(e as Error).message}` }] };
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

      // Parallel deployment to all targets
      const settled = await Promise.allSettled(
        targets.map(async (dst) => {
          const r = await transfer.transfer(src_node, src_path, dst, dst_path);
          return { dst, speed: r.speedMBps };
        })
      );

      const results = settled.map((s, i) =>
        s.status === 'fulfilled'
          ? `${s.value.dst}: OK (${s.value.speed.toFixed(1)} MB/s)`
          : `${targets[i]}: FAILED â ${(s.reason as Error).message}`
      );

      return { content: [{ type: 'text', text: `Deploy ${src_path} â ${dst_path}\n${results.join('\n')}` }] };
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
      return { content: [{ type: 'text', text: `[${node}] ${operation} ${args ?? ''}\n${output}` }] };
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

      return { content: [{ type: 'text', text: `[${node}] stream: ${command}\n${output}` }] };
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
      return { content: [{ type: 'text', text: `[${node}] persistent shell\n${output}` }] };
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
        case 'all': cmd = "echo '=== CPU ===' && top -bn1 | head -5 && echo '=== MEM ===' && free -h && echo '=== DISK ===' && df -h / 2>/dev/null"; break;
      }

      const results = await manager.execAll(cmd);
      const text = results.map((r) => `[${r.nodeId}]\n${r.stdout}`).join('\n\n');
      return { content: [{ type: 'text', text }] };
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
      const displayLabel = label ? ` (${label})` : '';
      const output = result.code === 0
        ? result.stdout || '(no output)'
        : result.code === 124
          ? `Timeout after ${timeoutSec}s: ${result.stdout || '(no output)'}`
          : `Error (exit ${result.code}): ${result.stderr}`;
      return { content: [{ type: 'text', text: `[${nodeId}]${displayLabel} (${result.durationMs}ms)\n${output}` }] };
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
        const lbl = item.label ? ` ${item.label}` : '';
        const output = result.code === 0
          ? result.stdout || '(no output)'
          : `Error (exit ${result.code}): ${result.stderr}`;
        return `[${nodeId}]${lbl} (${result.durationMs}ms)\n${output}`;
      };

      const results = runParallel
        ? await Promise.all(commands.map(execute))
        : await commands.reduce<Promise<string[]>>(async (acc, cmd) => {
            const prev = await acc;
            const result = await execute(cmd);
            return [...prev, result];
          }, Promise.resolve([]));

      return { content: [{ type: 'text', text: results.join('\n\n') }] };
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
        const text = check.updateAvailable
          ? `Update available: ${check.current} â ${check.latest}\nRun omniwire_update to install.\n\nSystem: ${info.platform}/${info.arch} node ${info.nodeVersion}`
          : `Up to date (${check.current})\n\nSystem: ${info.platform}/${info.arch} node ${info.nodeVersion}`;
        return { content: [{ type: 'text', text }] };
      }

      const result = await selfUpdate();
      return { content: [{ type: 'text', text: `${result.message}\n\nSystem: ${info.platform}/${info.arch} node ${info.nodeVersion}` }] };
    }
  );

  return server;
}
