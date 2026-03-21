// OmniWire Built-in Commands — cross-node system operations
// All remote commands run via SSH2 client.exec() (not child_process)

import type { NodeManager } from '../nodes/manager.js';
import type { TransferEngine } from '../nodes/transfer.js';
import type { ExecResult } from '../protocol/types.js';
import { allNodes, findNode, NODE_ROLES, getDefaultNodeForTask } from '../protocol/config.js';
import { parseMeshPath } from '../protocol/paths.js';
import { openBrowser } from './browser.js';
import { formatTable, nodeColor, dim, bold, red, green, yellow, cyan } from '../ui/format.js';

let transferEngine: TransferEngine | null = null;

export function setTransferEngine(engine: TransferEngine): void {
  transferEngine = engine;
}

export async function handleBuiltin(
  name: string,
  args: string[],
  raw: string,
  manager: NodeManager
): Promise<string> {
  switch (name) {
    case 'status':
    case 'nodes':
      return cmdStatus(manager);
    case 'ps':
      return cmdPs(args, manager);
    case 'df':
      return cmdDf(manager);
    case 'top':
      return cmdTop(args, manager);
    case 'find':
      return cmdFind(args, manager);
    case 'sync':
    case 'scp':
      return cmdSync(args, manager);
    case 'upload':
      return cmdUpload(args);
    case 'download':
      return cmdDownload(args);
    case 'cat':
      return cmdCat(args);
    case 'write':
      return cmdWrite(args);
    case 'mkdir':
      return cmdMkdir(args);
    case 'reconnect':
      return cmdReconnect(manager);
    case 'remote-exec':
      return cmdRemoteExec(raw, manager);
    case 'browser':
      return cmdBrowser(args, manager);
    case 'docker':
      return cmdDocker(raw, manager);
    case 'tunnel':
      return cmdTunnel();
    case 'help':
      return cmdHelp();
    default:
      return `Unknown builtin: ${name}`;
  }
}

async function cmdStatus(manager: NodeManager): Promise<string> {
  const statuses = await manager.getAllStatus();
  const rows = statuses.map((s) => {
    const node = allNodes().find((n) => n.id === s.nodeId);
    const role = NODE_ROLES[s.nodeId] ?? '-';
    const status = s.online ? green('● online') : red('○ offline');
    const latency = s.latencyMs !== null ? `${s.latencyMs}ms` : '-';
    const mem = s.memUsedPct !== null ? `${s.memUsedPct.toFixed(0)}%` : '-';
    const disk = s.diskUsedPct !== null ? `${s.diskUsedPct.toFixed(0)}%` : '-';
    const load = s.loadAvg ?? '-';
    return [
      nodeColor(s.nodeId),
      node?.host ?? '-',
      role,
      status,
      latency,
      load,
      mem,
      disk,
    ];
  });

  return formatTable(
    ['Node', 'IP', 'Role', 'Status', 'Latency', 'Load', 'Mem%', 'Disk%'],
    rows
  );
}

async function cmdPs(args: string[], manager: NodeManager): Promise<string> {
  const filter = args[0] ?? '';
  const cmd = filter
    ? `ps aux | head -1; ps aux | grep -iF '${filter.replace(/'/g, "'\\''")}' | grep -v grep | head -15`
    : 'ps aux --sort=-%cpu | head -12';
  const results = await manager.execAll(cmd);
  return formatMultiNodeOutput(results);
}

async function cmdDf(manager: NodeManager): Promise<string> {
  const results = await manager.execAll('df -h / /home 2>/dev/null | grep -v tmpfs');
  return formatMultiNodeOutput(results);
}

async function cmdTop(args: string[], manager: NodeManager): Promise<string> {
  const n = Math.min(Math.max(parseInt(args[0] ?? '5', 10) || 5, 1), 50);
  const results = await manager.execAll(
    `echo "=== CPU ===" && ps aux --sort=-%cpu | head -${n + 1} && echo "\\n=== MEM ===" && ps aux --sort=-%mem | head -${n + 1}`
  );
  return formatMultiNodeOutput(results);
}

async function cmdFind(args: string[], manager: NodeManager): Promise<string> {
  if (args.length === 0) return red('Usage: @find <pattern> [path]');
  const pattern = args[0].replace(/'/g, "'\\''");
  const searchPath = (args[1] ?? '/').replace(/'/g, "'\\''");
  const results = await manager.execAll(
    `find '${searchPath}' -name '${pattern}' -type f 2>/dev/null | head -20`
  );
  return formatMultiNodeOutput(results);
}

async function cmdSync(args: string[], manager: NodeManager): Promise<string> {
  if (args.length < 3) {
    return red('Usage: @sync <file> <src-node> <dst-node>');
  }
  const [file, srcId, dstId] = args;
  const src = findNode(srcId);
  const dst = findNode(dstId);
  if (!src) return red(`Unknown source node: ${srcId}`);
  if (!dst) return red(`Unknown destination node: ${dstId}`);

  // Use fast transfer engine if available
  if (transferEngine) {
    try {
      const result = await transferEngine.transfer(src.id, file, dst.id, file);
      const speed = result.speedMBps.toFixed(1);
      return green(`Synced ${file}: ${src.id} → ${dst.id} via ${result.mode} (${speed} MB/s, ${result.durationMs}ms)`);
    } catch (e) {
      return red(`Transfer failed: ${(e as Error).message}`);
    }
  }

  // Fallback to base64 if no transfer engine
  const escapedFile = file.replace(/'/g, "'\\''");
  const readResult = await manager.exec(src.id, `base64 '${escapedFile}'`);
  if (readResult.code !== 0) return red(`Failed to read from ${src.id}: ${readResult.stderr}`);

  const writeResult = await manager.exec(
    dst.id,
    `base64 -d > '${escapedFile}' << 'OMNIWIRE_EOF'\n${readResult.stdout}\nOMNIWIRE_EOF`
  );
  if (writeResult.code !== 0) return red(`Failed to write to ${dst.id}: ${writeResult.stderr}`);

  return green(`Synced ${file}: ${src.id} -> ${dst.id}`);
}

async function cmdUpload(args: string[]): Promise<string> {
  if (args.length < 2 || !transferEngine) {
    return yellow('Usage: @upload <local-path> <node>:<remote-path>');
  }
  const [localPath, meshPath] = args;
  const parsed = parseMeshPath(meshPath);
  if (!parsed) return red('Invalid destination. Use node:/path format.');

  try {
    const result = await transferEngine.transfer('windows', localPath, parsed.nodeId, parsed.path);
    return green(`Uploaded ${localPath} → ${parsed.nodeId}:${parsed.path} (${result.speedMBps.toFixed(1)} MB/s)`);
  } catch (e) {
    return red(`Upload failed: ${(e as Error).message}`);
  }
}

async function cmdDownload(args: string[]): Promise<string> {
  if (args.length < 2 || !transferEngine) {
    return yellow('Usage: @download <node>:<remote-path> <local-path>');
  }
  const [meshPath, localPath] = args;
  const parsed = parseMeshPath(meshPath);
  if (!parsed) return red('Invalid source. Use node:/path format.');

  try {
    const result = await transferEngine.transfer(parsed.nodeId, parsed.path, 'windows', localPath);
    return green(`Downloaded ${parsed.nodeId}:${parsed.path} → ${localPath} (${result.speedMBps.toFixed(1)} MB/s)`);
  } catch (e) {
    return red(`Download failed: ${(e as Error).message}`);
  }
}

async function cmdCat(args: string[]): Promise<string> {
  if (args.length === 0) return red('Usage: @cat <node>:<path> or @cat <path> [node]');
  if (!transferEngine) return red('Transfer engine not available');

  let nodeId: string;
  let filePath: string;

  const parsed = parseMeshPath(args[0]);
  if (parsed) {
    nodeId = parsed.nodeId;
    filePath = parsed.path;
  } else {
    filePath = args[0];
    nodeId = args[1] ?? getDefaultNodeForTask('storage');
  }

  try {
    const content = await transferEngine.readFile(nodeId, filePath);
    return `${nodeColor(nodeId)} ${dim(filePath)}\n${content}`;
  } catch (e) {
    return red((e as Error).message);
  }
}

async function cmdWrite(args: string[]): Promise<string> {
  if (args.length < 2) return red('Usage: @write <node>:<path> <content>');
  if (!transferEngine) return red('Transfer engine not available');

  const parsed = parseMeshPath(args[0]);
  if (!parsed) return red('Invalid path. Use node:/path format.');

  const content = args.slice(1).join(' ');
  try {
    await transferEngine.writeFile(parsed.nodeId, parsed.path, content);
    return green(`Written to ${parsed.nodeId}:${parsed.path}`);
  } catch (e) {
    return red((e as Error).message);
  }
}

async function cmdMkdir(args: string[]): Promise<string> {
  if (args.length === 0) return red('Usage: @mkdir <node>:<path>');
  if (!transferEngine) return red('Transfer engine not available');

  const parsed = parseMeshPath(args[0]);
  if (!parsed) return red('Invalid path. Use node:/path format.');

  try {
    await transferEngine.mkdir(parsed.nodeId, parsed.path);
    return green(`Created ${parsed.nodeId}:${parsed.path}`);
  } catch (e) {
    return red((e as Error).message);
  }
}

async function cmdBrowser(args: string[], manager: NodeManager): Promise<string> {
  if (args.length === 0) return red('Usage: @browser <url> [node]');
  return openBrowser(manager, args[0], args[1]);
}

async function cmdDocker(raw: string, manager: NodeManager): Promise<string> {
  const dockerCmd = raw.trim();
  if (!dockerCmd) return red('Usage: @docker <command>');
  const nodeId = getDefaultNodeForTask('storage');
  const result = await manager.exec(nodeId, `docker ${dockerCmd}`);
  return `${nodeColor(nodeId)} docker ${dockerCmd}\n${result.code === 0 ? result.stdout : red(result.stderr)}`;
}

function cmdTunnel(): string {
  return yellow('Tunnel management available via MCP tools. Use @claude for tunnel operations.');
}

async function cmdReconnect(manager: NodeManager): Promise<string> {
  manager.disconnect();
  await manager.connectAll();
  const online = manager.getOnlineNodes();
  return green(`Reconnected. Online: ${online.join(', ')}`);
}

async function cmdRemoteExec(raw: string, manager: NodeManager): Promise<string> {
  const results = await manager.execRemote(raw);
  return formatMultiNodeOutput(results);
}

function cmdHelp(): string {
  return `
${bold('OmniWire Terminal v2.0 — Command Reference')}

${cyan('Targeting:')}
  ${dim('(no prefix)')}     Execute on local machine
  ${cyan('@node')} cmd       Execute on specific node by id or alias
  ${cyan('@alias')} cmd      Use node alias (see @status for aliases)
  ${cyan('@all')} cmd        Broadcast to ALL nodes simultaneously
  ${cyan('@remote')} cmd     Execute on all remote nodes (skip local)

${cyan('AI Integration:')}
  ${cyan('@claude')} prompt  Ask Claude to orchestrate mesh operations
  ${cyan('@ai')} prompt      Same as @claude

${cyan('System Commands:')}
  ${cyan('@status')}         Node health + resources (with roles)
  ${cyan('@ps')} [filter]    Cross-node process listing
  ${cyan('@df')}             Disk usage across all nodes
  ${cyan('@top')} [n]        Top CPU/mem consumers per node
  ${cyan('@find')} pat [dir] Search files across all nodes
  ${cyan('@reconnect')}      Reconnect all SSH sessions

${cyan('File Operations (v2):')}
  ${cyan('@sync')} f src dst Fast transfer between nodes (nc/tar, aria2c)
  ${cyan('@upload')} f n:p   Upload local file to node
  ${cyan('@download')} n:p f Download file from node
  ${cyan('@cat')} n:/path    Read file from any node
  ${cyan('@write')} n:p text Write file to any node
  ${cyan('@mkdir')} n:/path  Create directory on node

${cyan('Services & Control:')}
  ${cyan('@browser')} url    Open URL on GPU/browser node
  ${cyan('@docker')} cmd     Run docker command on default storage node
  ${cyan('@shell')} node     Enter persistent interactive shell (Ctrl+] to exit)
  ${cyan('@kernel')} n cmd   Kernel operations (dmesg, sysctl, modprobe)
  ${cyan('@stream')} n cmd   Real-time streaming output (tail -f, watch)

${cyan('MCP Server:')}
  22 tools available via MCP (Claude Code, OpenCode, etc.)
  Start: ${dim('node dist/mcp/index.js --stdio')}
  SSE:   ${dim('node dist/mcp/index.js')} (port 3200)
  REST:  ${dim('localhost:3201/api/*')}

${cyan('Shortcuts:')}
  Ctrl+C            Cancel current command
  Ctrl+D / exit     Quit OmniWire Terminal
  @clear            Clear screen
`;
}

function formatMultiNodeOutput(results: ExecResult[]): string {
  return results
    .map((r) => {
      const header = `${nodeColor(r.nodeId)} ${dim(`(${r.durationMs}ms)`)}`;
      const output = r.code === 0
        ? r.stdout || dim('(no output)')
        : red(r.stderr || `exit code ${r.code}`);
      return `${header}\n${output}`;
    })
    .join('\n\n');
}
