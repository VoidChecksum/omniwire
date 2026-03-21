// OmniWire Browser Command — opens URLs on appropriate node
// Default: GPU/browser node (configured via mesh.json or OMNIWIRE_CONFIG)
// NOTE: Uses manager.exec() which is SSH2 client channel, not child_process

import type { NodeManager } from '../nodes/manager.js';
import { getDefaultNodeForTask, findNode } from '../protocol/config.js';

export async function openBrowser(
  manager: NodeManager,
  url: string,
  nodeId?: string
): Promise<string> {
  const target = nodeId ?? getDefaultNodeForTask('browser');
  const node = findNode(target);
  if (!node) return `Unknown node: ${target}`;

  if (!manager.isConnected(node.id)) {
    return `Node ${node.id} is offline`;
  }

  // Build open command based on OS — runs on remote node via SSH
  const openCmd = node.os === 'windows'
    ? `cmd.exe /c start "" "${url}"`
    : `xdg-open "${url}" 2>/dev/null || sensible-browser "${url}" 2>/dev/null || firefox "${url}" 2>/dev/null || chromium-browser "${url}" 2>/dev/null &`;

  const result = await manager.exec(node.id, openCmd);
  if (result.code !== 0 && result.stderr) {
    return `Failed to open browser on ${node.id}: ${result.stderr}`;
  }
  return `Opened ${url} on ${node.id}`;
}
