// OmniWire path parser — "node:/path" syntax

import type { MeshPath } from './types.js';
import { findNode } from './config.js';

export function parseMeshPath(input: string): MeshPath | null {
  const colonIdx = input.indexOf(':');
  if (colonIdx < 1) return null;

  const nodeQuery = input.slice(0, colonIdx);
  const path = input.slice(colonIdx + 1);
  if (!path.startsWith('/')) return null;

  const node = findNode(nodeQuery);
  if (!node) return null;

  return { nodeId: node.id, path };
}

export function formatMeshPath(mp: MeshPath): string {
  return `${mp.nodeId}:${mp.path}`;
}
