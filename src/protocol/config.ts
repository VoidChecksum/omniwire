// OmniWire mesh configuration — loaded from ~/.omniwire/mesh.json or env

import { homedir } from 'node:os';
import { join } from 'node:path';
import { readFileSync, existsSync } from 'node:fs';
import type { MeshConfig, MeshNode, NodeRole } from './types.js';

const home = homedir();
const sshDir = join(home, '.ssh');

interface MeshJsonNode {
  id: string;
  alias?: string;
  host: string;
  port?: number;
  user: string;
  identityFile?: string;
  role?: NodeRole;
  os?: 'linux' | 'windows';
  tags?: string[];
  isLocal?: boolean;
}

interface MeshJson {
  nodes?: MeshJsonNode[];
  meshSubnet?: string;
  roles?: Record<string, NodeRole>;
  claudePath?: string;
}

function resolveIdentityFile(identityFile: string | undefined): string {
  if (!identityFile) return '';
  // If already absolute, return as-is
  if (identityFile.startsWith('/') || identityFile.includes(':')) return identityFile;
  return join(sshDir, identityFile);
}

function buildLocalNode(): MeshNode {
  const isWindows = process.platform === 'win32';
  return {
    id: localNodeId(),
    alias: isWindows ? 'local' : 'local',
    host: '127.0.0.1',
    port: 0,
    user: isWindows ? (process.env.USERNAME ?? 'user') : (process.env.USER ?? 'user'),
    identityFile: '',
    os: isWindows ? 'windows' : 'linux',
    isLocal: true,
    tags: ['local', isWindows ? 'windows' : 'linux'],
  };
}

export function localNodeId(): string {
  if (process.platform === 'win32') return 'windows';
  return process.env.OMNIWIRE_NODE_ID ?? 'local';
}

function loadMeshJson(): MeshJson | null {
  // 1. Try ~/.omniwire/mesh.json
  const configPath = join(home, '.omniwire', 'mesh.json');
  if (existsSync(configPath)) {
    try {
      const raw = readFileSync(configPath, 'utf8');
      return JSON.parse(raw) as MeshJson;
    } catch {
      process.stderr.write(`[omniwire] Warning: failed to parse ${configPath}\n`);
    }
  }

  // 2. Try OMNIWIRE_CONFIG env var (JSON string)
  const envConfig = process.env.OMNIWIRE_CONFIG;
  if (envConfig) {
    try {
      return JSON.parse(envConfig) as MeshJson;
    } catch {
      process.stderr.write('[omniwire] Warning: failed to parse OMNIWIRE_CONFIG env var\n');
    }
  }

  return null;
}

function buildConfig(): { nodes: MeshNode[]; roles: Record<string, NodeRole>; meshSubnet: string; claudePath: string } {
  const json = loadMeshJson();
  const localNode = buildLocalNode();

  if (!json || !json.nodes || json.nodes.length === 0) {
    // Minimal fallback: local node only
    return {
      nodes: [localNode],
      roles: { [localNode.id]: 'controller' },
      meshSubnet: '10.0.0.0/24',
      claudePath: 'claude',
    };
  }

  const remoteNodes: MeshNode[] = json.nodes.map((n) => ({
    id: n.id,
    alias: n.alias ?? n.id.slice(0, 3),
    host: n.host,
    port: n.port ?? 22,
    user: n.user,
    identityFile: resolveIdentityFile(n.identityFile),
    os: n.os ?? 'linux',
    isLocal: n.isLocal ?? false,
    tags: n.tags ?? [],
  }));

  // Prepend local node if not already in json
  const hasLocal = remoteNodes.some((n) => n.isLocal);
  const nodes = hasLocal ? remoteNodes : [localNode, ...remoteNodes];

  // Build roles map: from json.roles, then fall back to per-node role fields
  const roles: Record<string, NodeRole> = { [localNode.id]: 'controller' };
  if (json.roles) {
    Object.assign(roles, json.roles);
  } else {
    for (const n of json.nodes) {
      if (n.role) roles[n.id] = n.role;
    }
  }

  return {
    nodes,
    roles,
    meshSubnet: json.meshSubnet ?? '10.0.0.0/24',
    claudePath: json.claudePath ?? 'claude',
  };
}

const _config = buildConfig();
const NODES = _config.nodes;

export const NODE_ROLES: Record<string, NodeRole> = _config.roles;

export function getNodeForRole(role: NodeRole): MeshNode | undefined {
  const id = Object.entries(NODE_ROLES).find(([, r]) => r === role)?.[0];
  return id ? NODES.find((n) => n.id === id) : undefined;
}

export function getDefaultNodeForTask(task: 'storage' | 'browser' | 'compute' | 'local'): string {
  switch (task) {
    case 'storage': return getNodeForRole('storage')?.id ?? localNodeId();
    case 'browser': return getNodeForRole('gpu+browser')?.id ?? localNodeId();
    case 'compute': return getNodeForRole('compute')?.id ?? getNodeForRole('storage')?.id ?? localNodeId();
    case 'local': return localNodeId();
  }
}

export const CONFIG: MeshConfig = {
  nodes: NODES,
  defaultNode: 'local',
  meshSubnet: _config.meshSubnet,
  claudePath: _config.claudePath,
};

export function findNode(query: string): MeshNode | undefined {
  const q = query.toLowerCase();
  return CONFIG.nodes.find(
    (n) => n.id === q || n.alias === q || n.host === q
  );
}

export function remoteNodes(): MeshNode[] {
  return CONFIG.nodes.filter((n) => !n.isLocal);
}

export function allNodes(): MeshNode[] {
  return [...CONFIG.nodes];
}
