// OmniWire mesh configuration
// Resolution order: env var → ~/.omniwire/mesh.json → built-in defaults
// Built-in defaults match upstream CyberNord infra so nothing breaks without config.

import { readFileSync, existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, isAbsolute } from 'node:path';
import type { MeshConfig, MeshNode, NodeRole } from './types.js';

const home = homedir();
const sshDir = join(home, '.ssh');
const meshJsonPath = process.env.OMNIWIRE_MESH_JSON ?? join(home, '.omniwire', 'mesh.json');

// Fallback host resolution order: WireGuard → Tailscale → Public IP
// NodeManager tries each in order until one connects
export interface HostFallback {
  readonly wg: string;
  readonly tailscale?: string;
  readonly publicIp?: string;
}

// Loaded per-node from mesh.json "hostFallbacks" field
export const HOST_FALLBACKS: Record<string, HostFallback> = {};

interface MeshJsonNode {
  id: string;
  alias: string;
  host: string;
  port: number;
  user: string;
  identityFile: string;
  os: string;
  role?: string;
  isLocal?: boolean;
  tags?: string[];
  hostFallbacks?: HostFallback;
}

interface MeshJson {
  nodes: MeshJsonNode[];
  defaultNode?: string;
  meshSubnet?: string;
}

function resolveIdentityFile(file: string): string {
  if (!file) return '';
  if (isAbsolute(file)) return file;
  return join(sshDir, file);
}

interface MeshLoadResult {
  nodes: MeshNode[];
  rawNodes: MeshJsonNode[];
  defaultNode: string;
  meshSubnet: string;
}

function loadMeshJson(): MeshLoadResult | null {
  if (!existsSync(meshJsonPath)) return null;
  try {
    const raw = readFileSync(meshJsonPath, 'utf-8');
    const json: MeshJson = JSON.parse(raw);
    if (!Array.isArray(json.nodes)) return null;

    const nodes: MeshNode[] = json.nodes.map((n) => ({
      id: n.id,
      alias: n.alias ?? n.id,
      host: n.host,
      port: n.port ?? 22,
      user: n.user ?? 'admin',
      identityFile: resolveIdentityFile(n.identityFile ?? ''),
      os: (n.os ?? 'linux') as MeshNode['os'],
      isLocal: n.isLocal ?? false,
      tags: n.tags ?? [],
    }));

    // Populate HOST_FALLBACKS from mesh.json
    for (const n of json.nodes) {
      if (n.hostFallbacks) {
        HOST_FALLBACKS[n.id] = n.hostFallbacks;
      }
    }

    return {
      nodes,
      rawNodes: json.nodes,
      defaultNode: json.defaultNode ?? 'local',
      meshSubnet: json.meshSubnet ?? '0.0.0.0/0',
    };
  } catch {
    return null;
  }
}

// Built-in defaults (upstream CyberNord infra) — used only if mesh.json is absent
function builtinNodes(): MeshNode[] {
  return [
    { id: 'windows', alias: 'win', host: '127.0.0.1', port: 0, user: 'Admin', identityFile: '', os: 'windows', isLocal: true, tags: ['workstation', 'desktop'] },
    { id: 'contabo', alias: 'c1', host: '10.10.0.1', port: 22, user: 'root', identityFile: join(sshDir, 'cybernord_contabo'), os: 'linux', isLocal: false, tags: ['vps', 'hub', 'docker', 'primary', 'db', 'storage'] },
    { id: 'hostinger', alias: 'h1', host: '10.10.0.2', port: 22, user: 'root', identityFile: join(sshDir, 'cybernord_vps'), os: 'linux', isLocal: false, tags: ['vps', 'secondary'] },
    { id: 'thinkpad', alias: 'tp', host: '10.10.0.4', port: 22, user: 'root', identityFile: join(sshDir, 'cybernord_contabo'), os: 'linux', isLocal: false, tags: ['laptop', 'mobile', 'browser', 'gpu'] },
  ];
}

function builtinRoles(): Record<string, NodeRole> {
  return { windows: 'controller', contabo: 'storage', hostinger: 'compute', thinkpad: 'gpu+browser' };
}

const loaded = loadMeshJson();
const NODES: MeshNode[] = loaded?.nodes ?? builtinNodes();

// Build NODE_ROLES dynamically from mesh.json "role" field, or use defaults
function buildNodeRoles(rawNodes: MeshJsonNode[] | null): Record<string, NodeRole> {
  if (!rawNodes) return builtinRoles();
  const roles: Record<string, NodeRole> = {};
  for (const n of rawNodes) {
    if (n.role) roles[n.id] = n.role;
  }
  return roles;
}

export const NODE_ROLES: Record<string, NodeRole> = buildNodeRoles(loaded?.rawNodes ?? null);

// ─── Node resolution helpers ─────────────────────────────────────
// Each follows: env var → mesh.json (by tag/role/isLocal) → built-in default
// This means void's setup works with zero config, custom meshes work via
// mesh.json, and individual overrides work via env vars.

/** Which node am I? */
export function getLocalNodeId(): string {
  if (process.env.OMNIWIRE_NODE_ID) return process.env.OMNIWIRE_NODE_ID;
  const local = NODES.find((n) => n.isLocal);
  if (local) return local.id;
  if (process.platform === 'win32') return 'windows';
  return NODES[0]?.id ?? 'local';
}

/** Which node has the database (PostgreSQL / CyberBase)? */
export function getDbNode(): string {
  if (process.env.OMNIWIRE_DB_NODE) return process.env.OMNIWIRE_DB_NODE;
  const byTag = NODES.find((n) => n.tags.includes('db') || n.tags.includes('storage'));
  if (byTag) return byTag.id;
  const byRole = Object.entries(NODE_ROLES).find(([, r]) => r === 'storage');
  if (byRole) return byRole[0];
  const remote = NODES.find((n) => !n.isLocal);
  return remote?.id ?? getLocalNodeId();
}

/** Which node runs Docker workloads? */
export function getDockerNode(): string {
  if (process.env.OMNIWIRE_DOCKER_NODE) return process.env.OMNIWIRE_DOCKER_NODE;
  const byTag = NODES.find((n) => n.tags.includes('docker'));
  if (byTag) return byTag.id;
  return getDbNode(); // often same node
}

/** Which node handles browser/GUI tasks? */
export function getBrowserNode(): string {
  if (process.env.OMNIWIRE_BROWSER_NODE) return process.env.OMNIWIRE_BROWSER_NODE;
  const byTag = NODES.find((n) => n.tags.includes('browser') || n.tags.includes('gui'));
  if (byTag) return byTag.id;
  const byRole = Object.entries(NODE_ROLES).find(([, r]) => r === 'gpu+browser');
  if (byRole) return byRole[0];
  return getLocalNodeId();
}

/** Which node handles compute-heavy tasks? */
export function getComputeNode(): string {
  if (process.env.OMNIWIRE_COMPUTE_NODE) return process.env.OMNIWIRE_COMPUTE_NODE;
  const byTag = NODES.find((n) => n.tags.includes('compute') || n.tags.includes('gpu'));
  if (byTag) return byTag.id;
  const byRole = Object.entries(NODE_ROLES).find(([, r]) => r === 'compute');
  if (byRole) return byRole[0];
  return getDbNode();
}

export function getNodeForRole(role: NodeRole): MeshNode | undefined {
  const id = Object.entries(NODE_ROLES).find(([, r]) => r === role)?.[0];
  return id ? NODES.find((n) => n.id === id) : undefined;
}

export function getDefaultNodeForTask(task: 'storage' | 'browser' | 'compute' | 'local'): string {
  switch (task) {
    case 'local': return getLocalNodeId();
    case 'storage': return getDbNode();
    case 'browser': return getBrowserNode();
    case 'compute': return getComputeNode();
  }
}

export const CONFIG: MeshConfig = {
  nodes: NODES,
  defaultNode: loaded?.defaultNode ?? 'local',
  meshSubnet: loaded?.meshSubnet ?? '10.10.0.0/24',
  claudePath: 'claude',
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

// Get ordered list of hosts to try for a node
export function getHostCandidates(nodeId: string): string[] {
  const fb = HOST_FALLBACKS[nodeId];
  if (!fb) {
    const host = NODES.find((n) => n.id === nodeId)?.host;
    return host ? [host] : [];
  }
  const hosts = [fb.wg];
  if (fb.tailscale) hosts.push(fb.tailscale);
  if (fb.publicIp) hosts.push(fb.publicIp);
  return hosts;
}

// ─── Database credentials ────────────────────────────────────────
// Resolution: CYBERSYNC_DB_URL → individual env vars → mesh.json dbNode host → defaults
export interface DbCredentials {
  readonly host: string;
  readonly port: number;
  readonly user: string;
  readonly database: string;
}

export function getDbCredentials(): DbCredentials {
  const dbUrl = process.env.CYBERSYNC_DB_URL;
  if (dbUrl) {
    try {
      const u = new URL(dbUrl);
      return {
        host: u.hostname || '127.0.0.1',
        port: u.port ? parseInt(u.port) : 5432,
        user: u.username || 'cyberbase',
        database: u.pathname.slice(1) || 'cyberbase',
      };
    } catch { /* fall through */ }
  }
  return {
    host: process.env.OMNIWIRE_PG_HOST ?? '127.0.0.1',
    port: parseInt(process.env.OMNIWIRE_PG_PORT ?? '5432'),
    user: process.env.OMNIWIRE_PG_USER ?? 'cyberbase',
    database: process.env.OMNIWIRE_PG_DB ?? 'cyberbase',
  };
}

/** Returns a psql command prefix suitable for SSH exec on the DB node */
export function pgExecPrefix(): string {
  const c = getDbCredentials();
  return `psql -h ${c.host} -U ${c.user} -d ${c.database}`;
}

// ─── Remote paths ────────────────────────────────────────────────
/** Remote .omniwire directory (on target nodes, resolves user home) */
export function getRemoteOmniDir(user?: string): string {
  const u = user ?? 'root';
  const homeDir = u === 'root' ? '/root' : `/home/${u}`;
  return process.env.OMNIWIRE_REMOTE_DIR ?? `${homeDir}/.omniwire`;
}

// ─── Vault paths ─────────────────────────────────────────────────
export function getVaultPath(): string {
  if (process.env.OMNIWIRE_VAULT_PATH) return process.env.OMNIWIRE_VAULT_PATH;
  if (process.platform === 'win32') {
    return join(home, 'Documents', 'CyberBase');
  }
  return join(home, '.cyberbase', 'vault');
}

// ─── Description helpers ─────────────────────────────────────────
/** Generic node description for tool schemas — avoids hardcoding specific node names */
export function nodeDesc(role: 'db' | 'docker' | 'browser' | 'compute' | 'any'): string {
  switch (role) {
    case 'db': return `Node id. Default: auto-selected db/storage node.`;
    case 'docker': return `Node id. Default: auto-selected docker node.`;
    case 'browser': return `Node id. Default: auto-selected browser/GPU node.`;
    case 'compute': return `Node id. Default: auto-selected compute node.`;
    case 'any': return `Target node id. Default: auto-selected based on task.`;
  }
}
