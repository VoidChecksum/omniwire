// OmniWire Protocol — Node and mesh type definitions

export interface MeshNode {
  readonly id: string;
  readonly alias: string;
  readonly host: string;
  readonly port: number;
  readonly user: string;
  readonly identityFile: string;
  readonly os: 'linux' | 'windows';
  readonly isLocal: boolean;
  readonly tags: readonly string[];
}

export interface NodeStatus {
  readonly nodeId: string;
  readonly online: boolean;
  readonly latencyMs: number | null;
  readonly lastSeen: Date | null;
  readonly uptime: string | null;
  readonly loadAvg: string | null;
  readonly memUsedPct: number | null;
  readonly diskUsedPct: number | null;
}

export interface ExecResult {
  readonly nodeId: string;
  readonly stdout: string;
  readonly stderr: string;
  readonly code: number;
  readonly durationMs: number;
}

export interface ParsedCommand {
  readonly target: CommandTarget;
  readonly command: string;
  readonly args: string[];
  readonly raw: string;
}

export type NodeRole = 'controller' | 'storage' | 'compute' | 'gpu+browser';

export type CommandTarget =
  | { type: 'node'; nodeId: string }
  | { type: 'all' }
  | { type: 'local' }
  | { type: 'claude'; prompt: string }
  | { type: 'builtin'; name: string }
  | { type: 'shell'; nodeId: string }
  | { type: 'kernel'; nodeId: string }
  | { type: 'stream'; nodeId: string };

export interface MeshConfig {
  readonly nodes: readonly MeshNode[];
  readonly defaultNode: string;
  readonly meshSubnet: string;
  readonly claudePath: string;
}

// Transfer types
export type TransferMode = 'netcat-tar' | 'aria2c' | 'ssh-pipe';

export interface TransferResult {
  readonly srcNode: string;
  readonly dstNode: string;
  readonly srcPath: string;
  readonly dstPath: string;
  readonly mode: TransferMode;
  readonly bytesTransferred: number;
  readonly durationMs: number;
  readonly speedMBps: number;
}

export interface FileInfo {
  readonly path: string;
  readonly size: number;
  readonly isDirectory: boolean;
  readonly permissions: string;
  readonly modified: string;
  readonly owner: string;
}

export interface DirEntry {
  readonly name: string;
  readonly size: number;
  readonly isDirectory: boolean;
  readonly permissions: string;
  readonly modified: string;
}

export interface MeshPath {
  readonly nodeId: string;
  readonly path: string;
}

// Shell types
export interface ShellSession {
  readonly id: string;
  readonly nodeId: string;
  readonly startedAt: Date;
}

// Tunnel types
export interface TunnelInfo {
  readonly id: string;
  readonly nodeId: string;
  readonly localPort: number;
  readonly remotePort: number;
  readonly remoteHost: string;
}
