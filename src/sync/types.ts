// CyberSync — Type definitions for unified mesh sync

export interface SyncItem {
  readonly id: string;
  readonly tool: ToolName;
  readonly category: string;
  readonly relPath: string;
  readonly contentHash: string;
  readonly content: Buffer | null;
  readonly contentSize: number;
  readonly metadata: Record<string, unknown>;
  readonly updatedAt: Date;
  readonly updatedByNode: string;
  readonly isDeleted: boolean;
}

export interface NodeSyncState {
  readonly nodeId: string;
  readonly itemId: string;
  readonly contentHash: string;
  readonly syncedAt: Date;
}

export interface SyncEvent {
  readonly id: number;
  readonly itemId: string | null;
  readonly nodeId: string;
  readonly eventType: SyncEventType;
  readonly detail: string | null;
  readonly createdAt: Date;
}

export type SyncEventType = 'push' | 'pull' | 'conflict' | 'delete' | 'reconcile' | 'error';

export interface KnowledgeEntry {
  readonly id: string;
  readonly sourceTool: ToolName;
  readonly key: string;
  readonly value: Record<string, unknown>;
  readonly createdAt: Date;
  readonly updatedAt: Date;
}

export interface ClaudeMemoryEntry {
  readonly id: number;
  readonly nodeId: string;
  readonly key: string;
  readonly value: string;
  readonly ingestedAt: Date;
}

export interface NodeHeartbeat {
  readonly nodeId: string;
  readonly lastSeen: Date;
  readonly itemsCount: number;
  readonly pendingSync: number;
}

export type ToolName = 'claude-code' | 'opencode' | 'openclaw' | 'codex' | 'gemini' | 'paperclip';

export interface ToolManifest {
  readonly tool: ToolName;
  readonly baseDir: string;
  readonly syncGlobs: readonly string[];
  readonly excludeGlobs: readonly string[];
  readonly ingestDb?: string;
}

export interface SyncDiff {
  readonly itemId: string;
  readonly relPath: string;
  readonly tool: ToolName;
  readonly localHash: string | null;
  readonly remoteHash: string;
  readonly direction: 'push' | 'pull' | 'conflict';
}

export interface SyncStatus {
  readonly nodeId: string;
  readonly totalItems: number;
  readonly pendingSync: number;
  readonly lastSync: Date | null;
  readonly online: boolean;
}

export interface SyncConfig {
  readonly nodeId: string;
  readonly pgHost: string;
  readonly pgPort: number;
  readonly pgDatabase: string;
  readonly pgUser: string;
  readonly pgPassword: string;
  readonly watchDebounceMs: number;
  readonly reconcileIntervalMs: number;
}

export const DEFAULT_SYNC_CONFIG: Omit<SyncConfig, 'nodeId'> = {
  pgHost: process.env.CYBERSYNC_PG_HOST ?? 'localhost',
  pgPort: parseInt(process.env.CYBERSYNC_PG_PORT ?? '5432'),
  pgDatabase: process.env.CYBERSYNC_PG_DATABASE ?? 'cybersync',
  pgUser: process.env.CYBERSYNC_PG_USER ?? 'cybersync',
  pgPassword: process.env.CYBERSYNC_PG_PASSWORD ?? '',
  watchDebounceMs: 300,
  reconcileIntervalMs: 5 * 60 * 1000,
};
