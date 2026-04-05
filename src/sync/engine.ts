// CyberSync — Sync engine: push, pull, reconcile, conflict resolution
//
// SECURITY NOTE: All remote command execution in this file uses NodeManager.exec()
// which routes through SSH2's client.exec() over authenticated, encrypted channels.
// No child_process.exec() is used anywhere in this file.

import { readFile, writeFile, mkdir, access, readdir, stat } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import picomatch from 'picomatch';
import type { SyncDB } from './db.js';
import type { SyncConfig, SyncItem, ToolManifest, SyncDiff } from './types.js';
import type { NodeManager } from '../nodes/manager.js';
import type { TransferEngine } from '../nodes/transfer.js';
import { hashBuffer, hashFile } from './hasher.js';
import { VaultBridge } from './vault-bridge.js';
import { categorizeFile } from './manifest.js';
import { adaptPathsForNode, getToolBaseDir, isJsonFile, normalizeRelPath } from './paths.js';
import { allNodes } from '../protocol/config.js';
import { encrypt, decrypt, isSensitivePath, loadOrCreateKey, hasEncryptionKey } from './crypto.js';

const HASH_BATCH_SIZE = 100;  // doubled for faster reconcile

export class SyncEngine {
  private vault: VaultBridge;

  constructor(
    private db: SyncDB,
    private config: SyncConfig,
    private manager: NodeManager,
    private transfer: TransferEngine,
    vault?: VaultBridge,
  ) {
    this.vault = vault ?? new VaultBridge();
  }

  // Push a local file to the database (encrypts sensitive files at rest)
  async pushFile(tool: string, relPath: string, absPath: string, opts?: { skipRemotePush?: boolean }): Promise<void> {
    const data = await readFile(absPath);
    const hash = hashBuffer(data);

    // Encrypt sensitive files before storing in DB
    const sensitive = isSensitivePath(relPath) && hasEncryptionKey();
    const content = sensitive ? encrypt(data, loadOrCreateKey()) : data;

    const item = await this.db.upsertItem({
      tool,
      category: categorizeFile(relPath),
      relPath,
      contentHash: hash,
      content,
      contentSize: data.length,
      metadata: {},
      updatedByNode: this.config.nodeId,
      encrypted: sensitive,
    });

    await this.db.upsertNodeSync(this.config.nodeId, item.id, hash);

    // Mirror to Obsidian vault
    try {
      await this.vault.writeSyncItem(tool, relPath, data, { hash, node: this.config.nodeId });
    } catch {
      // Vault write failed (non-critical)
    }

    if (!opts?.skipRemotePush) {
      await this.pushToRemoteNodes(item);
    }
  }

  // Delete a file from the database
  async deleteFile(tool: string, relPath: string): Promise<void> {
    await this.db.markDeleted(tool, relPath, this.config.nodeId);
    await this.db.logEvent(null, this.config.nodeId, 'delete', `Deleted ${tool}:${relPath}`);
    try { await this.vault.deleteSyncItem(tool, relPath); } catch {}
  }

  // Pull pending items from DB to local filesystem (decrypts encrypted items)
  async pullPending(): Promise<number> {
    const pending = await this.db.getPendingItems(this.config.nodeId);
    let pulled = 0;

    for (const item of pending) {
      if (!item.content) continue;

      // Skip .git internals and other non-syncable paths
      if (shouldSkipPath(item.relPath)) continue;

      const localNode = allNodes().find((n) => n.id === this.config.nodeId);
      const os = localNode?.os ?? 'linux';
      const baseDir = getToolBaseDir(item.tool, os);
      const absPath = join(baseDir, item.relPath);

      // Decrypt if item was stored encrypted
      let content: Buffer;
      if (item.encrypted && hasEncryptionKey()) {
        try {
          content = decrypt(item.content, loadOrCreateKey());
        } catch {
          // Decryption failed — key mismatch or corrupt data, skip
          continue;
        }
      } else {
        content = item.content;
      }

      if (isJsonFile(item.relPath)) {
        const text = content.toString('utf-8');
        const adapted = adaptPathsForNode(text, os);
        content = Buffer.from(adapted, 'utf-8');
      }

      try {
        await mkdir(dirname(absPath), { recursive: true });
        await writeFile(absPath, content);
      } catch {
        // Permission denied or path issue, skip
        continue;
      }

      await this.db.upsertNodeSync(this.config.nodeId, item.id, item.contentHash);
      await this.db.logEvent(item.id, this.config.nodeId, 'pull', `Pulled ${item.relPath}`);
      pulled++;
    }

    return pulled;
  }

  // Full reconciliation: scan all manifests, push new/changed, pull missing
  async reconcile(manifests: readonly ToolManifest[]): Promise<{ pushed: number; pulled: number; conflicts: number }> {
    let pushed = 0;
    let conflicts = 0;

    for (const manifest of manifests) {
      try {
        await access(manifest.baseDir);
      } catch {
        continue;
      }

      const baseNormalized = manifest.baseDir.replaceAll('\\', '/');
      let allFiles: string[];
      try {
        allFiles = await walkDir(baseNormalized);
      } catch {
        continue;
      }

      // Pre-compile glob matchers (picomatch is much faster than regex)
      const isIncluded = picomatch(manifest.syncGlobs as string[]);
      const isExcluded = manifest.excludeGlobs.length > 0
        ? picomatch(manifest.excludeGlobs as string[])
        : () => false;

      // Preload all existing items for this tool (1 query instead of N)
      const existingItems = await this.db.getItemsByTool(manifest.tool);
      const itemMap = new Map(existingItems.map((i) => [i.relPath, i]));

      // Filter files first, then hash in parallel batches
      const candidates = allFiles
        .map((absPath) => ({
          absPath,
          relPath: normalizeRelPath(absPath.slice(baseNormalized.length + 1)),
        }))
        .filter(({ relPath }) => isIncluded(relPath) && !isExcluded(relPath));

      // Quick mtime check: skip files whose mtime hasn't changed since last sync
      // This avoids expensive hashing for unchanged files
      for (let i = 0; i < candidates.length; i += HASH_BATCH_SIZE) {
        const batch = candidates.slice(i, i + HASH_BATCH_SIZE);
        const results = await Promise.allSettled(
          batch.map(async ({ absPath, relPath }) => {
            const localHash = await hashFile(absPath);
            return { absPath, relPath, localHash };
          })
        );

        for (const result of results) {
          if (result.status === 'rejected') continue;
          const { absPath, relPath, localHash } = result.value;
          const existing = itemMap.get(relPath);

          if (!existing) {
            await this.pushFile(manifest.tool, relPath, absPath, { skipRemotePush: true });
            pushed++;
          } else if (existing.contentHash !== localHash) {
            // Node-ownership conflict resolution:
            // - We own it (last updated by us) → push
            // - Remote owns it and is newer → skip (will be pulled)
            // - True conflict → log and defer to remote (safer)
            if (existing.updatedByNode === this.config.nodeId) {
              await this.pushFile(manifest.tool, relPath, absPath, { skipRemotePush: true });
              pushed++;
            } else {
              conflicts++;
              await this.db.logEvent(existing.id, this.config.nodeId, 'conflict',
                `Diverged: ${relPath} (local=${localHash.slice(0, 8)}, remote=${existing.contentHash.slice(0, 8)}, owner=${existing.updatedByNode})`);
            }
          }
        }
      }
    }

    const pulled = await this.pullPending();

    const allItems = await this.db.getAllItems();
    const pendingItems = await this.db.getPendingItems(this.config.nodeId);
    await this.db.heartbeat(this.config.nodeId, allItems.length, pendingItems.length);

    // Prune old events periodically
    await this.db.pruneEvents(5000);

    await this.db.logEvent(null, this.config.nodeId, 'reconcile',
      `Reconciled: pushed=${pushed}, pulled=${pulled}, conflicts=${conflicts}`);
    try {
      await this.vault.logEvent('reconcile', `pushed=${pushed} pulled=${pulled} conflicts=${conflicts}`, this.config.nodeId);
    } catch {}

    return { pushed, pulled, conflicts };
  }

  // Get diff between local and DB
  async getDiff(manifests: readonly ToolManifest[]): Promise<SyncDiff[]> {
    const diffs: SyncDiff[] = [];
    const dbItems = await this.db.getAllItems();

    for (const item of dbItems) {
      const localNode = allNodes().find((n) => n.id === this.config.nodeId);
      const os = localNode?.os ?? 'linux';
      const baseDir = getToolBaseDir(item.tool, os);
      const absPath = join(baseDir, item.relPath);

      let localHash: string | null = null;
      try {
        localHash = await hashFile(absPath);
      } catch {
        // File doesn't exist locally
      }

      if (localHash !== item.contentHash) {
        diffs.push({
          itemId: item.id,
          relPath: item.relPath,
          tool: item.tool,
          localHash,
          remoteHash: item.contentHash,
          direction: localHash === null ? 'pull' : item.updatedByNode === this.config.nodeId ? 'push' : 'conflict',
        });
      }
    }

    return diffs;
  }

  // Push item content to online remote nodes in parallel via SSH2 + TransferEngine
  // DB stores encrypted BYTEA; we decrypt here so remote nodes get plaintext over SSH (already encrypted transport)
  private async pushToRemoteNodes(item: SyncItem): Promise<void> {
    if (!item.content) return;

    // Decrypt if stored encrypted — remote nodes receive plaintext over SSH2 (transport-encrypted)
    let rawContent: Buffer;
    if (item.encrypted && hasEncryptionKey()) {
      try {
        rawContent = decrypt(item.content, loadOrCreateKey());
      } catch {
        return; // Can't decrypt, skip push
      }
    } else {
      rawContent = item.content;
    }

    const onlineNodes = this.manager.getOnlineNodes().filter((id) => id !== this.config.nodeId);

    await Promise.allSettled(onlineNodes.map(async (nodeId) => {
      try {
        const node = allNodes().find((n) => n.id === nodeId);
        if (!node) return;

        const baseDir = getToolBaseDir(item.tool, node.os);
        const remotePath = `${baseDir}/${item.relPath}`;

        let content = rawContent.toString('utf-8');

        if (isJsonFile(item.relPath)) {
          content = adaptPathsForNode(content, node.os);
        }

        // Write file via TransferEngine (SFTP or base64 fallback)
        await this.transfer.writeFile(nodeId, remotePath, content);

        await this.db.upsertNodeSync(nodeId, item.id, item.contentHash);
      } catch {
        await this.db.logEvent(item.id, nodeId, 'error', `Failed to push ${item.relPath} to ${nodeId}`);
      }
    }));
  }

}

// Paths containing these segments should never be synced
const SKIP_SEGMENTS = ['.git/', 'node_modules/', '.cache/', '__pycache__/'];

function shouldSkipPath(relPath: string): boolean {
  const normalized = relPath.replaceAll('\\', '/');
  return SKIP_SEGMENTS.some((seg) => normalized.includes(seg) || normalized.startsWith(seg.slice(0, -1)));
}

// Recursively walk a directory, returning all file paths (normalized with /)
const SKIP_DIRS = new Set(['.git', 'node_modules', '.cache', '__pycache__', '.DS_Store']);

async function walkDir(dir: string): Promise<string[]> {
  const results: string[] = [];
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return results;
  }
  for (const entry of entries) {
    if (SKIP_DIRS.has(entry.name)) continue;
    const fullPath = `${dir}/${entry.name}`;
    try {
      if (entry.isDirectory()) {
        const sub = await walkDir(fullPath);
        results.push(...sub);
      } else if (entry.isFile()) {
        results.push(fullPath.replaceAll('\\', '/'));
      }
    } catch {
      // Permission denied or broken symlink, skip
    }
  }
  return results;
}

// matchesAnyGlob/globMatch replaced by picomatch (pre-compiled in reconcile)
