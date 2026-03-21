// CyberSync — single consolidated chokidar watcher with batch debounce

import { watch, type FSWatcher } from 'chokidar';
import { existsSync } from 'node:fs';
import { relative } from 'node:path';
import type { ToolManifest } from './types.js';
import { normalizeRelPath } from './paths.js';

export type FileChangeEvent = {
  readonly type: 'add' | 'change' | 'unlink';
  readonly tool: string;
  readonly relPath: string;
  readonly absPath: string;
};

export type ChangeHandler = (event: FileChangeEvent) => void;

export class SyncWatcher {
  private watcher: FSWatcher | null = null;
  private pendingChanges: Map<string, FileChangeEvent> = new Map();
  private flushTimer: ReturnType<typeof setTimeout> | null = null;
  private baseDirMap: Array<{ baseDir: string; tool: string }> = [];

  constructor(
    private manifests: readonly ToolManifest[],
    private debounceMs: number,
    private onChange: ChangeHandler,
  ) {}

  start(): void {
    const allGlobs: string[] = [];
    const allIgnored: string[] = [];

    for (const manifest of this.manifests) {
      if (!existsSync(manifest.baseDir)) continue;

      const baseNormalized = manifest.baseDir.replaceAll('\\', '/');
      this.baseDirMap.push({ baseDir: baseNormalized, tool: manifest.tool });

      for (const g of manifest.syncGlobs) {
        allGlobs.push(`${baseNormalized}/${g}`);
      }
      for (const g of manifest.excludeGlobs) {
        allIgnored.push(`${baseNormalized}/${g}`);
      }
    }

    if (allGlobs.length === 0) return;

    this.watcher = watch(allGlobs, {
      ignored: allIgnored,
      persistent: true,
      ignoreInitial: true,
      awaitWriteFinish: { stabilityThreshold: 200, pollInterval: 50 },
      followSymlinks: false,
    });

    const emit = (type: FileChangeEvent['type'], absPath: string): void => {
      const normalized = absPath.replaceAll('\\', '/');

      // Find which tool manifest owns this file
      const match = this.baseDirMap.find((m) => normalized.startsWith(m.baseDir + '/'));
      if (!match) return;

      const relPath = normalizeRelPath(relative(match.baseDir, normalized));
      const key = `${match.tool}:${relPath}`;

      this.pendingChanges.set(key, {
        type,
        tool: match.tool,
        relPath,
        absPath: normalized,
      });

      this.scheduleFlush();
    };

    this.watcher.on('add', (p) => emit('add', p));
    this.watcher.on('change', (p) => emit('change', p));
    this.watcher.on('unlink', (p) => emit('unlink', p));
  }

  private scheduleFlush(): void {
    if (this.flushTimer) return;
    this.flushTimer = setTimeout(() => {
      this.flushTimer = null;
      const batch = [...this.pendingChanges.values()];
      this.pendingChanges.clear();
      for (const event of batch) {
        this.onChange(event);
      }
    }, this.debounceMs);
  }

  async stop(): Promise<void> {
    if (this.flushTimer) {
      clearTimeout(this.flushTimer);
      this.flushTimer = null;
    }
    this.pendingChanges.clear();
    if (this.watcher) {
      await this.watcher.close();
      this.watcher = null;
    }
  }
}
