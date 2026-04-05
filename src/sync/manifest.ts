// CyberSync — Tool manifests defining what to sync per AI tool

import { homedir } from 'node:os';
import type { ToolManifest, ToolName } from './types.js';
import { getToolBaseDir } from './paths.js';

function manifest(tool: ToolName, os: 'windows' | 'linux' | 'darwin', sync: string[], exclude: string[], ingestDb?: string, ingestDirs?: string[]): ToolManifest {
  return {
    tool,
    baseDir: getToolBaseDir(tool, os),
    syncGlobs: sync,
    excludeGlobs: exclude,
    ingestDb,
    ingestDirs,
  };
}

export function getManifests(os: 'windows' | 'linux' | 'darwin'): readonly ToolManifest[] {
  const home = os === 'windows' ? 'C:/Users/Admin' : os === 'darwin' ? homedir() : '/root';

  return [
    manifest('claude-code', os,
      [
        'agents/**/*.md',
        'skills/**/*',
        'commands/**/*.md',
        'rules/**/*.md',
        'hooks/**/*',
        'plugins/**/*.json',
        'memory/**/*',
        'settings.json',
        'settings.local.json',
        'keybindings.json',
        'CLAUDE.md',
        'scripts/**/*',
      ],
      [
        '.credentials.json',
        'history.jsonl',
        'logs/**',
        'cache/**',
        'sessions/**',
        'session-env/**',
        'file-history/**',
        'paste-cache/**',
        'downloads/**',
        'backups/**',
        'telemetry/**',
        'security_warnings_*',
        'shell-snapshots/**',
        'plans/**',
        'projects/**',
      ],
      `${home}/.claude/memory.db`
    ),
    manifest('opencode', os,
      [
        'opencode.json',
        'oh-my-opencode.json',
        'package.json',
        '.gitignore',
        'skills/**/*',
        'agents/**/*',
        'teams/**/*',
      ],
      [
        'node_modules/**',
        'bun.lock',
      ]
    ),
    manifest('openclaw', os,
      [
        'agents/**/*',
        'skills/**/*',
        'memory/**/*',
        'workspace/**/*',
        'openclaw.json',
        'identity/**/*',
        'cron/**/*',
      ],
      [
        'gateway.log',
        'update-check.json',
        'canvas/**',
        'telegram/**',
        'devices/**',
      ],
      undefined,
      ['agents', 'skills', 'memory', 'workspace', 'identity', 'cron']
    ),
    manifest('codex', os,
      [
        'config.toml',
        'AGENTS.md',
        'skills/**/*',
        'memories/**/*',
      ],
      []
    ),
    manifest('gemini', os,
      [
        'settings.json',
        'projects.json',
      ],
      []
    ),
    manifest('paperclip', os,
      [
        'config.json',
        'agents/**/*',
      ],
      []
    ),
  ];
}

export function categorizeFile(relPath: string): string {
  const parts = relPath.split('/');
  if (parts.length > 1) return parts[0];
  const ext = relPath.split('.').pop()?.toLowerCase() ?? '';
  if (ext === 'json' || ext === 'jsonc') return 'config';
  if (ext === 'md') return 'docs';
  if (ext === 'toml' || ext === 'yaml' || ext === 'yml') return 'config';
  return 'other';
}

export const ALL_TOOLS: readonly ToolName[] = [
  'claude-code', 'opencode', 'openclaw', 'codex', 'gemini', 'paperclip',
];
