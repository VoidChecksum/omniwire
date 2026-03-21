// OmniWire Sync — Windows/Linux path adaptation for JSON content

import { homedir } from 'node:os';

const WIN_HOME = homedir().replaceAll('\\', '/');
const WIN_HOME_BACKSLASH = homedir();
const LINUX_HOME = process.env.OMNIWIRE_LINUX_HOME ?? '/root';

const PATH_MAPS: ReadonlyArray<readonly [string, string]> = [
  [WIN_HOME_BACKSLASH, LINUX_HOME],
  [WIN_HOME, LINUX_HOME],
];

export function toLinuxPath(content: string): string {
  let result = content;
  for (const [win, linux] of PATH_MAPS) {
    result = result.replaceAll(win, linux);
  }
  return result.replaceAll('\\\\', '/').replaceAll('\\', '/');
}

export function toWindowsPath(content: string): string {
  let result = content;
  for (const [win, linux] of PATH_MAPS) {
    result = result.replaceAll(linux, win);
  }
  return result;
}

export function adaptPathsForNode(content: string, targetOs: 'windows' | 'linux'): string {
  return targetOs === 'windows' ? toWindowsPath(content) : toLinuxPath(content);
}

export function getToolBaseDir(tool: string, os: 'windows' | 'linux'): string {
  const home = os === 'windows' ? WIN_HOME : LINUX_HOME;

  switch (tool) {
    case 'claude-code':
      return `${home}/.claude`;
    case 'opencode':
      return `${home}/.config/opencode`;
    case 'openclaw':
      return `${home}/.openclaw`;
    case 'codex':
      return `${home}/.codex`;
    case 'gemini':
      return `${home}/.gemini`;
    case 'paperclip':
      return `${home}/.paperclip`;
    default:
      return `${home}/.${tool}`;
  }
}

export function isJsonFile(filePath: string): boolean {
  const lower = filePath.toLowerCase();
  return lower.endsWith('.json') || lower.endsWith('.jsonc');
}

export function normalizeRelPath(relPath: string): string {
  return relPath.replaceAll('\\', '/');
}
