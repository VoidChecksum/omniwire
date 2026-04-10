// CyberSync — Windows/Linux path adaptation for JSON content

import { homedir } from 'node:os';

// Upstream defaults preserve container-style assumptions:
//   Windows -> C:/Users/Admin (upstream author's username)
//   Linux   -> /root (upstream runs as root inside containers)
//
// OMNIWIRE_{WIN,LINUX}_HOME env vars override these, so non-root Linux
// hosts and Windows hosts with different usernames can deploy without
// forking. When the LINUX override is unset, we detect root vs non-root
// so upstream's root-container behavior is unchanged.
const WIN_HOME = (process.env.OMNIWIRE_WIN_HOME ?? 'C:/Users/Admin').replaceAll('\\', '/');
const WIN_HOME_BACKSLASH = WIN_HOME.replaceAll('/', '\\');
const LINUX_HOME = process.env.OMNIWIRE_LINUX_HOME
  ?? (process.getuid?.() === 0 ? '/root' : homedir());

/** Returns the canonical home directory for the given OS target */
export function getHomeForOs(os: 'windows' | 'linux'): string {
  return os === 'windows' ? WIN_HOME : LINUX_HOME;
}

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
      return os === 'windows' ? `${home}/.claude` : `${home}/.claude`;
    case 'opencode':
      return os === 'windows' ? `${home}/.config/opencode` : `${home}/.config/opencode`;
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
