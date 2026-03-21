// OmniWire Command Router — parse and route commands to mesh nodes

import type { ParsedCommand, CommandTarget } from '../protocol/types.js';
import { findNode } from '../protocol/config.js';

const BUILTIN_COMMANDS = new Set([
  'status', 'nodes', 'ps', 'df', 'top', 'sync', 'find',
  'help', 'exit', 'quit', 'clear', 'history', 'reconnect',
  'scp', 'upload', 'download', 'tunnel', 'proxy',
  'browser', 'docker', 'cat', 'write', 'mkdir',
]);

export function parseCommand(input: string): ParsedCommand {
  const trimmed = input.trim();
  if (!trimmed) {
    return { target: { type: 'local' }, command: '', args: [], raw: '' };
  }

  // @shell <node> — enter interactive shell
  if (trimmed.startsWith('@shell ')) {
    const nodeQuery = trimmed.slice(7).trim();
    const node = findNode(nodeQuery);
    if (node) {
      return {
        target: { type: 'shell', nodeId: node.id },
        command: 'shell',
        args: [],
        raw: trimmed,
      };
    }
  }

  // @kernel <node> <command> — kernel-level operations
  if (trimmed.startsWith('@kernel ')) {
    const rest = trimmed.slice(8).trim();
    const spaceIdx = rest.indexOf(' ');
    if (spaceIdx > 0) {
      const nodeQuery = rest.slice(0, spaceIdx);
      const cmd = rest.slice(spaceIdx + 1);
      const node = findNode(nodeQuery);
      if (node) {
        return {
          target: { type: 'kernel', nodeId: node.id },
          command: cmd,
          args: splitArgs(cmd),
          raw: cmd,
        };
      }
    }
  }

  // @stream <node> <command> — real-time streaming output
  if (trimmed.startsWith('@stream ')) {
    const rest = trimmed.slice(8).trim();
    const spaceIdx = rest.indexOf(' ');
    if (spaceIdx > 0) {
      const nodeQuery = rest.slice(0, spaceIdx);
      const cmd = rest.slice(spaceIdx + 1);
      const node = findNode(nodeQuery);
      if (node) {
        return {
          target: { type: 'stream', nodeId: node.id },
          command: cmd,
          args: splitArgs(cmd),
          raw: cmd,
        };
      }
    }
  }

  // @claude <prompt> — AI-routed command
  if (trimmed.startsWith('@claude ') || trimmed.startsWith('@ai ')) {
    const prompt = trimmed.replace(/^@(claude|ai)\s+/, '');
    return {
      target: { type: 'claude', prompt },
      command: 'claude',
      args: [prompt],
      raw: trimmed,
    };
  }

  // @all <command> — broadcast to all nodes
  if (trimmed.startsWith('@all ') || trimmed.startsWith('@* ')) {
    const cmd = trimmed.replace(/^@(all|\*)\s+/, '');
    const parts = splitArgs(cmd);
    return {
      target: { type: 'all' },
      command: parts[0],
      args: parts.slice(1),
      raw: cmd,
    };
  }

  // @remote <command> — all remote nodes only
  if (trimmed.startsWith('@remote ')) {
    const cmd = trimmed.replace(/^@remote\s+/, '');
    const parts = splitArgs(cmd);
    return {
      target: { type: 'builtin', name: 'remote-exec' },
      command: parts[0],
      args: parts.slice(1),
      raw: cmd,
    };
  }

  // @<node> <command> — target specific node
  if (trimmed.startsWith('@')) {
    const spaceIdx = trimmed.indexOf(' ');
    if (spaceIdx > 0) {
      const nodeQuery = trimmed.slice(1, spaceIdx);
      const cmd = trimmed.slice(spaceIdx + 1);

      // Check if it's a builtin command
      if (BUILTIN_COMMANDS.has(nodeQuery)) {
        return {
          target: { type: 'builtin', name: nodeQuery },
          command: nodeQuery,
          args: splitArgs(cmd),
          raw: cmd,
        };
      }

      // Check if it's a node reference
      const node = findNode(nodeQuery);
      if (node) {
        const parts = splitArgs(cmd);
        return {
          target: { type: 'node', nodeId: node.id },
          command: parts[0],
          args: parts.slice(1),
          raw: cmd,
        };
      }
    }

    // @builtin with no args
    const name = trimmed.slice(1);
    if (BUILTIN_COMMANDS.has(name)) {
      return {
        target: { type: 'builtin', name },
        command: name,
        args: [],
        raw: '',
      };
    }
  }

  // Plain command — execute locally
  const parts = splitArgs(trimmed);
  return {
    target: { type: 'local' },
    command: parts[0],
    args: parts.slice(1),
    raw: trimmed,
  };
}

function splitArgs(cmd: string): string[] {
  const args: string[] = [];
  let current = '';
  let inQuote = false;
  let quoteChar = '';

  for (const ch of cmd) {
    if (inQuote) {
      if (ch === quoteChar) {
        inQuote = false;
      } else {
        current += ch;
      }
    } else if (ch === '"' || ch === "'") {
      inQuote = true;
      quoteChar = ch;
    } else if (ch === ' ') {
      if (current) {
        args.push(current);
        current = '';
      }
    } else {
      current += ch;
    }
  }

  if (current) args.push(current);
  return args;
}
