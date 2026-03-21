// OmniWire Claude Integration — AI-powered mesh orchestration
// v2: streaming output, multi-turn sessions, MCP tool awareness
// SECURITY: Uses spawn() with explicit argv — prompt goes as argument, not through shell.
// The manager.execAll() calls below use SSH2 client channels, not child_process.

import { spawn } from 'node:child_process';
import type { NodeManager } from '../nodes/manager.js';
import { allNodes, NODE_ROLES } from '../protocol/config.js';
import { cyan, dim, green, red, Spinner } from '../ui/format.js';

export class ClaudeIntegration {
  private manager: NodeManager;
  private sessionId: string | null = null;

  constructor(manager: NodeManager) {
    this.manager = manager;
  }

  async handlePrompt(userPrompt: string): Promise<string> {
    const meshContext = this.buildMeshContext();
    const fullPrompt = this.buildClaudePrompt(userPrompt, meshContext);

    try {
      return await this.runClaude(fullPrompt);
    } catch {
      return red('Claude CLI not available. Install: npm i -g @anthropic-ai/claude-code');
    }
  }

  async handleSession(userPrompt: string): Promise<string> {
    const meshContext = this.buildMeshContext();
    const fullPrompt = this.buildClaudePrompt(userPrompt, meshContext);

    try {
      return await this.runClaude(fullPrompt, true);
    } catch {
      return red('Claude CLI not available.');
    }
  }

  private buildMeshContext(): string {
    const online = this.manager.getOnlineNodes();
    const nodes = allNodes();

    const nodeList = nodes
      .map((n) => {
        const status = online.includes(n.id) ? 'ONLINE' : 'OFFLINE';
        const role = NODE_ROLES[n.id] ?? 'unknown';
        return `  - ${n.id} (${n.alias}): ${n.host} [${n.os}] [${status}] role=${role} tags: ${n.tags.join(', ')}`;
      })
      .join('\n');

    const roleLines = Object.entries(NODE_ROLES)
      .map(([id, role]) => `- ${id} (${role})`)
      .join('\n');

    const storageNode = Object.entries(NODE_ROLES).find(([, r]) => r === 'storage')?.[0] ?? 'storage node';
    const browserNode = Object.entries(NODE_ROLES).find(([, r]) => r === 'gpu+browser')?.[0] ?? 'gpu+browser node';
    const computeNode = Object.entries(NODE_ROLES).find(([, r]) => r === 'compute')?.[0] ?? storageNode;
    const controllerNode = Object.entries(NODE_ROLES).find(([, r]) => r === 'controller')?.[0] ?? 'local';

    return `OMNIWIRE MESH STATUS:
Nodes:
${nodeList}

NODE ROLES:
${roleLines}

ROUTING DEFAULTS:
- File storage/retrieval → ${storageNode}
- Browser/GUI ops → ${browserNode}
- Heavy compute → ${computeNode}
- Local dev → ${controllerNode}

MCP TOOLS AVAILABLE:
You have 22 omniwire_* tools for direct mesh access via MCP.
Tools: omniwire_exec, omniwire_broadcast, omniwire_read_file, omniwire_write_file,
omniwire_transfer_file, omniwire_docker, omniwire_service_control, omniwire_kernel, etc.

LEGACY COMMANDS (still work):
- @<node> <command>, @all <command>, @sync <file> <src> <dst>
- Online nodes: ${online.join(', ')}`;
  }

  private buildClaudePrompt(userPrompt: string, meshContext: string): string {
    return `You are the AI brain of OmniWire Terminal, a unified terminal for a WireGuard mesh network.
The user treats all nodes as one machine. Help them accomplish their task across the mesh.

${meshContext}

IMPORTANT: If you have omniwire MCP tools available, use them directly.
Otherwise, output OmniWire commands (prefixed with @node or @all) that I can run.
Format each command on its own line starting with @.
After the commands, briefly explain what they do.

USER REQUEST: ${userPrompt}`;
  }

  // spawn with explicit argv — prompt goes as argument, not through shell
  private runClaude(prompt: string, useSession = false): Promise<string> {
    return new Promise((resolve, reject) => {
      const spinner = new Spinner('Claude is thinking...');
      spinner.start();

      let stdout = '';
      let stderr = '';

      const args = ['-p', prompt, '--no-input', '--output-format', 'text'];
      if (useSession && this.sessionId) {
        args.push('--resume', this.sessionId);
      }

      const proc = spawn('claude', args, {
        stdio: ['pipe', 'pipe', 'pipe'],
        timeout: 120000,
      });

      proc.stdout?.on('data', (data: Buffer) => {
        const chunk = data.toString();
        stdout += chunk;
        spinner.stop();
        process.stdout.write(dim('│ ') + chunk);
      });

      proc.stderr?.on('data', (data: Buffer) => {
        stderr += data.toString();
      });

      proc.on('close', (code) => {
        spinner.stop();
        if (code === 0 && stdout.trim()) {
          const sessionMatch = stderr.match(/session[:\s]+([a-f0-9-]+)/i);
          if (sessionMatch) {
            this.sessionId = sessionMatch[1];
          }
          resolve(formatClaudeResponse(stdout.trim()));
        } else {
          reject(new Error(stderr || `Claude exited with code ${code}`));
        }
      });

      proc.on('error', (err) => {
        spinner.stop();
        reject(err);
      });
    });
  }

  // Run Claude's suggested @ commands and return results (SSH2 channels)
  async runSuggestedCommands(response: string): Promise<string[]> {
    const lines = response.split('\n');
    const commands = lines.filter((l) => l.trim().startsWith('@'));
    const results: string[] = [];

    for (const cmd of commands) {
      const trimmed = cmd.trim();
      const match = trimmed.match(/^@(\w+)\s+(.+)$/);
      if (match) {
        const [, target, command] = match;
        if (target === 'all') {
          const r = await this.manager.execAll(command);
          for (const res of r) {
            results.push(`${green(`[${res.nodeId}]`)} ${res.stdout}`);
          }
        } else {
          const result = await this.manager.exec(target, command);
          results.push(`${green(`[${result.nodeId}]`)} ${result.stdout}`);
        }
      }
    }

    return results;
  }
}

function formatClaudeResponse(response: string): string {
  return `${cyan('┌─ Claude')}\n${dim('│')} ${response.split('\n').join(`\n${dim('│')} `)}\n${cyan('└─')}`;
}
