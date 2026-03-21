// OmniWire Shell Manager — persistent root shell sessions with PTY
// All connections are root — full kernel access by default
// NOTE: All remote commands in this file run over authenticated SSH2 channels
// (client.shell() and manager.exec() are SSH2 methods, NOT child_process)

import type { ClientChannel } from 'ssh2';
import type { NodeManager } from './manager.js';
import type { ShellSession } from '../protocol/types.js';

const IDLE_TIMEOUT_MS = 60_000; // 60s idle timeout

interface ActiveShell {
  session: ShellSession;
  channel: ClientChannel;
  idleTimer: ReturnType<typeof setTimeout>;
}

export class ShellManager {
  private shells: Map<string, ActiveShell> = new Map();
  private idCounter = 0;

  constructor(private manager: NodeManager) {}

  async openShell(nodeId: string): Promise<ShellSession> {
    const client = this.manager.getClient(nodeId);
    if (!client) throw new Error(`Node ${nodeId} is not connected`);

    const channel = await new Promise<ClientChannel>((resolve, reject) => {
      client.shell(
        { term: 'xterm-256color', rows: 40, cols: 120 },
        (err, stream) => {
          if (err) reject(err);
          else resolve(stream);
        }
      );
    });

    const id = `shell-${++this.idCounter}`;
    const session: ShellSession = { id, nodeId, startedAt: new Date() };

    const idleTimer = this.createIdleTimer(id);
    this.shells.set(id, { session, channel, idleTimer });

    // Auto-cleanup on channel close
    channel.on('close', () => {
      const s = this.shells.get(id);
      if (s) clearTimeout(s.idleTimer);
      this.shells.delete(id);
    });

    return session;
  }

  getChannel(shellId: string): ClientChannel | null {
    const shell = this.shells.get(shellId);
    if (shell) {
      // Reset idle timer on access
      clearTimeout(shell.idleTimer);
      shell.idleTimer = this.createIdleTimer(shellId);
    }
    return shell?.channel ?? null;
  }

  closeShell(shellId: string): void {
    const shell = this.shells.get(shellId);
    if (shell) {
      clearTimeout(shell.idleTimer);
      shell.channel.end();
      this.shells.delete(shellId);
    }
  }

  listShells(): ShellSession[] {
    return Array.from(this.shells.values()).map((s) => s.session);
  }

  closeAll(): void {
    for (const [id] of this.shells) {
      this.closeShell(id);
    }
  }

  private createIdleTimer(shellId: string): ReturnType<typeof setTimeout> {
    return setTimeout(() => {
      const shell = this.shells.get(shellId);
      if (shell) {
        process.stderr.write(`[shell] ${shellId} timed out after ${IDLE_TIMEOUT_MS / 1000}s idle\n`);
        shell.channel.end();
        this.shells.delete(shellId);
      }
    }, IDLE_TIMEOUT_MS);
  }

  // Interactive shell mode — pipes stdin/stdout directly
  async enterInteractive(
    nodeId: string,
    stdin: NodeJS.ReadableStream,
    stdout: NodeJS.WritableStream,
    onExit: () => void
  ): Promise<void> {
    const session = await this.openShell(nodeId);
    const channel = this.getChannel(session.id)!;

    // Pipe shell output to terminal
    channel.on('data', (data: Buffer) => stdout.write(data));
    channel.stderr.on('data', (data: Buffer) => stdout.write(data));

    // Handle Ctrl+] to exit interactive mode
    const rawMode = (stdin as NodeJS.ReadStream).isRaw;
    if ('setRawMode' in stdin) {
      (stdin as NodeJS.ReadStream).setRawMode(true);
    }

    const onData = (data: Buffer) => {
      // Ctrl+] (0x1d) exits interactive mode
      if (data[0] === 0x1d) {
        cleanup();
        return;
      }
      channel.write(data);
    };

    const cleanup = () => {
      stdin.removeListener('data', onData);
      if ('setRawMode' in stdin) {
        (stdin as NodeJS.ReadStream).setRawMode(rawMode ?? false);
      }
      this.closeShell(session.id);
      onExit();
    };

    stdin.on('data', onData);
    channel.on('close', cleanup);
  }
}

// Kernel-level operations (all nodes are root)
// Uses manager.exec() — SSH2 client.exec(), NOT child_process
export async function kernelExec(
  manager: NodeManager,
  nodeId: string,
  operation: string,
  args: string
): Promise<string> {
  let cmd: string;

  switch (operation) {
    case 'dmesg':
      cmd = `dmesg ${args}`;
      break;
    case 'sysctl':
      cmd = args.includes('=') ? `sysctl -w ${args}` : `sysctl ${args}`;
      break;
    case 'modprobe':
      cmd = `modprobe ${args}`;
      break;
    case 'lsmod':
      cmd = `lsmod ${args}`;
      break;
    case 'strace':
      cmd = `strace ${args}`;
      break;
    case 'perf':
      cmd = `perf ${args}`;
      break;
    default:
      cmd = `${operation} ${args}`;
  }

  const result = await manager.exec(nodeId, cmd);
  if (result.code !== 0 && result.stderr) {
    return `Error: ${result.stderr}`;
  }
  return result.stdout;
}
