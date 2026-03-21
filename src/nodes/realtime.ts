// OmniWire Realtime Channel — multiplexed low-latency command dispatch
// NOTE: All execution goes through manager.exec() / manager.streamExec()
// which use SSH2 client channels, NOT child_process. No local shell involved.

import type { NodeManager } from './manager.js';

export class RealtimeChannel {
  constructor(private manager: NodeManager) {}

  // Run command with minimal overhead, return result
  async run(nodeId: string, command: string): Promise<{ stdout: string; stderr: string; code: number }> {
    const result = await this.manager.exec(nodeId, command);
    return { stdout: result.stdout, stderr: result.stderr, code: result.code };
  }

  // Stream real-time output (tail -f, watch, top, etc.)
  async stream(
    nodeId: string,
    command: string,
    onData: (chunk: string) => void,
    signal?: AbortSignal
  ): Promise<number> {
    return new Promise((resolve) => {
      if (signal?.aborted) { resolve(-1); return; }

      const code = this.manager.streamExec(
        nodeId,
        command,
        onData,
        onData // stderr also goes to output for streams
      );

      signal?.addEventListener('abort', () => {
        resolve(-1);
      });

      code.then(resolve);
    });
  }

  // Fire-and-forget background task on a remote node
  async fire(nodeId: string, command: string): Promise<void> {
    // Escaping for nohup wrapper — runs entirely on remote node via SSH
    const escaped = command.replace(/'/g, "'\\''");
    await this.manager.exec(nodeId, `nohup bash -c '${escaped}' &>/dev/null &`);
  }

  // Run on all nodes simultaneously, interleaved output
  async multiplex(
    command: string,
    onData: (nodeId: string, chunk: string) => void
  ): Promise<Map<string, number>> {
    const nodes = this.manager.getOnlineNodes();
    const results = new Map<string, number>();

    await Promise.all(
      nodes.map(async (nodeId) => {
        const code = await this.manager.streamExec(
          nodeId,
          command,
          (chunk) => onData(nodeId, chunk),
          (chunk) => onData(nodeId, chunk)
        );
        results.set(nodeId, code);
      })
    );

    return results;
  }
}
