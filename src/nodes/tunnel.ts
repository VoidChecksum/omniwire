// OmniWire Tunnel Manager — SSH port forwarding over WireGuard mesh

import type { NodeManager } from './manager.js';
import type { TunnelInfo } from '../protocol/types.js';
import { createServer, type Server } from 'node:net';

interface ActiveTunnel extends TunnelInfo {
  server: Server;
}

export class TunnelManager {
  private tunnels: Map<string, ActiveTunnel> = new Map();
  private idCounter = 0;

  constructor(private manager: NodeManager) {}

  async create(
    nodeId: string,
    localPort: number,
    remotePort: number,
    remoteHost: string = '127.0.0.1'
  ): Promise<TunnelInfo> {
    const client = this.manager.getClient(nodeId);
    if (!client) throw new Error(`Node ${nodeId} is not connected`);

    const id = `tunnel-${++this.idCounter}`;

    const server = createServer((socket) => {
      client.forwardOut(
        '127.0.0.1',
        localPort,
        remoteHost,
        remotePort,
        (err, stream) => {
          if (err) {
            socket.end();
            return;
          }
          socket.pipe(stream);
          stream.pipe(socket);
        }
      );
    });

    await new Promise<void>((resolve, reject) => {
      server.listen(localPort, '127.0.0.1', () => resolve());
      server.on('error', reject);
    });

    const info: TunnelInfo = { id, nodeId, localPort, remotePort, remoteHost };
    this.tunnels.set(id, { ...info, server });

    return info;
  }

  close(tunnelId: string): void {
    const tunnel = this.tunnels.get(tunnelId);
    if (tunnel) {
      tunnel.server.close();
      this.tunnels.delete(tunnelId);
    }
  }

  list(): TunnelInfo[] {
    return Array.from(this.tunnels.values()).map(({ server: _, ...info }) => info);
  }

  closeAll(): void {
    for (const [id] of this.tunnels) {
      this.close(id);
    }
  }
}
