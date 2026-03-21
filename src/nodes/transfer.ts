// OmniWire Transfer Engine — raw TCP transfers over WireGuard mesh
// Modes: netcat+tar (fastest), aria2c (large files), SSH pipe (small files)
// NOTE: All commands execute via SSH on remote Linux nodes (not local shell).
// The manager.exec() method uses ssh2 client.exec() for remote nodes, which
// does not involve local shell interpretation. Path inputs come from trusted
// terminal/MCP context (operator's own commands).

import type { NodeManager } from './manager.js';
import type { TransferResult, TransferMode, FileInfo, DirEntry } from '../protocol/types.js';
import { findNode } from '../protocol/config.js';

const STAT_CACHE_TTL = 10_000; // 10s stat cache

export class TransferEngine {
  private statCache: Map<string, { info: FileInfo; at: number }> = new Map();

  constructor(private manager: NodeManager) {}

  async transfer(
    srcNode: string,
    srcPath: string,
    dstNode: string,
    dstPath: string,
    opts?: { mode?: TransferMode }
  ): Promise<TransferResult> {
    const start = Date.now();

    // Determine file size for auto mode selection
    const stat = await this.stat(srcNode, srcPath);
    const mode = opts?.mode ?? this.selectMode(stat.size, stat.isDirectory);

    let bytesTransferred = stat.size;

    switch (mode) {
      case 'netcat-tar':
        bytesTransferred = await this.transferNetcat(srcNode, srcPath, dstNode, dstPath, stat.isDirectory);
        break;
      case 'aria2c':
        bytesTransferred = await this.transferAria2c(srcNode, srcPath, dstNode, dstPath);
        break;
      case 'ssh-pipe':
        bytesTransferred = await this.transferSshPipe(srcNode, srcPath, dstNode, dstPath);
        break;
    }

    const durationMs = Date.now() - start;
    const speedMBps = durationMs > 0 ? (bytesTransferred / 1024 / 1024) / (durationMs / 1000) : 0;

    return { srcNode, dstNode, srcPath, dstPath, mode, bytesTransferred, durationMs, speedMBps };
  }

  private selectMode(sizeBytes: number, isDirectory: boolean): TransferMode {
    if (isDirectory) return 'netcat-tar';
    if (sizeBytes < 10 * 1024 * 1024) return 'ssh-pipe';   // < 10MB
    if (sizeBytes > 1024 * 1024 * 1024) return 'aria2c';    // > 1GB
    return 'netcat-tar';                                      // 10MB - 1GB
  }

  // Single SSH call to find free port — kernel assigns guaranteed free port via Python
  // Uses manager.exec() which runs via SSH2 client.exec(), not child_process
  private async findFreePort(nodeId: string): Promise<number> {
    const result = await this.manager.exec(nodeId,
      `python3 -c "import socket; s=socket.socket(); s.bind(('',0)); print(s.getsockname()[1]); s.close()"`
    );
    const port = parseInt(result.stdout.trim());
    if (!port || isNaN(port)) {
      // Fallback: random port
      return 49152 + Math.floor(Math.random() * (65535 - 49152));
    }
    return port;
  }

  private async transferNetcat(
    srcNode: string, srcPath: string,
    dstNode: string, dstPath: string,
    isDirectory: boolean
  ): Promise<number> {
    const dstIp = findNode(dstNode)?.host;
    if (!dstIp) throw new Error(`Unknown node: ${dstNode}`);

    const port = await this.findFreePort(dstNode);
    const dstDir = isDirectory ? dstPath : dstPath.substring(0, dstPath.lastIndexOf('/')) || '/tmp';
    const srcDir = srcPath.substring(0, srcPath.lastIndexOf('/')) || '/';
    const srcName = srcPath.substring(srcPath.lastIndexOf('/') + 1);

    // Start receiver first (background, timeout 30s) — gzip compressed
    const receiverCmd = `timeout 30 bash -c 'nc -l -p ${port} | tar xzf - -C "${dstDir}"'`;
    const receiverPromise = this.manager.exec(dstNode, `mkdir -p "${dstDir}" && ${receiverCmd}`);

    // Small delay to ensure receiver is listening
    await new Promise((r) => setTimeout(r, 200));

    // Start sender — gzip compressed
    const senderCmd = isDirectory
      ? `tar czf - -C "${srcPath}" . | nc -w 10 ${dstIp} ${port}`
      : `tar czf - -C "${srcDir}" "${srcName}" | nc -w 10 ${dstIp} ${port}`;

    const senderResult = await this.manager.exec(srcNode, senderCmd);
    await receiverPromise;

    if (senderResult.code !== 0) {
      throw new Error(`netcat transfer failed: ${senderResult.stderr}`);
    }

    const sizeResult = await this.manager.exec(dstNode, `du -sb "${dstPath}" 2>/dev/null | awk '{print $1}'`);
    return parseInt(sizeResult.stdout.trim()) || 0;
  }

  private async transferAria2c(
    srcNode: string, srcPath: string,
    dstNode: string, dstPath: string
  ): Promise<number> {
    const srcIp = findNode(srcNode)?.host;
    if (!srcIp) throw new Error(`Unknown node: ${srcNode}`);

    const port = await this.findFreePort(srcNode);
    const srcDir = srcPath.substring(0, srcPath.lastIndexOf('/')) || '/';
    const fileName = srcPath.substring(srcPath.lastIndexOf('/') + 1);
    const dstDir = dstPath.substring(0, dstPath.lastIndexOf('/')) || '/tmp';

    // Start HTTP server on source (background, auto-kill after transfer)
    const serverCmd = `cd "${srcDir}" && timeout 300 python3 -m http.server ${port} --bind 0.0.0.0 &`;
    await this.manager.exec(srcNode, `bash -c '${serverCmd}'`);
    await new Promise((r) => setTimeout(r, 500));

    try {
      const downloadCmd = `mkdir -p "${dstDir}" && aria2c -x16 -s16 --allow-overwrite=true -d "${dstDir}" -o "${fileName}" "http://${srcIp}:${port}/${fileName}" 2>&1`;
      const result = await this.manager.exec(dstNode, downloadCmd);
      if (result.code !== 0) throw new Error(`aria2c transfer failed: ${result.stderr || result.stdout}`);
    } finally {
      await this.manager.exec(srcNode, `pkill -f "python3 -m http.server ${port}" 2>/dev/null || true`);
    }

    const sizeResult = await this.manager.exec(dstNode, `stat -c%s "${dstPath}" 2>/dev/null || echo 0`);
    return parseInt(sizeResult.stdout.trim()) || 0;
  }

  private async transferSshPipe(
    srcNode: string, srcPath: string,
    dstNode: string, dstPath: string
  ): Promise<number> {
    // Try SFTP first (binary-safe, no encoding overhead)
    const srcClient = this.manager.getClient(srcNode);
    const dstClient = this.manager.getClient(dstNode);

    if (srcClient && dstClient) {
      try {
        return await this.transferSftp(srcClient, dstClient, srcPath, dstPath);
      } catch {
        // SFTP failed, fall through to base64 method
      }
    }

    // Fallback: base64 over SSH (for local node or SFTP failure)
    const b64Result = await this.manager.exec(srcNode, `base64 "${srcPath}"`);
    if (b64Result.code !== 0) throw new Error(`Failed to encode ${srcPath}: ${b64Result.stderr}`);

    const dstDir = dstPath.substring(0, dstPath.lastIndexOf('/')) || '/tmp';
    const b64Content = b64Result.stdout;
    // Use printf + base64 -d to avoid heredoc issues with special content
    const writeCmd = `mkdir -p "${dstDir}" && printf '%s' '${b64Content.replace(/'/g, "'\\''")}' | base64 -d > "${dstPath}"`;
    const writeResult = await this.manager.exec(dstNode, writeCmd);
    if (writeResult.code !== 0) throw new Error(`Failed to write ${dstPath} on ${dstNode}: ${writeResult.stderr}`);

    const sizeResult = await this.manager.exec(dstNode, `stat -c%s "${dstPath}" 2>/dev/null || echo 0`);
    return parseInt(sizeResult.stdout.trim()) || 0;
  }

  // SFTP-based transfer — zero encoding overhead, binary-safe
  private transferSftp(
    srcClient: import('ssh2').Client,
    dstClient: import('ssh2').Client,
    srcPath: string,
    dstPath: string
  ): Promise<number> {
    return new Promise((resolve, reject) => {
      srcClient.sftp((sftpErr, srcSftp) => {
        if (sftpErr) return reject(sftpErr);
        srcSftp.readFile(srcPath, (readErr, data) => {
          srcSftp.end();
          if (readErr) return reject(readErr);
          dstClient.sftp((dstSftpErr, dstSftp) => {
            if (dstSftpErr) return reject(dstSftpErr);
            dstSftp.writeFile(dstPath, data, (writeErr) => {
              dstSftp.end();
              if (writeErr) return reject(writeErr);
              resolve(data.length);
            });
          });
        });
      });
    });
  }

  async readFile(nodeId: string, path: string): Promise<string> {
    const result = await this.manager.exec(nodeId, `cat "${path}"`);
    if (result.code !== 0) throw new Error(`Failed to read ${path} on ${nodeId}: ${result.stderr}`);
    return result.stdout;
  }

  async writeFile(nodeId: string, path: string, content: string): Promise<void> {
    const dir = path.substring(0, path.lastIndexOf('/')) || '/tmp';

    // Try SFTP first (no heredoc issues, binary-safe)
    const client = this.manager.getClient(nodeId);
    if (client) {
      try {
        // Ensure directory exists
        await this.manager.exec(nodeId, `mkdir -p "${dir}"`);
        await new Promise<void>((resolve, reject) => {
          client.sftp((err, sftp) => {
            if (err) return reject(err);
            sftp.writeFile(path, Buffer.from(content, 'utf-8'), (writeErr) => {
              sftp.end();
              writeErr ? reject(writeErr) : resolve();
            });
          });
        });
        return;
      } catch {
        // SFTP failed, fall through to heredoc
      }
    }

    // Fallback: base64 pipe (safe for any content)
    const b64 = Buffer.from(content, 'utf-8').toString('base64');
    const cmd = `mkdir -p "${dir}" && echo '${b64}' | base64 -d > "${path}"`;
    const result = await this.manager.exec(nodeId, cmd);
    if (result.code !== 0) throw new Error(`Failed to write ${path} on ${nodeId}: ${result.stderr}`);
  }

  async stat(nodeId: string, path: string): Promise<FileInfo> {
    // Check cache first
    const cacheKey = `${nodeId}:${path}`;
    const cached = this.statCache.get(cacheKey);
    if (cached && Date.now() - cached.at < STAT_CACHE_TTL) {
      return cached.info;
    }

    const cmd = `stat -c '%s %F %a %Y %U' "${path}" 2>/dev/null && echo OK || echo NOTFOUND`;
    const result = await this.manager.exec(nodeId, cmd);

    if (result.stdout.includes('NOTFOUND') || result.code !== 0) {
      throw new Error(`File not found: ${path} on ${nodeId}`);
    }

    const lines = result.stdout.trim().split('\n');
    const parts = lines[0].split(' ');
    const info: FileInfo = {
      path,
      size: parseInt(parts[0]) || 0,
      isDirectory: parts[1]?.includes('directory') ?? false,
      permissions: parts[2] ?? '000',
      modified: parts[3] ?? '',
      owner: parts[4] ?? 'unknown',
    };

    this.statCache.set(cacheKey, { info, at: Date.now() });
    return info;
  }

  async readdir(nodeId: string, path: string): Promise<DirEntry[]> {
    const cmd = `ls -la --time-style=long-iso "${path}" 2>/dev/null | tail -n +2`;
    const result = await this.manager.exec(nodeId, cmd);
    if (result.code !== 0) throw new Error(`Failed to list ${path} on ${nodeId}: ${result.stderr}`);

    return result.stdout.split('\n').filter(Boolean).map((line) => {
      const parts = line.split(/\s+/);
      return {
        name: parts.slice(7).join(' '),
        size: parseInt(parts[4]) || 0,
        isDirectory: line.startsWith('d'),
        permissions: parts[0] ?? '',
        modified: `${parts[5]} ${parts[6]}`,
      };
    });
  }

  async mkdir(nodeId: string, path: string): Promise<void> {
    const result = await this.manager.exec(nodeId, `mkdir -p "${path}"`);
    if (result.code !== 0) throw new Error(`Failed to mkdir ${path} on ${nodeId}: ${result.stderr}`);
  }

  async unlink(nodeId: string, path: string): Promise<void> {
    const result = await this.manager.exec(nodeId, `rm -f "${path}"`);
    if (result.code !== 0) throw new Error(`Failed to unlink ${path} on ${nodeId}: ${result.stderr}`);
  }
}
