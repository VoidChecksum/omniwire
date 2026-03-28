// OmniWire Transfer Engine — raw TCP transfers over WireGuard mesh
// Modes: netcat+tar (fastest), aria2c (large files), SSH pipe (small files)
// NOTE: All commands execute via SSH on remote Linux nodes (not local shell).

import type { NodeManager } from './manager.js';
import type { TransferResult, TransferMode, FileInfo, DirEntry } from '../protocol/types.js';
import { findNode } from '../protocol/config.js';

const STAT_CACHE_TTL = 10_000;

export class TransferEngine {
  private statCache: Map<string, { info: FileInfo; at: number }> = new Map();

  constructor(private manager: NodeManager) {}

  async transfer(
    srcNode: string, srcPath: string,
    dstNode: string, dstPath: string,
    opts?: { mode?: TransferMode }
  ): Promise<TransferResult> {
    const start = Date.now();
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
    const speedMBps = durationMs > 0 ? (bytesTransferred / 1048576) / (durationMs / 1000) : 0;
    return { srcNode, dstNode, srcPath, dstPath, mode, bytesTransferred, durationMs, speedMBps };
  }

  private selectMode(sizeBytes: number, isDirectory: boolean): TransferMode {
    if (isDirectory) return 'netcat-tar';
    if (sizeBytes < 10 * 1024 * 1024) return 'ssh-pipe';
    if (sizeBytes > 1024 * 1024 * 1024) return 'aria2c';
    return 'netcat-tar';
  }

  // Fastest port finder — pure bash, no python fork
  private async findFreePort(nodeId: string): Promise<number> {
    const result = await this.manager.exec(nodeId,
      "shuf -i 49152-65535 -n 1"
    );
    const port = parseInt(result.stdout.trim());
    return (port && !isNaN(port)) ? port : 49152 + Math.floor(Math.random() * 16383);
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

    // Try lz4 first (10x faster than gzip), fallback to gzip
    // Start receiver + sender with minimal delay
    const hasLz4 = await this.manager.exec(dstNode, 'command -v lz4 >/dev/null && echo y || echo n');
    const useLz4 = hasLz4.stdout.trim() === 'y';

    const compress = useLz4 ? 'lz4 -1' : 'gzip -1';
    const decompress = useLz4 ? 'lz4 -d' : 'gzip -d';

    const receiverCmd = `timeout 30 bash -c 'nc -l -p ${port} | ${decompress} | tar xf - -C "${dstDir}"'`;
    const receiverPromise = this.manager.exec(dstNode, `mkdir -p "${dstDir}" && ${receiverCmd}`);

    // 50ms is enough for nc to bind — tested on WireGuard mesh
    await new Promise((r) => setTimeout(r, 50));

    const senderCmd = isDirectory
      ? `tar cf - -C "${srcPath}" . | ${compress} | nc -w 10 ${dstIp} ${port}`
      : `tar cf - -C "${srcDir}" "${srcName}" | ${compress} | nc -w 10 ${dstIp} ${port}`;

    const [senderResult] = await Promise.all([
      this.manager.exec(srcNode, senderCmd),
      receiverPromise,
    ]);

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

    const serverCmd = `cd "${srcDir}" && timeout 300 python3 -m http.server ${port} --bind 0.0.0.0 &`;
    await this.manager.exec(srcNode, `bash -c '${serverCmd}'`);
    await new Promise((r) => setTimeout(r, 150));

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
    const srcClient = this.manager.getClient(srcNode);
    const dstClient = this.manager.getClient(dstNode);

    if (srcClient && dstClient) {
      try {
        return await this.transferSftpStream(srcClient, dstClient, srcPath, dstPath);
      } catch (sftpErr) {
        const stat = await this.manager.exec(srcNode, `stat -c%s "${srcPath}" 2>/dev/null || echo 0`);
        const fileSize = parseInt(stat.stdout.trim()) || 0;
        if (fileSize > 1_000_000) {
          throw new Error(`SFTP failed, file too large for base64 (${fileSize}B): ${(sftpErr as Error).message}`);
        }
      }
    }

    // Fallback: base64 for tiny files
    const b64Result = await this.manager.exec(srcNode, `base64 "${srcPath}"`);
    if (b64Result.code !== 0) throw new Error(`Failed to encode ${srcPath}: ${b64Result.stderr}`);

    const dstDir = dstPath.substring(0, dstPath.lastIndexOf('/')) || '/tmp';
    const b64Content = b64Result.stdout;
    const writeCmd = `mkdir -p "${dstDir}" && printf '%s' '${b64Content.replace(/'/g, "'\\''")}' | base64 -d > "${dstPath}"`;
    const writeResult = await this.manager.exec(dstNode, writeCmd);
    if (writeResult.code !== 0) throw new Error(`Failed to write ${dstPath} on ${dstNode}: ${writeResult.stderr}`);

    const sizeResult = await this.manager.exec(dstNode, `stat -c%s "${dstPath}" 2>/dev/null || echo 0`);
    return parseInt(sizeResult.stdout.trim()) || 0;
  }

  // Stream-based SFTP — reads into buffer once, writes once. No double callback nesting.
  private transferSftpStream(
    srcClient: import('ssh2').Client,
    dstClient: import('ssh2').Client,
    srcPath: string,
    dstPath: string
  ): Promise<number> {
    return new Promise((resolve, reject) => {
      srcClient.sftp((err, srcSftp) => {
        if (err) return reject(err);
        srcSftp.readFile(srcPath, (readErr, data) => {
          srcSftp.end();
          if (readErr) return reject(readErr);
          dstClient.sftp((dstErr, dstSftp) => {
            if (dstErr) return reject(dstErr);
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
    // Try SFTP first — faster for larger files, avoids cat shell overhead
    const client = this.manager.getClient(nodeId);
    if (client) {
      try {
        return await new Promise<string>((resolve, reject) => {
          client.sftp((err, sftp) => {
            if (err) return reject(err);
            sftp.readFile(path, (readErr, data) => {
              sftp.end();
              if (readErr) return reject(readErr);
              resolve(data.toString('utf-8'));
            });
          });
        });
      } catch {
        // fall through to cat
      }
    }
    const result = await this.manager.exec(nodeId, `cat "${path}"`);
    if (result.code !== 0) throw new Error(`Failed to read ${path} on ${nodeId}: ${result.stderr}`);
    return result.stdout;
  }

  async writeFile(nodeId: string, path: string, content: string): Promise<void> {
    const dir = path.substring(0, path.lastIndexOf('/')) || '/tmp';
    const client = this.manager.getClient(nodeId);
    if (client) {
      try {
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
        // fall through to base64
      }
    }
    const b64 = Buffer.from(content, 'utf-8').toString('base64');
    const cmd = `mkdir -p "${dir}" && echo '${b64}' | base64 -d > "${path}"`;
    const result = await this.manager.exec(nodeId, cmd);
    if (result.code !== 0) throw new Error(`Failed to write ${path} on ${nodeId}: ${result.stderr}`);
  }

  async stat(nodeId: string, path: string): Promise<FileInfo> {
    const cacheKey = `${nodeId}:${path}`;
    const cached = this.statCache.get(cacheKey);
    if (cached && Date.now() - cached.at < STAT_CACHE_TTL) return cached.info;

    const cmd = `stat -c '%s %F %a %Y %U' "${path}" 2>/dev/null && echo OK || echo NOTFOUND`;
    const result = await this.manager.exec(nodeId, cmd);

    if (result.stdout.includes('NOTFOUND') || result.code !== 0) {
      throw new Error(`File not found: ${path} on ${nodeId}`);
    }

    const parts = result.stdout.trim().split('\n')[0].split(' ');
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
