// CyberSync — SHA-256 content hashing (streaming for large files)

import { createHash } from 'node:crypto';
import { readFile, stat } from 'node:fs/promises';
import { createReadStream } from 'node:fs';

const STREAM_THRESHOLD = 1_048_576; // 1MB — stream hash above this

export function hashBuffer(data: Buffer): string {
  return createHash('sha256').update(data).digest('hex');
}

export async function hashFile(filePath: string): Promise<string> {
  const info = await stat(filePath);

  // Small files: buffer hash (faster for <1MB, single syscall)
  if (info.size < STREAM_THRESHOLD) {
    const data = await readFile(filePath);
    return hashBuffer(data);
  }

  // Large files: streaming hash (constant memory)
  return new Promise<string>((resolve, reject) => {
    const hash = createHash('sha256');
    const stream = createReadStream(filePath);
    stream.on('data', (chunk: string | Buffer) => hash.update(chunk));
    stream.on('end', () => resolve(hash.digest('hex')));
    stream.on('error', reject);
  });
}
