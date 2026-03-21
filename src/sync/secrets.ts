// CyberSync — Pluggable secrets backend (1Password, env vars, file-based)
// Stores and retrieves secrets across all mesh nodes via a central vault
// 1Password uses the `op` CLI (execFile, not exec) — works on all platforms/architectures
// NOTE: All remote commands use NodeManager.exec() which is SSH2 client.exec()

import { execFile } from 'node:child_process';
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';

export type SecretsBackend = 'onepassword' | 'file' | 'env';

export interface SecretEntry {
  readonly key: string;
  readonly value: string;
  readonly vault?: string;
  readonly updatedAt?: string;
}

interface SecretsConfig {
  readonly backend: SecretsBackend;
  readonly vault?: string;        // 1Password vault name (default: "OmniWire")
  readonly itemPrefix?: string;   // 1Password item prefix (default: "omniwire/")
}

const CONFIG_DIR = join(homedir(), '.omniwire');
const SECRETS_CONFIG_PATH = join(CONFIG_DIR, 'secrets.json');
const FILE_SECRETS_PATH = join(CONFIG_DIR, 'secrets.enc');

function loadSecretsConfig(): SecretsConfig {
  if (existsSync(SECRETS_CONFIG_PATH)) {
    try {
      return JSON.parse(readFileSync(SECRETS_CONFIG_PATH, 'utf-8'));
    } catch { /* fall through */ }
  }
  return { backend: 'file' };
}

// Uses execFile (not exec) — arguments are passed as array, not interpolated into shell
function run(cmd: string, args: string[]): Promise<{ stdout: string; code: number }> {
  return new Promise((resolve) => {
    execFile(cmd, args, { timeout: 15_000 }, (err, stdout) => {
      resolve({ stdout: (stdout ?? '').trim(), code: err ? 1 : 0 });
    });
  });
}

// ── 1Password Backend (via `op` CLI, execFile with explicit argv) ────────

async function opAvailable(): Promise<boolean> {
  const { code } = await run('op', ['--version']);
  return code === 0;
}

async function opGet(key: string, vault: string): Promise<string | null> {
  const { stdout, code } = await run('op', [
    'item', 'get', key,
    '--vault', vault,
    '--fields', 'password',
    '--format', 'json',
  ]);
  if (code !== 0) return null;
  try {
    const parsed = JSON.parse(stdout);
    return parsed.value ?? parsed.password ?? stdout;
  } catch {
    return stdout || null;
  }
}

async function opSet(key: string, value: string, vault: string): Promise<boolean> {
  // Try edit first (update existing)
  const edit = await run('op', [
    'item', 'edit', key,
    '--vault', vault,
    `password=${value}`,
  ]);
  if (edit.code === 0) return true;

  // Create new item
  const create = await run('op', [
    'item', 'create',
    '--category', 'password',
    '--vault', vault,
    '--title', key,
    `password=${value}`,
  ]);
  return create.code === 0;
}

async function opDelete(key: string, vault: string): Promise<boolean> {
  const { code } = await run('op', ['item', 'delete', key, '--vault', vault]);
  return code === 0;
}

async function opList(vault: string, prefix: string): Promise<SecretEntry[]> {
  const { stdout, code } = await run('op', [
    'item', 'list',
    '--vault', vault,
    '--format', 'json',
  ]);
  if (code !== 0) return [];
  try {
    const items = JSON.parse(stdout) as Array<{ title: string; updated_at?: string }>;
    return items
      .filter((i) => i.title.startsWith(prefix))
      .map((i) => ({ key: i.title, value: '', updatedAt: i.updated_at, vault }));
  } catch {
    return [];
  }
}

// ── File Backend ─────────────────────────────────────────────────────────

function fileLoad(): Record<string, string> {
  if (!existsSync(FILE_SECRETS_PATH)) return {};
  try {
    return JSON.parse(readFileSync(FILE_SECRETS_PATH, 'utf-8'));
  } catch {
    return {};
  }
}

function fileSave(data: Record<string, string>): void {
  if (!existsSync(CONFIG_DIR)) mkdirSync(CONFIG_DIR, { recursive: true });
  writeFileSync(FILE_SECRETS_PATH, JSON.stringify(data, null, 2), { mode: 0o600 });
}

// ── Unified Secrets API ──────────────────────────────────────────────────

export class SecretsManager {
  private config: SecretsConfig;
  private vault: string;
  private prefix: string;

  constructor(config?: Partial<SecretsConfig>) {
    const loaded = loadSecretsConfig();
    this.config = { ...loaded, ...config };
    this.vault = this.config.vault ?? 'OmniWire';
    this.prefix = this.config.itemPrefix ?? 'omniwire/';
  }

  get backend(): SecretsBackend {
    return this.config.backend;
  }

  /** Get a secret by key */
  async get(key: string): Promise<string | null> {
    const fullKey = this.prefix + key;
    switch (this.config.backend) {
      case 'onepassword':
        return opGet(fullKey, this.vault);
      case 'env':
        return process.env[key.toUpperCase().replace(/[^A-Z0-9]/g, '_')] ?? null;
      case 'file':
      default: {
        const data = fileLoad();
        return data[key] ?? null;
      }
    }
  }

  /** Set a secret */
  async set(key: string, value: string): Promise<boolean> {
    const fullKey = this.prefix + key;
    switch (this.config.backend) {
      case 'onepassword':
        return opSet(fullKey, value, this.vault);
      case 'env':
        process.env[key.toUpperCase().replace(/[^A-Z0-9]/g, '_')] = value;
        return true;
      case 'file':
      default: {
        const data = fileLoad();
        data[key] = value;
        fileSave(data);
        return true;
      }
    }
  }

  /** Delete a secret */
  async delete(key: string): Promise<boolean> {
    const fullKey = this.prefix + key;
    switch (this.config.backend) {
      case 'onepassword':
        return opDelete(fullKey, this.vault);
      case 'env':
        delete process.env[key.toUpperCase().replace(/[^A-Z0-9]/g, '_')];
        return true;
      case 'file':
      default: {
        const data = fileLoad();
        delete data[key];
        fileSave(data);
        return true;
      }
    }
  }

  /** List all secrets (values omitted for security) */
  async list(): Promise<SecretEntry[]> {
    switch (this.config.backend) {
      case 'onepassword':
        return opList(this.vault, this.prefix);
      case 'file':
      default: {
        const data = fileLoad();
        return Object.keys(data).map((key) => ({ key, value: '***' }));
      }
      case 'env':
        return [];
    }
  }

  /** Sync a secret to all mesh nodes via SSH2 (NodeManager.exec) */
  async syncToNodes(key: string, nodeIds: string[], manager: import('../nodes/manager.js').NodeManager): Promise<Record<string, boolean>> {
    const value = await this.get(key);
    if (!value) return Object.fromEntries(nodeIds.map((id) => [id, false]));

    const results: Record<string, boolean> = {};
    const b64Value = Buffer.from(JSON.stringify({ [key]: value })).toString('base64');

    await Promise.allSettled(nodeIds.map(async (nodeId) => {
      try {
        // Merge into remote node's secrets file via SSH2 (base64 to avoid shell issues)
        const remoteDir = '/root/.omniwire';
        const remotePath = `${remoteDir}/secrets.enc`;
        // Read existing, merge, write back — all via SSH2 client.exec()
        const writeResult = await manager.exec(nodeId,
          `mkdir -p "${remoteDir}" && ` +
          `existing=$(cat "${remotePath}" 2>/dev/null || echo "{}") && ` +
          `echo '${b64Value}' | base64 -d | python3 -c "import sys,json; ` +
          `e=json.loads(sys.stdin.read()); o=json.loads('''$existing'''); o.update(e); ` +
          `print(json.dumps(o))" > "${remotePath}" && chmod 600 "${remotePath}"`
        );
        results[nodeId] = writeResult.code === 0;
      } catch {
        results[nodeId] = false;
      }
    }));
    return results;
  }

  /** Check if 1Password CLI is available */
  async isOnePasswordAvailable(): Promise<boolean> {
    return opAvailable();
  }
}
