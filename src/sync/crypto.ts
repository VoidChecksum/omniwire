// CyberSync — XChaCha20-Poly1305 encryption for sensitive sync items
// Uses @noble/ciphers — zero C dependencies, audited, constant-time

import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { randomBytes } from 'node:crypto';
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';

const KEY_LENGTH = 32;       // 256-bit key
const NONCE_LENGTH = 24;     // 192-bit nonce (XChaCha20)
const CONFIG_DIR = join(homedir(), '.omniwire');
const KEY_PATH = join(CONFIG_DIR, 'secret.key');

// Globs that trigger encryption — files matching these are encrypted at rest
export const SENSITIVE_GLOBS = [
  'settings.json',
  'settings.local.json',
  '.credentials.json',
  'memory/**',
  '*.env',
  'config.json',
  'opencode.json',
  'openclaw.json',
];

let cachedKey: Uint8Array | null = null;

/** Load or generate the master encryption key */
export function loadOrCreateKey(): Uint8Array {
  if (cachedKey) return cachedKey;

  if (existsSync(KEY_PATH)) {
    const hex = readFileSync(KEY_PATH, 'utf-8').trim();
    cachedKey = Buffer.from(hex, 'hex');
    if (cachedKey.length !== KEY_LENGTH) {
      throw new Error(`Invalid key length in ${KEY_PATH}: expected ${KEY_LENGTH} bytes, got ${cachedKey.length}`);
    }
    return cachedKey;
  }

  // Generate new key
  if (!existsSync(CONFIG_DIR)) {
    mkdirSync(CONFIG_DIR, { recursive: true });
  }
  const key = randomBytes(KEY_LENGTH);
  writeFileSync(KEY_PATH, Buffer.from(key).toString('hex') + '\n', { mode: 0o600 });
  cachedKey = new Uint8Array(key);
  return cachedKey;
}

/** Check if encryption key exists (don't auto-create) */
export function hasEncryptionKey(): boolean {
  return existsSync(KEY_PATH);
}

/** Encrypt plaintext → { nonce (24 bytes) || ciphertext+tag } */
export function encrypt(plaintext: Buffer, key: Uint8Array): Buffer {
  const nonce = randomBytes(NONCE_LENGTH);
  const cipher = xchacha20poly1305(key, nonce);
  const ciphertext = cipher.encrypt(new Uint8Array(plaintext));
  // Prepend nonce to ciphertext for storage
  const result = Buffer.alloc(NONCE_LENGTH + ciphertext.length);
  result.set(nonce, 0);
  result.set(ciphertext, NONCE_LENGTH);
  return result;
}

/** Decrypt { nonce (24 bytes) || ciphertext+tag } → plaintext */
export function decrypt(encrypted: Buffer, key: Uint8Array): Buffer {
  if (encrypted.length < NONCE_LENGTH + 16) {
    throw new Error('Encrypted data too short (missing nonce or auth tag)');
  }
  const nonce = new Uint8Array(encrypted.subarray(0, NONCE_LENGTH));
  const ciphertext = new Uint8Array(encrypted.subarray(NONCE_LENGTH));
  const cipher = xchacha20poly1305(key, nonce);
  const plaintext = cipher.decrypt(ciphertext);
  return Buffer.from(plaintext);
}

/** Check if a relative path should be encrypted based on sensitive globs */
export function isSensitivePath(relPath: string): boolean {
  const normalized = relPath.replaceAll('\\', '/');
  for (const pattern of SENSITIVE_GLOBS) {
    if (pattern.includes('**')) {
      // Directory glob: memory/** matches memory/anything
      const prefix = pattern.replace('/**', '');
      if (normalized.startsWith(prefix + '/') || normalized === prefix) return true;
    } else if (pattern.startsWith('*.')) {
      // Extension glob: *.env matches anything.env
      const ext = pattern.slice(1);
      if (normalized.endsWith(ext)) return true;
    } else {
      // Exact match or filename match
      if (normalized === pattern || normalized.endsWith('/' + pattern)) return true;
    }
  }
  return false;
}
