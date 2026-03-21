// OmniWire — self-update via npm registry
// Checks for new versions and updates in-place
// Works on all architectures: x64, arm64, armv7l (RPi), darwin, linux, win32

import { execFile } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));

interface UpdateResult {
  readonly currentVersion: string;
  readonly latestVersion: string;
  readonly updated: boolean;
  readonly message: string;
}

function getCurrentVersion(): string {
  try {
    const pkgPath = join(__dirname, '..', 'package.json');
    const pkg = JSON.parse(readFileSync(pkgPath, 'utf-8'));
    return pkg.version ?? '0.0.0';
  } catch {
    return '0.0.0';
  }
}

function runCommand(cmd: string, args: string[]): Promise<{ stdout: string; stderr: string; code: number }> {
  return new Promise((resolve) => {
    execFile(cmd, args, { timeout: 60_000 }, (err, stdout, stderr) => {
      resolve({
        stdout: (stdout ?? '').trim(),
        stderr: (stderr ?? '').trim(),
        code: err ? ((err as Record<string, unknown>).code as number | undefined) ?? 1 : 0,
      });
    });
  });
}

/** Check if a newer version is available on npm */
export async function checkForUpdate(): Promise<{ current: string; latest: string; updateAvailable: boolean }> {
  const current = getCurrentVersion();

  // Use npm view to check latest — works on all platforms/architectures
  const result = await runCommand('npm', ['view', 'omniwire', 'version']);
  const latest = result.stdout.trim();

  if (!latest || result.code !== 0) {
    return { current, latest: current, updateAvailable: false };
  }

  return {
    current,
    latest,
    updateAvailable: latest !== current && compareVersions(latest, current) > 0,
  };
}

/** Self-update OmniWire to the latest version */
export async function selfUpdate(): Promise<UpdateResult> {
  const current = getCurrentVersion();

  // Check latest version
  const check = await checkForUpdate();
  if (!check.updateAvailable) {
    return {
      currentVersion: current,
      latestVersion: check.latest,
      updated: false,
      message: `Already on latest version (${current})`,
    };
  }

  // Detect package manager (npm or global install)
  const npmCmd = process.platform === 'win32' ? 'npm.cmd' : 'npm';

  // Try global update first
  const globalResult = await runCommand(npmCmd, ['install', '-g', `omniwire@${check.latest}`]);
  if (globalResult.code === 0) {
    return {
      currentVersion: current,
      latestVersion: check.latest,
      updated: true,
      message: `Updated ${current} → ${check.latest} (global)`,
    };
  }

  // Fallback: local update (for non-global installs)
  const localResult = await runCommand(npmCmd, ['install', `omniwire@${check.latest}`]);
  if (localResult.code === 0) {
    return {
      currentVersion: current,
      latestVersion: check.latest,
      updated: true,
      message: `Updated ${current} → ${check.latest} (local)`,
    };
  }

  return {
    currentVersion: current,
    latestVersion: check.latest,
    updated: false,
    message: `Update failed: ${globalResult.stderr || localResult.stderr}`,
  };
}

/** Compare semver strings: returns >0 if a > b, <0 if a < b, 0 if equal */
function compareVersions(a: string, b: string): number {
  const pa = a.split('.').map(Number);
  const pb = b.split('.').map(Number);
  for (let i = 0; i < 3; i++) {
    const diff = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (diff !== 0) return diff;
  }
  return 0;
}

/** Get system info for diagnostics */
export function getSystemInfo(): Record<string, string> {
  return {
    version: getCurrentVersion(),
    platform: process.platform,
    arch: process.arch,
    nodeVersion: process.version,
    pid: String(process.pid),
  };
}
