// OmniWire — self-update via npm registry + GitHub releases
// Supports: auto-update on startup, periodic checks, mesh-wide updates, GitHub + npm sources
// Works on all architectures: x64, arm64, armv7l (RPi), darwin, linux, win32

import { exec } from 'node:child_process';
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));

const GITHUB_REPO = 'VoidChecksum/omniwire';
const NPM_PACKAGE = 'omniwire';
const UPDATE_CHECK_INTERVAL_MS = 3_600_000; // 1 hour
const STATE_DIR = join(__dirname, '..', '.omniwire-state');
const STATE_FILE = join(STATE_DIR, 'update-state.json');

export type UpdateSource = 'npm' | 'github' | 'auto';

export interface UpdateResult {
  readonly currentVersion: string;
  readonly latestVersion: string;
  readonly updated: boolean;
  readonly message: string;
  readonly source?: UpdateSource;
}

interface UpdateState {
  lastCheck: number;
  lastVersion: string;
  autoUpdateEnabled: boolean;
  source: UpdateSource;
  checkIntervalMs: number;
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

function runCommand(cmd: string, args: string[], timeoutMs = 60_000): Promise<{ stdout: string; stderr: string; code: number }> {
  return new Promise((resolve) => {
    // Quote args and use exec() — works on all platforms including .cmd/.bat on Windows
    const escaped = args.map((a) => a.includes(' ') || a.includes('"') ? `"${a.replace(/"/g, '\\"')}"` : a);
    exec(`${cmd} ${escaped.join(' ')}`, { timeout: timeoutMs, windowsHide: true }, (err, stdout, stderr) => {
      resolve({
        stdout: (stdout ?? '').trim(),
        stderr: (stderr ?? '').trim(),
        code: err ? ((err as unknown as Record<string, unknown>).code as number | undefined) ?? 1 : 0,
      });
    });
  });
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

function loadState(): UpdateState {
  try {
    if (existsSync(STATE_FILE)) {
      return JSON.parse(readFileSync(STATE_FILE, 'utf-8'));
    }
  } catch { /* fresh state */ }
  return { lastCheck: 0, lastVersion: getCurrentVersion(), autoUpdateEnabled: true, source: 'auto', checkIntervalMs: UPDATE_CHECK_INTERVAL_MS };
}

function saveState(state: UpdateState): void {
  try {
    if (!existsSync(STATE_DIR)) mkdirSync(STATE_DIR, { recursive: true });
    writeFileSync(STATE_FILE, JSON.stringify(state, null, 2));
  } catch { /* non-critical */ }
}

// --- Check sources ---

/** Check npm registry for latest version */
async function checkNpm(): Promise<{ version: string; source: 'npm' } | null> {
  const result = await runCommand(process.platform === 'win32' ? 'npm.cmd' : 'npm', ['view', NPM_PACKAGE, 'version'], 15_000);
  const version = result.stdout.trim();
  if (version && result.code === 0) return { version, source: 'npm' };
  return null;
}

/** Check GitHub releases for latest version */
async function checkGitHub(): Promise<{ version: string; tarballUrl: string; source: 'github' } | null> {
  const url = `https://api.github.com/repos/${GITHUB_REPO}/releases/latest`;

  // Try native fetch first (Node 18+), then curl, then PowerShell
  let resultStdout = '';
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10_000);
    const resp = await fetch(url, { headers: { Accept: 'application/vnd.github+json' }, signal: controller.signal });
    clearTimeout(timeout);
    resultStdout = await resp.text();
  } catch {
    // Fallback: curl (Linux/macOS) or PowerShell (Windows)
    const result = process.platform === 'win32'
      ? await runCommand('powershell', ['-NoProfile', '-Command', `(Invoke-WebRequest -Uri '${url}' -Headers @{Accept='application/vnd.github+json'} -TimeoutSec 10 -UseBasicParsing).Content`], 15_000)
      : await runCommand('curl', ['-s', '--max-time', '10', '-H', 'Accept: application/vnd.github+json', url], 15_000);
    if (result.code !== 0 || !result.stdout) return null;
    resultStdout = result.stdout;
  }
  if (!resultStdout) return null;
  try {
    const release = JSON.parse(resultStdout);
    const tag = (release.tag_name ?? '').replace(/^v/, '');
    const tarball = release.tarball_url ?? `https://github.com/${GITHUB_REPO}/archive/refs/tags/${release.tag_name}.tar.gz`;
    if (tag) return { version: tag, tarballUrl: tarball, source: 'github' };
  } catch { /* parse error */ }
  return null;
}

/** Check for update from best available source */
export async function checkForUpdate(source: UpdateSource = 'auto'): Promise<{ current: string; latest: string; updateAvailable: boolean; source: UpdateSource }> {
  const current = getCurrentVersion();

  if (source === 'npm' || source === 'auto') {
    const npm = await checkNpm();
    if (npm && compareVersions(npm.version, current) > 0) {
      return { current, latest: npm.version, updateAvailable: true, source: 'npm' };
    }
    if (source === 'npm') return { current, latest: npm?.version ?? current, updateAvailable: false, source: 'npm' };
  }

  if (source === 'github' || source === 'auto') {
    const gh = await checkGitHub();
    if (gh && compareVersions(gh.version, current) > 0) {
      return { current, latest: gh.version, updateAvailable: true, source: 'github' };
    }
    if (source === 'github') return { current, latest: gh?.version ?? current, updateAvailable: false, source: 'github' };
  }

  return { current, latest: current, updateAvailable: false, source: 'auto' };
}

// --- Update methods ---

/** Update via npm */
async function updateViaNpm(version: string): Promise<{ ok: boolean; message: string }> {
  const npmCmd = process.platform === 'win32' ? 'npm.cmd' : 'npm';

  // Try global update first
  const global = await runCommand(npmCmd, ['install', '-g', `${NPM_PACKAGE}@${version}`]);
  if (global.code === 0) return { ok: true, message: `npm global: ${version}` };

  // Fallback: local
  const local = await runCommand(npmCmd, ['install', `${NPM_PACKAGE}@${version}`]);
  if (local.code === 0) return { ok: true, message: `npm local: ${version}` };

  return { ok: false, message: global.stderr || local.stderr || 'npm update failed' };
}

/** Update via GitHub release tarball */
async function updateViaGitHub(version: string): Promise<{ ok: boolean; message: string }> {
  const tag = `v${version}`;
  const tarball = `https://github.com/${GITHUB_REPO}/archive/refs/tags/${tag}.tar.gz`;
  const tmpDir = process.platform === 'win32' ? '%TEMP%' : '/tmp';
  const archive = `${tmpDir}/omniwire-${version}.tar.gz`;

  // Download
  const dl = await runCommand('curl', ['-sL', '-o', archive, tarball], 30_000);
  if (dl.code !== 0) return { ok: false, message: `download failed: ${dl.stderr}` };

  // Determine install location
  const installDir = join(__dirname, '..');

  if (process.platform === 'win32') {
    // Windows: extract with tar (available on Win10+)
    const extract = await runCommand('tar', ['-xzf', archive, '-C', tmpDir]);
    if (extract.code !== 0) return { ok: false, message: `extract failed: ${extract.stderr}` };
    // Copy files over (xcopy)
    const src = `${tmpDir}\\omniwire-${version}`;
    const copy = await runCommand('xcopy', ['/E', '/Y', '/I', src, installDir]);
    return { ok: copy.code === 0, message: copy.code === 0 ? `github: ${version}` : copy.stderr };
  }

  // Linux/macOS: extract and install
  const extract = await runCommand('tar', ['-xzf', archive, '-C', '/tmp']);
  if (extract.code !== 0) return { ok: false, message: `extract failed: ${extract.stderr}` };

  const src = `/tmp/omniwire-${version}`;
  // npm install from extracted dir to rebuild
  const install = await runCommand('bash', ['-c', `cd ${src} && npm install --production && npm run build 2>/dev/null; cp -r dist/* ${installDir}/dist/ 2>/dev/null; cp package.json ${installDir}/ 2>/dev/null; echo "ok"`]);
  return { ok: install.stdout.includes('ok'), message: install.stdout.includes('ok') ? `github: ${version}` : install.stderr };
}

/** Self-update OmniWire to the latest version */
export async function selfUpdate(source: UpdateSource = 'auto'): Promise<UpdateResult> {
  const current = getCurrentVersion();
  const check = await checkForUpdate(source);

  if (!check.updateAvailable) {
    return {
      currentVersion: current,
      latestVersion: check.latest,
      updated: false,
      message: `Already on latest version (${current})`,
      source: check.source,
    };
  }

  // Try npm first (most reliable), then GitHub
  let result: { ok: boolean; message: string };
  let usedSource: UpdateSource;

  if (check.source === 'npm' || source === 'npm') {
    result = await updateViaNpm(check.latest);
    usedSource = 'npm';
  } else if (check.source === 'github' || source === 'github') {
    result = await updateViaGitHub(check.latest);
    usedSource = 'github';
  } else {
    // Auto: try npm, fallback to github
    result = await updateViaNpm(check.latest);
    usedSource = 'npm';
    if (!result.ok) {
      result = await updateViaGitHub(check.latest);
      usedSource = 'github';
    }
  }

  if (result.ok) {
    const state = loadState();
    saveState({ ...state, lastCheck: Date.now(), lastVersion: check.latest });
  }

  return {
    currentVersion: current,
    latestVersion: check.latest,
    updated: result.ok,
    message: result.ok ? `Updated ${current} → ${check.latest} via ${usedSource}` : `Update failed: ${result.message}`,
    source: usedSource,
  };
}

// --- Auto-update ---

let autoUpdateTimer: ReturnType<typeof setInterval> | null = null;

/** Start auto-update background checker */
export function startAutoUpdate(intervalMs?: number, onUpdate?: (result: UpdateResult) => void): void {
  stopAutoUpdate(); // Clear any existing timer

  const state = loadState();
  const interval = intervalMs ?? state.checkIntervalMs;
  saveState({ ...state, autoUpdateEnabled: true, checkIntervalMs: interval });

  // Run check immediately if enough time has passed
  const timeSinceCheck = Date.now() - state.lastCheck;
  if (timeSinceCheck >= interval) {
    void autoUpdateCheck(onUpdate);
  }

  autoUpdateTimer = setInterval(() => void autoUpdateCheck(onUpdate), interval);
  // Don't keep process alive just for updates
  if (autoUpdateTimer && 'unref' in autoUpdateTimer) {
    autoUpdateTimer.unref();
  }
}

/** Stop auto-update background checker */
export function stopAutoUpdate(): void {
  if (autoUpdateTimer) {
    clearInterval(autoUpdateTimer);
    autoUpdateTimer = null;
  }
  const state = loadState();
  saveState({ ...state, autoUpdateEnabled: false });
}

/** Single auto-update check + apply */
async function autoUpdateCheck(onUpdate?: (result: UpdateResult) => void): Promise<void> {
  try {
    const check = await checkForUpdate('auto');
    if (check.updateAvailable) {
      const result = await selfUpdate('auto');
      saveState({ ...loadState(), lastCheck: Date.now() });
      onUpdate?.(result);
    } else {
      saveState({ ...loadState(), lastCheck: Date.now() });
    }
  } catch { /* silent fail for background checks */ }
}

/** Check if auto-update is enabled */
export function isAutoUpdateEnabled(): boolean {
  return loadState().autoUpdateEnabled;
}

/** Get auto-update state info */
export function getAutoUpdateState(): UpdateState & { currentVersion: string; timerActive: boolean } {
  return {
    ...loadState(),
    currentVersion: getCurrentVersion(),
    timerActive: autoUpdateTimer !== null,
  };
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
