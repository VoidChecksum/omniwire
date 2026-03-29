// OmniMesh — Cross-platform WireGuard mesh network for OmniWire
// Manages peer discovery, key rotation, NAT traversal, and mesh topology
// Supports: Linux (wg-quick/networkd), Windows (wireguard.exe), macOS (wg-quick/brew)

import type { ExecResult } from '../protocol/types.js';

// --- Types ---

export interface OmniMeshPeer {
  readonly id: string;           // Node name (e.g., "contabo")
  readonly publicKey: string;    // WireGuard public key
  readonly endpoint?: string;    // Public endpoint (host:port) — empty for NAT'd peers
  readonly meshIp: string;       // Internal mesh IP (10.10.0.x)
  readonly allowedIps: string;   // AllowedIPs CIDR
  readonly latestHandshake?: number; // Unix timestamp
  readonly transferRx?: number;  // Bytes received
  readonly transferTx?: number;  // Bytes transmitted
  readonly keepalive?: number;   // Persistent keepalive interval (25 for NAT'd)
  readonly os: 'linux' | 'windows' | 'darwin';
  readonly tags?: readonly string[];
  readonly online?: boolean;
}

export interface OmniMeshConfig {
  readonly interfaceName: string;     // wg0, omnimesh0, etc.
  readonly meshSubnet: string;        // 10.10.0.0/24
  readonly listenPort: number;        // Default: 51820
  readonly dns?: readonly string[];   // DNS servers pushed to peers
  readonly mtu?: number;              // MTU (default: 1420 for WG)
  readonly fwmark?: number;           // Firewall mark
  readonly preUp?: string;            // Pre-up hook
  readonly postUp?: string;           // Post-up hook
  readonly preDown?: string;          // Pre-down hook
  readonly postDown?: string;         // Post-down hook
}

export interface OmniMeshStatus {
  readonly interfaceName: string;
  readonly publicKey: string;
  readonly listenPort: number;
  readonly peers: readonly OmniMeshPeer[];
  readonly meshIp: string;
  readonly uptime: string;
}

export interface KeyPair {
  readonly privateKey: string;
  readonly publicKey: string;
  readonly presharedKey?: string;     // Optional PSK for quantum-resistance
}

// --- Cross-platform command builders ---

export function detectOS(): 'linux' | 'windows' | 'darwin' {
  const p = process.platform;
  if (p === 'win32') return 'windows';
  if (p === 'darwin') return 'darwin';
  return 'linux';
}

/** Generate WireGuard key pair commands per OS */
export function genKeysCmd(os: 'linux' | 'windows' | 'darwin'): string {
  if (os === 'windows') {
    // wireguard.exe uses wg.exe for keygen on Windows
    return [
      'cd %TEMP%',
      'wg genkey > omnimesh_priv.key',
      'type omnimesh_priv.key | wg pubkey > omnimesh_pub.key',
      'wg genpsk > omnimesh_psk.key',
      'echo PRIV: & type omnimesh_priv.key',
      'echo PUB: & type omnimesh_pub.key',
      'echo PSK: & type omnimesh_psk.key',
    ].join(' && ');
  }
  // Linux/macOS
  return [
    'priv=$(wg genkey)',
    'pub=$(echo "$priv" | wg pubkey)',
    'psk=$(wg genpsk)',
    'echo "PRIV:$priv"',
    'echo "PUB:$pub"',
    'echo "PSK:$psk"',
  ].join('; ');
}

/** Parse key generation output */
export function parseKeys(stdout: string): KeyPair {
  const lines = stdout.split('\n').map((l) => l.trim()).filter(Boolean);
  let privateKey = '', publicKey = '', presharedKey = '';
  for (const line of lines) {
    if (line.startsWith('PRIV:')) privateKey = line.slice(5).trim();
    else if (line.startsWith('PUB:')) publicKey = line.slice(4).trim();
    else if (line.startsWith('PSK:')) presharedKey = line.slice(4).trim();
  }
  return { privateKey, publicKey, presharedKey: presharedKey || undefined };
}

/** Build WireGuard config file content */
export function buildWgConfig(
  localPeer: { privateKey: string; meshIp: string; listenPort: number },
  peers: readonly OmniMeshPeer[],
  config: Partial<OmniMeshConfig> = {},
  presharedKeys?: Record<string, string>,  // peerId -> PSK
): string {
  const lines: string[] = ['[Interface]'];
  lines.push(`PrivateKey = ${localPeer.privateKey}`);
  lines.push(`Address = ${localPeer.meshIp}/24`);
  lines.push(`ListenPort = ${localPeer.listenPort}`);
  if (config.dns?.length) lines.push(`DNS = ${config.dns.join(', ')}`);
  if (config.mtu) lines.push(`MTU = ${config.mtu}`);
  if (config.fwmark) lines.push(`FwMark = ${config.fwmark}`);
  if (config.postUp) lines.push(`PostUp = ${config.postUp}`);
  if (config.postDown) lines.push(`PostDown = ${config.postDown}`);
  if (config.preUp) lines.push(`PreUp = ${config.preUp}`);
  if (config.preDown) lines.push(`PreDown = ${config.preDown}`);

  for (const peer of peers) {
    lines.push('');
    lines.push('[Peer]');
    lines.push(`# ${peer.id}`);
    lines.push(`PublicKey = ${peer.publicKey}`);
    const psk = presharedKeys?.[peer.id];
    if (psk) lines.push(`PresharedKey = ${psk}`);
    lines.push(`AllowedIPs = ${peer.allowedIps}`);
    if (peer.endpoint) lines.push(`Endpoint = ${peer.endpoint}`);
    lines.push(`PersistentKeepalive = ${peer.keepalive ?? 25}`);
  }

  return lines.join('\n') + '\n';
}

/** Get WireGuard config path per OS */
export function wgConfigPath(os: 'linux' | 'windows' | 'darwin', iface: string): string {
  switch (os) {
    case 'linux': return `/etc/wireguard/${iface}.conf`;
    case 'darwin': return `/usr/local/etc/wireguard/${iface}.conf`;
    case 'windows': return `C:\\Program Files\\WireGuard\\Data\\Configurations\\${iface}.conf.dpapi`;
  }
}

/** Build command to bring interface up */
export function bringUpCmd(os: 'linux' | 'windows' | 'darwin', iface: string): string {
  switch (os) {
    case 'linux': return `wg-quick up ${iface} 2>&1 || (systemctl start wg-quick@${iface} 2>&1)`;
    case 'darwin': return `wg-quick up ${iface} 2>&1`;
    case 'windows': return `"C:\\Program Files\\WireGuard\\wireguard.exe" /installtunnelservice ${iface} 2>&1`;
  }
}

/** Build command to bring interface down */
export function bringDownCmd(os: 'linux' | 'windows' | 'darwin', iface: string): string {
  switch (os) {
    case 'linux': return `wg-quick down ${iface} 2>&1 || (systemctl stop wg-quick@${iface} 2>&1)`;
    case 'darwin': return `wg-quick down ${iface} 2>&1`;
    case 'windows': return `"C:\\Program Files\\WireGuard\\wireguard.exe" /uninstalltunnelservice ${iface} 2>&1`;
  }
}

/** Build command to get WireGuard status */
export function statusCmd(os: 'linux' | 'windows' | 'darwin', iface: string): string {
  if (os === 'windows') {
    return `wg show ${iface} 2>&1`;
  }
  return `wg show ${iface} 2>&1; echo "---addr---"; ip -4 addr show ${iface} 2>/dev/null || ifconfig ${iface} 2>/dev/null`;
}

/** Parse `wg show` output into structured peers */
export function parseWgShow(stdout: string): OmniMeshStatus {
  const lines = stdout.split('\n');
  let interfaceName = '', publicKey = '', listenPort = 0, meshIp = '';
  const peers: OmniMeshPeer[] = [];

  // Mutable builder for parsing — converted to readonly OmniMeshPeer on push
  interface PeerBuilder {
    publicKey: string; id: string; meshIp: string; allowedIps: string;
    os: 'linux' | 'windows' | 'darwin'; endpoint?: string;
    latestHandshake?: number; transferRx?: number; transferTx?: number; keepalive?: number;
  }
  let currentPeer: PeerBuilder | null = null;

  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed.startsWith('interface:')) interfaceName = trimmed.split(':')[1]?.trim() ?? '';
    else if (trimmed.startsWith('public key:') && !currentPeer) publicKey = trimmed.split(':').slice(1).join(':').trim();
    else if (trimmed.startsWith('listening port:')) listenPort = parseInt(trimmed.split(':')[1]?.trim() ?? '0');
    else if (trimmed.startsWith('peer:')) {
      if (currentPeer?.publicKey) peers.push(currentPeer);
      currentPeer = { publicKey: trimmed.split(':').slice(1).join(':').trim(), os: 'linux', id: '', meshIp: '', allowedIps: '' };
    } else if (currentPeer) {
      if (trimmed.startsWith('endpoint:')) currentPeer.endpoint = trimmed.split(':').slice(1).join(':').trim();
      else if (trimmed.startsWith('allowed ips:')) {
        const ips = trimmed.split(':').slice(1).join(':').trim();
        currentPeer.allowedIps = ips;
        currentPeer.meshIp = ips.split('/')[0] ?? '';
      }
      else if (trimmed.startsWith('latest handshake:')) currentPeer.latestHandshake = Date.now();
      else if (trimmed.startsWith('transfer:')) {
        const parts = trimmed.split(':')[1]?.trim().split(',') ?? [];
        currentPeer.transferRx = parseTransferBytes(parts[0] ?? '');
        currentPeer.transferTx = parseTransferBytes(parts[1] ?? '');
      }
      else if (trimmed.startsWith('persistent keepalive:')) {
        currentPeer.keepalive = parseInt(trimmed.split(':')[1]?.trim() ?? '25');
      }
    }

    // Parse address from ip addr output
    if (trimmed.startsWith('inet ') && trimmed.includes('/')) {
      meshIp = trimmed.split(' ')[1]?.split('/')[0] ?? '';
    }
  }
  if (currentPeer?.publicKey) peers.push(currentPeer);

  return { interfaceName, publicKey, listenPort, peers, meshIp, uptime: '' };
}

function parseTransferBytes(s: string): number {
  const trimmed = s.trim();
  const match = trimmed.match(/([\d.]+)\s*(B|KiB|MiB|GiB|TiB)/);
  if (!match) return 0;
  const val = parseFloat(match[1]);
  const unit = match[2];
  const multipliers: Record<string, number> = { B: 1, KiB: 1024, MiB: 1048576, GiB: 1073741824, TiB: 1099511627776 };
  return Math.round(val * (multipliers[unit] ?? 1));
}

/** Build command to add a peer dynamically (no restart) */
export function addPeerCmd(iface: string, peer: OmniMeshPeer, psk?: string): string {
  const parts = [`wg set ${iface} peer ${peer.publicKey}`];
  parts.push(`allowed-ips ${peer.allowedIps}`);
  if (peer.endpoint) parts.push(`endpoint ${peer.endpoint}`);
  parts.push(`persistent-keepalive ${peer.keepalive ?? 25}`);
  if (psk) parts.push(`preshared-key <(echo "${psk}")`);
  return parts.join(' ');
}

/** Build command to remove a peer dynamically */
export function removePeerCmd(iface: string, publicKey: string): string {
  return `wg set ${iface} peer ${publicKey} remove`;
}

/** Build command to install WireGuard per OS */
export function installCmd(os: 'linux' | 'windows' | 'darwin'): string {
  switch (os) {
    case 'linux': return 'apt-get update && apt-get install -y wireguard wireguard-tools 2>&1 || yum install -y wireguard-tools 2>&1 || dnf install -y wireguard-tools 2>&1 || pacman -S --noconfirm wireguard-tools 2>&1';
    case 'darwin': return 'brew install wireguard-tools 2>&1';
    case 'windows': return 'winget install WireGuard.WireGuard --accept-source-agreements --accept-package-agreements 2>&1 || choco install wireguard -y 2>&1';
  }
}

/** Build command to check if WireGuard is installed */
export function checkInstalledCmd(os: 'linux' | 'windows' | 'darwin'): string {
  if (os === 'windows') return 'where wg 2>NUL && echo "INSTALLED" || echo "NOT_INSTALLED"';
  return 'which wg >/dev/null 2>&1 && echo "INSTALLED" || echo "NOT_INSTALLED"';
}

/** Build NAT traversal PostUp rules (iptables/nftables) */
export function natTraversalPostUp(iface: string, publicIface: string = 'eth0'): string {
  return [
    `iptables -A FORWARD -i ${iface} -j ACCEPT`,
    `iptables -A FORWARD -o ${iface} -j ACCEPT`,
    `iptables -t nat -A POSTROUTING -o ${publicIface} -j MASQUERADE`,
  ].join('; ');
}

/** Build NAT traversal PostDown rules */
export function natTraversalPostDown(iface: string, publicIface: string = 'eth0'): string {
  return [
    `iptables -D FORWARD -i ${iface} -j ACCEPT`,
    `iptables -D FORWARD -o ${iface} -j ACCEPT`,
    `iptables -t nat -D POSTROUTING -o ${publicIface} -j MASQUERADE`,
  ].join('; ');
}

/** Build command to rotate keys for a peer */
export function rotateKeyCmd(iface: string, os: 'linux' | 'windows' | 'darwin'): string {
  if (os === 'windows') {
    return 'echo "Key rotation on Windows requires config file update + tunnel restart"';
  }
  return [
    'NEW_PRIV=$(wg genkey)',
    'NEW_PUB=$(echo "$NEW_PRIV" | wg pubkey)',
    `wg set ${iface} private-key <(echo "$NEW_PRIV")`,
    'echo "PRIV:$NEW_PRIV"',
    'echo "PUB:$NEW_PUB"',
  ].join('; ');
}

/** Build monitoring/health check command */
export function healthCheckCmd(iface: string, peers: readonly string[]): string {
  const pings = peers.map((ip) => `(ping -c1 -W2 ${ip} >/dev/null 2>&1 && echo "OK ${ip}" || echo "FAIL ${ip}")`);
  return [
    `wg show ${iface} latest-handshakes 2>/dev/null`,
    `echo "---pings---"`,
    ...pings,
    `echo "---transfer---"`,
    `wg show ${iface} transfer 2>/dev/null`,
  ].join('; ');
}

/** Build STUN/endpoint discovery command for NAT'd peers */
export function stunDiscoverCmd(): string {
  return [
    '# Discover public endpoint via STUN',
    'stun_servers="stun.l.google.com:19302 stun1.l.google.com:19302 stun.cloudflare.com:3478"',
    'for s in $stun_servers; do',
    '  result=$(stun $s 2>/dev/null | grep -i "mapped" | head -1)',
    '  [ -n "$result" ] && { echo "STUN:$result"; break; }',
    'done',
    '# Fallback: curl-based IP detection',
    'echo "PUBLIC_IP:$(curl -s --max-time 3 https://api.ipify.org 2>/dev/null || curl -s --max-time 3 https://ifconfig.me 2>/dev/null)"',
  ].join('\n');
}

/** Generate a mesh topology config for N peers (hub-and-spoke or full-mesh) */
export function generateMeshTopology(
  peers: readonly { id: string; meshIp: string; publicKey: string; endpoint?: string }[],
  topology: 'full-mesh' | 'hub-spoke' = 'full-mesh',
  hubId?: string,
): Map<string, OmniMeshPeer[]> {
  const result = new Map<string, OmniMeshPeer[]>();

  if (topology === 'full-mesh') {
    // Every peer connects to every other peer
    for (const peer of peers) {
      const others = peers
        .filter((p) => p.id !== peer.id)
        .map((p): OmniMeshPeer => ({
          id: p.id,
          publicKey: p.publicKey,
          endpoint: p.endpoint,
          meshIp: p.meshIp,
          allowedIps: `${p.meshIp}/32`,
          keepalive: 25,
          os: 'linux',
        }));
      result.set(peer.id, others);
    }
  } else {
    // Hub-and-spoke: only hub connects to all, spokes connect only to hub
    const hub = peers.find((p) => p.id === (hubId ?? peers[0]?.id));
    if (!hub) return result;

    const spokes = peers.filter((p) => p.id !== hub.id);
    // Hub gets all spokes
    result.set(hub.id, spokes.map((s): OmniMeshPeer => ({
      id: s.id,
      publicKey: s.publicKey,
      endpoint: s.endpoint,
      meshIp: s.meshIp,
      allowedIps: `${s.meshIp}/32`,
      keepalive: 25,
      os: 'linux',
    })));
    // Each spoke gets only the hub
    for (const spoke of spokes) {
      result.set(spoke.id, [{
        id: hub.id,
        publicKey: hub.publicKey,
        endpoint: hub.endpoint,
        meshIp: hub.meshIp,
        allowedIps: '10.10.0.0/24',  // Route all mesh traffic through hub
        keepalive: 25,
        os: 'linux',
      }]);
    }
  }

  return result;
}
