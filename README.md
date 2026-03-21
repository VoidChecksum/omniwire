<p align="center">
  <img src="https://img.shields.io/npm/v/omniwire?style=flat-square&color=0A0E14&labelColor=0A0E14&label=npm" alt="npm version" />
  <img src="https://img.shields.io/badge/MCP-30_tools-59C2FF?style=flat-square&labelColor=0A0E14" alt="MCP tools" />
  <img src="https://img.shields.io/badge/transport-stdio_%7C_SSE_%7C_REST-91B362?style=flat-square&labelColor=0A0E14" alt="transports" />
  <img src="https://img.shields.io/badge/license-MIT-E6B450?style=flat-square&labelColor=0A0E14" alt="license" />
  <img src="https://img.shields.io/badge/node-%3E%3D20-CC93E6?style=flat-square&labelColor=0A0E14" alt="node" />
</p>

<h1 align="center">OmniWire</h1>

<p align="center">
  <strong>Unified mesh control layer for distributed infrastructure</strong><br/>
  <sub>30-tool MCP server &bull; SSH2 connection pooling &bull; adaptive file transfers &bull; cross-node config sync</sub>
</p>

---

OmniWire connects all your machines into a single control plane. It exposes **30 MCP tools** that any AI agent (Claude Code, OpenCode, Cursor, etc.) can use to execute commands, transfer files, manage Docker containers, and sync configurations across your entire infrastructure — through one unified interface.

```
┌──────────────────────────────────────────────────────────────┐
│                     AI Agent (MCP Client)                    │
│              Claude Code / OpenCode / Cursor                 │
└──────────────────────┬───────────────────────────────────────┘
                       │ MCP Protocol (stdio / SSE / REST)
                       ▼
┌──────────────────────────────────────────────────────────────┐
│                    OmniWire MCP Server                       │
│  22 Core Tools  │  8 CyberSync Tools  │  3 Transports       │
└──────┬──────────┴──────────┬──────────┴──────────────────────┘
       │ SSH2 (compressed, pooled)       │ PostgreSQL
       ▼                                 ▼
  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌────────────┐
  │ Node A  │  │ Node B  │  │ Node C  │  │ CyberSync  │
  │ storage │  │ compute │  │   GPU   │  │  Database   │
  └─────────┘  └─────────┘  └─────────┘  └────────────┘
```

## Features

### MCP Server — 30 Tools

| Category | Tools | Description |
|----------|-------|-------------|
| **Execution** | `omniwire_exec`, `omniwire_broadcast` | Run commands on one or all nodes |
| **Monitoring** | `omniwire_mesh_status`, `omniwire_node_info`, `omniwire_live_monitor` | Health, latency, CPU/mem/disk |
| **Files** | `omniwire_read_file`, `omniwire_write_file`, `omniwire_list_files`, `omniwire_find_files` | Full remote filesystem access |
| **Transfer** | `omniwire_transfer_file`, `omniwire_deploy` | 3-mode adaptive transfer engine |
| **System** | `omniwire_process_list`, `omniwire_disk_usage`, `omniwire_tail_log`, `omniwire_install_package` | System administration |
| **Services** | `omniwire_service_control`, `omniwire_docker` | systemd + Docker management |
| **Network** | `omniwire_port_forward`, `omniwire_open_browser` | SSH tunnels, remote browsers |
| **Advanced** | `omniwire_kernel`, `omniwire_shell`, `omniwire_stream` | Kernel ops, persistent PTY, streaming |
| **CyberSync** | `cybersync_status`, `cybersync_sync_now`, `cybersync_diff`, `cybersync_history`, `cybersync_search_knowledge`, `cybersync_get_memory`, `cybersync_manifest`, `cybersync_force_push` | Cross-node config synchronization |

### SSH2 Connection Layer

- **Persistent connection pooling** — one SSH2 connection per node, reused for all operations
- **Zlib compression** — ~60% less data over the wire for text-heavy outputs
- **Exponential backoff reconnect** — 1s → 2s → 4s → ... → 30s cap with jitter
- **Circuit breaker** — 3 consecutive failures → 60s cooldown, auto-recovers
- **2MB output guard** — prevents memory exhaustion from runaway commands
- **Health pings** — 30s interval, detects degraded connections (>3s response)
- **Status caching** — 5s TTL eliminates redundant probes

### Adaptive File Transfer Engine

OmniWire automatically selects the fastest transfer mode based on file size:

| Mode | Size Range | Method | Speed |
|------|-----------|--------|-------|
| **SFTP** | < 10 MB | SSH2 native SFTP subsystem | Zero overhead, binary-safe |
| **netcat+tar+gzip** | 10 MB – 1 GB | Compressed TCP stream | ~70% smaller for text |
| **aria2c** | > 1 GB | 16-connection parallel HTTP download | Saturates bandwidth |

### CyberSync — Config Synchronization

Keeps AI tool configurations (Claude Code, OpenCode, Codex, etc.) synchronized across all your machines:

- **6 tools tracked** — claude-code, opencode, openclaw, codex, gemini, paperclip
- **File watching** — single chokidar instance with batch debounce
- **Parallel sync** — pushes to all nodes simultaneously via `Promise.allSettled`
- **Parallel hashing** — SHA-256 in 50-file batches with streaming for large files
- **Conflict resolution** — node-ownership model with detailed conflict logging
- **Memory bridge** — ingests Claude's `memory.db` (SQLite → PostgreSQL)
- **Auto-reconciliation** — every 5 minutes, with event log pruning

---

## Quick Start

### 1. Install

```bash
npm install -g omniwire
```

### 2. Configure Your Mesh

Create `~/.omniwire/mesh.json`:

```json
{
  "nodes": [
    {
      "id": "server1",
      "host": "10.0.0.1",
      "user": "root",
      "identityFile": "id_ed25519",
      "role": "storage",
      "tags": ["vps", "docker"]
    },
    {
      "id": "server2",
      "host": "10.0.0.2",
      "user": "root",
      "identityFile": "id_ed25519",
      "role": "compute"
    }
  ],
  "meshSubnet": "10.0.0.0/24"
}
```

SSH identity files are resolved relative to `~/.ssh/`. Full paths also work.

### 3. Use as MCP Server

Add to your AI tool's MCP config (`.mcp.json`, Claude Code settings, etc.):

```json
{
  "mcpServers": {
    "omniwire": {
      "command": "node",
      "args": ["/path/to/omniwire/dist/mcp/index.js", "--stdio"]
    }
  }
}
```

Or if installed globally:

```json
{
  "mcpServers": {
    "omniwire": {
      "command": "omniwire",
      "args": ["--stdio"]
    }
  }
}
```

### 4. Use as Interactive Terminal

```bash
omniwire
# or
ow
```

---

## Transport Modes

| Mode | Port | Use Case |
|------|------|----------|
| **stdio** | — | Claude Code, Cursor, any MCP subprocess client |
| **SSE** | 3200 | OpenCode, remote HTTP-based MCP clients |
| **REST** | 3201 | Non-MCP integrations, scripts, dashboards |

```bash
# stdio (default for MCP)
omniwire --stdio

# SSE + REST (for remote/HTTP clients)
omniwire --sse-port=3200 --rest-port=3201

# Disable CyberSync (MCP-only, no PostgreSQL needed)
omniwire --stdio --no-sync
```

---

## CyberSync Setup

CyberSync requires PostgreSQL for the sync database. Set via environment variables:

```bash
export CYBERSYNC_PG_HOST=10.0.0.1
export CYBERSYNC_PG_PORT=5432
export CYBERSYNC_PG_DATABASE=cybersync
export CYBERSYNC_PG_USER=cybersync
export CYBERSYNC_PG_PASSWORD=your_password
```

Run the sync daemon:

```bash
# Continuous daemon (watch + reconcile every 5 min)
omniwire sync

# Single reconciliation pass
omniwire sync:once

# Ingest Claude memory.db only
omniwire sync:ingest
```

If you don't need CyberSync, pass `--no-sync` to the MCP server — it works fine without PostgreSQL.

---

## Configuration Reference

### Mesh Config (`~/.omniwire/mesh.json`)

```typescript
interface MeshConfig {
  nodes: Array<{
    id: string;            // Unique node identifier
    alias?: string;        // Short alias (e.g., "s1")
    host: string;          // IP or hostname
    port?: number;         // SSH port (default: 22)
    user?: string;         // SSH user (default: "root")
    identityFile?: string; // SSH key filename or full path
    os?: "windows" | "linux"; // OS type (default: "linux")
    role?: "controller" | "storage" | "compute" | "gpu+browser";
    tags?: string[];       // Custom tags for filtering
  }>;
  meshSubnet?: string;     // Subnet notation (informational)
  defaultNode?: string;    // Default target node
}
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `OMNIWIRE_CONFIG` | JSON mesh config (alternative to file) | — |
| `OMNIWIRE_NODE_ID` | Override local node ID detection | auto-detected |
| `OMNIWIRE_LINUX_HOME` | Linux home directory for path mapping | `/root` |
| `CYBERSYNC_PG_HOST` | PostgreSQL host | `localhost` |
| `CYBERSYNC_PG_PORT` | PostgreSQL port | `5432` |
| `CYBERSYNC_PG_DATABASE` | Database name | `cybersync` |
| `CYBERSYNC_PG_USER` | Database user | `cybersync` |
| `CYBERSYNC_PG_PASSWORD` | Database password | — |

---

## Architecture

```
omniwire/
├── src/
│   ├── mcp/
│   │   ├── index.ts         # Entrypoint — dual transport (stdio + SSE)
│   │   ├── server.ts        # 22 core MCP tools
│   │   ├── sync-tools.ts    # 8 CyberSync MCP tools
│   │   ├── sse.ts           # SSE transport
│   │   └── rest.ts          # REST API
│   ├── nodes/
│   │   ├── manager.ts       # SSH2 connection pooling + circuit breaker
│   │   ├── transfer.ts      # 3-mode adaptive file transfer
│   │   ├── shell.ts         # Persistent PTY sessions
│   │   ├── tunnel.ts        # SSH port forwarding
│   │   └── realtime.ts      # Streaming command dispatch
│   ├── sync/
│   │   ├── engine.ts        # Push/pull/reconcile with parallel ops
│   │   ├── db.ts            # PostgreSQL pool (8 connections, FTS)
│   │   ├── watcher.ts       # Single chokidar, batch debounce
│   │   ├── hasher.ts        # SHA-256 (streaming for large files)
│   │   ├── manifest.ts      # Tool sync definitions
│   │   ├── memory-bridge.ts # SQLite → PostgreSQL ingestion
│   │   └── paths.ts         # Windows/Linux path adaptation
│   ├── protocol/
│   │   ├── config.ts        # Mesh topology loader
│   │   ├── types.ts         # Shared type definitions
│   │   └── paths.ts         # node:/path format parser
│   ├── commands/             # Interactive REPL commands
│   ├── claude/               # Claude Code AI integration
│   └── ui/                   # Terminal formatting
├── mesh.example.json         # Example mesh configuration
├── package.json
└── tsconfig.json
```

---

## Performance

Benchmarked on a 3-node WireGuard mesh (EU region):

| Operation | Latency | Notes |
|-----------|---------|-------|
| Single command exec | ~120ms | SSH2 + command + return |
| Mesh status (all nodes) | ~150ms | Parallel probes, 5s cache |
| File read (< 1MB) | ~80ms | SFTP, no encoding overhead |
| File transfer (10MB) | ~200ms | gzip netcat over WireGuard |
| Config sync (push) | ~200ms | Parallel to all nodes |
| Reconcile (500 files) | ~2s | 50-file parallel hash batches |

---

## Requirements

- **Node.js** >= 20
- **SSH access** to remote nodes (key-based auth)
- **PostgreSQL** (only if using CyberSync)
- **WireGuard / VPN** recommended for mesh connectivity

---

## License

MIT
