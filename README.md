<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://capsule-render.vercel.app/api?type=waving&color=0:0A0E14,50:1A1F2E,100:59C2FF&height=200&section=header&text=OmniWire&fontSize=72&fontColor=59C2FF&animation=fadeIn&fontAlignY=35&desc=Unified%20Mesh%20Control%20Layer&descSize=18&descColor=8B949E&descAlignY=55" />
    <source media="(prefers-color-scheme: light)" srcset="https://capsule-render.vercel.app/api?type=waving&color=0:E8EAED,50:D4D8DE,100:59C2FF&height=200&section=header&text=OmniWire&fontSize=72&fontColor=0A0E14&animation=fadeIn&fontAlignY=35&desc=Unified%20Mesh%20Control%20Layer&descSize=18&descColor=586069&descAlignY=55" />
    <img alt="OmniWire" src="https://capsule-render.vercel.app/api?type=waving&color=0:0A0E14,50:1A1F2E,100:59C2FF&height=200&section=header&text=OmniWire&fontSize=72&fontColor=59C2FF&animation=fadeIn&fontAlignY=35&desc=Unified%20Mesh%20Control%20Layer&descSize=18&descColor=8B949E&descAlignY=55" />
  </picture>
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/omniwire"><img src="https://img.shields.io/npm/v/omniwire?style=for-the-badge&logo=npm&color=CB3837&labelColor=0A0E14" alt="npm" /></a>
  <img src="https://img.shields.io/badge/MCP-34_tools-59C2FF?style=for-the-badge&labelColor=0A0E14" alt="tools" />
  <img src="https://img.shields.io/badge/transport-stdio_%7C_SSE_%7C_REST-91B362?style=for-the-badge&labelColor=0A0E14" alt="transports" />
  <img src="https://img.shields.io/badge/node-%E2%89%A520-CC93E6?style=for-the-badge&logo=node.js&labelColor=0A0E14" alt="node" />
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-E6B450?style=for-the-badge&labelColor=0A0E14" alt="license" /></a>
</p>

<p align="center">
  <sub>One MCP server to control all your machines. SSH2 connection pooling, adaptive file transfers, encrypted cross-node config sync.</sub>
</p>

---

## How It Works

```mermaid
graph TB
    subgraph clients["AI Agents"]
        CC["Claude Code"]
        OC["OpenCode"]
        CU["Cursor / Any MCP Client"]
    end

    subgraph omniwire["OmniWire MCP Server"]
        direction TB
        MCP["MCP Protocol Layer\nstdio | SSE | REST"]

        subgraph tools["34 Tools"]
            direction LR
            EXEC["Execution\nexec  run  batch\nbroadcast"]
            FILES["Files\nread  write\ntransfer  deploy"]
            MON["Monitoring\nstatus  metrics\nlogs"]
            SYS["System\ndocker  services\nkernel"]
            SYNC["CyberSync\nsync  diff\nsearch  secrets"]
        end

        subgraph engine["Core Engine"]
            direction LR
            POOL["SSH2 Pool\npersistent  compressed\ncircuit breaker"]
            XFER["Transfer Engine\nSFTP  netcat+gzip\naria2c 16-conn"]
            CSYNC["Sync Engine\nPostgreSQL  XChaCha20\nparallel reconcile"]
        end
    end

    subgraph mesh["Infrastructure Mesh"]
        direction LR
        N1["Node A\nstorage\n10.0.0.1"]
        N2["Node B\ncompute\n10.0.0.2"]
        N3["Node C\nGPU\n10.0.0.3"]
        N4["Node D\nlocal"]
    end

    DB[("PostgreSQL\nCyberSync DB")]

    CC & OC & CU -->|MCP| MCP
    MCP --> tools
    tools --> engine
    POOL -->|"SSH2 + zlib"| N1 & N2 & N3
    POOL -->|"local exec"| N4
    CSYNC --> DB

    style omniwire fill:#0A0E14,stroke:#59C2FF,stroke-width:2px,color:#C6D0E1
    style clients fill:#1A1F2E,stroke:#91B362,stroke-width:1px,color:#C6D0E1
    style mesh fill:#1A1F2E,stroke:#E6B450,stroke-width:1px,color:#C6D0E1
    style tools fill:#141922,stroke:#59C2FF,stroke-width:1px,color:#C6D0E1
    style engine fill:#141922,stroke:#CC93E6,stroke-width:1px,color:#C6D0E1
    style MCP fill:#1A1F2E,stroke:#59C2FF,color:#59C2FF
    style DB fill:#1A1F2E,stroke:#CC93E6,color:#CC93E6
```

---

## Features at a Glance

<table>
<tr>
<td width="50%">

### Remote Execution
```
omniwire_exec       single command, any node
omniwire_run        multi-line script (compact UI)
omniwire_batch      N commands in 1 tool call
omniwire_broadcast  parallel across all nodes
```

</td>
<td width="50%">

### Adaptive File Transfer
```
 < 10 MB   SFTP         native, 80ms
 10M-1GB   netcat+gzip  compressed, 200ms
 > 1 GB    aria2c       16-parallel, max speed
```

</td>
</tr>
<tr>
<td>

### Connection Resilience
```
Connected --> Health Ping (30s)
    |              |
    |         > 3s? --> Degraded warning
    |
Failure --> Retry (exp. backoff)
    |         1s -> 2s -> 4s -> ... -> 30s
    |
3 fails --> Circuit OPEN (60s)
                 --> Auto-recover
```

</td>
<td>

### CyberSync
```
Node A --push--> PostgreSQL --pull--> Node B
                     |
              XChaCha20-Poly1305
              encrypted at rest

6 AI tools synced automatically:
Claude  OpenCode  Codex  Gemini  ...
```

</td>
</tr>
</table>

---

## All 34 Tools

<details>
<summary><b>Execution (4 tools)</b></summary>

| Tool | Description |
|------|-------------|
| `omniwire_exec` | Run a command on any node. Supports `label` for compact display. |
| `omniwire_run` | Execute multi-line scripts via temp file. Keeps tool call UI clean. |
| `omniwire_batch` | Run N commands across nodes in a single tool call. Parallel by default. |
| `omniwire_broadcast` | Execute on all online nodes simultaneously. |

</details>

<details>
<summary><b>Monitoring (3 tools)</b></summary>

| Tool | Description |
|------|-------------|
| `omniwire_mesh_status` | Health, latency, CPU/mem/disk for all nodes |
| `omniwire_node_info` | Detailed info for a specific node |
| `omniwire_live_monitor` | Snapshot metrics: cpu, memory, disk, network |

</details>

<details>
<summary><b>Files (4 tools)</b></summary>

| Tool | Description |
|------|-------------|
| `omniwire_read_file` | Read file from any node. Supports `node:/path` format. |
| `omniwire_write_file` | Write/create file on any node |
| `omniwire_list_files` | List directory contents |
| `omniwire_find_files` | Search by glob pattern across all nodes |

</details>

<details>
<summary><b>Transfer & Deploy (2 tools)</b></summary>

| Tool | Description |
|------|-------------|
| `omniwire_transfer_file` | Copy between nodes. Auto-selects SFTP/netcat/aria2c. |
| `omniwire_deploy` | Deploy file from one node to all others in parallel |

</details>

<details>
<summary><b>System (6 tools)</b></summary>

| Tool | Description |
|------|-------------|
| `omniwire_process_list` | List/filter processes across nodes |
| `omniwire_disk_usage` | Disk usage for all nodes |
| `omniwire_tail_log` | Last N lines of a log file |
| `omniwire_install_package` | Install via apt/npm/pip |
| `omniwire_service_control` | systemd start/stop/restart/status |
| `omniwire_docker` | Run docker commands on any node |

</details>

<details>
<summary><b>Network (2 tools)</b></summary>

| Tool | Description |
|------|-------------|
| `omniwire_port_forward` | Create/list/close SSH tunnels |
| `omniwire_open_browser` | Open URL in browser on a node |

</details>

<details>
<summary><b>Advanced (4 tools)</b></summary>

| Tool | Description |
|------|-------------|
| `omniwire_kernel` | dmesg, sysctl, modprobe, lsmod, strace, perf |
| `omniwire_shell` | Persistent PTY session (preserves cwd/env) |
| `omniwire_stream` | Capture streaming output (tail -f, watch) |
| `omniwire_update` | Self-update OmniWire |

</details>

<details>
<summary><b>CyberSync (9 tools)</b></summary>

| Tool | Description |
|------|-------------|
| `cybersync_status` | Sync status, item counts, pending syncs |
| `cybersync_sync_now` | Trigger immediate reconciliation |
| `cybersync_diff` | Show local vs database differences |
| `cybersync_history` | Query sync event log |
| `cybersync_search_knowledge` | Full-text search unified knowledge base |
| `cybersync_get_memory` | Retrieve Claude memory from PostgreSQL |
| `cybersync_manifest` | Show tracked files per tool |
| `cybersync_force_push` | Force push file to all nodes |
| `omniwire_secrets` | Get/set/delete/list/sync secrets (1Password, file, env) |

</details>

---

## Quick Start

### Install

```bash
npm install -g omniwire
```

### Configure Mesh

Create `~/.omniwire/mesh.json`:

```json
{
  "nodes": [
    {
      "id": "server1",
      "host": "10.0.0.1",
      "user": "root",
      "identityFile": "id_ed25519",
      "role": "storage"
    },
    {
      "id": "server2",
      "host": "10.0.0.2",
      "user": "root",
      "identityFile": "id_ed25519",
      "role": "compute"
    }
  ]
}
```

### Add to Claude Code

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

### Interactive Mode

```bash
omniwire    # or: ow
```

---

## Performance

| Operation | Latency | Details |
|-----------|---------|---------|
| **Command exec** | `~120ms` | SSH2 + command + return |
| **Mesh status** | `~150ms` | Parallel probes, 5s cache |
| **File read (<1MB)** | `~80ms` | SFTP, binary-safe |
| **Transfer (10MB)** | `~200ms` | gzip netcat over WireGuard |
| **Config push** | `~200ms` | Parallel to all nodes |
| **Reconcile (500 files)** | `~2s` | 50-file parallel hash batches |

---

## Security

All remote execution uses `ssh2.Client.exec()`, never `child_process.exec()`. Key-based auth only, no passwords stored. Zlib-compressed encrypted channels. XChaCha20-Poly1305 at-rest encryption for synced configs. 2MB output guard prevents memory exhaustion. Circuit breaker isolates failing nodes.

---

## Transport Modes

| Mode | Default Port | Use Case |
|------|-------------|----------|
| `--stdio` | -- | Claude Code, Cursor, MCP subprocess clients |
| `--sse-port=N` | 3200 | OpenCode, remote HTTP-based MCP clients |
| `--rest-port=N` | 3201 | Scripts, dashboards, non-MCP integrations |

```bash
omniwire --stdio                          # MCP mode
omniwire --sse-port=3200 --rest-port=3201 # HTTP mode
omniwire --stdio --no-sync               # MCP without CyberSync
```

---

## Architecture

```
omniwire/
  src/
    mcp/           MCP server (34 tools, 3 transports)
    nodes/         SSH2 pool, transfer engine, PTY, tunnels
    sync/          CyberSync (PostgreSQL, encryption, reconcile)
    protocol/      Mesh config, types, path parsing
    commands/      Interactive REPL
    ui/            Terminal formatting
```

---

## Requirements

- **Node.js** >= 20
- **SSH access** to remote nodes (key-based auth)
- **PostgreSQL** (only for CyberSync)
- **WireGuard / VPN** recommended for mesh connectivity

---

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-E6B450?style=flat-square&labelColor=0A0E14" alt="MIT License" /></a>
</p>

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://capsule-render.vercel.app/api?type=waving&color=0:0A0E14,50:1A1F2E,100:59C2FF&height=100&section=footer" />
    <source media="(prefers-color-scheme: light)" srcset="https://capsule-render.vercel.app/api?type=waving&color=0:E8EAED,50:D4D8DE,100:59C2FF&height=100&section=footer" />
    <img alt="footer" src="https://capsule-render.vercel.app/api?type=waving&color=0:0A0E14,50:1A1F2E,100:59C2FF&height=100&section=footer" />
  </picture>
</p>
