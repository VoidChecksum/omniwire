<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://capsule-render.vercel.app/api?type=waving&color=0:0A0E14,50:1A1F2E,100:59C2FF&height=200&section=header&text=OmniWire&fontSize=72&fontColor=59C2FF&animation=fadeIn&fontAlignY=35&desc=Unified%20Mesh%20Control%20Layer&descSize=18&descColor=8B949E&descAlignY=55" />
    <source media="(prefers-color-scheme: light)" srcset="https://capsule-render.vercel.app/api?type=waving&color=0:E8EAED,50:D4D8DE,100:59C2FF&height=200&section=header&text=OmniWire&fontSize=72&fontColor=0A0E14&animation=fadeIn&fontAlignY=35&desc=Unified%20Mesh%20Control%20Layer&descSize=18&descColor=586069&descAlignY=55" />
    <img alt="OmniWire" src="https://capsule-render.vercel.app/api?type=waving&color=0:0A0E14,50:1A1F2E,100:59C2FF&height=200&section=header&text=OmniWire&fontSize=72&fontColor=59C2FF&animation=fadeIn&fontAlignY=35&desc=Unified%20Mesh%20Control%20Layer&descSize=18&descColor=8B949E&descAlignY=55" />
  </picture>
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/omniwire"><img src="https://img.shields.io/npm/v/omniwire?style=for-the-badge&logo=npm&color=CB3837&labelColor=0A0E14" alt="npm" /></a>
  <img src="https://img.shields.io/badge/MCP-49_tools-59C2FF?style=for-the-badge&labelColor=0A0E14" alt="tools" />
  <img src="https://img.shields.io/badge/A2A-ready-91B362?style=for-the-badge&labelColor=0A0E14" alt="A2A" />
  <img src="https://img.shields.io/badge/transport-stdio_%7C_SSE_%7C_REST-E6B450?style=for-the-badge&labelColor=0A0E14" alt="transports" />
  <img src="https://img.shields.io/badge/node-%E2%89%A520-CC93E6?style=for-the-badge&logo=node.js&labelColor=0A0E14" alt="node" />
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-8B949E?style=for-the-badge&labelColor=0A0E14" alt="license" /></a>
</p>

<p align="center">
  <b>One MCP server to control all your machines.</b><br/>
  <sub>49 tools. Multi-agent orchestration. A2A messaging. Distributed locking. Cross-node pipelines.</sub><br/>
  <sub>SSH2 failover, adaptive file transfers, encrypted config sync, agentic chaining.</sub>
</p>

---

## Quick Start

```bash
npm install -g omniwire
```

Add to your AI agent (Claude Code, Cursor, OpenCode, etc.):

```json
{
  "mcpServers": {
    "omniwire": { "command": "omniwire", "args": ["--stdio"] }
  }
}
```

---

## Why OmniWire?

| Problem | OmniWire Solution |
|---------|-------------------|
| Managing multiple servers manually | One tool call controls any node |
| Agents can't coordinate with each other | A2A messaging, events, semaphores |
| Multi-step deploys need many round-trips | Pipelines chain steps in 1 call |
| Flaky commands break agent loops | Built-in retry + assert + watch |
| Long tasks block the agent | Background dispatch with task IDs |
| Results lost between tool calls | Session store with `{{key}}` interpolation |
| Different transfer methods for diff sizes | Auto-selects SFTP / netcat / aria2c |
| SSH connections drop | Multi-path failover + circuit breaker |

---

## Architecture

```mermaid
graph TB
    subgraph clients["AI Agents"]
        CC["Claude Code"]
        OC["OpenCode / OpenClaw"]
        CU["Cursor / Any MCP Client"]
        A2["Other Agents (A2A)"]
    end

    subgraph omniwire["OmniWire MCP Server"]
        direction TB
        MCP["MCP Protocol Layer<br/>stdio | SSE | REST"]

        subgraph tools["49 Tools"]
            direction LR
            EXEC["Execution<br/>exec  run  batch<br/>broadcast  pipeline"]
            AGENT["Agentic<br/>store  watch  task<br/>a2a  events  locks"]
            FILES["Files & Deploy<br/>read  write  transfer<br/>deploy  find"]
            SYS["System & DevOps<br/>docker  services<br/>cron  env  git  syslog"]
            SYNC["CyberSync<br/>sync  diff  search<br/>secrets  knowledge"]
        end

        subgraph engine["Core Engine"]
            direction LR
            POOL["SSH2 Pool<br/>persistent  compressed<br/>circuit breaker"]
            XFER["Transfer Engine<br/>SFTP  netcat+gzip<br/>aria2c 16-conn"]
            CSYNC["Sync Engine<br/>PostgreSQL  XChaCha20<br/>parallel reconcile"]
        end
    end

    subgraph mesh["Infrastructure Mesh"]
        direction LR
        N1["Node A<br/>storage"]
        N2["Node B<br/>compute"]
        N3["Node C<br/>GPU"]
        N4["Node D<br/>local"]
    end

    DB[("PostgreSQL<br/>CyberBase")]

    CC & OC & CU & A2 -->|MCP| MCP
    MCP --> tools
    tools --> engine
    POOL -->|"SSH2 multi-path"| N1 & N2 & N3
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

## Key Capabilities

<table>
<tr>
<td width="50%">

### Execution
```
omniwire_exec       single command + retry + assert
omniwire_run        multi-line script (compact UI)
omniwire_batch      N commands, 1 tool call, chaining
omniwire_broadcast  parallel across all nodes
omniwire_pipeline   multi-step DAG with data flow
```

</td>
<td width="50%">

### Multi-Agent (A2A)
```
omniwire_store        session key-value store
omniwire_a2a_message  agent-to-agent queues
omniwire_event        pub/sub event bus
omniwire_semaphore    distributed locking
omniwire_agent_task   async background dispatch
omniwire_workflow     reusable named DAGs
```

</td>
</tr>
<tr>
<td>

### Adaptive File Transfer
```
 < 10 MB   SFTP         native, 80ms
 10M-1GB   netcat+gzip  compressed, 100ms
 > 1 GB    aria2c       16-parallel, max speed
```

</td>
<td>

### Connection Resilience
```
Connected --> Health Ping (30s, parallel)
    |
Failure --> Multi-path Failover
    |         WireGuard -> Tailscale -> Public IP
    |
    +--> Retry (500ms -> 1s -> ... -> 15s)
    |
3 fails --> Circuit OPEN (20s) -> Auto-recover
```

</td>
</tr>
<tr>
<td>

### Agentic Chaining
```
exec(store_as="ip")       store result
exec(command="ping {{ip}}") interpolate
batch(abort_on_fail=true)   fail-fast
exec(format="json")         structured output
exec(retry=3, assert="ok")  resilient
watch(assert="ready")       poll until
```

</td>
<td>

### CyberSync + CyberBase
```
Nodes --push--> PostgreSQL (cyberbase)
  |                  |
  |             XChaCha20-Poly1305
  |             encrypted at rest
  |
  +--mirror--> Obsidian Vault
                    |
               Obsidian Sync (cloud)
```

</td>
</tr>
</table>

---

## All 49 Tools

### Execution (5)

| Tool | Description |
|------|-------------|
| `omniwire_exec` | Run command on any node. `retry`, `assert`, `store_as`, `format:"json"`, `{{key}}` interpolation. |
| `omniwire_run` | Execute multi-line scripts via temp file. Keeps tool call UI clean. |
| `omniwire_batch` | N commands in 1 call. Chaining with `{{prev}}`, `abort_on_fail`, parallel or sequential. |
| `omniwire_broadcast` | Execute on all nodes simultaneously. JSON format support. |
| `omniwire_pipeline` | Multi-step DAG. `{{prev}}`/`{{stepN}}` interpolation, per-step error handling, cross-node. |

### Agentic / A2A (9)

| Tool | Description |
|------|-------------|
| `omniwire_store` | Session key-value store. Persist results across tool calls for chaining. |
| `omniwire_watch` | Poll command until assert pattern matches. For deploys, builds, service readiness. |
| `omniwire_healthcheck` | Parallel health probe across all nodes (connectivity, disk, mem, load, docker). Single call. |
| `omniwire_agent_task` | Dispatch background tasks. Get task IDs, poll status, retrieve results. A2A async. |
| `omniwire_a2a_message` | Agent-to-agent message queues. Send/receive/peek on named channels. |
| `omniwire_semaphore` | Distributed locking. Atomic acquire/release to prevent race conditions. |
| `omniwire_event` | Pub/sub events. Emit/poll timestamped events per topic. ACP/A2A/ACPX compatible. |
| `omniwire_workflow` | Define and run reusable named workflows (DAGs). Stored on disk, triggered by any agent. |

### Files & Transfer (6)

| Tool | Description |
|------|-------------|
| `omniwire_read_file` | Read file from any node. `node:/path` format. |
| `omniwire_write_file` | Write/create file on any node. |
| `omniwire_list_files` | List directory contents. |
| `omniwire_find_files` | Glob search across all nodes. |
| `omniwire_transfer_file` | Copy between nodes. Auto-selects SFTP/netcat/aria2c. |
| `omniwire_deploy` | Deploy file from one node to all others in parallel. |

### Monitoring (3)

| Tool | Description |
|------|-------------|
| `omniwire_mesh_status` | Health, latency, CPU/mem/disk for all nodes. Tabular output. |
| `omniwire_node_info` | Detailed info for a specific node. |
| `omniwire_live_monitor` | Snapshot metrics: cpu, memory, disk, network. |

### System & DevOps (12)

| Tool | Description |
|------|-------------|
| `omniwire_process_list` | List/filter processes across nodes |
| `omniwire_disk_usage` | Disk usage for all nodes |
| `omniwire_tail_log` | Last N lines of a log file |
| `omniwire_install_package` | Install via apt/npm/pip |
| `omniwire_service_control` | systemd start/stop/restart/status |
| `omniwire_docker` | Docker commands on any node |
| `omniwire_kernel` | dmesg, sysctl, modprobe, lsmod, strace, perf |
| `omniwire_cron` | List/add/remove cron jobs |
| `omniwire_env` | Get/set persistent environment variables |
| `omniwire_network` | ping, traceroute, dns, ports, speed, connections |
| `omniwire_git` | Git commands on repos on any node |
| `omniwire_syslog` | Query journalctl with filters |

### Network & Misc (5)

| Tool | Description |
|------|-------------|
| `omniwire_port_forward` | Create/list/close SSH tunnels |
| `omniwire_open_browser` | Open URL in browser on a node |
| `omniwire_shell` | Persistent PTY session (preserves cwd/env) |
| `omniwire_stream` | Capture streaming output (tail -f, watch) |
| `omniwire_clipboard` | Shared clipboard buffer across mesh |

### CyberSync (9)

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
| `omniwire_update` | Self-update OmniWire |

---

## Performance

| Operation | Latency | Details |
|-----------|---------|---------|
| Command exec | ~120ms | SSH2 channel on persistent connection |
| Mesh status (all nodes) | ~150ms | Parallel probes, 5s cache |
| File read (<1MB) | ~80ms | SFTP, binary-safe |
| Transfer (10MB) | ~200ms | gzip netcat over WireGuard |
| Pipeline (5 steps) | ~600ms | Sequential with interpolation |
| Health check (4 nodes) | ~200ms | Parallel, structured output |
| A2A message send | ~130ms | File-based queue |
| Config push (all nodes) | ~200ms | Parallel + Obsidian mirror |

---

## Security

- All remote execution via `ssh2.Client.exec()` -- never `child_process.exec()`
- Key-based auth only, no passwords stored, SSH key caching
- Multi-path failover: WireGuard -> Tailscale -> Public IP
- XChaCha20-Poly1305 at-rest encryption for synced configs
- 2MB output guard prevents memory exhaustion
- 4KB auto-truncation prevents context window bloat
- Circuit breaker with 20s auto-recovery isolates failing nodes
- CORS restricted to localhost on REST API

---

## Transport Modes

| Mode | Port | Use Case |
|------|------|----------|
| `--stdio` | -- | Claude Code, Cursor, MCP subprocess |
| `--sse-port=N` | 3200 | OpenCode, remote HTTP MCP clients |
| `--rest-port=N` | 3201 | Scripts, dashboards, non-MCP |

```bash
omniwire --stdio                          # MCP mode (default)
omniwire --sse-port=3200 --rest-port=3201 # HTTP mode
omniwire --stdio --no-sync               # MCP without CyberSync
omniwire    # or: ow                      # Interactive REPL
```

---

## Configure Mesh

Create `~/.omniwire/mesh.json`:

```json
{
  "nodes": [
    { "id": "server1", "host": "10.0.0.1", "user": "root", "identityFile": "id_ed25519", "role": "storage" },
    { "id": "server2", "host": "10.0.0.2", "user": "root", "identityFile": "id_ed25519", "role": "compute" }
  ]
}
```

---

## Changelog

<details>
<summary><b>v2.4.0 -- Agentic Loop, A2A, Multi-Agent Orchestration</b></summary>

**9 new agentic tools** (40 -> 49): store, pipeline, watch, healthcheck, agent_task, a2a_message, semaphore, event, workflow

**Agentic upgrades to existing tools**: `format:"json"`, `retry`, `assert`, `store_as`, `{{key}}` interpolation on exec/broadcast/batch

**Dynamic response processing**: Structured JSON output, step-to-step data flow, session result store, abort-on-fail chains

</details>

<details>
<summary><b>v2.3.0 -- Compact Output, Speed, New Tools</b></summary>

Output overhaul (auto-truncation, smart time, tabular multi-node). Performance (parallel health pings, 3s keepalive, 20s circuit breaker, 6s connect timeout). 6 new DevOps tools (cron, env, network, clipboard, git, syslog).

</details>

<details>
<summary><b>v2.2.1 -- Security & Bug Fixes</b></summary>

Fixed script-only exec, shell race condition, transfer size guard, CORS restriction, input validation.

</details>

<details>
<summary><b>v2.1.0 -- Multi-Path Failover & Performance</b></summary>

Multi-path SSH (WireGuard/Tailscale/Public), SSH key caching, CyberBase integration, VaultBridge Obsidian mirror.

</details>

---

## Architecture

```
omniwire/
  src/
    mcp/           MCP server (49 tools, 3 transports)
    nodes/         SSH2 pool, transfer engine, PTY, tunnels
    sync/          CyberSync + CyberBase (PostgreSQL, Obsidian, encryption)
    protocol/      Mesh config, types, path parsing
    commands/      Interactive REPL
    ui/            Terminal formatting
```

## Requirements

- **Node.js** >= 20
- **SSH access** to remote nodes (key-based auth)
- **PostgreSQL** (only for CyberSync)
- **WireGuard + Tailscale** recommended (multi-path failover)

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
