#!/usr/bin/env node

// OmniWire Terminal v2.0 — unified mesh terminal with MCP server
// Treats all WireGuard mesh nodes as one machine
// NOTE: Local execution uses execFile (via NodeManager), not child_process.exec
// Remote execution uses SSH2 client channels — no local shell injection risk

import * as readline from 'node:readline';
import { NodeManager } from './nodes/manager.js';
import { TransferEngine } from './nodes/transfer.js';
import { ShellManager, kernelExec } from './nodes/shell.js';
import { RealtimeChannel } from './nodes/realtime.js';
import { parseCommand } from './commands/router.js';
import { handleBuiltin, setTransferEngine } from './commands/builtins.js';
import { ClaudeIntegration } from './claude/integration.js';
import {
  banner, prompt as makePrompt, nodeColor, dim, red, yellow, cyan, Spinner,
} from './ui/format.js';
import { allNodes, getLocalNodeId } from './protocol/config.js';

async function main(): Promise<void> {
  const manager = new NodeManager();
  const transfer = new TransferEngine(manager);
  const shells = new ShellManager(manager);
  const realtime = new RealtimeChannel(manager);
  const claude = new ClaudeIntegration(manager);

  // Wire up transfer engine for builtins
  setTransferEngine(transfer);

  // Connect to all mesh nodes
  const connectSpinner = new Spinner('Connecting to OmniWire mesh...');
  connectSpinner.start();

  await manager.connectAll();

  const online = manager.getOnlineNodes();
  const total = allNodes().length;
  connectSpinner.stop();

  // Print banner
  console.log(banner(online.length, total));

  // Show initial node status
  for (const node of allNodes()) {
    const connected = manager.isConnected(node.id) || node.isLocal;
    const status = connected ? '\x1b[32m● connected\x1b[0m' : '\x1b[31m○ offline\x1b[0m';
    console.log(`  ${nodeColor(node.id)} ${dim(node.host)} ${status}`);
  }
  console.log();

  // Setup readline REPL
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    prompt: makePrompt(online),
    terminal: true,
    historySize: 500,
  });

  rl.prompt();

  rl.on('line', async (line: string) => {
    const input = line.trim();
    if (!input) {
      rl.prompt();
      return;
    }

    if (input === 'exit' || input === 'quit' || input === '@exit' || input === '@quit') {
      console.log(dim('\nDisconnecting from OmniWire mesh...'));
      shells.closeAll();
      manager.disconnect();
      process.exit(0);
    }

    if (input === 'clear' || input === '@clear') {
      console.clear();
      rl.prompt();
      return;
    }

    const parsed = parseCommand(input);

    try {
      let output = '';

      switch (parsed.target.type) {
        case 'local': {
          const result = await manager.exec(getLocalNodeId(), parsed.raw || input);
          if (result.stderr && result.code !== 0) {
            output = red(result.stderr);
          } else {
            output = result.stdout;
            if (result.stderr) output += '\n' + yellow(result.stderr);
          }
          break;
        }

        case 'node': {
          const { nodeId } = parsed.target;
          if (!manager.isConnected(nodeId)) {
            output = red(`Node ${nodeId} is offline. Try @reconnect`);
            break;
          }
          const spinner = new Spinner(`Running on ${nodeId}...`);
          spinner.start();
          const result = await manager.exec(nodeId, parsed.raw);
          spinner.stop();
          output = `${nodeColor(nodeId)} ${dim(`(${result.durationMs}ms)`)}\n`;
          output += result.code === 0
            ? (result.stdout || dim('(no output)'))
            : red(result.stderr || `exit code ${result.code}`);
          break;
        }

        case 'all': {
          const spinner = new Spinner('Broadcasting to all nodes...');
          spinner.start();
          const results = await manager.execAll(parsed.raw);
          spinner.stop();
          output = results
            .map((r) => {
              const header = `${nodeColor(r.nodeId)} ${dim(`(${r.durationMs}ms)`)}`;
              const body = r.code === 0
                ? r.stdout || dim('(no output)')
                : red(r.stderr || `exit code ${r.code}`);
              return `${header}\n${body}`;
            })
            .join('\n\n');
          break;
        }

        case 'claude': {
          output = await claude.handlePrompt(parsed.target.prompt);
          break;
        }

        case 'builtin': {
          const spinner = new Spinner(`Running @${parsed.target.name}...`);
          spinner.start();
          output = await handleBuiltin(
            parsed.target.name,
            parsed.args,
            parsed.raw,
            manager
          );
          spinner.stop();
          break;
        }

        case 'shell': {
          const { nodeId } = parsed.target;
          if (!manager.isConnected(nodeId)) {
            output = red(`Node ${nodeId} is offline.`);
            break;
          }
          console.log(cyan(`Entering shell on ${nodeId}. Press Ctrl+] to exit.`));
          rl.pause();
          await shells.enterInteractive(nodeId, process.stdin, process.stdout, () => {
            console.log(cyan(`\nExited shell on ${nodeId}`));
            rl.resume();
            rl.prompt();
          });
          return; // Don't prompt — the callback handles it
        }

        case 'kernel': {
          const { nodeId } = parsed.target;
          if (!manager.isConnected(nodeId)) {
            output = red(`Node ${nodeId} is offline.`);
            break;
          }
          const parts = parsed.raw.split(' ');
          const operation = parts[0] ?? 'dmesg';
          const args = parts.slice(1).join(' ');
          const spinner = new Spinner(`Kernel op on ${nodeId}...`);
          spinner.start();
          output = `${nodeColor(nodeId)} ${cyan('kernel')} ${operation}\n`;
          output += await kernelExec(manager, nodeId, operation, args);
          spinner.stop();
          break;
        }

        case 'stream': {
          const { nodeId } = parsed.target;
          if (!manager.isConnected(nodeId)) {
            output = red(`Node ${nodeId} is offline.`);
            break;
          }
          console.log(dim(`Streaming from ${nodeId}... (Ctrl+C to stop)`));
          const ac = new AbortController();
          const sigHandler = () => { ac.abort(); };
          process.once('SIGINT', sigHandler);
          await realtime.stream(
            nodeId,
            parsed.raw,
            (chunk) => process.stdout.write(chunk),
            ac.signal
          );
          process.removeListener('SIGINT', sigHandler);
          console.log(dim('\nStream ended.'));
          break;
        }
      }

      if (output) console.log(output);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.log(red(`Error: ${msg}`));
    }

    const currentOnline = manager.getOnlineNodes();
    rl.setPrompt(makePrompt(currentOnline));
    rl.prompt();
  });

  rl.on('close', () => {
    console.log(dim('\nDisconnecting from OmniWire mesh...'));
    shells.closeAll();
    manager.disconnect();
    process.exit(0);
  });

  process.on('SIGINT', () => {
    console.log(dim('\nInterrupted. Press Ctrl+D or type exit to quit.'));
    rl.prompt();
  });
}

main().catch((err) => {
  console.error(`Fatal: ${err.message}`);
  process.exit(1);
});
