// OmniWire UI — terminal formatting utilities

import chalk from 'chalk';

// Re-export chalk helpers for consistent styling
export const bold = chalk.bold;
export const dim = chalk.dim;
export const red = chalk.red;
export const green = chalk.green;
export const yellow = chalk.yellow;
export const cyan = chalk.cyan;
export const magenta = chalk.magenta;
export const blue = chalk.blue;
export const gray = chalk.gray;
export const white = chalk.white;

// Node-specific colors — auto-assigned from palette on first use
const COLOR_PALETTE = [chalk.blue.bold, chalk.green.bold, chalk.magenta.bold, chalk.cyan.bold, chalk.yellow.bold, chalk.red.bold];
const NODE_COLORS: Record<string, (s: string) => string> = {};
let colorIndex = 0;

function getNodeColorFn(nodeId: string): (s: string) => string {
  if (!NODE_COLORS[nodeId]) {
    NODE_COLORS[nodeId] = COLOR_PALETTE[colorIndex % COLOR_PALETTE.length];
    colorIndex++;
  }
  return NODE_COLORS[nodeId];
}

export function nodeColor(nodeId: string): string {
  return getNodeColorFn(nodeId)(`[${nodeId}]`);
}

export function nodeTag(nodeId: string): string {
  return getNodeColorFn(nodeId)(nodeId);
}

// Simple ASCII table formatter
export function formatTable(headers: string[], rows: string[][]): string {
  const allRows = [headers, ...rows];
  const colWidths = headers.map((_, colIdx) => {
    // Strip ANSI codes for width calculation
    return Math.max(
      ...allRows.map((row) => stripAnsi(row[colIdx] ?? '').length)
    );
  });

  const sep = colWidths.map((w) => '─'.repeat(w + 2)).join('┼');
  const headerLine = headers
    .map((h, i) => ` ${padRight(h, colWidths[i])} `)
    .join('│');

  const dataLines = rows.map((row) =>
    row.map((cell, i) => {
      const visible = stripAnsi(cell);
      const padding = colWidths[i] - visible.length;
      return ` ${cell}${' '.repeat(Math.max(0, padding))} `;
    }).join('│')
  );

  return [headerLine, `─${sep}─`, ...dataLines].join('\n');
}

function padRight(str: string, len: number): string {
  const visible = stripAnsi(str);
  return str + ' '.repeat(Math.max(0, len - visible.length));
}

// Strip ANSI escape codes for width calculation
function stripAnsi(str: string): string {
  return str.replace(/\x1B\[[0-9;]*[a-zA-Z]/g, '');
}

// Spinner frames for loading states
const SPINNER_FRAMES = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];

export class Spinner {
  private frame = 0;
  private interval: ReturnType<typeof setInterval> | null = null;
  private message: string;

  constructor(message: string) {
    this.message = message;
  }

  start(): void {
    this.interval = setInterval(() => {
      const frame = SPINNER_FRAMES[this.frame % SPINNER_FRAMES.length];
      process.stdout.write(`\r${cyan(frame)} ${this.message}`);
      this.frame++;
    }, 80);
  }

  stop(finalMessage?: string): void {
    if (this.interval) {
      clearInterval(this.interval);
      this.interval = null;
    }
    process.stdout.write(`\r${' '.repeat(this.message.length + 4)}\r`);
    if (finalMessage) {
      console.log(finalMessage);
    }
  }

  update(message: string): void {
    this.message = message;
  }
}

// Banner
export function banner(onlineCount: number, totalCount: number): string {
  const status = onlineCount === totalCount
    ? green(`${onlineCount}/${totalCount} online`)
    : yellow(`${onlineCount}/${totalCount} online`);

  return `
${bold(cyan('╔══════════════════════════════════════════════╗'))}
${bold(cyan('║'))}  ${bold(white('OmniWire Terminal'))} ${dim('v2.0')}                     ${bold(cyan('║'))}
${bold(cyan('║'))}  ${dim('Unified mesh • MCP • 22 tools')}              ${bold(cyan('║'))}
${bold(cyan('║'))}  ${dim('Nodes:')} ${status}                       ${bold(cyan('║'))}
${bold(cyan('╚══════════════════════════════════════════════╝'))}
  ${dim('Type @help for commands • @status for mesh health')}
`;
}

// Prompt string with node indicators
export function prompt(onlineNodes: string[]): string {
  const indicators = onlineNodes
    .map((id) => getNodeColorFn(id)('●'))
    .join('');
  return `${indicators} ${bold(cyan('omniwire'))}${dim('>')} `;
}
