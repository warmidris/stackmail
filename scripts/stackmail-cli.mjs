#!/usr/bin/env node

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import readline from 'node:readline';
import readlinePromises from 'node:readline/promises';

const stackmailModule = await import('./stackmail-client.ts');
const stackmail = stackmailModule.default ?? stackmailModule;

const {
  claimMessage,
  getInbox,
  getServerStatus,
  getTapState,
  keypairFromPrivkey,
  sendMessage,
} = stackmail;

const DEFAULT_SERVER_URL = process.env.STACKMAIL_SERVER_URL ?? 'http://127.0.0.1:8800';
const CONFIG_PATH = path.join(os.homedir(), '.config', 'stackmail', 'config.json');

function usage() {
  console.log(`Stackmail CLI

Human commands:
  stackmail inbox [--server <url>] [--claimed]
  stackmail compose [--server <url>] [--to <address>] [--subject <subject>]
  stackmail read <message-id> [--server <url>]
  stackmail reply <message-id> [--server <url>]
  stackmail status [--server <url>]

Agent/raw commands:
  stackmail inbox --json
  stackmail read <message-id> --json
  stackmail compose --to <address> --subject <subject> --body <text> --json

Auth:
  export STACKMAIL_PRIVATE_KEY=<64-hex-or-66-char-stacks-key>
  export STACKMAIL_PRIVATE_KEY_FILE=~/.config/stackmail/private-key
`);
}

function parseArgs(argv) {
  const [command, ...rest] = argv;
  const options = {};
  const positionals = [];
  for (let i = 0; i < rest.length; i += 1) {
    const arg = rest[i];
    if (!arg.startsWith('--')) {
      positionals.push(arg);
      continue;
    }
    const key = arg.slice(2);
    const value = rest[i + 1];
    if (!value || value.startsWith('--')) {
      options[key] = true;
      continue;
    }
    options[key] = value;
    i += 1;
  }
  return { command, options, positionals };
}

function normalizePrivateKey(input) {
  const trimmed = String(input ?? '').trim().replace(/^0x/i, '');
  if (/^[0-9a-fA-F]{66}$/.test(trimmed) && trimmed.toLowerCase().endsWith('01')) {
    return trimmed.slice(0, 64).toLowerCase();
  }
  if (/^[0-9a-fA-F]{64}$/.test(trimmed)) return trimmed.toLowerCase();
  throw new Error('Expected STACKMAIL_PRIVATE_KEY to be 64 hex chars or 66 chars ending in 01');
}

function loadJsonConfig() {
  try {
    return JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
  } catch {
    return {};
  }
}

function resolvePrivateKey(options) {
  const config = loadJsonConfig();
  const configuredPath = options['private-key-file'] ?? process.env.STACKMAIL_PRIVATE_KEY_FILE ?? config.privateKeyFile;
  const direct = options['private-key'] ?? process.env.STACKMAIL_PRIVATE_KEY ?? config.privateKey;
  if (typeof direct === 'string' && direct.trim()) return normalizePrivateKey(direct);
  if (typeof configuredPath === 'string' && configuredPath.trim()) {
    const expanded = configuredPath.startsWith('~/')
      ? path.join(os.homedir(), configuredPath.slice(2))
      : configuredPath;
    return normalizePrivateKey(fs.readFileSync(expanded, 'utf8'));
  }
  throw new Error(
    `Missing private key. Set STACKMAIL_PRIVATE_KEY or STACKMAIL_PRIVATE_KEY_FILE.\n` +
    `Example:\n  export STACKMAIL_PRIVATE_KEY=<your-64-char-hex-key>`
  );
}

function resolveServerUrl(options) {
  const config = loadJsonConfig();
  return String(options.server ?? process.env.STACKMAIL_SERVER_URL ?? config.serverUrl ?? DEFAULT_SERVER_URL);
}

function formatTimestamp(ms) {
  return new Date(ms).toISOString().replace('T', ' ').replace('.000Z', ' UTC');
}

function truncate(value, max) {
  if (value.length <= max) return value;
  return `${value.slice(0, Math.max(0, max - 1))}…`;
}

function formatAmount(amount, token) {
  return `${amount} ${token ?? 'units'}`;
}

function clearScreen() {
  process.stdout.write('\x1Bc');
}

async function prompt(question, initial = '') {
  const rl = readlinePromises.createInterface({ input: process.stdin, output: process.stdout });
  try {
    const suffix = initial ? ` [${initial}]` : '';
    const answer = await rl.question(`${question}${suffix}: `);
    return answer.trim() || initial;
  } finally {
    rl.close();
  }
}

async function pause(message = 'Press Enter to continue') {
  const rl = readlinePromises.createInterface({ input: process.stdin, output: process.stdout });
  try {
    await rl.question(`${message}`);
  } finally {
    rl.close();
  }
}

async function promptBody(initial = '') {
  console.log('Body: finish with a single "." on its own line.');
  if (initial) {
    console.log('Current body:');
    console.log(initial);
    console.log('---');
  }
  const promptRl = readlinePromises.createInterface({ input: process.stdin, output: process.stdout });
  const lines = [];
  try {
    while (true) {
      const line = await promptRl.question('');
      if (line === '.') break;
      lines.push(line);
    }
  } finally {
    promptRl.close();
  }
  const body = lines.join('\n').trim();
  if (!body && initial) return initial;
  return body;
}

async function composeFlow(ctx, defaults = {}) {
  const interactive = Boolean(process.stdin.isTTY && process.stdout.isTTY);
  const to = interactive ? await prompt('To', defaults.to ?? '') : (defaults.to ?? '').trim();
  if (!to) throw new Error('Recipient address is required');
  const subject = interactive ? await prompt('Subject', defaults.subject ?? '') : (defaults.subject ?? '').trim();
  const body = interactive ? await promptBody(defaults.body ?? '') : String(defaults.body ?? '').trim();
  if (!body) throw new Error('Message body is required');
  const result = await sendMessage({
    to,
    subject,
    body,
    privkeyHex: ctx.privateKey,
    serverUrl: ctx.serverUrl,
  });
  return { to, subject, body, result };
}

function renderInboxScreen(ctx, messages, selected) {
  clearScreen();
  const total = messages.length;
  const token = ctx.status.supportedToken ?? 'token';
  console.log(`Stackmail inbox for ${ctx.address}`);
  console.log(`Server: ${ctx.serverUrl}`);
  if (ctx.tap) {
    console.log(
      `Send capacity: ${formatAmount(ctx.tap.pipeState.myBalance.toString(), token)} | ` +
      `Receive liquidity: ${formatAmount(ctx.tap.pipeState.serverBalance.toString(), token)} | ` +
      `Nonce: ${ctx.tap.pipeState.nonce.toString()}`
    );
  }
  console.log('');
  if (total === 0) {
    console.log('No messages yet.');
  } else {
    messages.forEach((message, index) => {
      const marker = index === selected ? '>' : ' ';
      const status = message.claimed ? 'opened ' : 'new    ';
      const from = truncate(message.from, 18);
      console.log(
        `${marker} [${status}] ${String(index + 1).padStart(2, ' ')}  ${from}  ${truncate(message.id, 10)}  ${formatTimestamp(message.sentAt)}`
      );
    });
  }
  console.log('');
  console.log('Keys: ↑/↓ move, Enter open, R reply, C compose, J refresh, Q quit');
}

function withRawMode(fn) {
  const stdin = process.stdin;
  readline.emitKeypressEvents(stdin);
  if (stdin.isTTY) stdin.setRawMode(true);
  return fn().finally(() => {
    if (stdin.isTTY) stdin.setRawMode(false);
    stdin.removeAllListeners('keypress');
  });
}

async function selectInboxMessage(ctx, messages) {
  if (!process.stdin.isTTY || !process.stdout.isTTY) return null;
  let selected = 0;
  renderInboxScreen(ctx, messages, selected);
  return withRawMode(() => new Promise((resolve) => {
    const onKeypress = async (_, key) => {
      if (key.name === 'up') {
        selected = selected > 0 ? selected - 1 : Math.max(0, messages.length - 1);
        renderInboxScreen(ctx, messages, selected);
        return;
      }
      if (key.name === 'down') {
        selected = messages.length === 0 ? 0 : (selected + 1) % messages.length;
        renderInboxScreen(ctx, messages, selected);
        return;
      }
      if (key.name === 'return') {
        cleanup();
        resolve({ action: 'open', message: messages[selected] ?? null });
        return;
      }
      if (key.name === 'r') {
        cleanup();
        resolve({ action: 'reply', message: messages[selected] ?? null });
        return;
      }
      if (key.name === 'c') {
        cleanup();
        resolve({ action: 'compose', message: null });
        return;
      }
      if (key.name === 'j') {
        cleanup();
        resolve({ action: 'refresh', message: null });
        return;
      }
      if (key.name === 'q' || (key.ctrl && key.name === 'c')) {
        cleanup();
        resolve({ action: 'quit', message: null });
      }
    };
    const cleanup = () => process.stdin.removeListener('keypress', onKeypress);
    process.stdin.on('keypress', onKeypress);
  }));
}

async function renderMessageView(ctx, inboxEntry, message) {
  clearScreen();
  console.log(`From:    ${message.from}`);
  console.log(`Sent:    ${formatTimestamp(message.sentAt)}`);
  console.log(`Amount:  ${formatAmount(message.amount, ctx.status.supportedToken ?? 'token')}`);
  console.log(`Subject: ${message.subject || '(no subject)'}`);
  console.log('');
  console.log(message.body);
  console.log('');
  console.log('Keys: R reply, B back');

  if (!process.stdin.isTTY || !process.stdout.isTTY) return 'back';
  return withRawMode(() => new Promise((resolve) => {
    const onKeypress = (_, key) => {
      if (key.name === 'r') {
        cleanup();
        resolve('reply');
        return;
      }
      if (key.name === 'b' || key.name === 'escape' || key.name === 'q' || key.name === 'return' || (key.ctrl && key.name === 'c')) {
        cleanup();
        resolve('back');
      }
    };
    const cleanup = () => process.stdin.removeListener('keypress', onKeypress);
    process.stdin.on('keypress', onKeypress);
  }));
}

async function fetchContext(options) {
  const privateKey = resolvePrivateKey(options);
  const serverUrl = resolveServerUrl(options);
  const status = await getServerStatus(serverUrl);
  const kp = keypairFromPrivkey(privateKey);
  const tap = await getTapState(privateKey, serverUrl);
  return { privateKey, serverUrl, status, address: kp.addr, publicKey: kp.pubHex, tap };
}

async function printStatus(ctx) {
  const token = ctx.status.supportedToken ?? 'token';
  console.log(`Address: ${ctx.address}`);
  console.log(`Server:  ${ctx.serverUrl}`);
  console.log(`Token:   ${ctx.status.supportedToken ?? '(unknown)'}`);
  if (!ctx.tap) {
    console.log('Tap:     not found');
    return;
  }
  console.log(`Send capacity:      ${formatAmount(ctx.tap.pipeState.myBalance.toString(), token)}`);
  console.log(`Receive liquidity:  ${formatAmount(ctx.tap.pipeState.serverBalance.toString(), token)}`);
  console.log(`Nonce:              ${ctx.tap.pipeState.nonce.toString()}`);
  console.log(`Tap source:         ${ctx.tap.source}`);
}

async function readOne(ctx, messageId, asJson = false) {
  const message = await claimMessage(messageId, ctx.privateKey, ctx.serverUrl);
  if (asJson) {
    console.log(JSON.stringify(message, null, 2));
    return message;
  }
  console.log(`From:    ${message.from}`);
  console.log(`Sent:    ${formatTimestamp(message.sentAt)}`);
  console.log(`Amount:  ${formatAmount(message.amount, ctx.status.supportedToken ?? 'token')}`);
  console.log(`Subject: ${message.subject || '(no subject)'}`);
  console.log('');
  console.log(message.body);
  return message;
}

async function runInbox(ctx, options) {
  const includeClaimed = Boolean(options.claimed);
  const messages = await getInbox(ctx.privateKey, ctx.serverUrl, includeClaimed);

  if (options.json || !process.stdin.isTTY || !process.stdout.isTTY) {
    console.log(JSON.stringify({ address: ctx.address, messages }, null, 2));
    return;
  }

  while (true) {
    const selection = await selectInboxMessage(ctx, messages);
    if (!selection || selection.action === 'quit') return;
    if (selection.action === 'refresh') {
      const next = await getInbox(ctx.privateKey, ctx.serverUrl, includeClaimed);
      messages.splice(0, messages.length, ...next);
      continue;
    }
    if (selection.action === 'compose') {
      const sent = await composeFlow(ctx);
      console.log(`\nSent ${sent.result.messageId} to ${sent.to}.`);
      await pause();
      const next = await getInbox(ctx.privateKey, ctx.serverUrl, includeClaimed);
      messages.splice(0, messages.length, ...next);
      continue;
    }
    if (!selection.message) continue;
    if (selection.action === 'reply') {
      const sent = await composeFlow(ctx, {
        to: selection.message.from,
        subject: `Re: ${selection.message.subject ?? selection.message.id}`,
      });
      console.log(`\nSent ${sent.result.messageId} to ${sent.to}.`);
      await pause();
      const next = await getInbox(ctx.privateKey, ctx.serverUrl, includeClaimed);
      messages.splice(0, messages.length, ...next);
      continue;
    }

    const opened = await claimMessage(selection.message.id, ctx.privateKey, ctx.serverUrl);
    const action = await renderMessageView(ctx, selection.message, opened);
    if (action === 'reply') {
      const sent = await composeFlow(ctx, {
        to: opened.from,
        subject: `Re: ${opened.subject ?? selection.message.id}`,
      });
      console.log(`\nSent ${sent.result.messageId} to ${sent.to}.`);
      await pause();
    }
    const next = await getInbox(ctx.privateKey, ctx.serverUrl, includeClaimed);
    messages.splice(0, messages.length, ...next);
  }
}

async function main() {
  const { command, options, positionals } = parseArgs(process.argv.slice(2));
  if (!command || command === 'help' || command === '--help') {
    usage();
    return;
  }

  const ctx = await fetchContext(options);

  if (command === 'status') {
    await printStatus(ctx);
    return;
  }

  if (command === 'inbox') {
    await runInbox(ctx, options);
    return;
  }

  if (command === 'read') {
    const messageId = positionals[0];
    if (!messageId) throw new Error('read requires a message id');
    await readOne(ctx, messageId, Boolean(options.json));
    return;
  }

  if (command === 'reply') {
    const messageId = positionals[0];
    if (!messageId) throw new Error('reply requires a message id');
    const message = await claimMessage(messageId, ctx.privateKey, ctx.serverUrl);
    const sent = await composeFlow(ctx, {
      to: message.from,
      subject: `Re: ${message.subject ?? messageId}`,
    });
    console.log(JSON.stringify({ repliedTo: messageId, messageId: sent.result.messageId }, null, 2));
    return;
  }

  if (command === 'compose') {
    const sent = await composeFlow(ctx, {
      to: typeof options.to === 'string' ? options.to : '',
      subject: typeof options.subject === 'string' ? options.subject : '',
      body: typeof options.body === 'string' ? options.body : '',
    });
    if (options.json) {
      console.log(JSON.stringify(sent, (_, value) => typeof value === 'bigint' ? value.toString() : value, 2));
      return;
    }
    console.log(`Sent ${sent.result.messageId} to ${sent.to}`);
    return;
  }

  throw new Error(`Unknown command: ${command}`);
}

main().catch(error => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
