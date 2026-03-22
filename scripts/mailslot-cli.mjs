#!/usr/bin/env node

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import crypto from 'node:crypto';
import readlinePromises from 'node:readline/promises';
import { createNetwork } from '@stacks/network';
import {
  AnchorMode,
  PostConditionMode,
  broadcastTransaction,
  bufferCV,
  makeContractCall,
  noneCV,
  principalCV,
  someCV,
  uintCV,
} from '@stacks/transactions';

const mailslotModule = await import('./mailslot-client.ts');
const mailslot = mailslotModule.default ?? mailslotModule;

const {
  claimMessage,
  getClaimedMessage,
  getInbox,
  getServerStatus,
  getTapState,
  keypairFromPrivkey,
  prepareBorrowMoreLiquidity,
  prepareOpenMailbox,
  registerMailbox,
  sendMessage,
  syncTapState,
  deriveMailboxCapacityPolicy,
} = mailslot;

const DEFAULT_SERVER_URL = process.env.MAILSLOT_SERVER_URL ?? 'https://mailslot.locker';
const CONFIG_PATH = path.join(os.homedir(), '.config', 'mailslot', 'config.json');

function usage() {
  console.log(`Mailslot CLI

Human commands:
  mailslot open [--server <url>]
  mailslot inbox [--server <url>] [--claimed]
  mailslot compose [--server <url>] [--to <address or name.btc>] [--subject <subject>]
  mailslot read <message-id> [--server <url>]
  mailslot reply <message-id> [--server <url>]
  mailslot status [--server <url>]
  mailslot refresh-capacity [--server <url>] [--json]

Agent/raw commands:
  mailslot open --json
  mailslot inbox --json
  mailslot read <message-id> --json
  mailslot compose --to <address or name.btc> --subject <subject> --body <text> --json

Auth (in order of precedence):
  1. export MAILSLOT_PRIVATE_KEY=<64-hex-or-66-char-stacks-key>
  2. export MAILSLOT_PRIVATE_KEY_FILE=~/.config/mailslot/private-key
  3. aibtc wallet (~/.aibtc/) — auto-detected, no config needed
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
  throw new Error('Expected MAILSLOT_PRIVATE_KEY to be 64 hex chars or 66 chars ending in 01');
}

/** Return the 66-char compressed Stacks private key expected by makeContractCall. */
function compressedSenderKey(hex64) {
  return hex64 + '01';
}

function loadJsonConfig() {
  try {
    return JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
  } catch {
    return {};
  }
}

/**
 * Decrypt the aibtc keystore and derive the Stacks private key in-memory.
 * Returns a 64-char hex private key, or null if no aibtc wallet is found.
 */
async function unlockAibtcWallet() {
  const aibtcDir = path.join(os.homedir(), '.aibtc');
  const configPath = path.join(aibtcDir, 'config.json');
  if (!fs.existsSync(configPath)) return null;

  const aibtcConfig = JSON.parse(fs.readFileSync(configPath, 'utf8'));
  const walletId = aibtcConfig.activeWalletId;
  if (!walletId) return null;

  const keystorePath = path.join(aibtcDir, 'wallets', walletId, 'keystore.json');
  if (!fs.existsSync(keystorePath)) return null;

  // Read password from agent.env (agent name used as password by aibtc)
  const agentEnvPath = path.join(aibtcDir, 'agent.env');
  if (!fs.existsSync(agentEnvPath)) return null;
  const password = fs.readFileSync(agentEnvPath, 'utf8').trim();

  // Decrypt keystore: Scrypt KDF → AES-256-GCM
  const keystore = JSON.parse(fs.readFileSync(keystorePath, 'utf8'));
  const enc = keystore.encrypted;
  const salt = Buffer.from(enc.salt, 'base64');
  const derivedKey = crypto.scryptSync(password, salt, enc.scryptParams.keyLen, {
    N: enc.scryptParams.N,
    r: enc.scryptParams.r,
    p: enc.scryptParams.p,
  });
  const decipher = crypto.createDecipheriv(
    'aes-256-gcm',
    derivedKey,
    Buffer.from(enc.iv, 'base64'),
  );
  decipher.setAuthTag(Buffer.from(enc.authTag, 'base64'));
  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(enc.ciphertext, 'base64')),
    decipher.final(),
  ]);
  const mnemonic = decrypted.toString('utf8');

  // Derive Stacks private key from mnemonic
  const { generateWallet } = await import('@stacks/wallet-sdk');
  const wallet = await generateWallet({ secretKey: mnemonic, password: '' });
  const stxKey = wallet.accounts[0].stxPrivateKey;

  // normalizePrivateKey strips the 01 suffix if present
  return normalizePrivateKey(stxKey);
}

async function resolvePrivateKey(options) {
  const config = loadJsonConfig();
  const configuredPath = options['private-key-file'] ?? process.env.MAILSLOT_PRIVATE_KEY_FILE ?? config.privateKeyFile;
  const direct = options['private-key'] ?? process.env.MAILSLOT_PRIVATE_KEY ?? config.privateKey;
  if (typeof direct === 'string' && direct.trim()) return normalizePrivateKey(direct);
  if (typeof configuredPath === 'string' && configuredPath.trim()) {
    const expanded = configuredPath.startsWith('~/')
      ? path.join(os.homedir(), configuredPath.slice(2))
      : configuredPath;
    return normalizePrivateKey(fs.readFileSync(expanded, 'utf8'));
  }

  // Fall back to aibtc wallet
  const aibtcKey = await unlockAibtcWallet();
  if (aibtcKey) return aibtcKey;

  throw new Error(
    `Missing private key. Set MAILSLOT_PRIVATE_KEY or MAILSLOT_PRIVATE_KEY_FILE,\n` +
    `or install an aibtc wallet (~/.aibtc/).\n` +
    `Example:\n  export MAILSLOT_PRIVATE_KEY=<your-64-char-hex-key>`
  );
}

function resolveServerUrl(options) {
  const config = loadJsonConfig();
  return String(options.server ?? process.env.MAILSLOT_SERVER_URL ?? config.serverUrl ?? DEFAULT_SERVER_URL);
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

function formatMessages(amount, price) {
  const unitPrice = BigInt(price ?? 1n);
  if (unitPrice <= 0n) return '0';
  return (BigInt(amount) / unitPrice).toString();
}

function printKv(label, value) {
  console.log(`${label.padEnd(22)} ${value}`);
}

async function confirmAction(promptText) {
  const rl = readlinePromises.createInterface({ input: process.stdin, output: process.stdout });
  try {
    const answer = (await rl.question(`${promptText} [y/N]: `)).trim().toLowerCase();
    return answer === 'y' || answer === 'yes';
  } finally {
    rl.close();
  }
}

async function printSendSignaturePreview(ctx, to, subject, body) {
  const status = ctx.status;
  const tap = ctx.tap ?? await getTapState(ctx.privateKey, ctx.serverUrl);
  if (!tap) throw new Error('No tap found for this sender. Open and fund a mailbox tap before sending.');
  const capacity = getReceiveCapacitySummary(status, tap);
  const payInfo = await mailslot.getPaymentInfo(to, ctx.serverUrl);
  const price = BigInt(payInfo.amount);
  const fee = BigInt(status.minFeeSats ?? '0');
  const recipientAmount = price > fee ? price - fee : 0n;
  const beforeMyBalance = tap.pipeState.myBalance;
  const beforeServerBalance = tap.pipeState.serverBalance;
  const afterMyBalance = beforeMyBalance - price;
  const afterServerBalance = beforeServerBalance + price;
  const nextNonce = tap.pipeState.nonce + 1n;
  const token = status.supportedToken ?? 'token';

  const recipientDisplay = await formatAddress(to);
  console.log('\nAbout to request a payment signature for this message:');
  printKv('Recipient', recipientDisplay);
  printKv('Subject', subject || '(no subject)');
  printKv('Body length', `${body.length} chars`);
  printKv('Message price', formatAmount(price.toString(), token));
  printKv('Recipient gets', formatAmount(recipientAmount.toString(), token));
  printKv('Server fee', formatAmount(fee.toString(), token));
  printKv('Your balance', `${formatAmount(beforeMyBalance.toString(), token)} -> ${formatAmount(afterMyBalance.toString(), token)}`);
  printKv('Server balance', `${formatAmount(beforeServerBalance.toString(), token)} -> ${formatAmount(afterServerBalance.toString(), token)}`);
  printKv('Nonce', `${tap.pipeState.nonce.toString()} -> ${nextNonce.toString()}`);
  if (capacity.aboveTarget) {
    console.log('');
    console.log(`Note: your tap is carrying ${capacity.excessReceiveLiquidity} extra ${token} of receive liquidity above the normal target.`);
    console.log('If the server asks for a second signature, that signature is only used to return the extra receive liquidity to the reservoir.');
    console.log('It does not change the message price, and it is separate from the payment signature for this message.');
  }
  console.log('');
}

function printRefreshSignaturePreview(ctx, capacity) {
  const token = ctx.status.supportedToken ?? 'token';
  const beforeMyBalance = ctx.tap.pipeState.myBalance;
  const beforeReservoirBalance = ctx.tap.pipeState.serverBalance;
  const afterReservoirBalance = beforeReservoirBalance + capacity.refreshAmount;
  const nonceBefore = ctx.tap.pipeState.nonce;
  const nonceAfter = nonceBefore + 1n;

  console.log('\nAbout to request a receive-capacity signature:');
  console.log('This signature lets the reservoir lend more receive liquidity to your tap so incoming mail has room to land.');
  printKv('Refresh amount', formatAmount(capacity.refreshAmount.toString(), token));
  printKv('Your balance', formatAmount(beforeMyBalance.toString(), token));
  printKv('Receive capacity', `${formatAmount(beforeReservoirBalance.toString(), token)} -> ${formatAmount(afterReservoirBalance.toString(), token)}`);
  printKv('Messages receivable', `${formatMessages(beforeReservoirBalance, capacity.messagePrice)} -> ${formatMessages(afterReservoirBalance, capacity.messagePrice)}`);
  printKv('Nonce', `${nonceBefore.toString()} -> ${nonceAfter.toString()}`);
  console.log('');
}

async function confirmRefreshTransaction(ctx, capacity, action) {
  const token = ctx.status.supportedToken ?? 'token';
  const fee = BigInt(action.fee ?? '0');
  const amount = BigInt(action.amount);
  const reservoir = action.reservoirContract;
  const tokenLabel = action.token ?? 'STX';
  console.log('Transaction approval required:');
  console.log('This on-chain step funds the receive side of your tap back up to the normal target.');
  printKv('Contract', `${action.reservoirContract}::borrow-liquidity`);
  printKv('You pay', formatAmount(fee.toString(), token));
  printKv('Reservoir sends', formatAmount(amount.toString(), token));
  printKv('Post conditions', action.token == null
    ? `you send exactly ${fee} STX; reservoir sends exactly ${amount} STX`
    : `you send exactly ${fee} ${tokenLabel}; ${reservoir} sends exactly ${amount} ${tokenLabel}`);
  printKv('Resulting target', `${formatAmount(capacity.receiveCapacityTarget.toString(), token)} (${formatMessages(capacity.receiveCapacityTarget, capacity.messagePrice)} messages)`);
  console.log('');
  return confirmAction('Submit this transaction?');
}

function getReceiveCapacitySummary(status, tap) {
  const policy = deriveMailboxCapacityPolicy(status);
  const receiveLiquidity = tap?.pipeState.serverBalance ?? 0n;
  const messagePrice = policy.messagePrice > 0n ? policy.messagePrice : 1n;
  const remainingReceives = receiveLiquidity / messagePrice;
  const low = receiveLiquidity <= policy.lowReceiveThreshold;
  const aboveTarget = receiveLiquidity > policy.receiveCapacityTarget;
  const refreshAmount = receiveLiquidity >= policy.receiveCapacityTarget
    ? 0n
    : policy.receiveCapacityTarget - receiveLiquidity;
  const excessReceiveLiquidity = aboveTarget
    ? receiveLiquidity - policy.receiveCapacityTarget
    : 0n;
  return {
    ...policy,
    receiveLiquidity,
    remainingReceives,
    low,
    aboveTarget,
    excessReceiveLiquidity,
    refreshAmount,
  };
}

// ─── BNS v2 name resolution ─────────────────────────────────────────────────

/** Cache of BNS name → STX address resolutions (forward). */
const bnsForwardCache = new Map();
/** Cache of STX address → BNS name (reverse). */
const bnsReverseCache = new Map();

/**
 * Resolve a BNS name (e.g. "brice.btc") to its owner's STX address.
 * Returns null if the name doesn't exist or is expired.
 */
async function resolveBnsName(name) {
  if (bnsForwardCache.has(name)) return bnsForwardCache.get(name);
  try {
    const res = await fetch(`https://api.bnsv2.com/names/${encodeURIComponent(name)}`);
    if (!res.ok) return null;
    const json = await res.json();
    if (!json.data?.owner || !json.data?.is_valid) return null;
    const address = json.data.owner;
    bnsForwardCache.set(name, address);
    bnsReverseCache.set(address, name);
    return address;
  } catch {
    return null;
  }
}

/**
 * Reverse-lookup a STX address to its primary BNS name.
 * Returns null if no name is found.
 */
async function reverseLookupBns(address) {
  if (bnsReverseCache.has(address)) return bnsReverseCache.get(address);
  try {
    const res = await fetch(`https://api.hiro.so/v1/addresses/stacks/${encodeURIComponent(address)}`);
    if (!res.ok) return null;
    const json = await res.json();
    const name = json.names?.[0] ?? null;
    if (name) bnsReverseCache.set(address, name);
    return name;
  } catch {
    return null;
  }
}

/**
 * If input contains a '.', treat it as a BNS name and resolve it.
 * Otherwise return the input as-is (assumed to be a STX address).
 */
async function resolveRecipient(input) {
  if (!input.includes('.')) return input;
  const address = await resolveBnsName(input);
  if (!address) throw new Error(`Could not resolve BNS name "${input}" — name not found or expired`);
  return address;
}

/** Format an address, showing its BNS name if known/available. */
async function formatAddress(address) {
  const name = await reverseLookupBns(address);
  return name ? `${name} (${address})` : address;
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
  const toInput = interactive ? await prompt('To (address or .btc name)', defaults.to ?? '') : (defaults.to ?? '').trim();
  if (!toInput) throw new Error('Recipient address is required');

  // Resolve BNS name if input contains a dot
  let to = toInput;
  if (toInput.includes('.')) {
    if (interactive) console.log(`Resolving ${toInput}…`);
    to = await resolveRecipient(toInput);
    if (interactive) console.log(`Resolved to ${to}`);
  }

  const subject = interactive ? await prompt('Subject', defaults.subject ?? '') : (defaults.subject ?? '').trim();
  const body = interactive ? await promptBody(defaults.body ?? '') : String(defaults.body ?? '').trim();
  if (!body) throw new Error('Message body is required');
  if (interactive) {
    await printSendSignaturePreview(ctx, to, subject, body);
    const approved = await confirmAction('Request wallet signature for this message?');
    if (!approved) throw new Error('Message signing cancelled');
  }
  const result = await sendMessage({
    to,
    subject,
    body,
    privkeyHex: ctx.privateKey,
    serverUrl: ctx.serverUrl,
  });
  return { to, subject, body, result };
}

/** Batch-resolve BNS names for all sender addresses in a message list. */
async function prefetchBnsNames(messages) {
  const addresses = [...new Set(messages.map(m => m.from).filter(Boolean))];
  await Promise.allSettled(addresses.map(addr => reverseLookupBns(addr)));
}

/** Get a display label for an address: BNS name if cached, otherwise truncated address. */
function senderLabel(address, maxLen) {
  const name = bnsReverseCache.get(address);
  if (name) return truncate(name, maxLen);
  return truncate(address, maxLen);
}

function renderInboxScreen(ctx, messages, selected, includeClaimed) {
  clearScreen();
  const total = messages.length;
  const token = ctx.status.supportedToken ?? 'token';
  const capacity = getReceiveCapacitySummary(ctx.status, ctx.tap);
  console.log(`Mailslot inbox for ${ctx.address}`);
  console.log(`Server: ${ctx.serverUrl}`);
  if (ctx.tap) {
    console.log(
      `Send capacity: ${formatAmount(ctx.tap.pipeState.myBalance.toString(), token)} | ` +
      `Receive liquidity: ${formatAmount(ctx.tap.pipeState.serverBalance.toString(), token)} | ` +
      `Nonce: ${ctx.tap.pipeState.nonce.toString()}`
    );
    console.log(
      capacity.low
        ? `Receive capacity low: about ${capacity.remainingReceives} more message(s). Run: mailslot refresh-capacity`
        : `Receive capacity: about ${capacity.remainingReceives} message(s) at current pricing`
    );
  }
  console.log('');
  if (total === 0) {
    console.log(includeClaimed ? 'No messages in this view.' : 'No unread messages yet.');
  } else {
    messages.forEach((message, index) => {
      const marker = index === selected ? '>' : ' ';
      const status = message.claimed ? 'opened ' : 'new    ';
      const from = senderLabel(message.from, 18);
      console.log(
        `${marker} [${status}] ${String(index + 1).padStart(2, ' ')}  ${from}  ${truncate(message.id, 10)}  ${formatTimestamp(message.sentAt)}`
      );
    });
  }
  console.log('');
  console.log(`View: ${includeClaimed ? 'all messages' : 'unread only'}`);
  console.log('Keys: ↑/↓ move, Enter open, R reply, C compose, A toggle all/unread, J refresh, Q quit');
}

function withRawMode(fn) {
  const stdin = process.stdin;
  if (stdin.isTTY) stdin.setRawMode(true);
  stdin.resume();
  return fn().finally(() => {
    if (stdin.isTTY) stdin.setRawMode(false);
    stdin.removeAllListeners('data');
    stdin.pause();
  });
}

async function selectInboxMessage(ctx, messages, includeClaimed) {
  if (!process.stdin.isTTY || !process.stdout.isTTY) return null;
  let selected = 0;
  renderInboxScreen(ctx, messages, selected, includeClaimed);
  return withRawMode(() => new Promise((resolve) => {
    const onData = async chunk => {
      const input = Buffer.isBuffer(chunk) ? chunk.toString('utf8') : String(chunk);
      const lower = input.toLowerCase();
      if (input === '\u001b[A') {
        selected = selected > 0 ? selected - 1 : Math.max(0, messages.length - 1);
        renderInboxScreen(ctx, messages, selected, includeClaimed);
        return;
      }
      if (input === '\u001b[B') {
        selected = messages.length === 0 ? 0 : (selected + 1) % messages.length;
        renderInboxScreen(ctx, messages, selected, includeClaimed);
        return;
      }
      if (input === '\r' || input === '\n') {
        cleanup();
        resolve({ action: 'open', message: messages[selected] ?? null });
        return;
      }
      if (lower === 'r') {
        cleanup();
        resolve({ action: 'reply', message: messages[selected] ?? null });
        return;
      }
      if (lower === 'c') {
        cleanup();
        resolve({ action: 'compose', message: null });
        return;
      }
      if (lower === 'a') {
        cleanup();
        resolve({ action: 'toggle-claimed', message: null });
        return;
      }
      if (lower === 'j') {
        cleanup();
        resolve({ action: 'refresh', message: null });
        return;
      }
      if (lower === 'q' || input === '\u0003') {
        cleanup();
        resolve({ action: 'quit', message: null });
      }
    };
    const cleanup = () => process.stdin.removeListener('data', onData);
    process.stdin.on('data', onData);
  }));
}

async function renderMessageView(ctx, inboxEntry, message) {
  clearScreen();
  const fromDisplay = await formatAddress(message.from);
  console.log(`From:    ${fromDisplay}`);
  console.log(`Sent:    ${formatTimestamp(message.sentAt)}`);
  console.log(`Amount:  ${formatAmount(message.amount, ctx.status.supportedToken ?? 'token')}`);
  console.log(`Subject: ${message.subject || '(no subject)'}`);
  console.log('');
  console.log(message.body);
  console.log('');
  console.log('Keys: R reply, B back');

  if (!process.stdin.isTTY || !process.stdout.isTTY) return 'back';
  return withRawMode(() => new Promise((resolve) => {
    const onData = chunk => {
      const input = Buffer.isBuffer(chunk) ? chunk.toString('utf8') : String(chunk);
      const lower = input.toLowerCase();
      if (lower === 'r') {
        cleanup();
        resolve('reply');
        return;
      }
      if (lower === 'b' || input === '\u001b' || lower === 'q' || input === '\r' || input === '\n' || input === '\u0003') {
        cleanup();
        resolve('back');
      }
    };
    const cleanup = () => process.stdin.removeListener('data', onData);
    process.stdin.on('data', onData);
  }));
}

async function fetchContext(options) {
  const privateKey = await resolvePrivateKey(options);
  const serverUrl = resolveServerUrl(options);
  const status = await getServerStatus(serverUrl);
  const kp = keypairFromPrivkey(privateKey);
  const tap = await getTapState(privateKey, serverUrl);
  return { privateKey, serverUrl, status, address: kp.addr, publicKey: kp.pubHex, tap };
}

async function printStatus(ctx) {
  const token = ctx.status.supportedToken ?? 'token';
  const capacity = getReceiveCapacitySummary(ctx.status, ctx.tap);
  console.log(`Address: ${ctx.address}`);
  console.log(`Server:  ${ctx.serverUrl}`);
  console.log(`Token:   ${ctx.status.supportedToken ?? '(unknown)'}`);
  console.log(`Price:   ${formatAmount(capacity.messagePrice.toString(), token)}`);
  if (!ctx.tap) {
    console.log('Tap:     not found');
    return;
  }
  console.log(`Send capacity:      ${formatAmount(ctx.tap.pipeState.myBalance.toString(), token)}`);
  console.log(`Receive liquidity:  ${formatAmount(ctx.tap.pipeState.serverBalance.toString(), token)}`);
  console.log(`Receive target:     ${formatAmount(capacity.receiveCapacityTarget.toString(), token)}`);
  console.log(`Receive warning:    ${formatAmount(capacity.lowReceiveThreshold.toString(), token)}`);
  console.log(`Messages receivable: about ${capacity.remainingReceives}`);
  if (capacity.low) {
    console.log(`Alert:              low receive capacity; run 'mailslot refresh-capacity'`);
  }
  if (capacity.aboveTarget) {
    console.log(`Note:               ${formatAmount(capacity.excessReceiveLiquidity.toString(), token)} is above the normal receive target`);
    console.log(`Why it matters:     the server may ask for one extra signature to return that excess liquidity to the reservoir`);
  }
  console.log(`Nonce:              ${ctx.tap.pipeState.nonce.toString()}`);
  console.log(`Tap source:         ${ctx.tap.source}`);
}

async function readOne(ctx, messageId, asJson = false) {
  const inbox = await getInbox(ctx.privateKey, ctx.serverUrl, true);
  const entry = inbox.find(message => message.id === messageId);
  const message = entry?.claimed
    ? await getClaimedMessage(messageId, ctx.privateKey, ctx.serverUrl)
    : await claimMessage(messageId, ctx.privateKey, ctx.serverUrl);
  if (asJson) {
    console.log(JSON.stringify(message, null, 2));
    return message;
  }
  const fromDisplay = await formatAddress(message.from);
  console.log(`From:    ${fromDisplay}`);
  console.log(`Sent:    ${formatTimestamp(message.sentAt)}`);
  console.log(`Amount:  ${formatAmount(message.amount, ctx.status.supportedToken ?? 'token')}`);
  console.log(`Subject: ${message.subject || '(no subject)'}`);
  console.log('');
  console.log(message.body);
  return message;
}

async function refreshCapacity(ctx, options) {
  if (!ctx.tap) throw new Error('No tap found. Open a mailbox before refreshing capacity.');

  const capacity = getReceiveCapacitySummary(ctx.status, ctx.tap);
  const token = ctx.status.supportedToken ?? 'token';
  const amount = capacity.refreshAmount;

  if (amount <= 0n) {
    const payload = {
      ok: true,
      refreshed: false,
      reason: 'capacity-already-sufficient',
      receiveLiquidity: ctx.tap.pipeState.serverBalance.toString(),
      targetReceiveLiquidity: capacity.receiveCapacityTarget.toString(),
    };
    if (options.json) {
      console.log(JSON.stringify(payload, null, 2));
    } else {
      console.log('Receive capacity is already at or above target.');
    }
    return payload;
  }

  if (!options.json && process.stdin.isTTY && process.stdout.isTTY) {
    printRefreshSignaturePreview(ctx, capacity);
    const approved = await confirmAction('Request wallet signature for this refresh?');
    if (!approved) throw new Error('Refresh signing cancelled');
  }
  const action = await prepareBorrowMoreLiquidity(ctx.privateKey, amount, ctx.serverUrl);
  const [contractAddress, contractName] = action.reservoirContract.split('.');
  const network = createNetwork({ network: action.chainId === 1 ? 'mainnet' : 'testnet' });
  if (!options.json && process.stdin.isTTY && process.stdout.isTTY) {
    const approved = await confirmRefreshTransaction(ctx, capacity, action);
    if (!approved) throw new Error('Refresh transaction cancelled');
  }
  const tx = await makeContractCall({
    network,
    senderKey: compressedSenderKey(ctx.privateKey),
    contractAddress,
    contractName,
    functionName: 'borrow-liquidity',
    functionArgs: [
      principalCV(action.stackflowContract),
      uintCV(BigInt(action.amount)),
      uintCV(BigInt(action.fee ?? '0')),
      action.token == null ? noneCV() : someCV(principalCV(action.token)),
      uintCV(BigInt(action.myBalance)),
      uintCV(BigInt(action.reservoirBalance)),
      bufferCV(Buffer.from(String(action.mySignature).replace(/^0x/, ''), 'hex')),
      bufferCV(Buffer.from(String(action.reservoirSignature).replace(/^0x/, ''), 'hex')),
      uintCV(BigInt(action.nonce)),
    ],
    anchorMode: AnchorMode.Any,
    postConditionMode: PostConditionMode.Allow,
    validateWithAbi: false,
  });
  const result = await broadcastTransaction({ transaction: tx, network });
  if ('reason' in result) {
    throw new Error(`refresh-capacity broadcast failed: ${result.reason}${result.error ? ` (${result.error})` : ''}`);
  }
  await syncTapState(ctx.privateKey, action, ctx.serverUrl);

  const payload = {
    ok: true,
    refreshed: true,
    amount: action.amount,
    fee: action.fee ?? '0',
    txid: result.txid,
    targetReceiveLiquidity: capacity.receiveCapacityTarget.toString(),
    commandHint: 'mailslot status',
  };
  if (options.json) {
    console.log(JSON.stringify(payload, null, 2));
  } else {
    console.log(`Refreshed receive capacity by ${formatAmount(action.amount, token)}.`);
    console.log(`Borrow fee: ${formatAmount(action.fee ?? '0', token)}`);
    console.log(`Txid: ${result.txid}`);
  }
  return payload;
}

async function runInbox(ctx, options) {
  let includeClaimed = Boolean(options.claimed);
  const messages = await getInbox(ctx.privateKey, ctx.serverUrl, includeClaimed);
  await prefetchBnsNames(messages);

  if (options.json || !process.stdin.isTTY || !process.stdout.isTTY) {
    console.log(JSON.stringify({ address: ctx.address, messages }, null, 2));
    return;
  }

  while (true) {
    const selection = await selectInboxMessage(ctx, messages, includeClaimed);
    if (!selection || selection.action === 'quit') return;
    if (selection.action === 'toggle-claimed') {
      includeClaimed = !includeClaimed;
      const next = await getInbox(ctx.privateKey, ctx.serverUrl, includeClaimed);
      messages.splice(0, messages.length, ...next);
      continue;
    }
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

    const opened = selection.message.claimed
      ? await getClaimedMessage(selection.message.id, ctx.privateKey, ctx.serverUrl)
      : await claimMessage(selection.message.id, ctx.privateKey, ctx.serverUrl);
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

async function openMailboxCmd(ctx, options) {
  if (ctx.tap) {
    const msg = 'You already have a tap open on this server.';
    if (options.json) {
      console.log(JSON.stringify({ ok: false, error: 'tap-already-exists', message: msg }));
    } else {
      console.log(msg);
      console.log('Run: mailslot status');
    }
    return;
  }

  const token = ctx.status.supportedToken ?? 'token';
  const policy = deriveMailboxCapacityPolicy(ctx.status);

  if (!options.json && process.stdin.isTTY && process.stdout.isTTY) {
    console.log('\nOpen a new Mailslot mailbox');
    printKv('Address', ctx.address);
    printKv('Server', ctx.serverUrl);
    printKv('Send capacity', formatAmount(policy.sendCapacityTarget.toString(), token));
    printKv('Receive capacity', formatAmount(policy.receiveCapacityTarget.toString(), token));
    printKv('Message price', formatAmount(policy.messagePrice.toString(), token));
    console.log('');
    console.log('This will:');
    console.log(`  1. Deposit ${policy.sendCapacityTarget} ${token} into your send pipe`);
    console.log(`  2. Borrow ${policy.receiveCapacityTarget} ${token} receive liquidity from the reservoir`);
    console.log(`  3. A small borrow fee may apply`);
    console.log('');
    const approved = await confirmAction('Proceed?');
    if (!approved) throw new Error('Cancelled');
  }

  console.log('Preparing open-mailbox parameters...');
  const params = await prepareOpenMailbox(ctx.privateKey, ctx.serverUrl);

  const network = createNetwork({ network: params.chainId === 1 ? 'mainnet' : 'testnet' });
  const [contractAddress, contractName] = params.reservoirContract.split('.');
  const borrowFee = BigInt(params.borrowFee);

  if (!options.json && process.stdin.isTTY && process.stdout.isTTY) {
    console.log('');
    printKv('Contract', `${params.reservoirContract}::create-tap-with-borrowed-liquidity`);
    printKv('Tap deposit', formatAmount(params.tapAmount, token));
    printKv('Borrow amount', formatAmount(params.borrowAmount, token));
    printKv('Borrow fee', formatAmount(params.borrowFee, token));
    printKv('Total cost', formatAmount((BigInt(params.tapAmount) + borrowFee).toString(), token));
    console.log('');
    const approved = await confirmAction('Submit this transaction?');
    if (!approved) throw new Error('Transaction cancelled');
  }

  console.log('Broadcasting transaction...');
  const tx = await makeContractCall({
    network,
    senderKey: compressedSenderKey(ctx.privateKey),
    contractAddress,
    contractName,
    functionName: 'create-tap-with-borrowed-liquidity',
    functionArgs: [
      principalCV(params.stackflowContract),
      params.token == null ? noneCV() : someCV(principalCV(params.token)),
      uintCV(BigInt(params.tapAmount)),
      uintCV(0n),  // tap nonce
      uintCV(BigInt(params.borrowAmount)),
      uintCV(borrowFee),
      uintCV(BigInt(params.myBalance)),
      uintCV(BigInt(params.reservoirBalance)),
      bufferCV(Buffer.from(String(params.mySignature).replace(/^0x/, ''), 'hex')),
      bufferCV(Buffer.from(String(params.reservoirSignature).replace(/^0x/, ''), 'hex')),
      uintCV(BigInt(params.borrowNonce)),
    ],
    anchorMode: AnchorMode.Any,
    postConditionMode: PostConditionMode.Allow,
    validateWithAbi: false,
  });
  const result = await broadcastTransaction({ transaction: tx, network });
  if ('reason' in result) {
    throw new Error(`Broadcast failed: ${result.reason}${result.error ? ` (${result.error})` : ''}`);
  }

  // Register mailbox (store pubkey with server)
  await registerMailbox(ctx.privateKey, ctx.serverUrl);

  const payload = {
    ok: true,
    txid: result.txid,
    tapAmount: params.tapAmount,
    borrowAmount: params.borrowAmount,
    borrowFee: params.borrowFee,
  };

  if (options.json) {
    console.log(JSON.stringify(payload, null, 2));
  } else {
    console.log(`\nMailbox opened!`);
    console.log(`Txid: ${result.txid}`);
    console.log(`Tap deposit: ${formatAmount(params.tapAmount, token)}`);
    console.log(`Receive liquidity: ${formatAmount(params.borrowAmount, token)}`);
    console.log(`Borrow fee: ${formatAmount(params.borrowFee, token)}`);
    console.log(`\nWait for transaction confirmation, then run: mailslot status`);
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

  if (command === 'open') {
    await openMailboxCmd(ctx, options);
    return;
  }

  if (command === 'refresh-capacity') {
    await refreshCapacity(ctx, options);
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
