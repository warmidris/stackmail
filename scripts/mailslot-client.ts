/**
 * Mailslot TypeScript Client SDK
 *
 * Standalone client for the Mailslot mainnet deployment.
 * Copy this file into your project; it depends on @noble/curves and @stacks/encryption.
 *
 * ─── Mainnet Deployment ────────────────────────────────────────────────────────
 *
 * Deployer: SP3QFYVTMS0PRJT3K3GMDW9DGR33TDHENSDWVNQMR
 *   sm-test-token  – TEST SIP-010 token
 *   sm-stackflow   – StackFlow v0.6.0 payment channels
 *   sm-reservoir   – reservoir hub
 *
 * Server: SP1RCWQSAF1Q96CPX77Q9EAR236N19P09T6E2KDRE
 * URL:    http://127.0.0.1:8800
 *
 * ─── Quick Start ───────────────────────────────────────────────────────────────
 *
 *   // Create or load your keypair
 *   const kp = genKeypair();           // new keypair
 *   // const kp = keypairFromPrivkey("your_priv_key_hex");
 *
 *   // Register your mailbox (one-time, receives your pubkey)
 *   await registerMailbox(kp.privHex);
 *
 *   // Inspect your current tap state (tracked by the server when available,
 *   // otherwise read from chain)
 *   const tap = await getTapState(kp.privHex);
 *
 *   // Send a message (pipeState is optional if the tap can be resolved)
 *   const { messageId, newPipeState } = await sendMessage({
 *     to: recipientAddr,
 *     subject: 'Hello',
 *     body: 'World',
 *     privkeyHex: kp.privHex,
 *     pipeState: tap?.pipeState,
 *   });
 *
 *   // Check and claim new messages
 *   const messages = await readNewMessages(kp.privHex);
 *   console.log(messages[0].body);
 */

import { createHash, randomBytes } from 'node:crypto';
import { secp256k1 } from '@noble/curves/secp256k1';
import { decryptContent, encryptContent } from '@stacks/encryption';

// ─── Constants ────────────────────────────────────────────────────────────────

export const DEFAULTS = {
  SERVER_URL:    process.env.MAILSLOT_SERVER_URL ?? 'http://127.0.0.1:8800',
  /** The reservoir contract IS the server's on-chain identity. Taps are opened to this address. */
  RESERVOIR:     process.env.MAILSLOT_RESERVOIR_CONTRACT_ID ?? 'SP3QFYVTMS0PRJT3K3GMDW9DGR33TDHENSDWVNQMR.sm-reservoir',
  SF_CONTRACT:   process.env.MAILSLOT_SF_CONTRACT_ID ?? 'SP3QFYVTMS0PRJT3K3GMDW9DGR33TDHENSDWVNQMR.sm-stackflow',
  TOKEN:         process.env.MAILSLOT_TOKEN_CONTRACT_ID ?? 'SP3QFYVTMS0PRJT3K3GMDW9DGR33TDHENSDWVNQMR.sm-test-token',
  CHAIN_ID:      parseInt(process.env.MAILSLOT_CHAIN_ID ?? '1', 10),
  MESSAGE_PRICE: 1000n,
} as const;

export const MAILBOX_POLICY = {
  SEND_CAPACITY_MULTIPLIER: 10n,
  DEFAULT_RECEIVE_CAPACITY_MULTIPLIER: 20n,
  LOW_RECEIVE_CAPACITY_MULTIPLIER: 5n,
} as const;

// ─── Types ────────────────────────────────────────────────────────────────────

export interface Keypair {
  privHex: string;
  pubHex: string;
  addr: string;
}

export interface PipeState {
  serverBalance: bigint;
  myBalance: bigint;
  nonce: bigint;
}

export interface InboxEntry {
  id: string;
  from: string;
  sentAt: number;
  amount: string;
  claimed: boolean;
}

export interface DecryptedMessage {
  id: string;
  from: string;
  sentAt: number;
  amount: string;
  subject?: string;
  body: string;
  secret: string;
}

export interface ServerStatus {
  ok: boolean;
  serverAddress?: string;
  signerAddress?: string;
  reservoirContract?: string;
  sfContract?: string;
  messagePriceSats?: string;
  minFeeSats?: string;
  network?: string;
  chainId?: number;
  supportedToken?: string | null;
  authAudience?: string;
  runtimeSettings?: {
    maxBorrowPerTap?: string;
    receiveCapacityMultiplier?: number;
  };
}

export interface PreparedLiquidityAction {
  reservoirContract: string;
  stackflowContract: string;
  chainId: number;
  token: string | null;
  functionName: 'add-funds' | 'borrow-liquidity';
  amount: string;
  fee?: string;
  myBalance: string;
  reservoirBalance: string;
  nonce: string;
  mySignature: string;
  reservoirSignature: string;
}

export interface ResolvedTapState {
  pipeState: PipeState;
  contractId: string;
  token: string | null;
  source: 'server' | 'on-chain';
}

export interface EncryptedMail {
  iv: string;
  ephemeralPK: string;
  cipherText: string;
  mac: string;
  wasString: boolean;
  cipherTextEncoding?: 'hex' | 'base64';
}

export interface MailPayload {
  v: 1;
  secret: string;   // 32 bytes hex HTLC preimage
  subject?: string;
  body: string;
}

// ─── c32 Address Helpers ──────────────────────────────────────────────────────

const C32 = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

function isContractPrincipal(value: string): boolean {
  return /^S[PT][0-9A-Z]{39}\.[a-zA-Z][a-zA-Z0-9-]{0,39}$/.test(value);
}

function c32encode(data: Buffer): string {
  let n = BigInt('0x' + data.toString('hex'));
  const chars: string[] = [];
  while (n > 0n) { chars.push(C32[Number(n % 32n)]); n /= 32n; }
  for (const b of data) { if (b === 0) chars.push('0'); else break; }
  return chars.reverse().join('');
}

/** Decode a c32-encoded string to a fixed-size byte array. */
function c32DecodeFixed(encoded: string, expectedBytes: number): Buffer {
  const result = Buffer.alloc(expectedBytes, 0);
  let carry = 0, carryBits = 0, byteIdx = expectedBytes - 1;
  for (let i = encoded.length - 1; i >= 0 && byteIdx >= 0; i--) {
    const val = C32.indexOf(encoded[i].toUpperCase());
    if (val < 0) throw new Error(`Invalid c32 char: ${encoded[i]}`);
    carry |= (val << carryBits);
    carryBits += 5;
    if (carryBits >= 8) { result[byteIdx--] = carry & 0xff; carry >>= 8; carryBits -= 8; }
  }
  return result;
}

function parseStxAddress(address: string): { version: number; hash160: Buffer } {
  const addr = address.includes('.') ? address.slice(0, address.indexOf('.')) : address;
  if (addr[0] !== 'S') throw new Error(`Invalid STX address: ${addr}`);
  const version = C32.indexOf(addr[1].toUpperCase());
  const decoded = c32DecodeFixed(addr.slice(2), 24);
  return { version, hash160: decoded.subarray(0, 20) };
}

function hash160ToStxAddress(hash160: Buffer, version: number): string {
  const payload = Buffer.concat([Buffer.from([version]), hash160]);
  const h1 = createHash('sha256').update(payload).digest();
  const checksum = createHash('sha256').update(h1).digest().subarray(0, 4);
  return 'S' + C32[version] + c32encode(Buffer.concat([hash160, checksum]));
}

/** Derive STX mainnet address from compressed secp256k1 pubkey (33 bytes hex). */
export function pubkeyToStxAddress(pubkeyHex: string): string {
  const pub = Buffer.from(pubkeyHex, 'hex');
  const sha = createHash('sha256').update(pub).digest();
  const h160 = createHash('ripemd160').update(sha).digest();
  const version = 22;
  const payload = Buffer.concat([Buffer.from([version]), h160]);
  const h1 = createHash('sha256').update(payload).digest();
  const checksum = createHash('sha256').update(h1).digest().subarray(0, 4);
  return 'S' + C32[version] + c32encode(Buffer.concat([h160, checksum]));
}

/** Create a new random keypair. Keep privHex secret. */
export function genKeypair(): Keypair {
  const priv = randomBytes(32);
  const pub = secp256k1.getPublicKey(priv, true);
  const privHex = Buffer.from(priv).toString('hex');
  const pubHex = Buffer.from(pub).toString('hex');
  return { privHex, pubHex, addr: pubkeyToStxAddress(pubHex) };
}

/** Derive keypair from an existing private key hex string. */
export function keypairFromPrivkey(privHex: string): Keypair {
  const pub = secp256k1.getPublicKey(Buffer.from(privHex, 'hex'), true);
  const pubHex = Buffer.from(pub).toString('hex');
  return { privHex, pubHex, addr: pubkeyToStxAddress(pubHex) };
}

// ─── Canonical pipe key ───────────────────────────────────────────────────────

/**
 * Compute the Clarity consensus-buff representation of a principal.
 * Standard:  0x05 <version> <hash160>                      (22 bytes)
 * Contract:  0x06 <version> <hash160> <name_len> <name>    (22 + 1 + n bytes)
 *
 * Since 0x05 < 0x06, a standard address is always "less than" a contract principal,
 * meaning in a Mailslot tap the agent (standard) is always principal-1 and the
 * reservoir (contract) is always principal-2.
 */
function toConsensusBuff(addr: string): Buffer {
  const dotIdx = addr.indexOf('.');
  if (dotIdx < 0) {
    const { version, hash160 } = parseStxAddress(addr);
    return Buffer.concat([Buffer.from([0x05, version]), hash160]);
  } else {
    const { version, hash160 } = parseStxAddress(addr.slice(0, dotIdx));
    const nameBytes = Buffer.from(addr.slice(dotIdx + 1), 'ascii');
    return Buffer.concat([Buffer.from([0x06, version]), hash160, Buffer.from([nameBytes.length]), nameBytes]);
  }
}

function canonicalPipeKey(token: string | null, addr1: string, addr2: string) {
  const p1 = toConsensusBuff(addr1);
  const p2 = toConsensusBuff(addr2);
  return Buffer.compare(p1, p2) < 0
    ? { token, 'principal-1': addr1, 'principal-2': addr2 }
    : { token, 'principal-1': addr2, 'principal-2': addr1 };
}

// ─── Clarity serialization (for SIP-018) ──────────────────────────────────────
// Matches the consensus-buff encoding used by the StackFlow contract.

type ClarityValue =
  | { type: 'uint';         value: bigint | string | number }
  | { type: 'principal';    value: string }
  | { type: 'buff';         value: string }  // hex, optional 0x prefix
  | { type: 'none' }
  | { type: 'some';         value: ClarityValue }
  | { type: 'string-ascii'; value: string }
  | { type: 'tuple';        fields: Record<string, ClarityValue> };

function u32be(n: number): Buffer {
  const b = Buffer.alloc(4); b.writeUInt32BE(n, 0); return b;
}

function u128be(n: bigint): Buffer {
  const b = Buffer.alloc(16, 0);
  let v = BigInt.asUintN(128, n);
  for (let i = 15; i >= 0; i--) { b[i] = Number(v & 0xffn); v >>= 8n; }
  return b;
}

function serializePrincipal(value: string): Buffer {
  const dotIdx = value.indexOf('.');
  if (dotIdx < 0) {
    const { version, hash160 } = parseStxAddress(value);
    return Buffer.concat([Buffer.from([0x05, version]), hash160]);
  }
  const { version, hash160 } = parseStxAddress(value.slice(0, dotIdx));
  const nameBytes = Buffer.from(value.slice(dotIdx + 1), 'ascii');
  return Buffer.concat([Buffer.from([0x06, version]), hash160, Buffer.from([nameBytes.length]), nameBytes]);
}

function serializeClarityValue(cv: ClarityValue): Buffer {
  switch (cv.type) {
    case 'uint': {
      const n = typeof cv.value === 'bigint' ? cv.value : BigInt(String(cv.value));
      return Buffer.concat([Buffer.from([0x01]), u128be(n)]);
    }
    case 'principal': return serializePrincipal(cv.value);
    case 'buff': {
      const bytes = Buffer.from((cv.value as string).replace(/^0x/, ''), 'hex');
      return Buffer.concat([Buffer.from([0x02]), u32be(bytes.length), bytes]);
    }
    case 'none':  return Buffer.from([0x09]);
    case 'some':  return Buffer.concat([Buffer.from([0x0a]), serializeClarityValue(cv.value)]);
    case 'string-ascii': {
      const bytes = Buffer.from(cv.value as string, 'ascii');
      return Buffer.concat([Buffer.from([0x0d]), u32be(bytes.length), bytes]);
    }
    case 'tuple': {
      const names = Object.keys(cv.fields).sort();
      const parts: Buffer[] = [Buffer.from([0x0c]), u32be(names.length)];
      for (const name of names) {
        const nb = Buffer.from(name, 'utf-8');
        parts.push(Buffer.from([nb.length]), nb, serializeClarityValue(cv.fields[name]));
      }
      return Buffer.concat(parts);
    }
  }
}

type DecodedClarityValue =
  | { type: 'uint'; value: bigint }
  | { type: 'principal'; value: string }
  | { type: 'none' }
  | { type: 'some'; value: DecodedClarityValue }
  | { type: 'tuple'; fields: Record<string, DecodedClarityValue> };

function readU32be(buf: Buffer, offset: number): number {
  return buf.readUInt32BE(offset);
}

function readU128be(buf: Buffer, offset: number): bigint {
  let value = 0n;
  for (let i = offset; i < offset + 16; i++) {
    value = (value << 8n) | BigInt(buf[i]);
  }
  return value;
}

function decodeClarityValue(
  buf: Buffer,
  offset = 0,
): { value: DecodedClarityValue; nextOffset: number } {
  const tag = buf[offset];
  let cursor = offset + 1;

  switch (tag) {
    case 0x01:
      return {
        value: { type: 'uint', value: readU128be(buf, cursor) },
        nextOffset: cursor + 16,
      };
    case 0x05: {
      const version = buf[cursor];
      const hash160 = buf.subarray(cursor + 1, cursor + 21);
      return {
        value: { type: 'principal', value: hash160ToStxAddress(hash160, version) },
        nextOffset: cursor + 21,
      };
    }
    case 0x06: {
      const version = buf[cursor];
      const hash160 = buf.subarray(cursor + 1, cursor + 21);
      const nameLen = buf[cursor + 21];
      const name = buf.subarray(cursor + 22, cursor + 22 + nameLen).toString('ascii');
      return {
        value: { type: 'principal', value: `${hash160ToStxAddress(hash160, version)}.${name}` },
        nextOffset: cursor + 22 + nameLen,
      };
    }
    case 0x09:
      return { value: { type: 'none' }, nextOffset: cursor };
    case 0x0a: {
      const nested = decodeClarityValue(buf, cursor);
      return { value: { type: 'some', value: nested.value }, nextOffset: nested.nextOffset };
    }
    case 0x0c: {
      const entries = readU32be(buf, cursor);
      cursor += 4;
      const fields: Record<string, DecodedClarityValue> = {};
      for (let i = 0; i < entries; i++) {
        const nameLen = buf[cursor];
        cursor += 1;
        const name = buf.subarray(cursor, cursor + nameLen).toString('ascii');
        cursor += nameLen;
        const decoded = decodeClarityValue(buf, cursor);
        fields[name] = decoded.value;
        cursor = decoded.nextOffset;
      }
      return { value: { type: 'tuple', fields }, nextOffset: cursor };
    }
    default:
      throw new Error(`Unsupported Clarity type tag: 0x${tag.toString(16)}`);
  }
}

function decodeClarityHex(hex: string): DecodedClarityValue {
  const bytes = Buffer.from(hex.replace(/^0x/, ''), 'hex');
  const decoded = decodeClarityValue(bytes, 0);
  return decoded.value;
}

function parseOptionalPrincipalHex(hex: string): string | null {
  const decoded = decodeClarityHex(hex);
  if (decoded.type === 'none') return null;
  if (decoded.type === 'some' && decoded.value.type === 'principal') {
    return decoded.value.value;
  }
  throw new Error('expected optional principal result');
}

function parsePipeResultHex(hex: string): { balance1: bigint; balance2: bigint; nonce: bigint } | null {
  const decoded = decodeClarityHex(hex);
  const tuple = decoded.type === 'some' ? decoded.value : decoded;
  if (tuple.type === 'none') return null;
  if (tuple.type !== 'tuple') return null;
  const balance1 = tuple.fields['balance-1'];
  const balance2 = tuple.fields['balance-2'];
  const nonce = tuple.fields.nonce;
  if (balance1?.type !== 'uint' || balance2?.type !== 'uint' || nonce?.type !== 'uint') {
    return null;
  }
  return {
    balance1: balance1.value,
    balance2: balance2.value,
    nonce: nonce.value,
  };
}

// ─── SIP-018 signing ──────────────────────────────────────────────────────────

const SIP018_PREFIX = Buffer.from('534950303138', 'hex'); // "SIP018"

function sha256(data: Buffer | string): Buffer {
  return createHash('sha256').update(data as Buffer).digest();
}

function buildSip018Domain(contractId: string, chainId: number): ClarityValue {
  return {
    type: 'tuple',
    fields: {
      'chain-id': { type: 'uint', value: BigInt(chainId) },
      name:       { type: 'string-ascii', value: contractId },
      version:    { type: 'string-ascii', value: '0.6.0' },
    },
  };
}

/** Build the SIP-018 TypedMessage for a StackFlow transfer state update. */
function buildTransferMessage(state: {
  pipeKey: { token: string | null; 'principal-1': string; 'principal-2': string };
  forPrincipal: string;
  myBalance: string;
  theirBalance: string;
  nonce: string;
  action: string;
  actor: string;
  hashedSecret: string | null;
  validAfter: string | null;
}): Record<string, ClarityValue> {
  const isP1 = state.pipeKey['principal-1'] === state.forPrincipal;
  const balance1 = isP1 ? state.myBalance : state.theirBalance;
  const balance2 = isP1 ? state.theirBalance : state.myBalance;
  return {
    'principal-1': { type: 'principal', value: state.pipeKey['principal-1'] },
    'principal-2': { type: 'principal', value: state.pipeKey['principal-2'] },
    token: state.pipeKey.token == null
      ? { type: 'none' }
      : { type: 'some', value: { type: 'principal', value: state.pipeKey.token } },
    'balance-1': { type: 'uint', value: balance1 },
    'balance-2': { type: 'uint', value: balance2 },
    nonce:       { type: 'uint', value: state.nonce },
    action:      { type: 'uint', value: state.action },
    actor:       { type: 'principal', value: state.actor },
    'hashed-secret': state.hashedSecret == null
      ? { type: 'none' }
      : { type: 'some', value: { type: 'buff', value: state.hashedSecret } },
    'valid-after': state.validAfter == null
      ? { type: 'none' }
      : { type: 'some', value: { type: 'uint', value: state.validAfter } },
  };
}

function computeSip018Hash(
  contractId: string,
  message: Record<string, ClarityValue>,
  chainId: number,
): Buffer {
  const domainHash = sha256(serializeClarityValue(buildSip018Domain(contractId, chainId)));
  const messageHash = sha256(serializeClarityValue({ type: 'tuple', fields: message }));
  return sha256(Buffer.concat([SIP018_PREFIX, domainHash, messageHash]));
}

/** Sign a SIP-018 StackFlow state update. Returns 65-byte hex: "0x" + recovery + r + s. */
async function sip018Sign(
  contractId: string,
  message: Record<string, ClarityValue>,
  privkeyHex: string,
  chainId: number,
): Promise<string> {
  const hash = computeSip018Hash(contractId, message, chainId);
  const sig = secp256k1.sign(hash, Buffer.from(privkeyHex, 'hex'), { lowS: true });
  const full = Buffer.concat([Buffer.from([sig.recovery ?? 0]), Buffer.from(sig.toCompactRawBytes())]);
  return '0x' + full.toString('hex');
}

// ─── ECIES Encryption ─────────────────────────────────────────────────────────

/** Encrypt a MailPayload for a recipient's compressed secp256k1 pubkey. */
export async function encryptMail(payload: MailPayload, recipientPubkeyHex: string): Promise<EncryptedMail> {
  const content = await encryptContent(JSON.stringify(payload), {
    publicKey: recipientPubkeyHex.replace(/^0x/i, ''),
  });
  return JSON.parse(content) as EncryptedMail;
}

/** Decrypt an EncryptedMail using the recipient's secp256k1 private key (32 bytes hex). */
export async function decryptMail(encrypted: EncryptedMail, privkeyHex: string): Promise<MailPayload> {
  const plaintext = await decryptContent(JSON.stringify(encrypted), {
    privateKey: privkeyHex.replace(/^0x/i, ''),
  });
  return JSON.parse(typeof plaintext === 'string' ? plaintext : Buffer.from(plaintext).toString('utf-8')) as MailPayload;
}

/** Compute the HTLC hash: SHA-256 of the secret bytes. */
export function hashSecret(secretHex: string): string {
  return createHash('sha256').update(Buffer.from(secretHex, 'hex')).digest('hex');
}

// ─── Auth header ──────────────────────────────────────────────────────────────

function buildAuthHeader(
  privHex: string,
  pubHex: string,
  addr: string,
  action: 'get-inbox' | 'get-message' | 'claim-message',
  audience: string,
  messageId?: string,
): string {
  const payload = { action, address: addr, timestamp: Date.now(), audience, ...(messageId ? { messageId } : {}) };
  const hash = sha256(Buffer.from(JSON.stringify(payload)));
  const sig = secp256k1.sign(hash, Buffer.from(privHex, 'hex'), { lowS: true });
  const sigHex = Buffer.from(sig.toCompactRawBytes()).toString('hex');
  return Buffer.from(JSON.stringify({ pubkey: pubHex, payload, signature: sigHex })).toString('base64');
}

// ─── HTTP helpers ─────────────────────────────────────────────────────────────

async function http(
  method: string,
  url: string,
  body?: unknown,
  headers: Record<string, string> = {},
): Promise<{ status: number; ok: boolean; data: unknown }> {
  const opts: RequestInit = { method, headers: { ...headers } };
  if (body !== undefined) {
    (opts.headers as Record<string, string>)['content-type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  const r = await fetch(url, opts);
  const text = await r.text();
  let data: unknown;
  try { data = JSON.parse(text); } catch { data = text; }
  return { status: r.status, ok: r.ok, data };
}

export async function getServerStatus(
  serverUrl: string = DEFAULTS.SERVER_URL,
): Promise<ServerStatus> {
  const r = await http('GET', `${serverUrl}/status`);
  if (!r.ok) {
    throw new Error(`getServerStatus failed: ${r.status} ${JSON.stringify(r.data)}`);
  }
  return r.data as ServerStatus;
}

function resolveReservoirContract(status: ServerStatus): string {
  const reservoir = typeof status.reservoirContract === 'string' ? status.reservoirContract.trim() : '';
  if (isContractPrincipal(reservoir)) return reservoir;
  const serverAddress = typeof status.serverAddress === 'string' ? status.serverAddress.trim() : '';
  if (isContractPrincipal(serverAddress)) return serverAddress;
  return DEFAULTS.RESERVOIR;
}

function resolveSfContract(status: ServerStatus, fallback?: string): string {
  return status.sfContract?.trim() || fallback || DEFAULTS.SF_CONTRACT;
}

function resolveChainId(status: ServerStatus, fallback?: number): number {
  return typeof status.chainId === 'number' ? status.chainId : (fallback ?? DEFAULTS.CHAIN_ID);
}

function resolveMessagePrice(status: ServerStatus, fallback?: bigint): bigint {
  return status.messagePriceSats ? BigInt(status.messagePriceSats) : (fallback ?? DEFAULTS.MESSAGE_PRICE);
}

export function deriveMailboxCapacityPolicy(status: ServerStatus): {
  messagePrice: bigint;
  sendCapacityTarget: bigint;
  receiveCapacityTarget: bigint;
  lowReceiveThreshold: bigint;
} {
  const messagePrice = resolveMessagePrice(status);
  return {
    messagePrice,
    sendCapacityTarget: messagePrice * MAILBOX_POLICY.SEND_CAPACITY_MULTIPLIER,
    receiveCapacityTarget: messagePrice * BigInt(status.runtimeSettings?.receiveCapacityMultiplier ?? MAILBOX_POLICY.DEFAULT_RECEIVE_CAPACITY_MULTIPLIER),
    lowReceiveThreshold: messagePrice * MAILBOX_POLICY.LOW_RECEIVE_CAPACITY_MULTIPLIER,
  };
}

function resolveAuthAudience(status: ServerStatus): string {
  const audience = typeof status.authAudience === 'string' ? status.authAudience.trim() : '';
  if (audience) return audience;
  const reservoir = typeof status.reservoirContract === 'string' ? status.reservoirContract.trim() : '';
  if (reservoir) return reservoir;
  const serverAddress = typeof status.serverAddress === 'string' ? status.serverAddress.trim() : '';
  if (serverAddress) return serverAddress;
  return 'Mailslot';
}

function hiroApiForChain(chainId: number): string {
  return chainId === 1 ? 'https://api.mainnet.hiro.so' : 'https://api.testnet.hiro.so';
}

async function fetchSupportedToken(
  reservoirContract: string,
  chainId: number,
): Promise<string | null> {
  const [contractAddr, contractName] = reservoirContract.split('.');
  const r = await http(
    'GET',
    `${hiroApiForChain(chainId)}/v2/data_var/${contractAddr}/${contractName}/supported-token`,
  );
  if (!r.ok) {
    throw new Error(`fetchSupportedToken failed: ${r.status} ${JSON.stringify(r.data)}`);
  }
  const data = r.data as Record<string, unknown>;
  const hex =
    (typeof data.data === 'string' ? data.data : null)
    ?? (typeof data.result === 'string' ? data.result : null)
    ?? (typeof data.value === 'string' ? data.value : null)
    ?? (typeof data.hex === 'string' ? data.hex : null);
  if (!hex?.startsWith('0x')) {
    throw new Error('fetchSupportedToken returned an unexpected response');
  }
  return parseOptionalPrincipalHex(hex);
}

async function resolveSupportedToken(
  status: ServerStatus,
  reservoirContract: string,
  chainId: number,
  explicitToken?: string | null,
): Promise<string | null> {
  if (explicitToken !== undefined) return explicitToken;
  if (status.supportedToken !== undefined) return status.supportedToken ?? null;
  return fetchSupportedToken(reservoirContract, chainId);
}

async function fetchTrackedTapState(
  privkeyHex: string,
  serverUrl: string,
): Promise<ResolvedTapState | null> {
  const kp = keypairFromPrivkey(privkeyHex);
  const status = await getServerStatus(serverUrl);
  const auth = buildAuthHeader(kp.privHex, kp.pubHex, kp.addr, 'get-inbox', resolveAuthAudience(status));
  const r = await http('GET', `${serverUrl}/tap/state`, undefined, { 'x-mailslot-auth': auth });
  if (r.status === 404) return null;
  if (!r.ok) {
    throw new Error(`fetchTrackedTapState failed: ${r.status} ${JSON.stringify(r.data)}`);
  }

  const data = r.data as {
    tap?: {
      contractId?: string;
      token?: string | null;
      serverBalance?: string;
      myBalance?: string;
      nonce?: string;
    } | null;
  };
  if (!data.tap) return null;

  return {
    pipeState: {
      serverBalance: BigInt(String(data.tap.serverBalance ?? '0')),
      myBalance: BigInt(String(data.tap.myBalance ?? '0')),
      nonce: BigInt(String(data.tap.nonce ?? '0')),
    },
    contractId: typeof data.tap.contractId === 'string' && data.tap.contractId
      ? data.tap.contractId
      : DEFAULTS.SF_CONTRACT,
    token: typeof data.tap.token === 'string' ? data.tap.token : null,
    source: 'server',
  };
}

async function queryOnChainTapState(
  address: string,
  reservoirContract: string,
  sfContract: string,
  token: string | null,
  chainId: number,
): Promise<ResolvedTapState | null> {
  const pipeKey = canonicalPipeKey(token, address, reservoirContract);
  const [contractAddr, contractName] = sfContract.split('.');
  const endpoint = `${hiroApiForChain(chainId)}/v2/contracts/call-read/${contractAddr}/${contractName}/get-pipe`;

  const tokenArg = '0x' + serializeClarityValue(
    token == null
      ? { type: 'none' }
      : { type: 'some', value: { type: 'principal', value: token } },
  ).toString('hex');
  const withArg = '0x' + serializeClarityValue({ type: 'principal', value: reservoirContract }).toString('hex');
  const legacyPipeKeyArg = '0x' + serializeClarityValue({
    type: 'tuple',
    fields: {
      'principal-1': { type: 'principal', value: pipeKey['principal-1'] },
      'principal-2': { type: 'principal', value: pipeKey['principal-2'] },
      token: token == null
        ? { type: 'none' }
        : { type: 'some', value: { type: 'principal', value: token } },
    },
  }).toString('hex');

  let r = await http('POST', endpoint, { sender: address, arguments: [tokenArg, withArg] });
  let payload = r.data as { okay?: boolean; result?: string };
  if (!payload.okay) {
    r = await http('POST', endpoint, { sender: address, arguments: [legacyPipeKeyArg] });
    payload = r.data as { okay?: boolean; result?: string };
  }

  if (!r.ok || !payload.okay || typeof payload.result !== 'string') return null;
  const parsed = parsePipeResultHex(payload.result);
  if (!parsed) return null;

  const isPrincipal1 = pipeKey['principal-1'] === address;
  return {
    pipeState: {
      serverBalance: isPrincipal1 ? parsed.balance2 : parsed.balance1,
      myBalance: isPrincipal1 ? parsed.balance1 : parsed.balance2,
      nonce: parsed.nonce,
    },
    contractId: sfContract,
    token,
    source: 'on-chain',
  };
}

export async function getTapState(
  privkeyHex: string,
  serverUrl: string = DEFAULTS.SERVER_URL,
): Promise<ResolvedTapState | null> {
  const status = await getServerStatus(serverUrl);
  const reservoirContract = resolveReservoirContract(status);
  const chainId = resolveChainId(status);
  const tracked = await fetchTrackedTapState(privkeyHex, serverUrl);
  if (tracked) return tracked;

  const kp = keypairFromPrivkey(privkeyHex);
  const sfContract = resolveSfContract(status);
  const token = await resolveSupportedToken(status, reservoirContract, chainId);
  return queryOnChainTapState(kp.addr, reservoirContract, sfContract, token, chainId);
}

export async function prepareAddFunds(
  privkeyHex: string,
  amount: bigint,
  serverUrl: string = DEFAULTS.SERVER_URL,
): Promise<PreparedLiquidityAction> {
  if (amount <= 0n) throw new Error('amount must be > 0');
  const kp = keypairFromPrivkey(privkeyHex);
  const status = await getServerStatus(serverUrl);
  const tap = await getTapState(privkeyHex, serverUrl);
  if (!tap) throw new Error('No tap found. Open a mailbox before adding funds.');

  const nextMyBalance = tap.pipeState.myBalance + amount;
  const nextReservoirBalance = tap.pipeState.serverBalance;
  const nextNonce = tap.pipeState.nonce + 1n;
  const pipeKey = canonicalPipeKey(tap.token, kp.addr, resolveReservoirContract(status));
  const message = buildTransferMessage({
    pipeKey,
    forPrincipal: kp.addr,
    myBalance: nextMyBalance.toString(),
    theirBalance: nextReservoirBalance.toString(),
    nonce: nextNonce.toString(),
    action: '2',
    actor: kp.addr,
    hashedSecret: null,
    validAfter: null,
  });
  const mySignature = await sip018Sign(tap.contractId, message, privkeyHex, resolveChainId(status));

  const r = await http(
    'POST',
    `${serverUrl}/tap/add-funds-params`,
    {
      user: kp.addr,
      token: tap.token,
      amount: amount.toString(),
      myBalance: nextMyBalance.toString(),
      reservoirBalance: nextReservoirBalance.toString(),
      nonce: nextNonce.toString(),
      mySignature,
    },
  );
  if (!r.ok) throw new Error(`prepareAddFunds failed: ${r.status} ${JSON.stringify(r.data)}`);
  const data = r.data as { reservoirSignature?: string };
  if (!data.reservoirSignature) throw new Error('prepareAddFunds: server returned no reservoir signature');
  return {
    reservoirContract: resolveReservoirContract(status),
    stackflowContract: tap.contractId,
    chainId: resolveChainId(status),
    token: tap.token,
    functionName: 'add-funds',
    amount: amount.toString(),
    myBalance: nextMyBalance.toString(),
    reservoirBalance: nextReservoirBalance.toString(),
    nonce: nextNonce.toString(),
    mySignature,
    reservoirSignature: data.reservoirSignature,
  };
}

export async function prepareBorrowMoreLiquidity(
  privkeyHex: string,
  amount: bigint,
  serverUrl: string = DEFAULTS.SERVER_URL,
): Promise<PreparedLiquidityAction> {
  if (amount <= 0n) throw new Error('amount must be > 0');
  const kp = keypairFromPrivkey(privkeyHex);
  const status = await getServerStatus(serverUrl);
  const tap = await getTapState(privkeyHex, serverUrl);
  if (!tap) throw new Error('No tap found. Open a mailbox before borrowing.');

  const nextMyBalance = tap.pipeState.myBalance;
  const nextReservoirBalance = tap.pipeState.serverBalance + amount;
  const nextNonce = tap.pipeState.nonce + 1n;
  const reservoir = resolveReservoirContract(status);
  const pipeKey = canonicalPipeKey(tap.token, kp.addr, reservoir);
  const message = buildTransferMessage({
    pipeKey,
    forPrincipal: kp.addr,
    myBalance: nextMyBalance.toString(),
    theirBalance: nextReservoirBalance.toString(),
    nonce: nextNonce.toString(),
    action: '2',
    actor: reservoir,
    hashedSecret: null,
    validAfter: null,
  });
  const mySignature = await sip018Sign(tap.contractId, message, privkeyHex, resolveChainId(status));

  const r = await http(
    'POST',
    `${serverUrl}/tap/borrow-more-params`,
    {
      borrower: kp.addr,
      token: tap.token,
      borrowAmount: amount.toString(),
      myBalance: nextMyBalance.toString(),
      reservoirBalance: nextReservoirBalance.toString(),
      borrowNonce: nextNonce.toString(),
      mySignature,
    },
  );
  if (!r.ok) throw new Error(`prepareBorrowMoreLiquidity failed: ${r.status} ${JSON.stringify(r.data)}`);
  const data = r.data as { reservoirSignature?: string; borrowFee?: string };
  if (!data.reservoirSignature || !data.borrowFee) {
    throw new Error('prepareBorrowMoreLiquidity: server returned incomplete borrow params');
  }
  return {
    reservoirContract: reservoir,
    stackflowContract: tap.contractId,
    chainId: resolveChainId(status),
    token: tap.token,
    functionName: 'borrow-liquidity',
    amount: amount.toString(),
    fee: data.borrowFee,
    myBalance: nextMyBalance.toString(),
    reservoirBalance: nextReservoirBalance.toString(),
    nonce: nextNonce.toString(),
    mySignature,
    reservoirSignature: data.reservoirSignature,
  };
}

export async function syncTapState(
  privkeyHex: string,
  action: PreparedLiquidityAction,
  serverUrl: string = DEFAULTS.SERVER_URL,
): Promise<void> {
  const kp = keypairFromPrivkey(privkeyHex);
  const status = await getServerStatus(serverUrl);
  const auth = buildAuthHeader(kp.privHex, kp.pubHex, kp.addr, 'get-inbox', resolveAuthAudience(status));
  const actor = action.functionName === 'add-funds' ? kp.addr : action.reservoirContract;
  const r = await http(
    'POST',
    `${serverUrl}/tap/sync-state`,
    {
      user: kp.addr,
      token: action.token,
      myBalance: action.myBalance,
      reservoirBalance: action.reservoirBalance,
      nonce: action.nonce,
      action: '2',
      actor,
      mySignature: action.mySignature,
      reservoirSignature: action.reservoirSignature,
    },
    { 'x-mailslot-auth': auth },
  );
  if (!r.ok) throw new Error(`syncTapState failed: ${r.status} ${JSON.stringify(r.data)}`);
}

// ─── Public Client API ────────────────────────────────────────────────────────

/**
 * Register your mailbox with the server (one-time).
 *
 * Authenticates with the server, which stores your pubkey so senders can
 * look you up via GET /payment-info/:addr.
 *
 * Must be called before you can receive messages.
 */
export async function registerMailbox(
  privkeyHex: string,
  serverUrl: string = DEFAULTS.SERVER_URL,
): Promise<{ address: string }> {
  const kp = keypairFromPrivkey(privkeyHex);
  const status = await getServerStatus(serverUrl);
  const authHeader = buildAuthHeader(kp.privHex, kp.pubHex, kp.addr, 'get-inbox', resolveAuthAudience(status));
  const r = await http('GET', `${serverUrl}/inbox`, undefined, { 'x-mailslot-auth': authHeader });
  if (r.status !== 200 && r.status !== 404) {
    throw new Error(`registerMailbox failed: ${r.status} ${JSON.stringify(r.data)}`);
  }
  console.log(`Mailbox registered: ${kp.addr}`);
  return { address: kp.addr };
}

/**
 * Get payment info for a recipient address.
 *
 * Returns their public key and the message price.
 * The recipient must have called registerMailbox() first.
 */
export async function getPaymentInfo(
  recipientAddr: string,
  serverUrl: string = DEFAULTS.SERVER_URL,
): Promise<{ recipientPublicKey: string; amount: string; serverAddress: string }> {
  const r = await http('GET', `${serverUrl}/payment-info/${recipientAddr}`);
  if (!r.ok) throw new Error(`getPaymentInfo failed: ${r.status} ${JSON.stringify(r.data)}`);
  return r.data as { recipientPublicKey: string; amount: string; serverAddress: string };
}

/**
 * Send a message to a recipient.
 *
 * Builds a SIP-018 payment proof and sends the ECIES-encrypted message.
 *
 * @param to           Recipient's STX address
 * @param subject      Message subject line
 * @param body         Message body text
 * @param privkeyHex   Your secp256k1 private key (32 bytes hex)
 * @param pipeState    Current state of your payment channel to the server.
 *                     Optional: if omitted, the client first asks the server
 *                     for tracked state and then falls back to an on-chain read.
 *                     { serverBalance, myBalance, nonce }
 *                     For a fresh channel: { serverBalance: 0n, myBalance: <funded_amount>, nonce: 0n }
 * @param serverUrl    Mailbox server URL
 *
 * @returns messageId and the updated pipeState after the payment
 */
export async function sendMessage({
  to,
  subject,
  body,
  privkeyHex,
  pipeState,
  serverUrl = DEFAULTS.SERVER_URL,
  sfContract,
  token,
  chainId,
  messagePrice,
}: {
  to: string;
  subject: string;
  body: string;
  privkeyHex: string;
  pipeState?: PipeState;
  serverUrl?: string;
  sfContract?: string;
  token?: string | null;
  chainId?: number;
  messagePrice?: bigint;
}): Promise<{ messageId: string; newPipeState: PipeState }> {
  const kp = keypairFromPrivkey(privkeyHex);
  const status = await getServerStatus(serverUrl);
  const resolvedReservoir = resolveReservoirContract(status);
  const resolvedSfContract = resolveSfContract(status, sfContract);
  const resolvedChainId = resolveChainId(status, chainId);
  const resolvedMessagePrice = resolveMessagePrice(status, messagePrice);
  const resolvedToken = await resolveSupportedToken(status, resolvedReservoir, resolvedChainId, token);

  const activeTap = pipeState == null
    ? await getTapState(privkeyHex, serverUrl)
    : {
        pipeState,
        contractId: resolvedSfContract,
        token: resolvedToken,
        source: 'server' as const,
      };
  if (!activeTap) {
    throw new Error('No tap found for this sender. Open and fund a mailbox tap before sending.');
  }
  const activeContractId = activeTap.contractId || resolvedSfContract;
  if (activeTap.pipeState.myBalance < resolvedMessagePrice) {
    throw new Error(
      `Insufficient channel balance: have ${activeTap.pipeState.myBalance}, need ${resolvedMessagePrice}`,
    );
  }

  // 1. Look up recipient's public key
  const payInfo = await getPaymentInfo(to, serverUrl);
  const serverAddr = payInfo.serverAddress || resolvedReservoir;

  // 2. Generate HTLC secret and encrypt message body
  const secretHex = randomBytes(32).toString('hex');
  const hashedSecretHex = hashSecret(secretHex);
  const encPayload = await encryptMail({ v: 1, secret: secretHex, subject, body }, payInfo.recipientPublicKey);

  // 3. Compute new channel balances
  const currentPipeState = activeTap.pipeState;
  const newServerBalance = currentPipeState.serverBalance + resolvedMessagePrice;
  const newMyBalance     = currentPipeState.myBalance - resolvedMessagePrice;
  const nextNonce        = currentPipeState.nonce + 1n;
  const pipeKey          = canonicalPipeKey(activeTap.token, kp.addr, serverAddr);

  // 4. Build and sign the state update (from sender's perspective)
  const state = {
    pipeKey,
    forPrincipal: kp.addr,
    myBalance: newMyBalance.toString(),
    theirBalance: newServerBalance.toString(),
    nonce: nextNonce.toString(),
    action: '1',
    actor: kp.addr,
    hashedSecret: hashedSecretHex,
    validAfter: null,
  };
  const message = buildTransferMessage(state);
  const sig = await sip018Sign(activeContractId, message, privkeyHex, resolvedChainId);

  // 5. Encode payment proof (from server's perspective)
  const proof = {
    contractId: activeContractId,
    pipeKey,
    forPrincipal: serverAddr,
    withPrincipal: kp.addr,
    myBalance: newServerBalance.toString(),
    theirBalance: newMyBalance.toString(),
    nonce: nextNonce.toString(),
    action: '1',
    actor: kp.addr,
    hashedSecret: hashedSecretHex,
    theirSignature: sig,
    validAfter: null,
  };
  const proofHeader = Buffer.from(JSON.stringify(proof)).toString('base64url');

  // 6. Send
  const r = await http(
    'POST',
    `${serverUrl}/messages/${to}`,
    { from: kp.addr, encryptedPayload: encPayload },
    { 'x-mailslot-payment': proofHeader },
  );
  if (!r.ok) throw new Error(`sendMessage failed: ${r.status} ${JSON.stringify(r.data)}`);

  return {
    messageId: (r.data as { messageId: string }).messageId,
    newPipeState: { serverBalance: newServerBalance, myBalance: newMyBalance, nonce: nextNonce },
  };
}

/**
 * Get your inbox (message headers, no content).
 *
 * @param privkeyHex      Your private key (32 bytes hex)
 * @param serverUrl       Mailbox server URL
 * @param includeClaimed  Include already-claimed messages (default: false)
 */
export async function getInbox(
  privkeyHex: string,
  serverUrl: string = DEFAULTS.SERVER_URL,
  includeClaimed = false,
): Promise<InboxEntry[]> {
  const kp = keypairFromPrivkey(privkeyHex);
  const status = await getServerStatus(serverUrl);
  const auth = buildAuthHeader(kp.privHex, kp.pubHex, kp.addr, 'get-inbox', resolveAuthAudience(status));
  const url = `${serverUrl}/inbox${includeClaimed ? '?claimed=true' : ''}`;
  const r = await http('GET', url, undefined, { 'x-mailslot-auth': auth });
  if (!r.ok) throw new Error(`getInbox failed: ${r.status} ${JSON.stringify(r.data)}`);
  return ((r.data as { messages: InboxEntry[] }).messages) ?? [];
}

/**
 * Preview a message: fetch the encrypted envelope without decrypting.
 * The encrypted payload contains subject, body, AND the HTLC secret.
 */
export async function previewMessage(
  messageId: string,
  privkeyHex: string,
  serverUrl: string = DEFAULTS.SERVER_URL,
): Promise<{ from: string; sentAt: number; amount: string; encryptedPayload: EncryptedMail; hashedSecret: string }> {
  const kp = keypairFromPrivkey(privkeyHex);
  const status = await getServerStatus(serverUrl);
  const auth = buildAuthHeader(kp.privHex, kp.pubHex, kp.addr, 'get-message', resolveAuthAudience(status), messageId);
  const r = await http('GET', `${serverUrl}/inbox/${messageId}/preview`, undefined, { 'x-mailslot-auth': auth });
  if (!r.ok) throw new Error(`previewMessage failed: ${r.status} ${JSON.stringify(r.data)}`);
  return r.data as Awaited<ReturnType<typeof previewMessage>>;
}

/**
 * Fetch an already-claimed message and decrypt it locally.
 *
 * @param messageId   Message ID to fetch
 * @param privkeyHex  Your private key (used for auth and decryption)
 * @param serverUrl   Mailbox server URL
 */
export async function getClaimedMessage(
  messageId: string,
  privkeyHex: string,
  serverUrl: string = DEFAULTS.SERVER_URL,
): Promise<DecryptedMessage> {
  const kp = keypairFromPrivkey(privkeyHex);
  const status = await getServerStatus(serverUrl);
  const auth = buildAuthHeader(kp.privHex, kp.pubHex, kp.addr, 'get-message', resolveAuthAudience(status), messageId);
  const r = await http('GET', `${serverUrl}/inbox/${messageId}`, undefined, { 'x-mailslot-auth': auth });
  if (!r.ok) throw new Error(`getClaimedMessage failed: ${r.status} ${JSON.stringify(r.data)}`);

  const payload = r.data as {
    message: {
      id: string;
      from: string;
      sentAt: number;
      amount: string;
      encryptedPayload: EncryptedMail;
    };
  };
  const message = payload.message;
  const decrypted = await decryptMail(message.encryptedPayload, kp.privHex);
  return {
    id: message.id,
    from: message.from,
    sentAt: message.sentAt,
    amount: message.amount,
    subject: decrypted.subject,
    body: decrypted.body,
    secret: decrypted.secret,
  };
}

/**
 * Claim a message by revealing the HTLC preimage.
 *
 * This decrypts the message payload (getting the secret), verifies the HTLC
 * hash matches, and claims it from the server to unlock your payment.
 *
 * After claiming, the server forwards payment to you via the outgoing channel.
 *
 * @param messageId   Message ID to claim
 * @param privkeyHex  Your private key (used for auth and decryption)
 * @param serverUrl   Mailbox server URL
 */
export async function claimMessage(
  messageId: string,
  privkeyHex: string,
  serverUrl: string = DEFAULTS.SERVER_URL,
): Promise<DecryptedMessage> {
  const kp = keypairFromPrivkey(privkeyHex);

  // Get encrypted payload
  const preview = await previewMessage(messageId, privkeyHex, serverUrl);

  // Decrypt to get the HTLC secret + message content
  const decrypted = await decryptMail(preview.encryptedPayload, kp.privHex);

  // Verify the secret matches the payment commitment
  const computedHash = hashSecret(decrypted.secret);
  const expectedHash = preview.hashedSecret.startsWith('0x')
    ? preview.hashedSecret.slice(2)
    : preview.hashedSecret;
  if (computedHash !== expectedHash) {
    throw new Error('Secret hash mismatch — message may be corrupted');
  }

  // Reveal the secret to claim the payment
  const status = await getServerStatus(serverUrl);
  const auth = buildAuthHeader(kp.privHex, kp.pubHex, kp.addr, 'claim-message', resolveAuthAudience(status), messageId);
  const r = await http(
    'POST',
    `${serverUrl}/inbox/${messageId}/claim`,
    { secret: decrypted.secret },
    { 'x-mailslot-auth': auth },
  );
  if (!r.ok) throw new Error(`claimMessage failed: ${r.status} ${JSON.stringify(r.data)}`);

  return {
    id: messageId,
    from: preview.from,
    sentAt: preview.sentAt,
    amount: preview.amount,
    subject: decrypted.subject,
    body: decrypted.body,
    secret: decrypted.secret,
  };
}

/**
 * Read and claim all new (unclaimed) messages in your inbox.
 * Returns fully decrypted messages.
 */
export async function readNewMessages(
  privkeyHex: string,
  serverUrl: string = DEFAULTS.SERVER_URL,
): Promise<DecryptedMessage[]> {
  const inbox = await getInbox(privkeyHex, serverUrl, false);
  const unclaimed = inbox.filter(m => !m.claimed);
  const results: DecryptedMessage[] = [];
  for (const entry of unclaimed) {
    try {
      results.push(await claimMessage(entry.id, privkeyHex, serverUrl));
    } catch (e) {
      console.error(`Failed to claim ${entry.id}:`, e);
    }
  }
  return results;
}
