/**
 * Inbox authentication — two formats supported:
 *
 * ── Format 1: agent / programmatic (legacy) ───────────────────────────────────
 * x-stackmail-auth: base64(JSON({ pubkey, payload, signature }))
 *   pubkey:    compressed secp256k1 pubkey (33 bytes hex)
 *   payload:   { action, address, timestamp, messageId? }
 *   signature: compact ECDSA 64-byte r||s over sha256(JSON.stringify(payload))
 *
 * ── Format 2: Stacks wallet (SIP-018 structured data) ────────────────────────
 * x-stackmail-auth: base64(JSON({ type: "sip018", pubkey, message, signature }))
 *   pubkey:    compressed secp256k1 pubkey (33 bytes hex) from wallet
 *   message:   TypedMessage { action, address, timestamp, messageId? } (Clarity types)
 *   signature: 65-byte [recovery, r, s] hex from stx_signStructuredMessage
 *
 * SIP-018 auth domain: name="Stackmail", version="0.6.0", chain-id=<chainId>
 *
 * In both formats the server verifies:
 *   1. signature is valid over the payload / message
 *   2. pubkey hashes to the claimed STX address
 *   3. timestamp is fresh (within authTimestampTtlMs)
 *
 * The pubkey is verified but not stored server-side — senders look up recipient
 * pubkeys from the blockchain (Stacks transaction history via Hiro API).
 */

import { createHash, createHmac, createVerify, timingSafeEqual } from 'node:crypto';
import type { Config } from './types.js';
import type { MessageStore } from './store.js';
import { sip018Verify, type TypedMessage } from './sip018.js';

/** Domain name used for SIP-018 wallet authentication */
export const AUTH_DOMAIN = 'Stackmail';

export class AuthError extends Error {
  readonly statusCode: number;
  readonly reason: string;
  constructor(statusCode: number, message: string, reason: string) {
    super(message);
    this.name = 'AuthError';
    this.statusCode = statusCode;
    this.reason = reason;
  }
}

export interface AuthPayload {
  action: string;
  address: string;    // STX address (SP...)
  timestamp: number;  // unix ms
  audience?: string;
  messageId?: string;
}

export interface AuthResult {
  payload: AuthPayload;
  pubkeyHex: string;
}

export interface InboxSessionPayload {
  address: string;
  exp: number;
}

export function getAuthAudience(config: Config): string {
  const configured = config.authAudience.trim();
  if (configured) return configured;
  if (config.reservoirContractId.trim()) return config.reservoirContractId.trim();
  if (config.serverStxAddress.trim()) return config.serverStxAddress.trim();
  return AUTH_DOMAIN;
}

/**
 * Compute the STX c32check address from a compressed secp256k1 pubkey.
 * STX mainnet: version byte 22 (0x16), testnet: 26 (0x1a)
 *
 * address = c32check_encode(version, hash160(pubkey))
 * hash160 = RIPEMD160(SHA256(pubkey))
 */
export function pubkeyToStxAddress(pubkeyHex: string, testnet = false): string {
  const pubkey = Buffer.from(pubkeyHex.replace(/^0x/, ''), 'hex');

  // hash160: SHA256 then RIPEMD160
  const sha = createHash('sha256').update(pubkey).digest();
  const hash160 = createHash('ripemd160').update(sha).digest();

  // c32check encode
  const version = testnet ? 26 : 22;
  return c32checkEncode(version, hash160);
}

/**
 * Encode a raw hash160 + version byte into an STX c32check address.
 * Used to decode on-chain Clarity principal values.
 */
export function hash160ToStxAddress(hash160Hex: string, version: number): string {
  return c32checkEncode(version, Buffer.from(hash160Hex, 'hex'));
}

// Minimal c32check encoder (no external deps)
const C32_CHARS = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

function c32encode(data: Buffer): string {
  // Treat data as a big-endian big integer, extract 5-bit chunks.
  let n = BigInt('0x' + data.toString('hex') || '0');
  const chars: string[] = [];
  while (n > 0n) {
    chars.push(C32_CHARS[Number(n % 32n)]);
    n /= 32n;
  }
  // Leading zero bytes → leading '0' chars
  for (let i = 0; i < data.length && data[i] === 0; i++) {
    chars.push('0');
  }
  return chars.reverse().join('');
}

function c32checkEncode(version: number, data: Buffer): string {
  const versionBuf = Buffer.from([version]);
  const payload = Buffer.concat([versionBuf, data]);

  // checksum = first 4 bytes of sha256(sha256(payload))
  const h1 = createHash('sha256').update(payload).digest();
  const checksum = createHash('sha256').update(h1).digest().subarray(0, 4);

  const full = Buffer.concat([data, checksum]);
  const encoded = c32encode(full);
  return `S${C32_CHARS[version & 0x1f]}${encoded}`;
}

/**
 * Verify a compact ECDSA secp256k1 signature (64 bytes hex: r||s)
 * over sha256(message) using the given compressed pubkey.
 *
 * Uses Node.js crypto with the 'spki' DER-wrapped key format for secp256k1.
 */
function verifySecp256k1Signature(
  messageJson: string,
  signatureHex: string,
  pubkeyHex: string,
): boolean {
  try {
    const sigBytes = Buffer.from(signatureHex.replace(/^0x/, ''), 'hex');
    if (sigBytes.length !== 64) return false;

    const pubkeyBytes = Buffer.from(pubkeyHex.replace(/^0x/, ''), 'hex');
    if (pubkeyBytes.length !== 33) return false;

    // Wrap compressed pubkey in SubjectPublicKeyInfo (SPKI) DER for secp256k1
    // OID for secp256k1: 1.3.132.0.10 = 2b 81 04 00 0a
    const spki = Buffer.concat([
      Buffer.from('3036301006072a8648ce3d020106052b8104000a032200', 'hex'),
      pubkeyBytes,
    ]);

    // Convert compact (r||s) to DER for Node.js verify
    const r = sigBytes.subarray(0, 32);
    const s = sigBytes.subarray(32);

    // DER-encode each component (add 0x00 prefix if high bit set)
    const derInt = (buf: Buffer): Buffer => {
      const padded = buf[0] & 0x80 ? Buffer.concat([Buffer.from([0x00]), buf]) : buf;
      return Buffer.concat([Buffer.from([0x02, padded.length]), padded]);
    };
    const rDer = derInt(r);
    const sDer = derInt(s);
    const seqContent = Buffer.concat([rDer, sDer]);
    const der = Buffer.concat([Buffer.from([0x30, seqContent.length]), seqContent]);

    const verifier = createVerify('SHA256');
    verifier.update(Buffer.from(messageJson, 'utf-8'));
    return verifier.verify({ key: spki, format: 'der', type: 'spki', dsaEncoding: 'ieee-p1363' }, sigBytes);
  } catch {
    return false;
  }
}

export async function verifyInboxAuth(
  authHeader: string,
  config: Config,
  store: MessageStore,
): Promise<AuthResult> {
  let parsed: Record<string, unknown>;
  try {
    const json = Buffer.from(authHeader, 'base64').toString('utf-8');
    parsed = JSON.parse(json) as Record<string, unknown>;
  } catch {
    throw new AuthError(401, 'invalid auth header encoding', 'invalid-auth-encoding');
  }

  // Route to wallet (SIP-018) or legacy auth based on the 'type' field
  if (parsed['type'] === 'sip018') {
    return verifyWalletAuth(parsed, config, store);
  }
  return verifyLegacyAuth(parsed as { pubkey: string; payload: AuthPayload; signature: string }, config, store);
}

function base64UrlEncode(value: Buffer | string): string {
  return Buffer.from(value).toString('base64url');
}

function base64UrlDecode(value: string): Buffer {
  return Buffer.from(value, 'base64url');
}

function getSessionSecret(config: Config): Buffer {
  return createHash('sha256')
    .update(`stackmail-session-v1|${config.serverPrivateKey}|${config.serverStxAddress}|${config.chainId}`)
    .digest();
}

export function issueInboxSessionToken(address: string, config: Config): { token: string; expiresAt: number } {
  const exp = Date.now() + config.inboxSessionTtlMs;
  const payload: InboxSessionPayload = { address, exp };
  const payloadEncoded = base64UrlEncode(JSON.stringify(payload));
  const sig = createHmac('sha256', getSessionSecret(config)).update(payloadEncoded).digest();
  return {
    token: `${payloadEncoded}.${base64UrlEncode(sig)}`,
    expiresAt: exp,
  };
}

export function verifyInboxSessionToken(token: string, config: Config): InboxSessionPayload {
  const [payloadEncoded, sigEncoded] = token.split('.');
  if (!payloadEncoded || !sigEncoded) {
    throw new AuthError(401, 'invalid inbox session token', 'invalid-session');
  }
  const expectedSig = createHmac('sha256', getSessionSecret(config)).update(payloadEncoded).digest();
  const actualSig = base64UrlDecode(sigEncoded);
  if (actualSig.length !== expectedSig.length || !timingSafeEqual(actualSig, expectedSig)) {
    throw new AuthError(401, 'invalid inbox session token', 'invalid-session');
  }
  let payload: InboxSessionPayload;
  try {
    payload = JSON.parse(base64UrlDecode(payloadEncoded).toString('utf-8')) as InboxSessionPayload;
  } catch {
    throw new AuthError(401, 'invalid inbox session token', 'invalid-session');
  }
  if (!payload.address || typeof payload.address !== 'string' || typeof payload.exp !== 'number') {
    throw new AuthError(401, 'invalid inbox session token', 'invalid-session');
  }
  if (Date.now() > payload.exp) {
    throw new AuthError(401, 'inbox session expired', 'session-expired');
  }
  return payload;
}

/** Format 1: raw secp256k1 sig over sha256(JSON(payload)) — for agents */
async function verifyLegacyAuth(
  parsed: { pubkey: string; payload: AuthPayload; signature: string },
  config: Config,
  store: MessageStore,
): Promise<AuthResult> {
  const { pubkey, payload, signature } = parsed;

  if (!pubkey || typeof pubkey !== 'string') {
    throw new AuthError(401, 'auth header missing pubkey', 'missing-pubkey');
  }
  if (!payload?.action || !payload?.address || !payload?.timestamp) {
    throw new AuthError(401, 'auth payload missing required fields', 'invalid-auth-payload');
  }
  if (!signature || typeof signature !== 'string') {
    throw new AuthError(401, 'auth header missing signature', 'missing-signature');
  }

  const age = Date.now() - payload.timestamp;
  if (age < 0 || age > config.authTimestampTtlMs) {
    throw new AuthError(401, 'auth timestamp expired', 'auth-expired');
  }

  const expectedAudience = getAuthAudience(config);
  if ((payload.audience ?? '') !== expectedAudience) {
    throw new AuthError(401, 'auth audience mismatch', 'audience-mismatch');
  }

  const derivedAddress = pubkeyToStxAddress(pubkey);
  if (derivedAddress !== payload.address) {
    const derivedTestnet = pubkeyToStxAddress(pubkey, true);
    if (derivedTestnet !== payload.address) {
      throw new AuthError(401, 'pubkey does not match claimed address', 'address-mismatch');
    }
  }

  const messageJson = JSON.stringify(payload);
  if (!verifySecp256k1Signature(messageJson, signature, pubkey)) {
    throw new AuthError(401, 'invalid signature', 'invalid-signature');
  }

  return { payload, pubkeyHex: pubkey };
}

/** Format 2: SIP-018 structured data sig from Stacks wallet (stx_signStructuredMessage) */
async function verifyWalletAuth(
  parsed: Record<string, unknown>,
  config: Config,
  store: MessageStore,
): Promise<AuthResult> {
  const pubkey    = typeof parsed['pubkey']    === 'string' ? parsed['pubkey']    : '';
  const message   = parsed['message'] as TypedMessage | undefined;
  const signature = typeof parsed['signature'] === 'string' ? parsed['signature'] : '';

  if (!pubkey)    throw new AuthError(401, 'wallet auth missing pubkey',    'missing-pubkey');
  if (!message)   throw new AuthError(401, 'wallet auth missing message',   'missing-message');
  if (!signature) throw new AuthError(401, 'wallet auth missing signature', 'missing-signature');

  // Extract payload fields from the TypedMessage
  const action    = String((message['action']    as { value?: unknown })?.value    ?? '');
  const address   = String((message['address']   as { value?: unknown })?.value   ?? '');
  const tsRaw     = (message['timestamp'] as { value?: unknown })?.value;
  const timestamp = typeof tsRaw === 'bigint' ? Number(tsRaw) : Number(String(tsRaw ?? '0'));
  const msgIdRaw  = (message['messageId'] as { value?: unknown })?.value;
  const messageId = msgIdRaw != null ? String(msgIdRaw) : undefined;
  const audience = String((message['audience'] as { value?: unknown })?.value ?? '');

  if (!action || !address || !timestamp || !audience) {
    throw new AuthError(401, 'wallet auth message missing required fields', 'invalid-auth-payload');
  }

  const age = Date.now() - timestamp;
  if (age < 0 || age > config.authTimestampTtlMs) {
    throw new AuthError(401, 'auth timestamp expired', 'auth-expired');
  }

  if (audience !== getAuthAudience(config)) {
    throw new AuthError(401, 'auth audience mismatch', 'audience-mismatch');
  }

  // Verify pubkey matches claimed address
  const derivedAddress = pubkeyToStxAddress(pubkey);
  if (derivedAddress !== address) {
    const derivedTestnet = pubkeyToStxAddress(pubkey, true);
    if (derivedTestnet !== address) {
      throw new AuthError(401, 'pubkey does not match claimed address', 'address-mismatch');
    }
  }

  // Verify SIP-018 signature using AUTH_DOMAIN as the contract/domain name
  const valid = await sip018Verify(AUTH_DOMAIN, message, signature, address, config.chainId);
  if (!valid) {
    throw new AuthError(401, 'invalid wallet signature', 'invalid-signature');
  }

  const payload: AuthPayload = {
    action: action as AuthPayload['action'],
    address,
    timestamp,
    audience,
    ...(messageId != null ? { messageId } : {}),
  };
  return { payload, pubkeyHex: pubkey };
}
