/**
 * Inbox authentication
 *
 * Recipients prove ownership of their STX address by signing a challenge
 * with their secp256k1 private key.
 *
 * Auth header: x-stackmail-auth: base64(JSON({ pubkey, payload, signature }))
 *
 * Where:
 *   pubkey:    compressed secp256k1 pubkey (33 bytes hex) corresponding to the STX address
 *   payload:   { action, address, timestamp, messageId? }
 *   signature: compact ECDSA signature (64 bytes hex: r||s) over sha256(JSON(payload))
 *
 * Server verifies:
 *   1. signature is valid over payload using pubkey
 *   2. pubkey hashes to the claimed STX address (c32-encoded hash160)
 *   3. timestamp is fresh (within authTimestampTtlMs)
 *
 * On first successful auth, the pubkey is stored for the address (enabling
 * GET /payment-info/{addr} to return it for senders).
 */

import { createHash, createVerify } from 'node:crypto';
import type { Config } from './types.js';
import type { MessageStore } from './store.js';

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
  action: 'get-inbox' | 'claim-message' | 'get-message';
  address: string;    // STX address (SP...)
  timestamp: number;  // unix ms
  messageId?: string;
}

export interface AuthResult {
  payload: AuthPayload;
  pubkeyHex: string;
}

/**
 * Compute the STX c32check address from a compressed secp256k1 pubkey.
 * STX mainnet: version byte 22 (0x16), testnet: 26 (0x1a)
 *
 * address = c32check_encode(version, hash160(pubkey))
 * hash160 = RIPEMD160(SHA256(pubkey))
 */
function pubkeyToStxAddress(pubkeyHex: string, testnet = false): string {
  const pubkey = Buffer.from(pubkeyHex.replace(/^0x/, ''), 'hex');

  // hash160: SHA256 then RIPEMD160
  const sha = createHash('sha256').update(pubkey).digest();
  const hash160 = createHash('ripemd160').update(sha).digest();

  // c32check encode
  const version = testnet ? 26 : 22;
  return c32checkEncode(version, hash160);
}

// Minimal c32check encoder (no external deps)
const C32_CHARS = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

function c32encode(data: Buffer): string {
  let result = '';
  let carry = 0;
  let carryBits = 0;

  for (let i = data.length - 1; i >= 0; i--) {
    const b = data[i];
    const val = (b << carryBits) | carry;
    result = C32_CHARS[val & 0x1f] + result;
    carryBits += 3;
    carry = b >> (8 - carryBits + 3);
    if (carryBits >= 5) {
      result = C32_CHARS[carry & 0x1f] + result;
      carryBits -= 5;
      carry = b >> (8 - carryBits);
    }
  }

  if (carryBits > 0) {
    result = C32_CHARS[carry & 0x1f] + result;
  }

  // Leading zero bytes → leading 0s in c32
  for (let i = 0; i < data.length && data[i] === 0; i++) {
    result = '0' + result;
  }

  return result;
}

function c32checkEncode(version: number, data: Buffer): string {
  const versionBuf = Buffer.from([version]);
  const payload = Buffer.concat([versionBuf, data]);

  // checksum = first 4 bytes of sha256(sha256(payload))
  const h1 = createHash('sha256').update(payload).digest();
  const checksum = createHash('sha256').update(h1).digest().subarray(0, 4);

  const full = Buffer.concat([data, checksum]);
  const encoded = c32encode(full);
  return `SP${C32_CHARS[version & 0x1f]}${encoded}`;
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
  let parsed: { pubkey: string; payload: AuthPayload; signature: string };
  try {
    const json = Buffer.from(authHeader, 'base64').toString('utf-8');
    parsed = JSON.parse(json) as typeof parsed;
  } catch {
    throw new AuthError(401, 'invalid auth header encoding', 'invalid-auth-encoding');
  }

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

  // Timestamp freshness
  const age = Date.now() - payload.timestamp;
  if (age < 0 || age > config.authTimestampTtlMs) {
    throw new AuthError(401, 'auth timestamp expired', 'auth-expired');
  }

  // Verify pubkey corresponds to claimed STX address
  const derivedAddress = pubkeyToStxAddress(pubkey);
  if (derivedAddress !== payload.address) {
    // Also try testnet
    const derivedTestnet = pubkeyToStxAddress(pubkey, true);
    if (derivedTestnet !== payload.address) {
      throw new AuthError(401, 'pubkey does not match claimed address', 'address-mismatch');
    }
  }

  // Verify signature
  const messageJson = JSON.stringify(payload);
  if (!verifySecp256k1Signature(messageJson, signature, pubkey)) {
    throw new AuthError(401, 'invalid signature', 'invalid-signature');
  }

  // Store pubkey on first successful auth (makes it available for senders)
  await store.savePublicKey(payload.address, pubkey).catch(() => {
    // Non-fatal
  });

  return { payload, pubkeyHex: pubkey };
}
