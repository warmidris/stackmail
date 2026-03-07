/**
 * Stackmail ECIES encryption over secp256k1
 *
 * Encrypt to a recipient's STX public key (compressed, 33 bytes).
 * Uses only Node.js built-in crypto — no external dependencies.
 *
 * Scheme:
 *   1. Generate ephemeral secp256k1 keypair (esk, epk)
 *   2. shared = ECDH(esk, recipient_pubkey)
 *   3. key = HKDF-SHA256(shared, salt="stackmail-v1", info="encrypt", len=32)
 *   4. ciphertext = AES-256-GCM(key, iv=random_12, plaintext=JSON(MailPayload))
 *   5. output = { v, epk, iv, data: ciphertext || auth_tag }
 */

import {
  createECDH,
  createCipheriv,
  createDecipheriv,
  createHash,
  hkdfSync,
  randomBytes,
} from 'node:crypto';

const HKDF_SALT = Buffer.from('stackmail-v1', 'utf-8');
const HKDF_INFO = Buffer.from('encrypt', 'utf-8');
const AES_KEY_LEN = 32;
const IV_LEN = 12;
const AUTH_TAG_LEN = 16;

// ─── Types ───────────────────────────────────────────────────────────────────

/**
 * The plaintext payload encrypted inside every message.
 * Both the payment secret and message content live here together,
 * so neither is accessible without the recipient's private key.
 */
export interface MailPayload {
  /** Schema version */
  v: 1;
  /** 32-byte hex HTLC preimage. hash256(secret) == hashedSecret in the payment. */
  secret: string;
  /** Optional subject line, max 100 chars */
  subject?: string;
  /** Message body */
  body: string;
}

/**
 * The encrypted envelope stored by the server and returned to the recipient.
 * All fields are lowercase hex strings (no 0x prefix).
 */
export interface EncryptedMail {
  /** Schema version */
  v: 1;
  /** Sender's ephemeral compressed secp256k1 pubkey, 33 bytes hex */
  epk: string;
  /** AES-GCM nonce/IV, 12 bytes hex */
  iv: string;
  /** AES-256-GCM ciphertext || auth_tag, hex */
  data: string;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function stripHex(s: string): string {
  return s.startsWith('0x') || s.startsWith('0X') ? s.slice(2) : s;
}

function deriveKey(sharedSecret: Buffer): Buffer {
  return Buffer.from(hkdfSync('sha256', sharedSecret, HKDF_SALT, HKDF_INFO, AES_KEY_LEN));
}

// ─── Public API ──────────────────────────────────────────────────────────────

/**
 * Encrypt a MailPayload for a recipient identified by their compressed
 * secp256k1 public key (33 bytes hex, with or without 0x prefix).
 *
 * This is what the sender calls before POSTing to the mailbox server.
 */
export function encryptMail(payload: MailPayload, recipientPubkeyHex: string): EncryptedMail {
  const recipientPubkey = Buffer.from(stripHex(recipientPubkeyHex), 'hex');
  if (recipientPubkey.length !== 33) {
    throw new TypeError(`recipientPubkey must be 33 bytes (compressed), got ${recipientPubkey.length}`);
  }

  // Ephemeral keypair
  const ecdh = createECDH('secp256k1');
  ecdh.generateKeys();
  const epk = ecdh.getPublicKey(undefined, 'compressed'); // 33 bytes

  // Shared secret + key derivation
  const sharedSecret = ecdh.computeSecret(recipientPubkey);
  const key = deriveKey(sharedSecret);

  // Encrypt
  const iv = randomBytes(IV_LEN);
  const plaintext = Buffer.from(JSON.stringify(payload), 'utf-8');
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag(); // 16 bytes

  return {
    v: 1,
    epk: epk.toString('hex'),
    iv: iv.toString('hex'),
    data: Buffer.concat([ciphertext, authTag]).toString('hex'),
  };
}

/**
 * Decrypt an EncryptedMail using the recipient's secp256k1 private key
 * (32 bytes hex, with or without 0x prefix).
 *
 * This is what the recipient calls after polling and receiving the ciphertext.
 */
export function decryptMail(encrypted: EncryptedMail, privkeyHex: string): MailPayload {
  const privkey = Buffer.from(stripHex(privkeyHex), 'hex');
  if (privkey.length !== 32) {
    throw new TypeError(`privkey must be 32 bytes, got ${privkey.length}`);
  }

  const epk = Buffer.from(stripHex(encrypted.epk), 'hex');
  const iv = Buffer.from(stripHex(encrypted.iv), 'hex');
  const combined = Buffer.from(stripHex(encrypted.data), 'hex');

  if (epk.length !== 33) throw new TypeError('epk must be 33 bytes (compressed)');
  if (iv.length !== IV_LEN) throw new TypeError(`iv must be ${IV_LEN} bytes`);
  if (combined.length < AUTH_TAG_LEN) throw new TypeError('data too short');

  // ECDH
  const ecdh = createECDH('secp256k1');
  ecdh.setPrivateKey(privkey);
  const sharedSecret = ecdh.computeSecret(epk);
  const key = deriveKey(sharedSecret);

  // Decrypt
  const ciphertext = combined.subarray(0, combined.length - AUTH_TAG_LEN);
  const authTag = combined.subarray(combined.length - AUTH_TAG_LEN);
  const decipher = createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(authTag);

  let plaintext: Buffer;
  try {
    plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    throw new Error('decryption failed: wrong key or corrupted ciphertext');
  }

  return JSON.parse(plaintext.toString('utf-8')) as MailPayload;
}

/**
 * Compute the HTLC hash that goes into the StackFlow payment proof.
 * hash = SHA-256(secret_bytes)
 *
 * Both sender (when creating the payment) and recipient (when verifying)
 * use this to confirm hash(secret) == hashedSecret.
 */
export function hashSecret(secretHex: string): string {
  const bytes = Buffer.from(stripHex(secretHex), 'hex');
  return createHash('sha256').update(bytes).digest('hex');
}

/**
 * Verify that hash(secret) == hashedSecret.
 * Call this after decrypting to confirm the payment proof is consistent
 * with the encrypted secret before revealing.
 */
export function verifySecretHash(secretHex: string, hashedSecretHex: string): boolean {
  const computed = hashSecret(secretHex);
  const expected = stripHex(hashedSecretHex).toLowerCase();
  return computed === expected;
}
